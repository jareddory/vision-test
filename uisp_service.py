#!/usr/bin/env python3
# UISP Service
# Last updated: 2026-11-14
# Changes: POST /twilio/inbound validates X-Twilio-Signature and forwards inbound SMS
#          to the chief webhook, then returns empty TwiML.
#          /rename-cpe keeps going when UISP saves the alias but returns an error
#          (422 "Failed to update wireless device hostname by alias."), then pushes
#          a sanitized airOS hostname. The UISP alias is stored exactly as sent.
#          /cancel-cpe is delete-only. It does not check reachability and does not reboot.
#          Vision owns reboot and manual kick-on-fail before calling cancel.
#          find_device_cancel identity rules and empty-site delete are unchanged.
import os, re, ipaddress, logging, time
from datetime import datetime, timezone
from typing import Any, List
from urllib.parse import parse_qsl
import requests
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, Response
from twilio.request_validator import RequestValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uisp")

app = FastAPI(title="UISP Service")
UISP_BASE = os.getenv("UISP_BASE_URL", "https://btwi.uisp.com/nms/api/v2.1").rstrip("/")
UISP_TOKEN = os.getenv("UISP_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
if not UISP_TOKEN or not WEBHOOK_SECRET:
    raise RuntimeError("UISP_TOKEN and WEBHOOK_SECRET required")

HEADERS = {"x-auth-token": UISP_TOKEN, "Accept": "application/json"}
SITE_DELETE_DELAY = 15  # seconds to wait after device delete before checking if site is empty

# /rename-cpe settings
# Separator between customer name and optional location. Placeholder until Jared finalizes it.
RENAME_LOCATION_SEPARATOR = os.getenv("RENAME_LOCATION_SEPARATOR", " - ")
# UISP alias limit: PayloadUnmsSettings.meta.alias has maxLength 30 in the NMS v2.1 spec.
UISP_ALIAS_MAX = 30
# airOS system.hostname is pushed only for these UISP identification.type values (comma list).
# airMax is the documented airOS family; add others (e.g. airFiber) only after testing on a real unit.
RENAME_HOSTNAME_AIROS_TYPES = {
    t.strip().lower() for t in os.getenv("RENAME_HOSTNAME_AIROS_TYPES", "airMax").split(",") if t.strip()
}
# Master switch for the radio push. Request param push_hostname can turn it off per call.
RENAME_PUSH_HOSTNAME = os.getenv("RENAME_PUSH_HOSTNAME", "true").strip().lower() in ("1", "true", "yes")
# Substituted for each whitespace run in the radio hostname only. The UISP alias is not changed.
RENAME_HOSTNAME_SPACE_CHAR = os.getenv("RENAME_HOSTNAME_SPACE_CHAR", "-")
# airOS 8 user guide describes Device Name but does not document a max length. 32 is the cap we send.
AIROS_HOSTNAME_MAX = 32
# Hyphen at the end so it is literal. A hyphen between 9 and _ would be a character range.
_HOSTNAME_DISALLOWED = re.compile(r"[^A-Za-z0-9_.-]")
# Keys accepted by PUT /devices/{id}/system/unms (PayloadUnmsSettings).
_UNMS_PAYLOAD_KEYS = ("overrideGlobal", "devicePingAddress", "devicePingIntervalNormal",
                      "devicePingIntervalOutage", "deviceTransmissionFrequency", "deviceGracePeriodOutage")
_UNMS_META_KEYS = ("alias", "note", "maintenance", "customIpAddress")

def norm_mac(v: Any) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", str(v or "")).upper()

def norm_ip(v: Any) -> str:
    s = str(v or "").split("/")[0].strip()
    try:
        ip = ipaddress.ip_address(s)
        return str(ip) if ip.version == 4 else ""
    except:
        return ""

def device_ips(d: dict) -> List[str]:
    addrs = []
    if d.get("ipAddress"): addrs.append(d["ipAddress"])
    if d.get("ipAddressList"):
        lst = d["ipAddressList"]
        addrs.extend(lst if isinstance(lst, list) else [lst])
    return list({norm_ip(a) for a in addrs if norm_ip(a)})

def safe_ident(d: dict) -> dict:
    return d.get("identification") or {}

def safe_site_id(d: dict) -> str:
    ident = safe_ident(d)
    site = ident.get("site") or {}
    return str(site.get("id") or "")

def check_secret(req: Request, hdr: str | None):
    if (hdr or req.query_params.get("secret")) != WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid or missing webhook secret")

def get_devices():
    r = requests.get(f"{UISP_BASE}/devices", headers=HEADERS, timeout=60)
    r.raise_for_status()
    raw = r.json()
    return raw if isinstance(raw, list) else raw.get("items") or raw.get("data") or []

def is_infra(device: dict) -> bool:
    ident = safe_ident(device)
    role = str(ident.get("role") or "") + str(ident.get("category") or "")
    return bool(re.search(r"(?i)ap|backhaul|gateway|router|switch|tower|access\.point|ptp", role))

def find_device_strict(mac: str, ip: str) -> dict:
    matches = [d for d in get_devices() if norm_mac(safe_ident(d).get("mac")) == mac]
    if len(matches) != 1:
        raise HTTPException(409, f"MAC did not uniquely identify a device (found {len(matches)})")
    if ip not in device_ips(matches[0]):
        raise HTTPException(409, "MAC matched but management IP did not match")
    if is_infra(matches[0]):
        raise HTTPException(403, "Potential infrastructure device — refused")
    return matches[0]

def find_device_cancel(mac: str, ip: str, name: str) -> tuple:
    """Returns (device, match_method). Tries MAC+IP first, then MAC+name (handles reversed/no-space names)."""
    devices = get_devices()
    mac_matches = [d for d in devices if norm_mac(safe_ident(d).get("mac")) == mac]
    if len(mac_matches) != 1:
        raise HTTPException(409, f"MAC did not uniquely identify a device (found {len(mac_matches)})")
    device = mac_matches[0]
    if is_infra(device):
        raise HTTPException(403, "Potential infrastructure device — refused")
    if ip and ip in device_ips(device):
        return device, "mac+ip"
    if name:
        dev_name = re.sub(r"[^a-z0-9]", "", str(safe_ident(device).get("name") or "").lower())
        input_clean = re.sub(r"[^a-z0-9]", "", name.lower())
        if dev_name and input_clean:
            if input_clean in dev_name or dev_name in input_clean:
                return device, "mac+name"
            for size in range(min(len(input_clean), 8), 3, -1):
                for i in range(len(input_clean) - size + 1):
                    if input_clean[i:i+size] in dev_name:
                        return device, "mac+name"
    raise HTTPException(409, "MAC matched but neither IP nor name matched")

def log_req(ep, wid, mac, ip, result, detail=""):
    log.info("workflow_id=%s endpoint=%s mac=%s ip=%s result=%s %s", wid or "-", ep, mac or "-", ip or "-", result, detail)

def ok(data: dict, status=200):
    data["result"] = "success"
    data["success"] = True
    return JSONResponse(data, status_code=status)

def fail(message: str, status=400, extra: dict = None):
    body = {"result": "failed", "success": False, "message": message}
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status)

@app.api_route("/remove-cpe", methods=["GET", "POST"])
async def remove_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    delete_site = str(data.get("delete_site") or "").lower() in ("1", "true", "yes")
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    try:
        dev = find_device_strict(mac, ip)
        ident = safe_ident(dev)
        did = str(ident.get("id") or "")
        site_id = safe_site_id(dev) or None
        url = f"{UISP_BASE}/devices/{did}"
        fr = requests.get(url, headers=HEADERS, timeout=45)
        fr.raise_for_status()
        fresh = fr.json()
        if (str(safe_ident(fresh).get("id") or "") != did or
            norm_mac(safe_ident(fresh).get("mac")) != mac or
            ip not in device_ips(fresh)):
            return fail("Fresh identity check failed", 409, {"workflow_id": wid})
        dr = requests.delete(url, headers=HEADERS, timeout=60)
        if dr.status_code not in (200, 204):
            return fail(f"UISP DELETE failed: {dr.text}", dr.status_code, {"workflow_id": wid})
        site_deleted, site_msg = False, None
        if delete_site and site_id:
            time.sleep(SITE_DELETE_DELAY)
            still = [d for d in get_devices() if safe_site_id(d) == site_id]
            if not still:
                sr = requests.delete(f"{UISP_BASE}/sites/{site_id}", headers=HEADERS, timeout=45)
                site_deleted = sr.status_code in (200, 204)
                site_msg = "Empty site also removed" if site_deleted else f"Site delete failed: {sr.status_code} {sr.text}"
            else:
                site_msg = f"Site not empty ({len(still)} device(s) remain)"
        log_req("/remove-cpe", wid, mac, ip, "success", f"device_id={did}")
        return ok({
            "message": "CPE removed from UISP",
            "workflow_id": wid, "device_id": did, "mac": mac, "ip": ip,
            "name": ident.get("name"), "site_id": site_id,
            "site_deleted": site_deleted, "site_message": site_msg
        })
    except HTTPException as e:
        log_req("/remove-cpe", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/remove-cpe", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

@app.api_route("/reboot-cpe", methods=["GET", "POST"])
async def reboot_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    try:
        dev = find_device_strict(mac, ip)
        did = str(safe_ident(dev).get("id") or "")
        status = str(dev.get("overview", {}).get("status") or dev.get("status") or "").lower()
        if status in ("disconnected", "offline", "inactive", "unreachable", "down", ""):
            return fail("UISP cannot currently communicate with this device. It may be offline or unreachable. Please check power and connectivity before retrying.", 409, {"workflow_id": wid})
        rr = requests.post(f"{UISP_BASE}/devices/{did}/reboot", headers=HEADERS, timeout=45)
        if rr.status_code not in (200, 202, 204):
            return fail(f"Reboot command failed: {rr.text}", rr.status_code, {"workflow_id": wid})
        log_req("/reboot-cpe", wid, mac, ip, "success", f"device_id={did}")
        return ok({
            "message": "Reboot command sent",
            "workflow_id": wid, "device_id": did, "mac": mac, "ip": ip,
            "name": safe_ident(dev).get("name"), "status": status
        })
    except HTTPException as e:
        log_req("/reboot-cpe", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/reboot-cpe", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

@app.api_route("/cancel-cpe", methods=["GET", "POST"])
async def cancel_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    """Delete the matched CPE only. Do not check reachability and do not reboot.

    Vision reboots the CPE and handles a manual kick if that reboot fails, then calls
    this endpoint. Identity stays in find_device_cancel. An empty site is still removed
    after the device delete.
    """
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid = data.get("workflow_id") or ""
    mac = norm_mac(data.get("mac"))
    ip = norm_ip(data.get("ip"))
    name = (data.get("name") or "").strip()
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    try:
        dev, method = find_device_cancel(mac, ip, name)
        ident = safe_ident(dev)
        did = str(ident.get("id") or "")
        site_id = safe_site_id(dev) or None
        action = "device_deleted"
        dr = requests.delete(f"{UISP_BASE}/devices/{did}", headers=HEADERS, timeout=60)
        if dr.status_code not in (200, 204):
            return fail(f"Device delete failed: {dr.text}", dr.status_code, {"workflow_id": wid})
        site_deleted, site_msg = False, None
        if site_id:
            time.sleep(SITE_DELETE_DELAY)
            still = [d for d in get_devices() if safe_site_id(d) == site_id]
            if not still:
                sr = requests.delete(f"{UISP_BASE}/sites/{site_id}", headers=HEADERS, timeout=45)
                site_deleted = sr.status_code in (200, 204)
                site_msg = "Empty site also removed" if site_deleted else f"Site delete failed: {sr.status_code} {sr.text}"
            else:
                site_msg = f"Site not empty ({len(still)} device(s) remain)"
        log_req("/cancel-cpe", wid, mac, ip, "success", f"{action} method={method}")
        return ok({
            "message": "Cancel complete — device removed",
            "action": action,
            "workflow_id": wid,
            "device_id": did,
            "mac": mac,
            "name": ident.get("name"),
            "match_method": method,
            "site_id": site_id,
            "site_deleted": site_deleted,
            "site_message": site_msg
        })
    except HTTPException as e:
        log_req("/cancel-cpe", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/cancel-cpe", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

@app.api_route("/outage-check", methods=["GET", "POST"])
async def outage_check(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    try:
        dev = find_device_strict(mac, ip)
        did = str(safe_ident(dev).get("id") or "")
        status = dev.get("overview", {}).get("status") or dev.get("status")
        last_seen = dev.get("overview", {}).get("lastSeen") or dev.get("lastSeen")
        outages = []
        try:
            orr = requests.get(f"{UISP_BASE}/outages", headers=HEADERS, timeout=30, params={"deviceId": did})
            if orr.status_code == 200:
                raw = orr.json()
                outages = raw if isinstance(raw, list) else raw.get("items") or raw.get("data") or []
        except: pass
        in_outage = len(outages) > 0 or str(status).lower() in ("disconnected", "offline", "inactive")
        log_req("/outage-check", wid, mac, ip, "success", f"in_outage={in_outage}")
        return ok({
            "workflow_id": wid, "device_id": did, "mac": mac, "ip": ip,
            "name": safe_ident(dev).get("name"), "status": status,
            "last_seen": last_seen, "in_outage": in_outage, "active_outages": len(outages)
        })
    except HTTPException as e:
        log_req("/outage-check", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/outage-check", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

@app.api_route("/device-status", methods=["GET", "POST"])
async def device_status(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    try:
        dev = find_device_strict(mac, ip)
        did = str(safe_ident(dev).get("id") or "")
        dr = requests.get(f"{UISP_BASE}/devices/{did}", headers=HEADERS, timeout=45)
        dr.raise_for_status()
        detail = dr.json()
        ov = detail.get("overview") or {}
        ident = safe_ident(detail)
        fw = detail.get("firmware") or {}
        signal = next((i.get("wireless") for i in (detail.get("interfaces") or []) if isinstance(i, dict) and i.get("wireless")), None)
        log_req("/device-status", wid, mac, ip, "success")
        return ok({
            "workflow_id": wid, "device_id": did, "mac": mac, "ip": ip,
            "name": ident.get("name"), "status": ov.get("status"), "last_seen": ov.get("lastSeen"),
            "uptime": ov.get("uptime"), "cpu": ov.get("cpu"), "ram": ov.get("ram"),
            "firmware_version": fw.get("version") or ident.get("firmwareVersion"),
            "model": ident.get("model"), "signal": signal, "site_id": safe_site_id(detail) or None
        })
    except HTTPException as e:
        log_req("/device-status", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/device-status", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

@app.api_route("/signal-history", methods=["GET", "POST"])
async def signal_history(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    interval = data.get("interval") or "day"
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    try:
        dev = find_device_strict(mac, ip)
        did = str(safe_ident(dev).get("id") or "")
        sr = requests.get(f"{UISP_BASE}/devices/{did}/statistics", headers=HEADERS, timeout=45, params={"interval": interval})
        stats = sr.json() if sr.status_code == 200 else {"note": "non-200", "status_code": sr.status_code}
        log_req("/signal-history", wid, mac, ip, "success", f"interval={interval}")
        return ok({
            "workflow_id": wid, "device_id": did, "mac": mac, "ip": ip,
            "name": safe_ident(dev).get("name"), "interval": interval, "statistics": stats
        })
    except HTTPException as e:
        log_req("/signal-history", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except Exception as e:
        log_req("/signal-history", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, {"workflow_id": wid})

def truthy(v: Any) -> bool:
    return str(v if v is not None else "").strip().lower() in ("1", "true", "yes", "on")

def build_rename(name: Any, location: Any) -> str:
    """Name exactly as Vision sent it (outer whitespace trimmed). A non-blank location is appended."""
    base = str(name or "").strip()
    loc = str(location or "").strip()
    return f"{base}{RENAME_LOCATION_SEPARATOR}{loc}" if loc else base

def _uisp_err(resp) -> str:
    return f"{resp.status_code} {getattr(resp, 'text', '')}".strip()

class UispCallError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status

def uisp_get_json(url: str) -> dict:
    r = requests.get(url, headers=HEADERS, timeout=45)
    if r.status_code != 200:
        raise UispCallError(f"UISP GET {url.replace(UISP_BASE, '')} failed: {_uisp_err(r)}")
    return r.json() or {}

def unms_payload(current: dict, alias: str) -> dict:
    """Body for PUT /devices/{id}/system/unms that keeps current settings and changes only meta.alias."""
    body = {k: current[k] for k in _UNMS_PAYLOAD_KEYS if current.get(k) is not None}
    body["overrideGlobal"] = bool(current.get("overrideGlobal", False))
    meta_cur = current.get("meta") or {}
    meta = {k: meta_cur[k] for k in _UNMS_META_KEYS if meta_cur.get(k) is not None}
    meta["maintenance"] = bool(meta_cur.get("maintenance", False))
    meta["alias"] = alias
    body["meta"] = meta
    return body

def sanitize_hostname(name: Any) -> str:
    """airOS hostname derived from the alias. Does not modify the alias itself.

    Whitespace runs become RENAME_HOSTNAME_SPACE_CHAR (default "-"). Characters
    outside [A-Za-z0-9-_.] are removed, repeated "-" collapse, leading and trailing
    "-" are removed, and the result is capped at AIROS_HOSTNAME_MAX.
    """
    text = re.sub(r"\s+", RENAME_HOSTNAME_SPACE_CHAR, str(name or ""))
    text = _HOSTNAME_DISALLOWED.sub("", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text[:AIROS_HOSTNAME_MAX].strip("-")

def uisp_error_message(resp) -> str:
    """UISP's own error message, preferring JSON `message` over the raw body."""
    body = None
    try:
        body = resp.json()
    except Exception:
        body = None
    if isinstance(body, dict) and str(body.get("message") or "").strip():
        return str(body["message"]).strip()
    text = str(getattr(resp, "text", "") or "").strip()
    return text or f"HTTP {getattr(resp, 'status_code', '')}".strip()

def unms_alias(settings: Any) -> str:
    meta = settings.get("meta") if isinstance(settings, dict) else None
    if not isinstance(meta, dict):
        return ""
    return meta.get("alias") or ""

@app.api_route("/rename-cpe", methods=["GET", "POST"])
async def rename_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    """Rename a CPE in UISP (device alias) and push a sanitized hostname to the radio where supported.

    Strict MAC + management IP match; infrastructure devices refused. New name is the name Vision
    sends (outer whitespace trimmed) plus RENAME_LOCATION_SEPARATOR + location when location is non-blank.
    That string is stored as the UISP alias unchanged.
    UISP:  PUT /devices/{id}/system/unms  (meta.alias). A non-2xx response is still success when a
           re-read shows meta.alias already equals the requested name (UISP 422s after saving the
           alias while trying to sync it onto the radio hostname itself).
    Radio: PUT /devices/airos/{id}/configuration?isComposeRequest=false  (system.hostname), airOS
           types only. The hostname is sanitize_hostname(new_name), not the alias.
    dry_run=true reports what would change and writes nothing. new_name and new_hostname are both returned.
    """
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid, mac, ip = data.get("workflow_id") or "", norm_mac(data.get("mac")), norm_ip(data.get("ip"))
    dry_run = truthy(data.get("dry_run"))
    push_hostname = RENAME_PUSH_HOSTNAME and (data.get("push_hostname") in (None, "") or truthy(data.get("push_hostname")))
    new_name = build_rename(data.get("name"), data.get("location"))
    new_hostname = sanitize_hostname(new_name)
    if not re.fullmatch(r"[A-F0-9]{12}", mac):
        return fail("Invalid or missing MAC", 400, {"workflow_id": wid})
    if not ip:
        return fail("Invalid or missing IP", 400, {"workflow_id": wid})
    if not str(data.get("name") or "").strip():
        return fail("Invalid or missing name", 400, {"workflow_id": wid})
    if len(new_name) > UISP_ALIAS_MAX:
        return fail(f"New name is {len(new_name)} characters; UISP alias limit is {UISP_ALIAS_MAX}", 400,
                    {"workflow_id": wid, "new_name": new_name, "new_hostname": new_hostname})
    did = None
    changed = {"uisp": False, "radio": False}
    uisp_warning = None

    def failure_extra():
        extra = {"workflow_id": wid, "device_id": did, "new_name": new_name,
                 "new_hostname": new_hostname, "changed": changed}
        if uisp_warning:
            extra["uisp_warning"] = uisp_warning
        return extra

    try:
        dev = find_device_strict(mac, ip)
        ident = safe_ident(dev)
        did = str(ident.get("id") or "")
        dev_type = str(ident.get("type") or "")
        old_name = ident.get("displayName") or ident.get("name")
        base = {"workflow_id": wid, "device_id": did, "mac": mac, "ip": ip, "match_method": "mac+ip",
                "device_type": dev_type or None, "old_name": old_name, "new_name": new_name,
                "new_hostname": new_hostname, "dry_run": dry_run}

        # UISP side: current alias from device-specific UISP settings.
        unms = uisp_get_json(f"{UISP_BASE}/devices/{did}/system/unms")
        old_alias = unms_alias(unms)
        # Already named if the alias matches, or there is no alias and the shown name already matches.
        uisp_needed = not (old_alias == new_name or (not old_alias and old_name == new_name))

        # Radio side: airOS hostname, only for configured types. Compare against the sanitized hostname.
        radio_supported = dev_type.lower() in RENAME_HOSTNAME_AIROS_TYPES
        radio_status, old_hostname, airos_cfg = None, None, None
        if not push_hostname:
            radio_status = "skipped_disabled"
        elif not radio_supported:
            radio_status = "unsupported_device_type"
        elif not new_hostname:
            radio_status = "skipped_empty_hostname"
        else:
            airos_cfg = uisp_get_json(f"{UISP_BASE}/devices/airos/{did}/configuration")
            old_hostname = (airos_cfg.get("system") or {}).get("hostname")
            radio_status = "already_named" if old_hostname == new_hostname else "pending"
        base["old_hostname"] = old_hostname
        radio_needed = radio_status == "pending"

        if not uisp_needed and not radio_needed:
            log_req("/rename-cpe", wid, mac, ip, "success", f"device_id={did} no_change")
            return ok({**base, "message": "Already named — no change", "changed": changed,
                       "would_change": changed, "radio_status": radio_status})

        if dry_run:
            would = {"uisp": uisp_needed, "radio": radio_needed}
            log_req("/rename-cpe", wid, mac, ip, "success", f"device_id={did} dry_run would={would}")
            return ok({**base, "message": "Dry run — no changes made", "changed": changed,
                       "would_change": would, "radio_status": "would_push" if radio_needed else radio_status})

        if uisp_needed:
            ur = requests.put(f"{UISP_BASE}/devices/{did}/system/unms", headers=HEADERS, timeout=45,
                              json=unms_payload(unms, new_name))
            if ur.status_code in (200, 204):
                changed["uisp"] = True
            else:
                # UISP writes meta.alias, then tries to copy that alias onto the radio hostname
                # and returns 422 "Failed to update wireless device hostname by alias." when the
                # copy fails. The alias is what this step owns; the hostname push below is ours.
                warning = uisp_error_message(ur)
                try:
                    fresh = uisp_get_json(f"{UISP_BASE}/devices/{did}/system/unms")
                except UispCallError as read_err:
                    raise UispCallError(
                        f"UISP rename failed: {_uisp_err(ur)} (alias re-read failed: {read_err})",
                        ur.status_code if ur.status_code >= 400 else 502,
                    )
                if unms_alias(fresh) != new_name:
                    raise UispCallError(
                        f"UISP rename failed: {_uisp_err(ur)}",
                        ur.status_code if ur.status_code >= 400 else 502,
                    )
                changed["uisp"] = True
                uisp_warning = warning

        if radio_needed:
            system = dict(airos_cfg.get("system") or {})
            system["hostname"] = new_hostname
            rr = requests.put(f"{UISP_BASE}/devices/airos/{did}/configuration", headers=HEADERS, timeout=60,
                              params={"isComposeRequest": "false"}, json={"system": system})
            if rr.status_code not in (200, 202, 204):
                raise UispCallError(f"Radio hostname push failed: {_uisp_err(rr)}", rr.status_code if rr.status_code >= 400 else 502)
            try:
                st = rr.json() if rr.status_code == 200 else {}
            except Exception:
                st = {}
            if isinstance(st, dict) and st.get("result") is False:
                raise UispCallError(f"Radio hostname push failed: {st.get('message') or 'UISP returned result=false'}")
            changed["radio"] = True
            radio_status = "pushed"

        detail = f"device_id={did} changed={changed}"
        if uisp_warning:
            detail += f" uisp_warning={uisp_warning}"
        log_req("/rename-cpe", wid, mac, ip, "success", detail)
        body = {**base, "message": "CPE renamed", "changed": changed, "radio_status": radio_status}
        if uisp_warning:
            body["uisp_warning"] = uisp_warning
        return ok(body)
    except HTTPException as e:
        log_req("/rename-cpe", wid, mac, ip, "failed", str(e.detail))
        return fail(str(e.detail), e.status_code, {"workflow_id": wid})
    except UispCallError as e:
        log_req("/rename-cpe", wid, mac, ip, "failed", str(e))
        return fail(str(e), e.status, failure_extra())
    except Exception as e:
        log_req("/rename-cpe", wid, mac, ip, "failed", str(e))
        return fail(str(e), 500, failure_extra())

@app.get("/health")
def health():
    return {"result": "success", "status": "ok"}

# Inbound SMS forwarding. Empty TwiML so Twilio does not auto-reply.
TWIML_EMPTY = '<?xml version="1.0" encoding="UTF-8"?><Response/>'
CHIEF_FORWARD_TIMEOUT = 10
MAX_TWILIO_MEDIA = 20


def _forwarded_first(value: str | None) -> str:
    if not value:
        return ""
    return value.split(",")[0].strip()


def twilio_validation_url(request: Request) -> str:
    """URL Twilio signed: the configured public URL, or the proxy-facing URL.

    Render terminates TLS in front of the app, so request.url is the internal
    address. TWILIO_WEBHOOK_PUBLIC_URL, when set, is used exactly. Otherwise the
    URL is scheme + host + path + query from X-Forwarded-Proto, X-Forwarded-Host
    or Host.
    """
    configured = os.getenv("TWILIO_WEBHOOK_PUBLIC_URL", "").strip()
    if configured:
        return configured
    proto = _forwarded_first(request.headers.get("x-forwarded-proto")) or request.url.scheme
    host = (
        _forwarded_first(request.headers.get("x-forwarded-host"))
        or _forwarded_first(request.headers.get("host"))
        or request.url.netloc
    )
    url = f"{proto.lower()}://{host}{request.url.path}"
    if request.url.query:
        url += "?" + request.url.query
    return url


def twilio_form_params(request_body: bytes) -> dict:
    text = request_body.decode("utf-8")
    return dict(parse_qsl(text, keep_blank_values=True))


def twilio_signature_ok(url: str, params: dict, signature: str, token: str) -> bool:
    try:
        return bool(RequestValidator(token).validate(url, params, signature))
    except Exception:
        return False


def collect_media(params: dict) -> tuple:
    """NumMedia plus MediaUrl0..N paired with MediaContentType0..N."""
    raw = str(params.get("NumMedia", "")).strip()
    declared = None
    if raw:
        try:
            declared = int(raw)
        except ValueError:
            declared = None
    if declared is not None and declared < 0:
        declared = 0
    limit = min(declared if declared is not None else MAX_TWILIO_MEDIA, MAX_TWILIO_MEDIA)
    items = []
    for i in range(limit):
        url_key = f"MediaUrl{i}"
        type_key = f"MediaContentType{i}"
        if url_key not in params and type_key not in params:
            if declared is None:
                break
            continue
        items.append({
            "url": str(params.get(url_key, "")),
            "content_type": str(params.get(type_key, "")),
        })
    num_media = declared if declared is not None else len(items)
    return num_media, items


def chief_key_header() -> tuple:
    """Header name and value for the chief webhook key.

    CHIEF_WEBHOOK_KEY_HEADER defaults to Authorization.
    CHIEF_WEBHOOK_KEY_FORMAT defaults to "Bearer {key}"; "{key}" is replaced
    with CHIEF_WEBHOOK_KEY.
    """
    name = os.getenv("CHIEF_WEBHOOK_KEY_HEADER")
    if name is None or name.strip() == "":
        name = "Authorization"
    else:
        name = name.strip()
    fmt = os.getenv("CHIEF_WEBHOOK_KEY_FORMAT")
    if fmt is None or fmt == "":
        fmt = "Bearer {key}"
    key = os.getenv("CHIEF_WEBHOOK_KEY") or ""
    return name, fmt.replace("{key}", key)


def twilio_forbidden(reason: str) -> Response:
    # reason is a fixed label (missing_auth_token, missing_signature, bad_signature).
    log.info("twilio inbound rejected reason=%s", reason)
    return Response(content="Forbidden", status_code=403, media_type="text/plain")


def twiml_response(forward_status: str) -> Response:
    return Response(
        content=TWIML_EMPTY,
        status_code=200,
        media_type="text/xml",
        headers={
            "Content-Type": "text/xml",
            "X-Forward-Status": forward_status,
        },
    )


def forward_inbound_sms(payload: dict) -> str:
    """POST the inbound SMS JSON to the chief webhook.

    Returns "forwarded" or "failed". On failure, log the HTTP status code only.
    """
    url = os.getenv("CHIEF_WEBHOOK_URL", "").strip()
    if not url:
        log.warning("twilio inbound forward failed status=%s", "none")
        return "failed"
    header_name, header_value = chief_key_header()
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={header_name: header_value},
            timeout=CHIEF_FORWARD_TIMEOUT,
        )
    except Exception:
        log.warning("twilio inbound forward failed status=%s", "none")
        return "failed"
    if not 200 <= resp.status_code < 300:
        log.warning("twilio inbound forward failed status=%s", resp.status_code)
        return "failed"
    return "forwarded"


def inbound_sms_payload(params: dict) -> dict:
    num_media, media_urls = collect_media(params)
    received_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "from": params.get("From", ""),
        "to": params.get("To", ""),
        "body": params.get("Body", ""),
        "num_media": num_media,
        "media_urls": media_urls,
        "message_sid": params.get("MessageSid", ""),
        "received_at": received_at,
    }


@app.post("/twilio/inbound")
async def twilio_inbound(request: Request):
    """Accept Twilio's inbound-message webhook and forward it.

    Validates X-Twilio-Signature with TWILIO_AUTH_TOKEN. Forwards from, to, body,
    num_media, media_urls, message_sid, and received_at to CHIEF_WEBHOOK_URL.
    Always answers with empty TwiML on success so Twilio sends no auto-reply.
    Forward failures still return that 200, with X-Forward-Status: failed.
    """
    token = os.getenv("TWILIO_AUTH_TOKEN")
    if token is None or token.strip() == "":
        return twilio_forbidden("missing_auth_token")
    signature = (request.headers.get("x-twilio-signature") or "").strip()
    if not signature:
        return twilio_forbidden("missing_signature")
    try:
        params = twilio_form_params(await request.body())
    except UnicodeDecodeError:
        return twilio_forbidden("bad_signature")
    if not twilio_signature_ok(twilio_validation_url(request), params, signature, token.strip()):
        return twilio_forbidden("bad_signature")
    payload = inbound_sms_payload(params)
    forward_status = forward_inbound_sms(payload)
    if forward_status == "forwarded":
        sid = "".join(ch for ch in str(payload.get("message_sid") or "") if ch.isalnum())[:34] or "-"
        log.info("twilio inbound accepted message_sid=%s forward=%s", sid, forward_status)
    return twiml_response(forward_status)
