#!/usr/bin/env python3
# UISP Service
# Last updated: 2026-11-05
# Changes: /cancel-cpe is delete-only. It does not check reachability and does not reboot.
#          Vision owns reboot and manual kick-on-fail before calling cancel.
#          find_device_cancel identity rules and empty-site delete are unchanged.
import os, re, ipaddress, logging, time
from typing import Any, List
import requests
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse

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

@app.get("/health")
def health():
    return {"result": "success", "status": "ok"}
