#!/usr/bin/env python3
"""
UISP automation webhooks for Vision.
"""

import os
import re
import ipaddress
import logging
from typing import List, Any

import requests
from fastapi import FastAPI, Request, HTTPException, Header

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uisp-automation")

app = FastAPI(title="UISP Automation")

UISP_BASE = os.getenv("UISP_BASE_URL", "https://btwi.uisp.com/nms/api/v2.1").rstrip("/")
UISP_TOKEN = os.getenv("UISP_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

if not UISP_TOKEN:
    raise RuntimeError("UISP_TOKEN environment variable is required")
if not WEBHOOK_SECRET:
    raise RuntimeError("WEBHOOK_SECRET environment variable is required")

HEADERS = {
    "x-auth-token": UISP_TOKEN,
    "Accept": "application/json",
}


def normalize_mac(value: Any) -> str:
    if not value:
        return ""
    return re.sub(r"[^0-9a-fA-F]", "", str(value)).upper()


def normalize_ip(value: Any) -> str:
    if not value:
        return ""
    s = str(value).strip()
    if "/" in s:
        s = s.split("/")[0]
    try:
        ip = ipaddress.ip_address(s)
        return str(ip) if ip.version == 4 else ""
    except ValueError:
        return ""


def device_ips(device: dict) -> List[str]:
    addresses = []
    if device.get("ipAddress"):
        addresses.append(device["ipAddress"])
    if device.get("ipAddressList"):
        lst = device["ipAddressList"]
        addresses.extend(lst if isinstance(lst, list) else [lst])
    return list({normalize_ip(a) for a in addresses if normalize_ip(a)})


def check_secret(request: Request, header_secret: str | None = None):
    provided = header_secret or request.query_params.get("secret")
    if not provided or provided != WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid or missing webhook secret")


def get_devices() -> list:
    r = requests.get(f"{UISP_BASE}/devices", headers=HEADERS, timeout=60)
    r.raise_for_status()
    raw = r.json()
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and "items" in raw:
        return raw["items"]
    if isinstance(raw, dict) and "data" in raw:
        return raw["data"]
    raise HTTPException(400, "Unrecognized UISP inventory response")


def find_device_by_mac_ip(mac: str, ip: str) -> dict:
    devices = get_devices()
    mac_matches = [
        d for d in devices
        if normalize_mac(d.get("identification", {}).get("mac")) == mac
    ]
    if len(mac_matches) != 1:
        raise HTTPException(409, f"MAC did not uniquely identify a device (found {len(mac_matches)})")

    device = mac_matches[0]
    if ip not in device_ips(device):
        raise HTTPException(409, "MAC matched but management IP did not match")

    ident = device.get("identification", {})
    role = str(ident.get("role") or "")
    category = str(ident.get("category") or "")
    infra_pattern = re.compile(r"(?i)ap|backhaul|gateway|router|switch|tower|access\.point|ptp")
    if infra_pattern.search(role) or infra_pattern.search(category):
        raise HTTPException(403, "Potential infrastructure device — refused")

    return device


def log_request(endpoint: str, workflow_id: str, mac: str, ip: str, result: str, detail: str = ""):
    log.info(
        "workflow_id=%s endpoint=%s mac=%s ip=%s result=%s %s",
        workflow_id or "-",
        endpoint,
        mac or "-",
        ip or "-",
        result,
        detail,
    )
@app.api_route("/remove-cpe", methods=["GET", "POST"])
async def remove_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    workflow_id = data.get("workflow_id") or ""
    wanted_mac = normalize_mac(data.get("mac"))
    wanted_ip = normalize_ip(data.get("ip"))
    delete_site = str(data.get("delete_site") or "").lower() in ("1", "true", "yes")

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", "Invalid MAC")
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", "Invalid IP")
        raise HTTPException(400, "Invalid or missing IP")

    try:
        device = find_device_by_mac_ip(wanted_mac, wanted_ip)
        ident = device.get("identification", {})
        device_id = str(ident.get("id") or "")
        site_id = str(ident.get("site", {}).get("id") or "") if ident.get("site") else None

        detail_url = f"{UISP_BASE}/devices/{device_id}"
        fr = requests.get(detail_url, headers=HEADERS, timeout=45)
        fr.raise_for_status()
        fresh = fr.json()
        fresh_ident = fresh.get("identification", {})
        if (str(fresh_ident.get("id") or "") != device_id or
            normalize_mac(fresh_ident.get("mac")) != wanted_mac or
            wanted_ip not in device_ips(fresh)):
            log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", "Fresh identity check failed")
            raise HTTPException(409, "Fresh identity check failed")

        dr = requests.delete(detail_url, headers=HEADERS, timeout=60)
        if dr.status_code not in (200, 204):
            log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", f"DELETE failed {dr.status_code}")
            raise HTTPException(dr.status_code, f"UISP DELETE failed: {dr.text}")

        site_deleted = False
        site_message = None
        if delete_site and site_id:
            devices_after = get_devices()
            still_there = [d for d in devices_after if str(d.get("identification", {}).get("site", {}).get("id") or "") == site_id]
            if not still_there:
                sr = requests.delete(f"{UISP_BASE}/sites/{site_id}", headers=HEADERS, timeout=45)
                site_deleted = sr.status_code in (200, 204)
                site_message = "Empty site also removed" if site_deleted else f"Site delete failed: {sr.status_code}"
            else:
                site_message = f"Site not empty ({len(still_there)} device(s) remain)"

        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "success", f"device_id={device_id}")
        return {
            "success": True,
            "message": "CPE removed from UISP",
            "workflow_id": workflow_id,
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": ident.get("name"),
            "site_id": site_id,
            "site_deleted": site_deleted,
            "site_message": site_message,
        }
    except HTTPException as e:
        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", str(e.detail))
        raise
    except requests.RequestException as e:
        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", f"UISP API error: {e}")
        raise HTTPException(502, f"UISP API error: {e}")
    except Exception as e:
        log_request("/remove-cpe", workflow_id, wanted_mac, wanted_ip, "error", str(e))
        raise HTTPException(500, str(e))


@app.api_route("/reboot-cpe", methods=["GET", "POST"])
async def reboot_cpe(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    workflow_id = data.get("workflow_id") or ""
    wanted_mac = normalize_mac(data.get("mac"))
    wanted_ip = normalize_ip(data.get("ip"))

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", "Invalid MAC")
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", "Invalid IP")
        raise HTTPException(400, "Invalid or missing IP")

    try:
        device = find_device_by_mac_ip(wanted_mac, wanted_ip)
        device_id = str(device.get("identification", {}).get("id") or "")
        overview = device.get("overview", {})
        status = str(overview.get("status") or device.get("status") or "").lower()

        unreachable_statuses = ("disconnected", "offline", "inactive", "unreachable", "down", "")
        if status in unreachable_statuses:
            msg = "UISP cannot currently communicate with this device. It may be offline or unreachable. Please check power and connectivity before retrying."
            log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", msg)
            raise HTTPException(409, msg)

        rr = requests.post(f"{UISP_BASE}/devices/{device_id}/reboot", headers=HEADERS, timeout=45)
        if rr.status_code not in (200, 202, 204):
            log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", f"Reboot failed {rr.status_code}")
            raise HTTPException(rr.status_code, f"Reboot command failed: {rr.text}")

        log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "success", f"device_id={device_id}")
        return {
            "success": True,
            "message": "Reboot command sent",
            "workflow_id": workflow_id,
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": device.get("identification", {}).get("name"),
            "status": status,
        }
    except HTTPException:
        raise
    except requests.RequestException as e:
        log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", f"UISP API error: {e}")
        raise HTTPException(502, f"UISP API error: {e}")
    except Exception as e:
        log_request("/reboot-cpe", workflow_id, wanted_mac, wanted_ip, "error", str(e))
        raise HTTPException(500, str(e))


@app.api_route("/outage-check", methods=["GET", "POST"])
async def outage_check(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    workflow_id = data.get("workflow_id") or ""
    wanted_mac = normalize_mac(data.get("mac"))
    wanted_ip = normalize_ip(data.get("ip"))

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "error", "Invalid MAC")
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "error", "Invalid IP")
        raise HTTPException(400, "Invalid or missing IP")

    try:
        device = find_device_by_mac_ip(wanted_mac, wanted_ip)
        device_id = str(device.get("identification", {}).get("id") or "")
        overview = device.get("overview", {})
        status = overview.get("status") or device.get("status")
        last_seen = overview.get("lastSeen") or device.get("lastSeen")

        outages = []
        try:
            orr = requests.get(f"{UISP_BASE}/outages", headers=HEADERS, timeout=30, params={"deviceId": device_id})
            if orr.status_code == 200:
                raw_out = orr.json()
                outages = raw_out if isinstance(raw_out, list) else raw_out.get("items") or raw_out.get("data") or []
        except Exception:
            pass

        in_outage = len(outages) > 0 or str(status).lower() in ("disconnected", "offline", "inactive")

        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "success", f"in_outage={in_outage}")
        return {
            "success": True,
            "workflow_id": workflow_id,
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": device.get("identification", {}).get("name"),
            "status": status,
            "last_seen": last_seen,
            "in_outage": in_outage,
            "active_outages": len(outages),
        }
    except HTTPException as e:
        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "error", str(e.detail))
        raise
    except requests.RequestException as e:
        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "error", f"UISP API error: {e}")
        raise HTTPException(502, f"UISP API error: {e}")
    except Exception as e:
        log_request("/outage-check", workflow_id, wanted_mac, wanted_ip, "error", str(e))
        raise HTTPException(500, str(e))


@app.api_route("/device-status", methods=["GET", "POST"])
async def device_status(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    workflow_id = data.get("workflow_id") or ""
    wanted_mac = normalize_mac(data.get("mac"))
    wanted_ip = normalize_ip(data.get("ip"))

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "error", "Invalid MAC")
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "error", "Invalid IP")
        raise HTTPException(400, "Invalid or missing IP")

    try:
        device = find_device_by_mac_ip(wanted_mac, wanted_ip)
        device_id = str(device.get("identification", {}).get("id") or "")

        dr = requests.get(f"{UISP_BASE}/devices/{device_id}", headers=HEADERS, timeout=45)
        dr.raise_for_status()
        detail = dr.json()

        overview = detail.get("overview") or {}
        identification = detail.get("identification") or {}
        firmware = detail.get("firmware") or {}
        interfaces = detail.get("interfaces") or []

        signal = None
        for iface in interfaces:
            if isinstance(iface, dict) and iface.get("wireless"):
                signal = iface.get("wireless")
                break

        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "success")
        return {
            "success": True,
            "workflow_id": workflow_id,
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": identification.get("name"),
            "status": overview.get("status"),
            "last_seen": overview.get("lastSeen"),
            "uptime": overview.get("uptime"),
            "cpu": overview.get("cpu"),
            "ram": overview.get("ram"),
            "firmware_version": firmware.get("version") or identification.get("firmwareVersion"),
            "model": identification.get("model"),
            "signal": signal,
            "site_id": (identification.get("site") or {}).get("id"),
        }
    except HTTPException as e:
        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "error", str(e.detail))
        raise
    except requests.RequestException as e:
        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "error", f"UISP API error: {e}")
        raise HTTPException(502, f"UISP API error: {e}")
    except Exception as e:
        log_request("/device-status", workflow_id, wanted_mac, wanted_ip, "error", str(e))
        raise HTTPException(500, str(e))


@app.api_route("/signal-history", methods=["GET", "POST"])
async def signal_history(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    check_secret(request, x_webhook_secret)
    data = dict(request.query_params) if request.method == "GET" else await request.json()
    workflow_id = data.get("workflow_id") or ""
    wanted_mac = normalize_mac(data.get("mac"))
    wanted_ip = normalize_ip(data.get("ip"))
    interval = data.get("interval") or "day"

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "error", "Invalid MAC")
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "error", "Invalid IP")
        raise HTTPException(400, "Invalid or missing IP")

    try:
        device = find_device_by_mac_ip(wanted_mac, wanted_ip)
        device_id = str(device.get("identification", {}).get("id") or "")

        stats_url = f"{UISP_BASE}/devices/{device_id}/statistics"
        sr = requests.get(stats_url, headers=HEADERS, timeout=45, params={"interval": interval})
        stats = sr.json() if sr.status_code == 200 else {"note": "Statistics endpoint returned non-200", "status_code": sr.status_code}

        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "success", f"interval={interval}")
        return {
            "success": True,
            "workflow_id": workflow_id,
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": device.get("identification", {}).get("name"),
            "interval": interval,
            "statistics": stats,
        }
    except HTTPException as e:
        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "error", str(e.detail))
        raise
    except requests.RequestException as e:
        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "error", f"UISP API error: {e}")
        raise HTTPException(502, f"UISP API error: {e}")
    except Exception as e:
        log_request("/signal-history", workflow_id, wanted_mac, wanted_ip, "error", str(e))
        raise HTTPException(500, str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
