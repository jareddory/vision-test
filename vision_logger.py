#!/usr/bin/env python3
"""
UISP automation webhooks for Vision.
Endpoints:
- /remove-cpe (optional delete_site=true)
- /reboot-cpe (checks UISP can talk to device first)
- /outage-check
- /device-status
- /signal-history
Requires shared secret. Logs workflow_id when provided.
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
async def remove_cpe(
    request: Request,
    x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret"),
):
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
        fresh_ident = 
