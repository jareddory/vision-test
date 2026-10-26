#!/usr/bin/env python3
"""
UISP CPE removal webhook for Vision.
Requires a shared secret (header or query param).
"""

import os
import re
import ipaddress
from typing import List, Any

import requests
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse

app = FastAPI(title="UISP CPE Remover")

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
    # Accept secret from header or query parameter
    provided = header_secret or request.query_params.get("secret")
    if not provided or provided != WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid or missing webhook secret")


@app.api_route("/remove-cpe", methods=["GET", "POST"])
async def remove_cpe(
    request: Request,
    x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret"),
):
    check_secret(request, x_webhook_secret)

    # Support both query string (GET) and JSON body (POST)
    if request.method == "GET":
        data = dict(request.query_params)
    else:
        try:
            data = await request.json()
        except Exception:
            data = {}

    raw_mac = data.get("mac") or ""
    raw_ip = data.get("ip") or ""

    wanted_mac = normalize_mac(raw_mac)
    wanted_ip = normalize_ip(raw_ip)

    if not re.fullmatch(r"[A-F0-9]{12}", wanted_mac):
        raise HTTPException(400, "Invalid or missing MAC")
    if not wanted_ip:
        raise HTTPException(400, "Invalid or missing IP")

    try:
        # List devices
        r = requests.get(f"{UISP_BASE}/devices", headers=HEADERS, timeout=60)
        r.raise_for_status()
        raw = r.json()
        if isinstance(raw, list):
            devices = raw
        elif isinstance(raw, dict) and "items" in raw:
            devices = raw["items"]
        elif isinstance(raw, dict) and "data" in raw:
            devices = raw["data"]
        else:
            raise HTTPException(400, "Unrecognized UISP inventory response")

        mac_matches = [
            d for d in devices
            if normalize_mac(d.get("identification", {}).get("mac")) == wanted_mac
        ]
        if len(mac_matches) != 1:
            raise HTTPException(409, f"MAC did not uniquely identify a device (found {len(mac_matches)})")

        device = mac_matches[0]
        listed_ips = device_ips(device)
        if wanted_ip not in listed_ips:
            raise HTTPException(409, "MAC matched but management IP did not match")

        ident = device.get("identification", {})
        device_id = str(ident.get("id") or "")
        role = str(ident.get("role") or "")
        category = str(ident.get("category") or "")

        if not device_id:
            raise HTTPException(400, "Device ID missing")

        infra_pattern = re.compile(r"(?i)ap|backhaul|gateway|router|switch|tower|access\.point|ptp")
        if infra_pattern.search(role) or infra_pattern.search(category):
            raise HTTPException(403, "Potential infrastructure device — refused")

        # Fresh re-check
        detail_url = f"{UISP_BASE}/devices/{device_id}"
        fr = requests.get(detail_url, headers=HEADERS, timeout=45)
        fr.raise_for_status()
        fresh = fr.json()
        fresh_ident = fresh.get("identification", {})
        fresh_id = str(fresh_ident.get("id") or fresh.get("id") or "")
        fresh_mac = normalize_mac(fresh_ident.get("mac") or fresh.get("mac"))
        fresh_ips = device_ips(fresh)

        if fresh_id != device_id or fresh_mac != wanted_mac or wanted_ip not in fresh_ips:
            raise HTTPException(409, "Fresh identity check failed")

        # DELETE
        dr = requests.delete(detail_url, headers=HEADERS, timeout=60)
        if dr.status_code not in (200, 204):
            raise HTTPException(dr.status_code, f"UISP DELETE failed: {dr.text}")

        return {
            "success": True,
            "message": "CPE removed from UISP",
            "device_id": device_id,
            "mac": wanted_mac,
            "ip": wanted_ip,
            "name": ident.get("name"),
            "http_status": dr.status_code,
        }

    except requests.RequestException as e:
        raise HTTPException(502, f"UISP API error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
