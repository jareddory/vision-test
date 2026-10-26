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
    raise 
