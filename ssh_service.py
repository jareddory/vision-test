#!/usr/bin/env python3
"""
CPE station kick / reconnect service.
Logs into a CPE's airOS web interface and sends stakick.cgi.
"""

import os
import re
import logging
import requests
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("reconnect")

app = FastAPI(title="CPE Reconnect")

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
CPE_USER = os.getenv("CPE_USER", "ubnt")
CPE_PASS = os.getenv("CPE_PASS")
CPE_PORT = int(os.getenv("CPE_PORT", "11443"))

if not WEBHOOK_SECRET or not CPE_PASS:
    raise RuntimeError("WEBHOOK_SECRET and CPE_PASS are required")

def check_secret(req: Request, hdr: str | None):
    if (hdr or req.query_params.get("secret")) != WEBHOOK_SECRET:
        return False
    return True

def norm_mac(v: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", str(v or "")).upper()
    return ":".join(clean[i:i+2] for i in range(0, 12, 2)) if len(clean) == 12 else ""

def ok(data: dict):
    data["result"] = "success"
    data["success"] = True
    return JSONResponse(data)

def fail(message: str, status=400):
    return JSONResponse({"result": "failed", "success": False, "message": message}, status_code=status)

@app.api_route("/kick", methods=["GET", "POST"])
async def kick(request: Request, x_webhook_secret: str | None = Header(None, alias="X-Webhook-Secret")):
    if not check_secret(request, x_webhook_secret):
        return fail("Invalid or missing webhook secret", 401)

    data = dict(request.query_params) if request.method == "GET" else await request.json()
    wid = data.get("workflow_id") or ""
    ip = (data.get("ip") or "").strip()
    mac = norm_mac(data.get("mac"))

    if not ip or not mac:
        return fail("ip