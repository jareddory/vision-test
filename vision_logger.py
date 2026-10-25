#!/usr/bin/env python3
import json
import logging
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vision-logger")

app = FastAPI(title="Vision Webhook Logger")

@app.api_route("/remove-cpe", methods=["GET", "POST"])
async def log_webhook(request: Request):
    query = dict(request.query_params)
    headers = dict(request.headers)
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    body_json = None
    if body_text:
        try:
            body_json = json.loads(body_text)
        except Exception:
            body_json = None

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": request.method,
        "url": str(request.url),
        "query": query,
        "headers": headers,
        "body_text": body_text,
        "body_json": body_json,
    }
    log.info("VISION WEBHOOK RECEIVED:\n%s", json.dumps(entry, indent=2))

    return JSONResponse({
        "ok": True,
        "message": "Logged",
        "received_query": query,
        "received_body": body_json or body_text or None,
    })

@app.get("/health")
def health():
    return {"status": "ok"}