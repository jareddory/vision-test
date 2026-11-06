# UISP Automation Webhooks

Internal webhooks that Fibersmith Vision workflows call to perform actions in UISP.
All device endpoints require a shared secret.
Every response includes a result field (success or failed) so Vision can trigger manual tasks on failure.

Base URL: https://vision-test-yz19.onrender.com

## Authentication

Pass the shared secret either as a query parameter (?secret=YOUR_SECRET) or header (X-Webhook-Secret: YOUR_SECRET).

## Consistent response format

Success:
{
  "result": "success",
  "success": true,
  "message": "...",
  "workflow_id": "..."
}

Failure:
{
  "result": "failed",
  "success": false,
  "message": "error reason",
  "workflow_id": "..."
}

### Vision manual-task setup (all endpoints)

Webhook Response Field: result
Webhook Response Value: failed

When result equals failed, create the manual task.

## Endpoints

- /remove-cpe (GET/POST) — Delete a CPE. Optionally delete empty site. Params: mac, ip, delete_site=true
- /reboot-cpe (GET/POST) — Reboot a CPE (refuses if unreachable). Params: mac, ip
- /cancel-cpe (GET/POST) — For cancellations. Deletes the matched CPE and, if the site is then empty, the site. Does not check whether the CPE is offline and does not reboot (Vision owns reboot and manual kick-on-fail first). Name fallback if IP fails. Params: mac, name (recommended), ip (optional)
- /outage-check (GET/POST) — Check if device is offline or in an outage. Params: mac, ip
- /device-status (GET/POST) — Detailed status. Params: mac, ip
- /signal-history (GET/POST) — Signal statistics. Params: mac, ip, interval
- /health (GET) — Health check (no auth)

### Common parameters

- mac — Device MAC address
- ip — Management IP (required for most; optional for /cancel-cpe)
- secret — Shared webhook secret
- workflow_id — (optional) Vision Workflow Process ID
- name — (for /cancel-cpe) Customer or location name for partial match fallback

### Example calls

Cancel CPE:
https://vision-test-yz19.onrender.com/cancel-cpe?mac=24:5A:4C:0E:1C:18&name=Scott%20Swanson&secret=YOUR_SECRET&workflow_id=WF-123

Remove CPE:
https://vision-test-yz19.onrender.com/remove-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

Reboot:
https://vision-test-yz19.onrender.com/reboot-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

Device status:
https://vision-test-yz19.onrender.com/device-status?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

## /cancel-cpe details

Delete-only. This endpoint does not check reachability and does not reboot the CPE. Vision reboots first and opens a manual task if that reboot fails, then calls cancel to remove the device.

1. Requires MAC.
2. Tries MAC + IP match first (if IP provided).
3. If IP missing or does not match, falls back to partial name match (handles reversed names like sohncindy vs Cindy Sohn, missing spaces, etc.). The name fallback is unchanged.
4. If the MAC is not unique, or neither IP nor name matches, fails closed (409). Infrastructure devices are refused (403).
5. Deletes the CPE from UISP.
6. Deletes the site if it is now empty.
7. Returns result: success or result: failed, with success, message, and workflow_id. Success sets action to device_deleted.

## Safety checks

- MAC must uniquely match one device
- Infrastructure devices (AP, backhaul, gateway, etc.) are refused
- /remove-cpe and /reboot-cpe still require matching management IP
- Fresh re-fetch before destructive actions on remove

## Environment variables (Render)

- UISP_TOKEN (required) — UISP NMS API token
- WEBHOOK_SECRET (required) — Shared secret Vision must send
- UISP_BASE_URL (optional) — Defaults to https://btwi.uisp.com/nms/api/v2.1

## Deployment

Build: pip install -r requirements.txt
Start: uvicorn vision_logger:app --host 0.0.0.0 --port $PORT


## Currently In Production At

Vision Cancelation Workflow
