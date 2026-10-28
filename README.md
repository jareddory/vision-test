# UISP Automation Webhooks

Internal webhooks that Fibersmith Vision workflows call to perform actions in UISP.
All device endpoints require a shared secret.
Every response includes a result field (success or failed) so Vision can trigger manual tasks on failure.

Base URL: https://vision-test-yz19.onrender.com

## Authentication

Pass the shared secret either as:
- Query parameter: ?secret=YOUR_SECRET
- Or header: X-Webhook-Secret: YOUR_SECRET

## Consistent response format

Every endpoint returns:

{
  "result": "success",
  "success": true,
  "message": "...",
  "workflow_id": "...",
  ...
}

or

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

| Endpoint        | Method   | Description                                                                 | Key Parameters                          |
|-----------------|----------|-----------------------------------------------------------------------------|-----------------------------------------|
| /remove-cpe     | GET/POST | Delete a CPE. Optionally delete empty site.                                 | mac, ip, delete_site=true               |
| /reboot-cpe     | GET/POST | Reboot a CPE (refuses if unreachable).                                      | mac, ip                                 |
| /cancel-cpe     | GET/POST | For cancellations. Offline = done. Online = reboot. Name fallback if IP fails. | mac, name (recommended), ip (optional) |
| /outage-check   | GET/POST | Check if device is offline or in an outage.                                 | mac, ip                                 |
| /device-status  | GET/POST | Detailed status (uptime, CPU, RAM, firmware, etc.).                         | mac, ip                                 |
| /signal-history | GET/POST | Signal / wireless statistics.                                               | mac, ip, interval                       |
| /health         | GET      | Health check (no auth).                                                     | —                                       |

### Common parameters

- mac — Device MAC address
- ip — Management IP (required for most; optional for /cancel-cpe)
- secret — Shared webhook secret
- workflow_id — (optional) Vision Workflow Process ID
- name — (for /cancel-cpe) Customer or location name used for partial match fallback

### Example calls

Cancel CPE (name fallback):
https://vision-test-yz19.onrender.com/cancel-cpe?mac=24:5A:4C:0E:1C:18&name=Scott%20Swanson&secret=YOUR_SECRET&workflow_id=WF-123

Remove CPE:
https://vision-test-yz19.onrender.com/remove-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

Reboot:
https://vision-test-yz19.onrender.com/reboot-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

Device status:
https://vision-test-yz19.onrender.com/device-status?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

## /cancel-cpe details

1. Requires MAC.
2. Tries MAC + IP match first (if IP provided).
3. If IP missing or does not match, falls back to partial name match (case-insensitive).
4. If device is offline, returns result: success, action: already_offline.
5. If device is online, sends reboot and returns result: success, action: reboot_issued.
6. Any problem returns result: failed.

## Safety checks

- MAC must uniquely match one device
- Infrastructure devices (AP, backhaul, gateway, etc.) are refused
- /remove-cpe and /reboot-cpe still require matching management IP
- Fresh re-fetch before destructive actions on remove

## Environment variables (Render)

| Variable       | Required | Description                                      |
|----------------|----------|--------------------------------------------------|
| UISP_TOKEN     | Yes      | UISP NMS API token                               |
| WEBHOOK_SECRET | Yes      | Shared secret Vision must send                   |
| UISP_BASE_URL  | No       | Defaults to https://btwi.uisp.com/nms/api/v2.1   |

## Deployment

Build: pip install -r requirements.txt
Start: uvicorn vision_logger:app --host 0.0.0.0 --port $PORT
