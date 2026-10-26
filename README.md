# UISP Automation Webhooks

Internal webhooks that Fibersmith Vision workflows call to perform actions in UISP.  
All device endpoints require a shared secret plus MAC + management IP.  
When provided, the Vision Workflow Process ID is logged and returned in the response.

**Base URL:** `https://vision-test-yz19.onrender.com`

## Authentication

Pass the shared secret either as:
- Query parameter: `?secret=YOUR_SECRET`
- Or header: `X-Webhook-Secret: YOUR_SECRET`

The secret is set in the Render environment variable `WEBHOOK_SECRET`.

## Endpoints

| Endpoint | Method | Description | Extra Parameters |
|----------|--------|-------------|------------------|
| `/remove-cpe` | GET/POST | Delete a CPE from UISP. Optionally delete the site if it becomes empty. | `delete_site=true` |
| `/reboot-cpe` | GET/POST | Reboot a CPE. Checks that UISP can communicate with the device first. Returns a plain-language error if unreachable. | — |
| `/outage-check` | GET/POST | Check if the device is offline or in an active outage. | — |
| `/device-status` | GET/POST | Detailed device status (uptime, CPU, RAM, firmware, signal, model, site). | — |
| `/signal-history` | GET/POST | Recent signal / wireless statistics. | `interval` (day/week/month) |
| `/health` | GET | Service health check (no authentication required). | — |

### Common parameters (all device endpoints)

- `mac` — Device MAC address
- `ip` — Management IP address
- `secret` — Shared webhook secret
- `workflow_id` — (optional) Vision Workflow Process ID. Logged on every request and included in the JSON response.

### Example calls
Remove CPEhttps://vision-test-yz19.onrender.com/remove-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-12345Remove CPE and site if emptyhttps://vision-test-yz19.onrender.com/remove-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&delete_site=true&workflow_id=WF-12345Reboothttps://vision-test-yz19.onrender.com/reboot-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-12345Outage checkhttps://vision-test-yz19.onrender.com/outage-check?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-12345Device statushttps://vision-test-yz19.onrender.com/device-status?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-12345Signal historyhttps://vision-test-yz19.onrender.com/signal-history?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&interval=day&workflow_id=WF-12345text

## Logging

Every device endpoint logs a line in this format (visible in Render Logs):
workflow_id=WF-12345 endpoint=/reboot-cpe mac=70A74144AC10 ip=172.20.170.196 result=success

On errors the `result` is `error` and a short detail is included.  
The same `workflow_id` is also returned in the JSON response body.

## Safety checks

All device endpoints enforce:
- MAC must uniquely match exactly one device
- Management IP must match one of the IPs reported by UISP
- Infrastructure devices (AP, backhaul, gateway, router, switch, tower, etc.) are refused
- Fresh re-fetch of the device before destructive actions

## Environment variables (Render)

| Variable | Required | Description |
|----------|----------|-------------|
| `UISP_TOKEN` | Yes | UISP NMS API token with appropriate permissions |
| `WEBHOOK_SECRET` | Yes | Shared secret Vision must send |
| `UISP_BASE_URL` | No | Defaults to `https://btwi.uisp.com/nms/api/v2.1` |

## Deployment

Deployed on Render from this repository.  
Build command: `pip install -r requirements.txt`  
Start command: `uvicorn vision_logger:app --host 0.0.0.0 --port $PORT`

## Notes

- Signal history responses can be large (especially with `interval=week`). Prefer `day` unless you need the longer range.
- Reboot will refuse to run if UISP currently shows the device as unreachable, and returns a plain-language message suitable for CSRs.
- Site deletion (`delete_site=true`) only occurs if the site has no remaining devices after the CPE is removed.
