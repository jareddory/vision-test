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
