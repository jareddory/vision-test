# UISP Automation Webhooks

Internal webhooks that Fibersmith Vision workflows call to perform actions in UISP.  
All device endpoints require a shared secret.  
Every response includes a `result` field (`success` or `failed`) so Vision can trigger manual tasks on failure.

**Base URL:** `https://vision-test-yz19.onrender.com`

## Authentication

Pass the shared secret either as:
- Query parameter: `?secret=YOUR_SECRET`
- Or header: `X-Webhook-Secret: YOUR_SECRET`

## Consistent response format

Every endpoint returns:

```json
{
  "result": "success",     // or "failed"
  "success": true,         // or false
  "message": "...",
  "workflow_id": "...",
  ...
}
Vision manual-task setup (all endpoints)












Webhook Response FieldWebhook Response ValueresultfailedWhen result equals failed, create the manual task.Endpoints




















































EndpointMethodDescriptionKey Parameters/remove-cpeGET/POSTDelete a CPE. Optionally delete empty site.mac, ip, delete_site=true/reboot-cpeGET/POSTReboot a CPE (refuses if unreachable).mac, ip/cancel-cpeGET/POSTFor cancellations. If offline → done. If online → reboot. Falls back to partial name match when IP doesn't match.mac, name (recommended), ip (optional)/outage-checkGET/POSTCheck if device is offline or in an outage.mac, ip/device-statusGET/POSTDetailed status (uptime, CPU, RAM, firmware, etc.).mac, ip/signal-historyGET/POSTSignal / wireless statistics.mac, ip, interval/healthGETHealth check (no auth).—Common parameters
mac — Device MAC address
ip — Management IP (required for most; optional for /cancel-cpe)
secret — Shared webhook secret
workflow_id — (optional) Vision Workflow Process ID
name — (for /cancel-cpe) Customer or location name used for partial match fallback
Example callstext# Cancel CPE (name fallback)
https://vision-test-yz19.onrender.com/cancel-cpe?mac=24:5A:4C:0E:1C:18&name=Scott%20Swanson&secret=YOUR_SECRET&workflow_id=WF-123

# Remove CPE
https://vision-test-yz19.onrender.com/remove-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

# Reboot
https://vision-test-yz19.onrender.com/reboot-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123

# Device status
https://vision-test-yz19.onrender.com/device-status?mac=70:A7:41:44:AC:10&ip=172.20.170.196&secret=YOUR_SECRET&workflow_id=WF-123/cancel-cpe details
Requires MAC.
Tries MAC + IP match first (if IP provided).
If IP missing or doesn’t match, falls back to partial name match (case-insensitive).
If device is offline → result: success, action: already_offline.
If device is online → sends reboot → result: success, action: reboot_issued.
Any problem → result: failed.
Safety checks
MAC must uniquely match one device
Infrastructure devices (AP, backhaul, gateway, etc.) are refused
/remove-cpe and /reboot-cpe still require matching management IP
Fresh re-fetch before destructive actions on remove
Environment variables (Render)
























VariableRequiredDescriptionUISP_TOKENYesUISP NMS API tokenWEBHOOK_SECRETYesShared secret Vision must sendUISP_BASE_URLNoDefaults to https://btwi.uisp.com/nms/api/v2.1DeploymentBuild: pip install -r requirements.txt

Start: uvicorn vision_logger:app --host 0.0.0.0 --port $PORT
