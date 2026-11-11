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
- /rename-cpe (GET/POST) — Rename a CPE in UISP and push the hostname to the radio (airMAX/airOS only for now). Strict MAC + IP match. Params: mac, ip, name, location (optional; blank = none), dry_run (optional), push_hostname (optional, default true)
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

## /rename-cpe details

Draft endpoint. Renames the matched CPE.

1. Requires mac, ip and name. Strict MAC + management IP match (same as /remove-cpe). Infrastructure devices are refused (403). No name fallback.
2. New name = name exactly as Vision sends it (only leading/trailing spaces trimmed; case and inner spaces kept). If location is non-blank, the new name is name + RENAME_LOCATION_SEPARATOR + location (default " - ", e.g. "John Doe - Shop"). A blank or whitespace-only location is treated as absent, so Vision can always send the field.
3. UISP rename: sets the device alias (the name shown in UISP) with PUT /devices/{id}/system/unms, keeping the device's other UISP settings (note, maintenance, ping settings). UISP limits the alias to 30 characters; longer names fail with 400 before anything is changed.
4. Radio hostname: for airMAX devices, reads GET /devices/airos/{id}/configuration and sends back only the system section with hostname changed via PUT /devices/airos/{id}/configuration?isComposeRequest=false. Other device types (airFiber, Wave, LTU, airCube, ONU, …) get radio_status unsupported_device_type and are renamed in UISP only. Pass push_hostname=false to skip the radio push for one call.
5. If both the UISP alias and the radio hostname already equal the new name, returns success with message "Already named — no change".
6. dry_run=true does the lookups and returns would_change without writing anything.

Example:
https://vision-test-yz19.onrender.com/rename-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&name=John%20Doe&location=Shop&dry_run=true&secret=YOUR_SECRET&workflow_id=WF-123

Success response fields: old_name, new_name, old_hostname, device_id, device_type, match_method (mac+ip), changed {uisp, radio}, would_change (dry_run / no-change), radio_status (pushed, would_push, already_named, unsupported_device_type, skipped_disabled), dry_run.
On failure after the UISP rename succeeded (e.g. radio push failed), result is failed and changed shows {"uisp": true, "radio": false} so Vision can open a manual task to set the hostname.

## Safety checks

- MAC must uniquely match one device
- Infrastructure devices (AP, backhaul, gateway, etc.) are refused
- /remove-cpe and /reboot-cpe still require matching management IP
- Fresh re-fetch before destructive actions on remove

## Environment variables (Render)

- UISP_TOKEN (required) — UISP NMS API token
- WEBHOOK_SECRET (required) — Shared secret Vision must send
- UISP_BASE_URL (optional) — Defaults to https://btwi.uisp.com/nms/api/v2.1
- RENAME_LOCATION_SEPARATOR (optional) — Separator between name and location for /rename-cpe. Default " - " (placeholder until finalized)
- RENAME_PUSH_HOSTNAME (optional) — true/false master switch for the /rename-cpe radio hostname push. Default true
- RENAME_HOSTNAME_AIROS_TYPES (optional) — Comma list of UISP device types that get the airOS hostname push. Default airMax

## Deployment

Build: pip install -r requirements.txt
Start: uvicorn vision_logger:app --host 0.0.0.0 --port $PORT


## Currently In Production At

Vision Cancelation Workflow
