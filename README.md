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
- /rename-cpe (GET/POST) — Rename a CPE in UISP and push a sanitized hostname to the radio (airMAX/airOS only for now). Strict MAC + IP match. Params: mac, ip, name, location (optional; blank = none), dry_run (optional), push_hostname (optional, default true)
- radio-kick /rename-cpe (GET/POST, `ssh_service.py`) — SSH to the one IP in the call, set the radio name, and apply the SNMP and syslog standard. Served at `https://api.btwi.net/radio-kick/rename-cpe`. See [Radio-kick /rename-cpe](#radio-kick-rename-cpe).
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

Draft endpoint. Renames the matched CPE in UISP and, for airOS radios, pushes a sanitized hostname.

1. Requires mac, ip and name. Strict MAC + management IP match (same as /remove-cpe). Infrastructure devices are refused (403). No name fallback.
2. New name = name exactly as Vision sends it (only leading/trailing spaces trimmed; case and inner spaces kept). If location is non-blank, the new name is name + RENAME_LOCATION_SEPARATOR + location (default " - ", e.g. "John Doe - Shop"). A blank or whitespace-only location is treated as absent, so Vision can always send the field. This exact string is the UISP alias (`new_name`). It is not sanitized.
3. UISP rename: sets the device alias with PUT /devices/{id}/system/unms, keeping the device's other UISP settings (note, maintenance, ping settings). UISP limits the alias to 30 characters; longer names fail with 400 before anything is changed.
4. If that PUT returns an error, including HTTP 422 `{"message":"Failed to update wireless device hostname by alias."}`, the service re-reads GET /devices/{id}/system/unms. UISP saves `meta.alias` and then tries to copy the alias onto the radio hostname itself; on airOS (seen on a PBE-5AC-Gen2 running 8.7.25) that copy fails with 422 even though the alias was stored. When the re-read shows `meta.alias` equal to the requested name, the UISP rename counts as successful (`changed.uisp` true), the response includes `uisp_warning` set to UISP's error message, and the service continues to its own hostname push. When the alias did not change, the call fails the same way as any other UISP rename error and the radio is not touched.
5. Radio hostname (airOS only): the alias is sanitized for the radio and only the radio. Whitespace runs are replaced with RENAME_HOSTNAME_SPACE_CHAR (default `-`). Characters outside `[A-Za-z0-9-_.]` are removed, repeated `-` are collapsed, leading and trailing `-` are trimmed, and the result is capped at 32 characters. The airOS 8 user guide describes Device Name and does not document a maximum length; 32 is the limit this service enforces. The sanitized value is `new_hostname`. The service reads GET /devices/airos/{id}/configuration and sends back only the system section with `hostname` set to `new_hostname` via PUT /devices/airos/{id}/configuration?isComposeRequest=false. `already_named` and `would_push` compare the radio's current hostname to `new_hostname`, not to the alias. Other device types (airFiber, Wave, LTU, airCube, ONU, …) get radio_status `unsupported_device_type` and are renamed in UISP only. Pass push_hostname=false to skip the radio push for one call. If sanitizing leaves an empty hostname, the push is skipped with radio_status `skipped_empty_hostname`.
6. A later call where the alias already matches and the radio hostname does not equal `new_hostname` still pushes the hostname. That repairs a device left with the alias saved and the old hostname (for example alias `Mike Roberts`, hostname `robertsmichael`, pushed hostname `Mike-Roberts`).
7. If the alias already matches and the radio hostname already equals `new_hostname` (or the radio push does not apply), the call returns success with message "Already named — no change".
8. dry_run=true does the lookups and returns `would_change`, `new_name`, and `new_hostname` without writing anything.

Example:
https://vision-test-yz19.onrender.com/rename-cpe?mac=70:A7:41:44:AC:10&ip=172.20.170.196&name=John%20Doe&location=Shop&dry_run=true&secret=YOUR_SECRET&workflow_id=WF-123

Success response fields: old_name, new_name, new_hostname, old_hostname, device_id, device_type, match_method (mac+ip), changed {uisp, radio}, would_change (dry_run / no-change), uisp_warning (present when UISP returned an error after the alias had saved), radio_status (pushed, would_push, already_named, unsupported_device_type, skipped_disabled, skipped_empty_hostname), dry_run.
On failure after the UISP rename succeeded (for example the radio push failed), result is failed and changed shows {"uisp": true, "radio": false} so Vision can open a manual task to set the hostname. That failure also includes uisp_warning when the alias PUT returned an error that was accepted because the alias had saved.

## Radio-kick /rename-cpe

`ssh_service.py` serves this endpoint at `https://api.btwi.net/radio-kick/rename-cpe`. It is a per-call service, not a network crawl. Vision's webhook, or anyone with the secret, calls it with GET or POST. The call carries one radio's IP and the customer's name. The service SSHes into just that radio, sets the hostname from the Vision name, and applies the BTWI SNMP and syslog standard. It reads `/tmp/system.cfg` before the edit and checks the same keys again after the edit, before anything is saved.

The single IP in the call is the only device this step will touch. The value has to be one IPv4 address. Malformed input and anything that is not a single IP (a prefix, a list, a hostname) is rejected, and no connection is opened.

### Call inputs

| field | required | notes |
|---|---|---|
| `ip` (alias `cpe_ip`, `radio_ip`) | yes | The one radio to SSH to. One IPv4 address. |
| `name` | yes | Vision customer name. Whitespace becomes `-`, other punctuation is removed, max 32 characters (`Mike Roberts` becomes `Mike-Roberts`). |
| `snmp_location` | no | SNMP location override, for example `HUT W`. When this is set, UISP is not consulted. |
| `uisp_device_id` | no | UISP device id of this CPE. Used to look up the tower and sector when `snmp_location` is omitted. |
| `mac` | no | CPE MAC. Used for the same tower and sector lookup when `uisp_device_id` is omitted. |
| `workflow_id` | no | Vision workflow id. Echoed back and logged. |
| `dry_run` | no | Reads the radio and returns the diff. The config is not changed, saved, or restarted. |

Auth matches `/kick`: `Authorization: Bearer <secret>`, the `X-Webhook-Secret` header, or `secret` in the body. `?secret=` is accepted only when `ALLOW_QUERY_SECRET=true`.

### Server settings

These are process environment variables, not fields on the call. The template is `radio-kick.env.example` (placeholders only; the filled file stays off the repo).

`RADIO_SSH_KNOWN_HOSTS` chooses how host keys are checked. Point it at an OpenSSH known_hosts file and unknown or changed keys are rejected. Leave it blank and the service accepts the radio's key the first time it connects.

SSH login, port, timeouts, the SNMP community and contact, and the syslog collector are the other server settings (`RADIO_SSH_USER`, `RADIO_SSH_PASSWORD`, `RADIO_SSH_PORT`, `CPE_SNMP_COMMUNITY`, `CPE_SNMP_CONTACT`, `CPE_SYSLOG_IP`, `CPE_SYSLOG_PORT`). `UISP_BASE_URL` and `UISP_API_TOKEN` are used only for the optional tower and sector lookup (read-only GETs). With no token, and no `snmp_location` override, `snmp.location` is left as it is.

### What gets written

Each changed key is replaced in place, or appended when the line is missing. `snmp.location` is written only when the override or the UISP lookup produced a tower and sector. A soft restart then applies the saved config and the customer link drops for a few seconds.

| key | value |
|---|---|
| `resolv.host.1.name` | sanitized Vision name |
| `snmp.status` | `enabled` |
| `snmp.community` | `BTWI` (`CPE_SNMP_COMMUNITY`) |
| `snmp.contact` | `BTWI` (`CPE_SNMP_CONTACT`) |
| `snmp.location` | `TOWER SECTOR` when known. Otherwise the key is skipped. |
| `syslog.status` | `enabled` |
| `syslog.remote.status` | `enabled` |
| `syslog.remote.ip` | `10.55.12.244` (`CPE_SYSLOG_IP`) |
| `syslog.remote.port` | `514` (`CPE_SYSLOG_PORT`) |

A dry run returns `state: dry_run` plus `changed_keys` and the before/after `keys` map. A radio that already matches returns `state: already_compliant` and does not save or restart. A real change returns `state: changed` with `saved` and `applied`.

### nginx

nginx on api.btwi.net proxies `location /radio-kick/` to this service. The rename waits on SSH, `cfgmtd`, and the soft restart, which can take 20–60 seconds, so `proxy_read_timeout` on that location is `90s`. See `nginx-radio-kick.conf.example`.

### Example

```bash
curl -s -X POST https://api.btwi.net/radio-kick/rename-cpe \
  -H "Authorization: Bearer $SECRET" -H 'Content-Type: application/json' \
  -d '{"ip":"203.0.113.10","name":"Mike Roberts","snmp_location":"HUT W","dry_run":true,"workflow_id":"WF-123"}'
```

`203.0.113.10` is a documentation address. A dry run still opens SSH to that one address and changes nothing.

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
- RENAME_HOSTNAME_SPACE_CHAR (optional) — Replaces each whitespace run when building the /rename-cpe radio hostname. Default "-". Characters outside [A-Za-z0-9-_.] are still removed, so the value should be one of those. The UISP alias is not affected.

## Deployment

Build: pip install -r requirements.txt
Start: uvicorn vision_logger:app --host 0.0.0.0 --port $PORT


## Currently In Production At

Vision Cancelation Workflow
