#!/usr/bin/env python3
"""
ssh_service.py - BTWI radio station-kick and per-call CPE rename API.

Fibersmith Vision workflow webhook -> POST /kick -> this service logs in to the
airOS radio (https://<ap_ip>:11443/api/auth), reads the X-Csrf-Id header, then
POSTs /stakick.cgi (staif=<interface>&staid=<mac>) to disconnect that station.
The station normally reconnects on its own within seconds.

Endpoints
  POST /kick    JSON or form body (Vision fields): ip (radio IP), mac (station to kick),
                workflow_id (logged), secret (auth), name (customer, logged)
                optional: interface=ath0, dry_run=false. Aliases: ap_ip / radio_ip for ip.
                /kick still refuses addresses outside ALLOWED_NETWORKS.
  GET|POST /rename-cpe  Per-call SSH to the one CPE IP in the request. Sets resolv.host.1.name
                from the Vision customer name and applies the BTWI CPE standard (SNMP on,
                community/contact, snmp.location "TOWER SECTOR", syslog on to the collector),
                then cfgmtd save + rc.softrestart. Reads the config before the edit and checks
                it again after. Fields: ip, name, optional snmp_location, uisp_device_id or mac
                (to derive the location from UISP), dry_run, workflow_id.
                There is no IP allowlist. The supplied address is the only SSH target.
                Loopback, link-local, multicast, reserved, unspecified, and 0.x are rejected.
                Host keys default to reject. RADIO_SSH_HOST_KEY_POLICY=accept-new is the
                less secure opt-in: save the first key, then reject a changed key.
  GET  /health  no auth, no radio contact

Auth: "secret" field in the body (Vision), or X-Webhook-Secret header, or
"Authorization: Bearer <secret>", or (only if ALLOW_QUERY_SECRET=true) ?secret=<secret>. Compared in constant time.

Every response: {"result": "success"|"failed", "success": bool, "message": str,
"workflow_id": str, ...}. Vision manual task: Webhook Response Field result = failed.

All settings come from environment variables (systemd EnvironmentFile
/etc/btwi-tools/radio-kick.env). Nothing secret is hardcoded or logged.
"""
from __future__ import annotations

import copy
import hmac
import ipaddress
import json
import logging
import os
import re
import shlex
import socket
import threading
import time
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import anyio
import paramiko
import requests
import urllib3
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # airOS uses self-signed certs

log = logging.getLogger("radio-kick")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TZ = ZoneInfo("America/Chicago")
MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$")
IFACE_RE = re.compile(r"^(ath|wlan|wifi)\d{1,2}$")


def _bool(v: Any, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


class Settings:
    def __init__(self) -> None:
        env = os.environ
        self.webhook_secret = env.get("WEBHOOK_SECRET", "")
        self.radio_username = env.get("RADIO_USERNAME", "")
        self.radio_password = env.get("RADIO_PASSWORD", "")
        self.radio_port = int(env.get("RADIO_PORT", "11443"))
        self.connect_timeout = float(env.get("RADIO_CONNECT_TIMEOUT", "5"))
        self.read_timeout = float(env.get("RADIO_READ_TIMEOUT", "10"))
        self.allowed_networks = [
            ipaddress.ip_network(n.strip(), strict=False)
            for n in env.get("ALLOWED_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")
            if n.strip()
        ]
        self.allowed_interfaces = {
            i.strip() for i in env.get("ALLOWED_INTERFACES", "ath0").split(",") if i.strip()
        }
        self.allow_query_secret = _bool(env.get("ALLOW_QUERY_SECRET"), False)
        self.trust_proxy = _bool(env.get("TRUST_PROXY_HEADERS"), False)
        self.cooldown = float(env.get("KICK_COOLDOWN_SECONDS", "30"))
        self.log_path = env.get("KICK_LOG", "/var/log/btwi-tools/radio-kick/kicks.jsonl")
        # /rename-cpe (SSH to the CPE). Optional at startup so /kick keeps working without it.
        self.radio_ssh_port = int(env.get("RADIO_SSH_PORT", "11222"))
        self.radio_ssh_user = env.get("RADIO_SSH_USER", "BTTW")
        self.radio_ssh_password = env.get("RADIO_SSH_PASSWORD", "")
        self.radio_ssh_known_hosts = env.get("RADIO_SSH_KNOWN_HOSTS", "")
        # reject (default): do not send the password unless the key is pinned.
        # accept-new: save the first key, then reject a different one. Less secure.
        self.radio_ssh_host_key_policy = env.get("RADIO_SSH_HOST_KEY_POLICY", "reject").strip().lower() or "reject"
        self.radio_ssh_connect_timeout = float(env.get("RADIO_SSH_CONNECT_TIMEOUT", "8"))
        self.radio_ssh_command_timeout = float(env.get("RADIO_SSH_COMMAND_TIMEOUT", "20"))
        self.cpe_softrestart_timeout = float(env.get("CPE_SOFTRESTART_TIMEOUT", "45"))
        # Whole /rename-cpe attempt (UISP + SSH). Stays under nginx's 90s proxy_read_timeout.
        self.rename_time_budget = float(env.get("RENAME_TIME_BUDGET_SECONDS", "75"))
        # /rename-cpe has no IP allowlist. It SSHes only to the one address in the request.
        self.cpe_snmp_community = env.get("CPE_SNMP_COMMUNITY", "BTWI")
        self.cpe_snmp_contact = env.get("CPE_SNMP_CONTACT", "BTWI")
        # Blank is allowed at startup so /kick can run. /rename-cpe checks it per call.
        self.cpe_syslog_ip = env.get("CPE_SYSLOG_IP", "10.55.12.244")
        self.cpe_syslog_port = env.get("CPE_SYSLOG_PORT", "514")
        self.uisp_base_url = env.get("UISP_BASE_URL", "https://uisp.btwi.net/nms/api/v2.1").rstrip("/")
        self.uisp_api_token = env.get("UISP_API_TOKEN", "")
        # Off until the PUT /sites body is confirmed against the live NMS swagger.
        self.uisp_rename_site = _bool(env.get("UISP_RENAME_SITE"), False)
        # Write calls prefer this token. Empty falls back to UISP_API_TOKEN.
        self.uisp_write_token = env.get("UISP_WRITE_TOKEN", "")
        self.uisp_timeout = float(env.get("UISP_TIMEOUT", "30"))
        for k, v in (("CPE_SNMP_COMMUNITY", self.cpe_snmp_community), ("CPE_SNMP_CONTACT", self.cpe_snmp_contact),
                     ("CPE_SYSLOG_PORT", self.cpe_syslog_port)):
            if not v or any(c in v for c in "|&\\'\"`\n\r"):
                raise RuntimeError(f"{k} is empty or contains characters that are not allowed")
        if not self.cpe_syslog_port.isdigit():
            raise RuntimeError("CPE_SYSLOG_PORT must be a number")
        if self.radio_ssh_host_key_policy not in ("reject", "accept-new"):
            raise RuntimeError("RADIO_SSH_HOST_KEY_POLICY must be reject or accept-new")
        missing = [k for k, v in (("WEBHOOK_SECRET", self.webhook_secret),
                                  ("RADIO_USERNAME", self.radio_username),
                                  ("RADIO_PASSWORD", self.radio_password)) if not v]
        if missing:
            raise RuntimeError("Missing required settings: " + ", ".join(missing))
        if len(self.webhook_secret) < 24:
            raise RuntimeError("WEBHOOK_SECRET must be at least 24 characters")


S = Settings()
app = FastAPI(title="BTWI Radio Kick", docs_url=None, redoc_url=None, openapi_url=None)

_log_lock = threading.Lock()
_recent: dict[str, float] = {}  # "ap_ip|mac" -> monotonic time of last real kick attempt
_recent_lock = threading.Lock()


# ---------------------------------------------------------------- helpers
def now_local() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def write_log(entry: dict) -> None:
    """Append one JSON line. Never contains passwords, CSRF ids, cookies or the secret."""
    line = json.dumps({"time": now_local(), **entry}, ensure_ascii=False)
    try:
        with _log_lock, open(S.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        log.error("could not write kick log %s: %s", S.log_path, e)
    log.info("kick %s", line)


def client_ip(request: Request) -> str:
    if S.trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
        xri = request.headers.get("x-real-ip")
        if xri:
            return xri.strip()
    return request.client.host if request.client else "-"


def secret_ok(request: Request, data: dict) -> bool:
    supplied = request.headers.get("x-webhook-secret")
    if not supplied:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
    if not supplied:
        body_secret = data.get("secret")  # Vision sends "secret" in the body
        supplied = str(body_secret).strip() if body_secret not in (None, "") else None
    if not supplied and S.allow_query_secret:
        supplied = request.query_params.get("secret")
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode(), S.webhook_secret.encode())


def norm_mac(value: Any) -> str:
    """Accept aa:bb:cc:dd:ee:ff, AA-BB-..., aabb.ccdd.eeff, aabbccddeeff -> aa:bb:cc:dd:ee:ff."""
    clean = re.sub(r"[\s:\-\.]", "", str(value or "")).lower()
    if not MAC_HEX_RE.match(clean):
        raise ValueError("mac must be 12 hex digits (any of : - . separators)")
    if clean in ("000000000000", "ffffffffffff") or int(clean[1], 16) & 1:
        raise ValueError("mac is a zero, broadcast or multicast address")
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def norm_ip(value: Any, networks: list | None = None) -> str:
    """Validate an IP for /kick and require it to sit inside ALLOWED_NETWORKS."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("ip is required")
    raw = raw.split("/")[0]  # tolerate "172.20.1.2/30" as stored by UISP/Vision
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError(f"ip '{raw[:45]}' is not a valid IP address")
    if ip.version != 4:
        raise ValueError("ip must be IPv4")
    if not any(ip in net for net in (networks if networks is not None else S.allowed_networks)):
        raise ValueError(f"ip {ip} is not in an allowed network")
    return str(ip)


_ZERO_NET = ipaddress.ip_network("0.0.0.0/8")


def unacceptable_rename_ip(ip: ipaddress.IPv4Address) -> str | None:
    """Why this address must not be an SSH target, or None when it may be."""
    if ip.is_unspecified or ip in _ZERO_NET:
        return "an unspecified or 0.x address"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_reserved:
        return "a reserved address"
    return None


def norm_rename_ip(value: Any) -> str:
    """The one IPv4 address /rename-cpe may SSH to.

    No allowlist and no fallback to ALLOWED_NETWORKS. A prefix, a list, or anything
    that is not a single IP is rejected here, before any socket is opened.
    Loopback, link-local, multicast, reserved, unspecified, and 0.x addresses are
    rejected too: 0.0.0.0 and 127.0.0.1 would SSH back into this server.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("ip is required")
    if any(c in raw for c in "/,; \t"):
        raise ValueError("ip must be a single IP address")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError(f"ip '{raw[:45]}' is not a valid IP address")
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("ip must be IPv4")
    reason = unacceptable_rename_ip(ip)
    if reason:
        raise ValueError(f"ip {ip} is {reason} and cannot be used")
    return str(ip)


def norm_iface(value: Any) -> str:
    iface = str(value or "ath0").strip() or "ath0"
    if not IFACE_RE.match(iface) or iface not in S.allowed_interfaces:
        raise ValueError(f"interface '{iface[:20]}' is not allowed (allowed: {', '.join(sorted(S.allowed_interfaces))})")
    return iface


def respond(ok: bool, message: str, workflow_id: str, status: int = 200, **extra) -> JSONResponse:
    body = {"result": "success" if ok else "failed", "success": ok,
            "message": message, "workflow_id": workflow_id or ""}
    body.update(extra)
    return JSONResponse(body, status_code=status)


async def read_payload(request: Request) -> dict:
    ctype = request.headers.get("content-type", "").lower()
    data: dict = {}
    if "application/json" in ctype:
        try:
            parsed = await request.json()
        except Exception:
            raise ValueError("body is not valid JSON")
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object")
        data = parsed
    elif "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
        form = await request.form()
        data = {k: v for k, v in form.items()}
    else:
        body = (await request.body()).strip()
        if body:
            try:
                parsed = json.loads(body)
                data = parsed if isinstance(parsed, dict) else {}
            except Exception:
                raise ValueError("unsupported body; send JSON or form-encoded")
    # query parameters fill gaps (never 'secret')
    for k, v in request.query_params.items():
        if k != "secret":
            data.setdefault(k, v)
    return data


def cooldown_hit(key: str) -> float:
    """Returns seconds remaining if this AP+MAC was kicked too recently, else records it and returns 0."""
    if S.cooldown <= 0:
        return 0.0
    now = time.monotonic()
    with _recent_lock:
        last = _recent.get(key)
        if last is not None and now - last < S.cooldown:
            return S.cooldown - (now - last)
        _recent[key] = now
        for k in [k for k, t in _recent.items() if now - t > S.cooldown]:
            _recent.pop(k, None)
    return 0.0


def clear_cooldown(key: str) -> None:
    with _recent_lock:
        _recent.pop(key, None)


class KickError(Exception):
    pass


def airos_kick(ap_ip: str, mac: str, iface: str) -> str:
    """Log in to airOS and send stakick.cgi. Returns a short status message; raises KickError."""
    base = f"https://{ap_ip}:{S.radio_port}"
    timeout = (S.connect_timeout, S.read_timeout)
    with requests.Session() as s:
        s.verify = False  # self-signed airOS certificate (same as the PowerShell script)
        try:
            r = s.post(f"{base}/api/auth",
                       data={"username": S.radio_username, "password": S.radio_password},
                       timeout=timeout, allow_redirects=False)
        except requests.exceptions.ConnectTimeout:
            raise KickError(f"login: timed out connecting to {ap_ip}:{S.radio_port}")
        except requests.exceptions.ReadTimeout:
            raise KickError(f"login: {ap_ip} did not answer in time")
        except requests.exceptions.RequestException as e:
            raise KickError(f"login: cannot reach {ap_ip}:{S.radio_port} ({type(e).__name__})")
        if r.status_code in (401, 403):
            raise KickError(f"login rejected by {ap_ip} (HTTP {r.status_code}); check RADIO_USERNAME/RADIO_PASSWORD")
        if r.status_code != 200:
            raise KickError(f"login to {ap_ip} failed (HTTP {r.status_code})")
        csrf = r.headers.get("X-Csrf-Id")
        if not csrf:
            raise KickError(f"login to {ap_ip} returned no X-Csrf-Id header (not airOS 8, or login failed)")
        try:
            k = s.post(f"{base}/stakick.cgi", data={"staif": iface, "staid": mac},
                       headers={"X-Csrf-Id": csrf}, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            raise KickError(f"kick: request to {ap_ip} failed ({type(e).__name__})")
        finally:
            # best-effort logout so sessions don't pile up on the radio
            try:
                s.post(f"{base}/logout.cgi", headers={"X-Csrf-Id": csrf}, timeout=(2, 3))
            except Exception:
                pass
        if k.status_code != 200:
            raise KickError(f"stakick.cgi on {ap_ip} returned HTTP {k.status_code}")
        text = (k.text or "").strip()
        # airOS answers with JSON or a short body; treat explicit error flags as failure
        try:
            j = json.loads(text) if text else {}
            if isinstance(j, dict) and (j.get("ok") is False or j.get("success") is False or "error" in j):
                raise KickError(f"stakick.cgi on {ap_ip} reported an error: {str(j)[:150]}")
        except ValueError:
            pass
        return f"Kick sent to {mac} on {ap_ip} ({iface}); station should reconnect shortly"


# ---------------------------------------------------------------- /rename-cpe (SSH)
# Proven by hand 2026-11-11 on a PBE-5AC-Gen2 (airOS 8.7.25): edit /tmp/system.cfg with the
# shell function below, then `cfgmtd -w -p /etc/ && /usr/etc/rc.d/rc.softrestart save`.
CPE_CFG = "/tmp/system.cfg"
CPE_CFG_BAK = "/tmp/system.cfg.rename-bak"
# Exact line edit. `case` matches the key literally, so a dot is not a wildcard.
# The marker btwi-cfg-edit is how tests recognize an edit. Backup is a temp file
# then mv, which is atomic on the same filesystem.
SET_FN = '''F=/tmp/system.cfg
# btwi-cfg-edit
s() {
  key=$1
  val=$2
  tmp=$F.edit.tmp
  found=0
  : > "$tmp"
  cr=$(printf '\\r')
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%"$cr"}
    case "$line" in
      "$key"=*)
        if [ "$found" -eq 0 ]; then
          printf '%s=%s\\n' "$key" "$val" >> "$tmp"
          found=1
        fi
        ;;
      *)
        printf '%s\\n' "$line" >> "$tmp"
        ;;
    esac
  done < "$F"
  if [ "$found" -eq 0 ]; then
    printf '%s=%s\\n' "$key" "$val" >> "$tmp"
  fi
  mv "$tmp" "$F"
}
'''
SAVE_CMD = "cfgmtd -w -p /etc/"
APPLY_CMD = "/usr/etc/rc.d/rc.softrestart save"
# Harmless noise printed by rc.softrestart / cfgmtd on airOS 8
BENIGN_LINE_RE = re.compile(
    r"^(RTNETLINK answers: (Cannot assign requested address|File exists)|Fixup Startup_list.*|"
    r"Found\s+Active on.*|Found Backup\d* on.*|Storing Active.*|Active->Backup.*|WA#.*|XW#.*|XC#.*)$")
SED_BAD_CHARS = set("|&\\'\"`\n\r")
LOCATION_RE = re.compile(r"^[A-Za-z0-9._/\-]+( [A-Za-z0-9._/\-]+)*$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SECTOR_RE = re.compile(r"^[A-Z0-9][A-Z0-9.\-]*$")
BOTSEC = "BOTSEC"

_rename_busy: set[str] = set()
_rename_lock = threading.Lock()


class RenameError(Exception):
    def __init__(self, message: str, status: int = 502, **extra):
        super().__init__(message)
        self.status = status
        self.extra = extra


def sanitize_name(raw: Any) -> str:
    """Vision customer name -> airOS device name.

    Whitespace runs become one space. Keep [A-Za-z0-9 _.-], collapse repeated
    spaces and dashes, strip leading and trailing space and '-', max 32 characters.
    airOS 8.7.25 accepts a space in resolv.host.1.name. Raises ValueError when
    nothing is left.
    """
    s = re.sub(r"\s+", " ", str(raw or "").strip())
    s = re.sub(r"[^A-Za-z0-9 _.\-]", "", s)
    s = re.sub(r" {2,}", " ", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip(" -")
    s = s[:32].strip(" -")
    if not s:
        raise ValueError("name is empty after sanitizing (needs letters or digits)")
    check_sed_safe("name", s)
    return s


def check_sed_safe(field: str, value: str) -> None:
    bad = sorted({c for c in value if c in SED_BAD_CHARS})
    if bad:
        raise ValueError(f"{field} contains characters that are not allowed: {' '.join(repr(c) for c in bad)}")


def clean_location(raw: Any) -> str:
    """Validate an snmp_location override. Single spaces between words are allowed."""
    s = str(raw or "")
    check_sed_safe("snmp_location", s)
    s = re.sub(r"[ \t]+", " ", s.strip())
    if not s:
        raise ValueError("snmp_location is empty")
    if len(s) > 64 or not LOCATION_RE.match(s):
        raise ValueError("snmp_location may only contain letters, digits, . _ - / and single spaces (max 64)")
    return s


def site_code(site_name: str) -> str:
    """'20_TL' -> 'TL', '03_PRYHUT' -> 'PRYHUT', '74_I-35' -> 'I35', 'AHQ' -> 'AHQ', '150TH.' -> '150TH'."""
    s = str(site_name or "").strip()
    m = re.match(r"^\d+_(.+)$", s)
    if m:
        s = m.group(1)
    return re.sub(r"[^A-Za-z0-9]", "", s).upper()


def derive_location(ap_name: str, site_name: str) -> tuple[str | None, str]:
    """AP name + AP site name -> ('TOWER SECTOR', note) or (None, warning). Never guesses.
    Rules (Jared, 2026-11-11): strip BOTSEC, find the tower code from the AP's site code,
    put one space between tower and sector, uppercase."""
    name = str(ap_name or "").strip()
    if not name:
        return None, "no AP name"
    if re.search(r"\s", name):
        return None, f"AP name '{name}' contains spaces; can't split it confidently"
    if "," in str(site_name or ""):
        return None, f"AP '{name}' is on customer site '{site_name}', not a tower"
    up = name.upper()
    botsec = up.startswith(BOTSEC)
    rem = up[len(BOTSEC):] if botsec else up
    code = site_code(site_name)
    if not code:
        return None, f"AP '{name}' has no usable site name"
    tower = None
    if rem.startswith(code):
        tower = code if len(rem) > len(code) else None
    elif botsec:
        # (fuzzy match only for BOTSEC sector names; other names must start with the full site code)
        # longest prefix of the remainder (>=2 chars) that the site code ends with (PRYHUT + HUTW -> HUT)
        # or starts with (150TH + 150E -> 150, GJC81 + GJCWAVEN -> GJC)
        for k in range(min(len(code), len(rem) - 1), 1, -1):
            p = rem[:k]
            if code.endswith(p) or code.startswith(p):
                tower = p
                break
    if not tower:
        return None, f"can't find tower code '{code}' (site '{site_name}') in AP name '{name}'"
    sector = rem[len(tower):].lstrip("-_.").replace("_", "-")
    if not sector or not SECTOR_RE.match(sector) or len(sector) > 24:
        return None, f"AP name '{name}' has no clean sector after tower '{tower}'"
    return f"{tower} {sector}", f"from AP {name} (site {site_name})"


def _uisp_request(method: str, path: str, budget: "TimeBudget | None" = None,
                  token: str | None = None, body: dict | None = None) -> Any:
    """One UISP call. Redirects are errors so the x-auth-token is not forwarded.

    `token` is sent only as a header and is never included in errors or logs.
    """
    auth = S.uisp_api_token if token is None else token
    read_timeout = S.uisp_timeout
    connect_timeout = S.connect_timeout
    if budget is not None:
        read_timeout = budget.slice(read_timeout)
        connect_timeout = min(connect_timeout, read_timeout)
    url = f"{S.uisp_base_url}{path}"
    headers = {"x-auth-token": auth, "accept": "application/json"}
    timeout = (connect_timeout, read_timeout)
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        elif method == "PUT":
            r = requests.put(url, headers=headers, timeout=timeout, json=body, allow_redirects=False)
        else:
            raise RuntimeError(f"UISP method {method} is not used")
    except requests.exceptions.RequestException:
        raise RuntimeError(f"UISP unreachable ({method} {path.split('?')[0]})")
    short = path.split("?")[0]
    if r.status_code in (301, 302, 303, 307, 308):
        raise RuntimeError(f"UISP {short} returned HTTP {r.status_code} redirect; not followed")
    if method == "PUT" and r.status_code in (200, 201, 204):
        return None
    if r.status_code != 200:
        raise RuntimeError(f"UISP {short} returned HTTP {r.status_code}")
    return r.json()


def _uisp_get(path: str, budget: "TimeBudget | None" = None) -> Any:
    """GET one UISP path with the read token. Redirects are not followed."""
    return _uisp_request("GET", path, budget, None)


def _device_ips(dev: dict) -> set[str]:
    ips = {str(dev.get("ipAddress") or "").split("/")[0]}
    ips |= {str(x).split("/")[0] for x in (dev.get("ipAddressList") or [])}
    return {ip for ip in ips if ip}


# UISP site identification.type for a customer map dot. "site" is a tower and is never renamed.
_ENDPOINT_SITE_TYPES = {"endpoint", "client"}


def uisp_find_station(ip: str, device_id: str | None, mac: str | None, get) -> tuple[dict | None, str]:
    """Find one station. `get(path)` performs the GET.

    Order is uisp_device_id, else MAC, else IP. A MAC match counts only when that
    device's IP is `ip`. Returns (device, error). error is empty when a device is returned.
    """
    if device_id:
        return get(f"/devices/{device_id}"), ""
    mac_ip_mismatch = False
    for d in get("/devices?role=station"):
        ident = d.get("identification") or {}
        d_mac = (ident.get("mac") or "").lower()
        d_ips = _device_ips(d)
        if mac:
            if d_mac == mac and ip in d_ips:
                return d, ""
            if d_mac == mac and ip not in d_ips:
                mac_ip_mismatch = True
        elif ip in d_ips:
            return d, ""
    if mac_ip_mismatch:
        return None, f"UISP device for mac {mac} does not use {ip}"
    return None, f"CPE not found in UISP by {'mac ' + mac if mac else 'ip ' + ip}"


def uisp_location(ip: str, device_id: str | None, mac: str | None, budget: "TimeBudget | None" = None) -> dict:
    """Look up the CPE in UISP (read-only GETs) and derive TOWER SECTOR from its AP.
    Returns {location, source ('uisp_ap'|'none'), warning, ap_name, ap_site}.

    A MAC match is used only when that device's IP is the IP in this call.
    """
    out = {"location": None, "source": "none", "warning": "", "ap_name": "", "ap_site": ""}
    if not S.uisp_api_token:
        out["warning"] = "UISP_API_TOKEN not set; snmp.location skipped"
        return out
    try:
        dev, err = uisp_find_station(ip, device_id, mac, lambda path: _uisp_get(path, budget))
        if err or not dev:
            out["warning"] = f"{err or 'CPE not found in UISP'}; snmp.location skipped"
            return out
        ap = (dev.get("attributes") or {}).get("apDevice") or {}
        out["ap_name"] = ap.get("name") or ""
        if not ap.get("id"):
            out["warning"] = "UISP shows no AP for this CPE; snmp.location skipped"
            return out
        ap_dev = _uisp_get(f"/devices/{ap['id']}", budget)
        out["ap_site"] = ((ap_dev.get("identification") or {}).get("site") or {}).get("name") or ""
    except (RuntimeError, ValueError) as e:
        out["warning"] = f"{e}; snmp.location skipped"
        return out
    loc, note = derive_location(out["ap_name"], out["ap_site"])
    if loc:
        out.update(location=loc, source="uisp_ap")
    else:
        out["warning"] = f"{note}; snmp.location skipped"
    return out


def _site_rename_result(state: str, site_id: str, before: str | None, after: str | None, message: str) -> dict:
    return {"state": state, "site_id": site_id, "before": before, "after": after, "message": message}


def _device_site_ref(dev: dict) -> tuple[str, str]:
    site = (dev.get("identification") or {}).get("site") or {}
    if isinstance(site, str):
        return site, ""
    if not isinstance(site, dict):
        return "", ""
    return str(site.get("id") or ""), str(site.get("type") or "")


def rename_customer_uisp_site(ip: str, name: str, device_id: str | None, mac: str | None,
                              dry_run: bool, radio_saved: bool, radio_applied: bool,
                              budget: "TimeBudget") -> tuple[dict, str]:
    """Rename the customer's endpoint/client site. Never the device, never a tower.

    Returns (site_rename, warning). A UISP error is reported here and does not raise,
    so a finished radio rename is left in place. The token is not put in either value.
    """
    intended = name
    if not S.uisp_rename_site:
        msg = "UISP site rename is off (UISP_RENAME_SITE is not true)"
        return _site_rename_result("skipped", "", None, intended, msg), msg
    if not (dry_run or (radio_saved and radio_applied)):
        msg = "radio was not changed; UISP site was not renamed"
        return _site_rename_result("skipped", "", None, intended, msg), ""
    token = (S.uisp_write_token or S.uisp_api_token or "").strip()
    if not token:
        msg = "UISP site rename skipped; set UISP_WRITE_TOKEN or UISP_API_TOKEN"
        return _site_rename_result("skipped", "", None, intended, msg), msg
    try:
        dev, err = uisp_find_station(
            ip, device_id, mac, lambda path: _uisp_request("GET", path, budget, token))
        if err or not dev:
            msg = err or "CPE not found in UISP"
            return _site_rename_result("skipped", "", None, intended, msg), msg
        site_id, site_type = _device_site_ref(dev)
        if not site_id:
            msg = "UISP device has no site; site was not renamed"
            return _site_rename_result("skipped", "", None, intended, msg), msg
        if site_type and site_type.lower() not in _ENDPOINT_SITE_TYPES:
            msg = (f"UISP site {site_id} type is {site_type}; "
                   "only an endpoint or client site is renamed")
            return _site_rename_result("skipped", site_id, None, intended, msg), msg
        site = _uisp_request("GET", f"/sites/{site_id}", budget, token)
        if not isinstance(site, dict):
            msg = f"UISP site {site_id} response was not an object"
            return _site_rename_result("failed", site_id, None, intended, msg), msg
        ident = site.get("identification") if isinstance(site.get("identification"), dict) else {}
        if not site_type:
            site_type = str(ident.get("type") or "")
            if site_type.lower() not in _ENDPOINT_SITE_TYPES:
                msg = (f"UISP site {site_id} type is {site_type or 'unknown'}; "
                       "only an endpoint or client site is renamed")
                return _site_rename_result("skipped", site_id, None, intended, msg), msg
        before = ident.get("name") if isinstance(ident.get("name"), str) else ""
        if before == intended:
            return _site_rename_result("unchanged", site_id, before, intended,
                                       "UISP site name already matches"), ""
        if dry_run:
            msg = f"dry run: would rename the endpoint site from {before!r} to {intended!r}; no PUT sent"
            return _site_rename_result("skipped", site_id, before, intended, msg), ""
        payload = copy.deepcopy(site)
        if not isinstance(payload.get("identification"), dict):
            payload["identification"] = {}
        payload["identification"]["name"] = intended
        _uisp_request("PUT", f"/sites/{site_id}", budget, token, payload)
        return _site_rename_result("renamed", site_id, before, intended, "UISP endpoint site renamed"), ""
    except (RuntimeError, RenameError) as e:
        msg = str(e)
        return _site_rename_result("failed", "", None, intended, msg), msg
    except Exception:
        msg = "UISP site rename failed"
        return _site_rename_result("failed", "", None, intended, msg), msg


def parse_cfg(text: str) -> dict[str, list[str]]:
    vals: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals.setdefault(k.strip(), []).append(v.rstrip("\r"))
    return vals


def cpe_targets(name: str, location: str | None) -> dict[str, str]:
    t = {"resolv.host.1.name": name,
         "snmp.status": "enabled",
         "snmp.community": S.cpe_snmp_community,
         "snmp.contact": S.cpe_snmp_contact}
    if location:
        t["snmp.location"] = location
    t.update({"syslog.status": "enabled",
              "syslog.remote.status": "enabled",
              "syslog.remote.ip": S.cpe_syslog_ip,
              "syslog.remote.port": S.cpe_syslog_port})
    return t


def cfg_diff(cfg: dict[str, list[str]], targets: dict[str, str]) -> list[str]:
    """Keys whose line is missing, wrong, or duplicated with a wrong value."""
    return [k for k, v in targets.items() if not cfg.get(k) or any(x != v for x in cfg[k])]


def edit_command(changes: dict[str, str]) -> str:
    """Backup atomically (temp file, then mv), then edit only if that backup exists."""
    calls = []
    for k, v in changes.items():
        check_sed_safe(k, v)
        calls.append(f"s {shlex.quote(k)} {shlex.quote(v)}")
    backup = 'cp "$F" "$F.rename-bak.tmp" && mv "$F.rename-bak.tmp" "$F.rename-bak"'
    return SET_FN + backup + " && { " + "; ".join(calls) + "; }"


class SSHDropped(Exception):
    pass


class TimeBudget:
    """One deadline for every UISP and SSH step in a single /rename-cpe call."""

    def __init__(self, seconds: float):
        self.seconds = float(seconds)
        self.deadline = time.monotonic() + self.seconds
        self.timed_out = False

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def message(self) -> str:
        return (f"Rename timed out after {self.seconds:.0f}s. "
                "No further save or restart will be started.")

    def slice(self, requested: float) -> float:
        left = self.remaining()
        if left <= 0.05:
            self.timed_out = True
            raise RenameError(self.message(), 504)
        return min(float(requested), left)


class AcceptNewPolicy(paramiko.MissingHostKeyPolicy):
    """Save the first key for a host, then rely on the saved key for later calls.

    A changed key raises BadHostKeyException inside connect(), before the password
    is sent. This is less secure than pinning the key ahead of time.
    """

    def missing_host_key(self, client, hostname, key):
        if not client._host_keys_filename:
            raise paramiko.SSHException("accept-new has nowhere to save the host key")
        client._host_keys.add(hostname, key.get_name(), key)
        client.save_host_keys(client._host_keys_filename)
        try:
            os.chmod(client._host_keys_filename, 0o600)
        except OSError:
            pass
        log.warning("RADIO_SSH_HOST_KEY_POLICY=accept-new saved a new host key for %s "
                    "(less secure than a pinned key)", hostname)


def syslog_problem() -> str | None:
    value = (S.cpe_syslog_ip or "").strip()
    if not value:
        return "CPE_SYSLOG_IP is not configured"
    if any(c in value for c in "|&\\'\"`\n\r"):
        return "CPE_SYSLOG_IP contains characters that are not allowed"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "CPE_SYSLOG_IP is not a valid IP address"
    return None


def host_key_config_error() -> str | None:
    """None when it is safe to connect. Otherwise a message and the password is not sent."""
    policy = S.radio_ssh_host_key_policy
    path = (S.radio_ssh_known_hosts or "").strip()
    if policy not in ("reject", "accept-new"):
        return "RADIO_SSH_HOST_KEY_POLICY must be reject or accept-new"
    if not path:
        if policy == "accept-new":
            return ("RADIO_SSH_HOST_KEY_POLICY=accept-new needs RADIO_SSH_KNOWN_HOSTS "
                    "so the first key can be saved. Refusing to send the SSH password.")
        return ("Refusing to send the SSH password: RADIO_SSH_KNOWN_HOSTS is not set. "
                "Pin the radio key in that file, or set RADIO_SSH_HOST_KEY_POLICY=accept-new "
                "to save the first key and then reject a changed key (less secure).")
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        return (f"RADIO_SSH_KNOWN_HOSTS directory does not exist ({parent}). "
                "Refusing to send the SSH password.")
    if policy == "reject" and not os.path.isfile(path):
        return (f"RADIO_SSH_KNOWN_HOSTS file is missing ({path}). "
                "Refusing to send the SSH password.")
    return None


def rename_preflight_error() -> str | None:
    return syslog_problem() or host_key_config_error()


def redact_community(payload: dict) -> dict:
    """Hide snmp.community values in anything we send back to the caller."""
    keys = payload.get("keys")
    entry = keys.get("snmp.community") if isinstance(keys, dict) else None
    if not isinstance(entry, dict):
        return payload
    cloned = dict(payload)
    cloned_keys = dict(keys)
    cloned_keys["snmp.community"] = {
        field: (None if entry.get(field) in (None, "") else "***")
        for field in ("before", "after", "target")
    }
    cloned["keys"] = cloned_keys
    return cloned


class RadioSSH:
    """Thin paramiko wrapper. The password is only handed to paramiko, never logged.

    The password is not sent unless the host key is pinned, or accept-new has a file
    to save the first key into. `ip` is the only address this session contacts.
    """

    def __init__(self, ip: str, budget: TimeBudget):
        self.ip = ip
        self.budget = budget
        self.client = paramiko.SSHClient()
        # Ignore ~/.ssh/known_hosts. Only RADIO_SSH_KNOWN_HOSTS counts.
        self.client._system_host_keys.clear()
        path = (S.radio_ssh_known_hosts or "").strip()
        if S.radio_ssh_host_key_policy == "accept-new" and path and not os.path.exists(path):
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        try:
            self.client.load_host_keys(path)
        except OSError as e:
            raise RenameError(
                f"RADIO_SSH_KNOWN_HOSTS file could not be read ({path}): {e}. "
                "Refusing to send the SSH password.",
                400,
            )
        if S.radio_ssh_host_key_policy == "accept-new":
            self.client.set_missing_host_key_policy(AcceptNewPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def __enter__(self) -> "RadioSSH":
        timeout = self.budget.slice(S.radio_ssh_connect_timeout)
        try:
            self.client.connect(self.ip, port=S.radio_ssh_port, username=S.radio_ssh_user,
                                password=S.radio_ssh_password, timeout=timeout,
                                banner_timeout=timeout, auth_timeout=timeout,
                                look_for_keys=False, allow_agent=False)
        except RenameError:
            raise
        except paramiko.AuthenticationException:
            raise RenameError(f"SSH login rejected by {self.ip}:{S.radio_ssh_port}; check RADIO_SSH_USER/RADIO_SSH_PASSWORD")
        except paramiko.BadHostKeyException:
            raise RenameError(
                f"SSH host key for {self.ip}:{S.radio_ssh_port} does not match RADIO_SSH_KNOWN_HOSTS. "
                "The password was not sent.",
                502,
            )
        except paramiko.SSHException as e:
            if "not found in known_hosts" in str(e):
                raise RenameError(
                    f"SSH host key for {self.ip}:{S.radio_ssh_port} was not found in RADIO_SSH_KNOWN_HOSTS. "
                    f"A line for this port must be [{self.ip}]:{S.radio_ssh_port}, not a bare IP. "
                    "The password was not sent.",
                    502,
                )
            self._timeout_or_unreachable(e)
        except (socket.timeout, TimeoutError, OSError) as e:
            self._timeout_or_unreachable(e)
        return self

    def _timeout_or_unreachable(self, exc: BaseException) -> None:
        if self.budget.timed_out or self.budget.remaining() <= 0:
            self.budget.timed_out = True
            raise RenameError(self.budget.message(), 504)
        if isinstance(exc, (socket.timeout, TimeoutError)):
            raise RenameError(f"SSH: timed out connecting to {self.ip}:{S.radio_ssh_port}")
        raise RenameError(f"SSH: cannot reach {self.ip}:{S.radio_ssh_port} ({type(exc).__name__})")

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def run(self, cmd: str, timeout: float) -> tuple[int, str]:
        """Run one command. Returns (exit_status, stdout+stderr). Raises SSHDropped if the
        session dies or times out before an exit status arrives."""
        timeout = self.budget.slice(timeout)
        try:
            _, stdout, _ = self.client.exec_command(cmd, timeout=timeout, get_pty=False)
            ch = stdout.channel
            ch.set_combine_stderr(True)
            out = stdout.read().decode("utf-8", "replace")
            if not ch.exit_status_ready() and not ch.status_event.wait(timeout):
                self.budget.timed_out = True
                self.close()
                raise SSHDropped("no exit status")
            status = ch.recv_exit_status()
            if status == -1:
                raise SSHDropped("session closed without exit status")
            return status, out
        except SSHDropped:
            raise
        except (socket.timeout, TimeoutError, EOFError, OSError, paramiko.SSHException) as e:
            if self.budget.remaining() <= 0.2:
                self.budget.timed_out = True
                self.close()
            raise SSHDropped(type(e).__name__)


def _noise_free(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not BENIGN_LINE_RE.match(l.strip())]


def _restore_working_copy(ip: str, budget: TimeBudget) -> str:
    """Copy the backup back in a new SSH session and cmp it. Honest if that fails."""
    if budget.timed_out or budget.remaining() <= 0.2:
        return ("restore was not attempted because the time budget ran out; "
                "the working config may still be changed")
    cmd = (
        f"test -s {CPE_CFG_BAK} || {{ echo 'backup missing'; exit 2; }}; "
        f"cp {CPE_CFG_BAK} {CPE_CFG}.restore.tmp && mv {CPE_CFG}.restore.tmp {CPE_CFG} && "
        f"cmp -s {CPE_CFG_BAK} {CPE_CFG} && echo verified || {{ echo 'checksum mismatch'; exit 3; }}"
    )
    try:
        with RadioSSH(ip, budget) as sh:
            st, out = sh.run(cmd, S.radio_ssh_command_timeout)
    except RenameError as e:
        return f"restore could not be verified ({e})"
    except SSHDropped as e:
        return f"restore could not be verified (session dropped: {e})"
    if st == 0 and "verified" in out:
        return "working config restored and verified against the backup"
    detail = " ".join(_noise_free(out))[:200] or f"exit {st}"
    return f"restore could not be verified ({detail})"


def _dropped(ip: str, budget: TimeBudget, what: str, res: dict) -> None:
    if budget.timed_out or budget.remaining() <= 0:
        budget.timed_out = True
        raise RenameError(
            budget.message() + f" SSH session closed during {what}; save and restart were not started.",
            504, **res)
    raise RenameError(f"SSH session to {ip} dropped while {what}; nothing saved", **res)


def cpe_rename_job(ip: str, name: str, location: str | None, dry_run: bool, budget: TimeBudget) -> dict:
    """SSH in, read, diff, (edit, verify, save, apply). Returns a result dict; raises RenameError."""
    res: dict = {"saved": False, "applied": False, "apply_confirmed": False, "changed_keys": [],
                 "keys": {}, "state": ""}
    targets = cpe_targets(name, location)
    bad: list[str] = []
    with RadioSSH(ip, budget) as sh:
        def read_cfg() -> dict[str, list[str]]:
            try:
                st, out = sh.run(f"cat {CPE_CFG}", S.radio_ssh_command_timeout)
            except SSHDropped as e:
                _dropped(ip, budget, f"reading config ({e})", res)
            if st != 0 or "=" not in out:
                raise RenameError(f"could not read {CPE_CFG} on {ip} (exit {st})")
            return parse_cfg(out)

        before = read_cfg()
        changes = cfg_diff(before, targets)
        b = {k: (before.get(k) or [None])[0] for k in targets}
        res["changed_keys"] = changes
        if dry_run or not changes:
            res["keys"] = {k: {"before": b[k], "after": targets[k] if dry_run else b[k], "target": targets[k]}
                           for k in targets}
            res["state"] = "dry_run" if dry_run else "already_compliant"
            return res

        edit_note = None
        try:
            st, out = sh.run(edit_command({k: targets[k] for k in changes}), S.radio_ssh_command_timeout)
        except SSHDropped as e:
            _dropped(ip, budget, f"editing config ({e})", res)
        if st != 0:
            edit_note = (f"config edit on {ip} failed (exit {st}): "
                         f"{' | '.join(_noise_free(out))[:200]}")
        else:
            after = read_cfg()
            res["keys"] = {k: {"before": b[k], "after": (after.get(k) or [None])[0], "target": targets[k]}
                           for k in targets}
            bad = cfg_diff(after, targets)
        if edit_note or bad:
            pass
        else:
            try:
                sh.run(f"rm -f {CPE_CFG_BAK}", S.radio_ssh_command_timeout)
                st, out = sh.run(SAVE_CMD, S.radio_ssh_command_timeout)
            except SSHDropped as e:
                if budget.timed_out or budget.remaining() <= 0:
                    budget.timed_out = True
                    raise RenameError(budget.message() + " Save was not confirmed.", 504, **res)
                raise RenameError(f"SSH session to {ip} dropped during cfgmtd save ({e}); save state unknown", **res)
            if st != 0:
                raise RenameError(f"cfgmtd save on {ip} failed (exit {st}): {' | '.join(_noise_free(out))[:200]}", **res)
            res["saved"] = True

            # Soft restart drops the customer link for a few seconds and may drop this SSH session too.
            try:
                st, out = sh.run(APPLY_CMD, S.cpe_softrestart_timeout)
            except SSHDropped:
                if budget.timed_out:
                    raise RenameError(
                        budget.message() + " SSH session closed during soft restart; it was not confirmed.",
                        504, **res)
                res.update(applied=True, apply_confirmed=False, state="changed",
                           apply_note="SSH session dropped during soft restart (expected); config is saved")
                return res
            noise = _noise_free(out)
            if st != 0 and noise:
                raise RenameError(f"config saved on {ip} but soft restart reported exit {st}: {' | '.join(noise)[:200]}; "
                                  "it will apply on next reboot", **res)
            res.update(applied=True, apply_confirmed=True, state="changed")
            return res

    # The edit session is closed. Restore from the backup on a new session.
    note = _restore_working_copy(ip, budget)
    if edit_note:
        raise RenameError(f"{edit_note}; {note}; nothing saved", **res)
    raise RenameError(f"verify failed on {ip} for {', '.join(bad)}; {note}; nothing saved", **res)


def _busy(ip: str, take: bool) -> bool:
    with _rename_lock:
        if take:
            if ip in _rename_busy:
                return True
            _rename_busy.add(ip)
            return False
        _rename_busy.discard(ip)
        return False


# ---------------------------------------------------------------- routes
@app.get("/health")
def health():
    return {"status": "ok", "service": "radio-kick", "time": now_local()}


@app.post("/kick")
async def kick(request: Request):
    src = client_ip(request)
    entry: dict = {"action": "kick", "source_ip": src, "workflow_id": "", "name": "", "ip": "", "mac": "",
                   "interface": "", "dry_run": None}

    try:
        data = await read_payload(request)
    except ValueError as e:
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), "", 400)

    if not secret_ok(request, data):
        write_log({**entry, "result": "failed", "message": "unauthorized"})
        return respond(False, "Invalid or missing webhook secret", "", 401)
    data.pop("secret", None)  # never log or echo it

    wid = str(data.get("workflow_id") or "")[:100]
    name = str(data.get("name") or "").strip()[:150]
    entry.update(workflow_id=wid, name=name)
    dry_run = _bool(data.get("dry_run"), False)
    entry["dry_run"] = dry_run
    raw_ip = data.get("ip") or data.get("ap_ip") or data.get("radio_ip")
    entry.update(ip=str(raw_ip or "")[:64], mac=str(data.get("mac") or "")[:32])

    try:
        ap_ip = norm_ip(raw_ip)
        mac = norm_mac(data.get("mac"))
        iface = norm_iface(data.get("interface"))
    except ValueError as e:
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), wid, 400, name=name)
    entry.update(ip=ap_ip, mac=mac, interface=iface)

    if dry_run:
        msg = f"Dry run OK: would kick {mac} on {ap_ip}:{S.radio_port} ({iface}); radio not contacted"
        write_log({**entry, "result": "success", "message": msg})
        return respond(True, msg, wid, name=name, ip=ap_ip, mac=mac, interface=iface, dry_run=True)

    wait = cooldown_hit(f"{ap_ip}|{mac}")
    if wait:
        msg = f"{mac} on {ap_ip} was kicked in the last {int(S.cooldown)}s; try again in {int(wait) + 1}s"
        write_log({**entry, "result": "failed", "message": msg})
        return respond(False, msg, wid, 429, name=name, ip=ap_ip, mac=mac)

    try:
        msg = await anyio.to_thread.run_sync(airos_kick, ap_ip, mac, iface)
    except KickError as e:
        clear_cooldown(f"{ap_ip}|{mac}")  # a failed attempt shouldn't block Vision's retry
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), wid, 502, name=name, ip=ap_ip, mac=mac, interface=iface, dry_run=False)
    except Exception as e:  # never leak internals
        clear_cooldown(f"{ap_ip}|{mac}")
        log.exception("unexpected error")
        write_log({**entry, "result": "failed", "message": f"internal error ({type(e).__name__})"})
        return respond(False, "Internal error while kicking; see service log", wid, 500, name=name)

    write_log({**entry, "result": "success", "message": msg})
    return respond(True, msg, wid, name=name, ip=ap_ip, mac=mac, interface=iface, dry_run=False)


@app.api_route("/rename-cpe", methods=["GET", "POST"])
async def rename_cpe(request: Request):
    """Set the CPE name + BTWI standard SNMP/syslog config over SSH (see README).

    SSHes only to the single IP in this call. There is no network allowlist.
    """
    src = client_ip(request)
    entry: dict = {"action": "rename-cpe", "source_ip": src, "workflow_id": "", "name": "", "ip": "",
                   "dry_run": None}

    try:
        data = await read_payload(request)
    except ValueError as e:
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), "", 400)

    if not secret_ok(request, data):
        write_log({**entry, "result": "failed", "message": "unauthorized"})
        return respond(False, "Invalid or missing webhook secret", "", 401)
    data.pop("secret", None)

    wid = str(data.get("workflow_id") or "")[:100]
    raw_name = str(data.get("name") or "")[:150]
    dry_run = _bool(data.get("dry_run"), False)
    raw_ip = data.get("ip") or data.get("cpe_ip") or data.get("radio_ip")
    entry.update(workflow_id=wid, name=raw_name.strip(), ip=str(raw_ip or "")[:64], dry_run=dry_run)

    try:
        ip = norm_rename_ip(raw_ip)
        name = sanitize_name(raw_name)
        override = data.get("snmp_location")
        override = clean_location(override) if override not in (None, "") else None
        dev_id = str(data.get("uisp_device_id") or "").strip() or None
        if dev_id and not UUID_RE.match(dev_id):
            raise ValueError("uisp_device_id must be a UISP device UUID")
        mac = norm_mac(data.get("mac")) if data.get("mac") not in (None, "") else None
    except ValueError as e:
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), wid, 400, name=raw_name.strip())
    entry.update(ip=ip, name=name)

    if not S.radio_ssh_password:
        msg = "RADIO_SSH_PASSWORD is not configured on the server"
        write_log({**entry, "result": "failed", "message": msg})
        return respond(False, msg, wid, 500, name=name, ip=ip)

    preflight = rename_preflight_error()
    if preflight:
        write_log({**entry, "result": "failed", "message": preflight})
        return respond(False, preflight, wid, 400, name=name, ip=ip)

    warnings: list[str] = []
    loc_info = {"ap_name": "", "ap_site": ""}
    budget = TimeBudget(S.rename_time_budget)
    try:
        if override:
            location, location_source = override, "override"
        else:
            info = await anyio.to_thread.run_sync(uisp_location, ip, dev_id, mac, budget)
            location, location_source = info["location"], info["source"]
            loc_info = {"ap_name": info["ap_name"], "ap_site": info["ap_site"]}
            if info["warning"]:
                warnings.append(info["warning"])
    except RenameError as e:
        write_log({**entry, "result": "failed", "message": str(e)})
        return respond(False, str(e), wid, e.status, name=name, ip=ip)
    entry.update(location=location, location_source=location_source)
    base = dict(name=name, ip=ip, dry_run=dry_run, location=location, location_source=location_source,
                **loc_info)

    if _busy(ip, True):
        msg = f"a rename is already running on {ip}"
        write_log({**entry, "result": "failed", "message": msg})
        return respond(False, msg, wid, 409, **base)
    try:
        res = await anyio.to_thread.run_sync(cpe_rename_job, ip, name, location, dry_run, budget)
    except RenameError as e:
        extra = redact_community({**{"saved": False, "applied": False, "changed_keys": [], "keys": {}}, **e.extra})
        write_log({**entry, "result": "failed", "message": str(e), "changed_keys": extra["changed_keys"],
                   "saved": extra["saved"], "applied": extra["applied"]})
        return respond(False, str(e), wid, e.status, **base, state="failed", already_compliant=False,
                       warnings=warnings, **{k: v for k, v in extra.items() if k != "state"})
    except Exception as e:  # never leak internals
        log.exception("unexpected rename error")
        write_log({**entry, "result": "failed", "message": f"internal error ({type(e).__name__})"})
        return respond(False, "Internal error during rename; see service log", wid, 500, **base)
    finally:
        _busy(ip, False)

    if res.get("apply_note"):
        warnings.append(res.pop("apply_note"))
    if location_source == "none":
        res["skipped_keys"] = ["snmp.location"]
    else:
        res["skipped_keys"] = []
    st = res["state"]
    res["already_compliant"] = st == "already_compliant"
    if st == "dry_run":
        msg = (f"Dry run: {len(res['changed_keys'])} key(s) would change on {ip}"
               f"{': ' + ', '.join(res['changed_keys']) if res['changed_keys'] else ' (already compliant)'}; nothing changed")
    elif st == "already_compliant":
        msg = f"{ip} already matches the CPE standard; nothing saved, no restart"
    else:
        msg = f"Renamed {ip} to {name} and applied the CPE standard ({len(res['changed_keys'])} key(s) changed); link drops for a few seconds"
    if location_source == "none":
        msg += "; snmp.location NOT set (no location)"
    site_rename, site_warning = rename_customer_uisp_site(
        ip, name, dev_id, mac, dry_run, bool(res.get("saved")), bool(res.get("applied")), budget)
    if site_warning:
        warnings.append(site_warning)
    res["site_rename"] = site_rename
    public = redact_community(res)
    write_log({**entry, "result": "success", "message": msg, "state": st, "changed_keys": public["changed_keys"],
               "saved": public["saved"], "applied": public["applied"],
               "site_rename": (public.get("site_rename") or {}).get("state"),
               "site_id": (public.get("site_rename") or {}).get("site_id")})
    return respond(True, msg, wid, **base, warnings=warnings, **public)
