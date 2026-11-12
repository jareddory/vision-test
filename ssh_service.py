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
  GET  /health  no auth, no radio contact

Auth: "secret" field in the body (Vision), or X-Webhook-Secret header, or
"Authorization: Bearer <secret>", or (only if ALLOW_QUERY_SECRET=true) ?secret=<secret>. Compared in constant time.

Every response: {"result": "success"|"failed", "success": bool, "message": str,
"workflow_id": str, ...}. Vision manual task: Webhook Response Field result = failed.

All settings come from environment variables (systemd EnvironmentFile
/etc/btwi-tools/radio-kick.env). Nothing secret is hardcoded or logged.
"""
from __future__ import annotations

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
        self.radio_ssh_connect_timeout = float(env.get("RADIO_SSH_CONNECT_TIMEOUT", "8"))
        self.radio_ssh_command_timeout = float(env.get("RADIO_SSH_COMMAND_TIMEOUT", "20"))
        self.cpe_softrestart_timeout = float(env.get("CPE_SOFTRESTART_TIMEOUT", "45"))
        # /rename-cpe has no IP allowlist. It SSHes only to the one address in the request.
        self.cpe_snmp_community = env.get("CPE_SNMP_COMMUNITY", "BTWI")
        self.cpe_snmp_contact = env.get("CPE_SNMP_CONTACT", "BTWI")
        self.cpe_syslog_ip = env.get("CPE_SYSLOG_IP", "10.55.12.244")
        self.cpe_syslog_port = env.get("CPE_SYSLOG_PORT", "514")
        self.uisp_base_url = env.get("UISP_BASE_URL", "https://uisp.btwi.net/nms/api/v2.1").rstrip("/")
        self.uisp_api_token = env.get("UISP_API_TOKEN", "")
        self.uisp_timeout = float(env.get("UISP_TIMEOUT", "30"))
        for k, v in (("CPE_SNMP_COMMUNITY", self.cpe_snmp_community), ("CPE_SNMP_CONTACT", self.cpe_snmp_contact),
                     ("CPE_SYSLOG_IP", self.cpe_syslog_ip), ("CPE_SYSLOG_PORT", self.cpe_syslog_port)):
            if not v or any(c in v for c in "|&\\'\"`\n\r"):
                raise RuntimeError(f"{k} is empty or contains characters that are not allowed")
        ipaddress.ip_address(self.cpe_syslog_ip)
        if not self.cpe_syslog_port.isdigit():
            raise RuntimeError("CPE_SYSLOG_PORT must be a number")
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


def norm_rename_ip(value: Any) -> str:
    """The one IPv4 address /rename-cpe may SSH to.

    No allowlist and no fallback to ALLOWED_NETWORKS. A prefix, a list, or anything
    that is not a single IP is rejected here, before any socket is opened.
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
    if ip.version != 4:
        raise ValueError("ip must be IPv4")
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
SET_FN = 'F=/tmp/system.cfg; s(){ grep -q "^$1=" $F && sed -i "s|^$1=.*|$1=$2|" $F || echo "$1=$2" >> $F; }'
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
    """Vision customer name -> airOS device name: whitespace runs -> '-', keep [A-Za-z0-9-_.],
    collapse '--', trim '-' both ends, max 32 chars. Raises ValueError when nothing is left."""
    s = re.sub(r"\s+", "-", str(raw or "").strip())
    s = re.sub(r"[^A-Za-z0-9\-_.]", "", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    s = s[:32].strip("-")
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


def _uisp_get(path: str) -> Any:
    try:
        r = requests.get(f"{S.uisp_base_url}{path}", headers={"x-auth-token": S.uisp_api_token,
                                                             "accept": "application/json"},
                         timeout=(S.connect_timeout, S.uisp_timeout))
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"UISP unreachable ({type(e).__name__})")
    if r.status_code != 200:
        raise RuntimeError(f"UISP {path.split('?')[0]} returned HTTP {r.status_code}")
    return r.json()


def uisp_location(ip: str, device_id: str | None, mac: str | None) -> dict:
    """Look up the CPE in UISP (read-only GETs) and derive TOWER SECTOR from its AP.
    Returns {location, source ('uisp_ap'|'none'), warning, ap_name, ap_site}."""
    out = {"location": None, "source": "none", "warning": "", "ap_name": "", "ap_site": ""}
    if not S.uisp_api_token:
        out["warning"] = "UISP_API_TOKEN not set; snmp.location skipped"
        return out
    try:
        dev = None
        if device_id:
            dev = _uisp_get(f"/devices/{device_id}")
        else:
            for d in _uisp_get("/devices?role=station"):
                ident = d.get("identification") or {}
                d_mac = (ident.get("mac") or "").lower()
                d_ips = {str(d.get("ipAddress") or "").split("/")[0]}
                d_ips |= {str(x).split("/")[0] for x in (d.get("ipAddressList") or [])}
                if (mac and d_mac == mac) or (not mac and ip in d_ips):
                    dev = d
                    break
        if not dev:
            out["warning"] = f"CPE not found in UISP by {'mac ' + mac if mac else 'ip ' + ip}; snmp.location skipped"
            return out
        ap = (dev.get("attributes") or {}).get("apDevice") or {}
        out["ap_name"] = ap.get("name") or ""
        if not ap.get("id"):
            out["warning"] = "UISP shows no AP for this CPE; snmp.location skipped"
            return out
        ap_dev = _uisp_get(f"/devices/{ap['id']}")
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
    parts = [SET_FN, f"cp $F {CPE_CFG_BAK}"]
    for k, v in changes.items():
        check_sed_safe(k, v)
        parts.append(f"s {k} {shlex.quote(v)}")
    # backup first; only edit if the backup worked
    return f"{parts[0]}; {parts[1]} && {{ {'; '.join(parts[2:])}; }}"


class SSHDropped(Exception):
    pass


class RadioSSH:
    """Thin paramiko wrapper. The password is only handed to paramiko, never logged."""

    def __init__(self, ip: str):
        # `ip` is the single address from this call. Nothing else is contacted.
        self.ip = ip
        self.client = paramiko.SSHClient()
        if S.radio_ssh_known_hosts:
            self.client.load_host_keys(S.radio_ssh_known_hosts)
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Blank RADIO_SSH_KNOWN_HOSTS: accept this radio's key the first time we connect.
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __enter__(self) -> "RadioSSH":
        try:
            self.client.connect(self.ip, port=S.radio_ssh_port, username=S.radio_ssh_user,
                                password=S.radio_ssh_password, timeout=S.radio_ssh_connect_timeout,
                                banner_timeout=S.radio_ssh_connect_timeout,
                                auth_timeout=S.radio_ssh_connect_timeout,
                                look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            raise RenameError(f"SSH login rejected by {self.ip}:{S.radio_ssh_port}; check RADIO_SSH_USER/RADIO_SSH_PASSWORD")
        except paramiko.BadHostKeyException:
            raise RenameError(f"SSH host key for {self.ip} does not match RADIO_SSH_KNOWN_HOSTS")
        except (socket.timeout, TimeoutError):
            raise RenameError(f"SSH: timed out connecting to {self.ip}:{S.radio_ssh_port}")
        except (OSError, paramiko.SSHException) as e:
            raise RenameError(f"SSH: cannot reach {self.ip}:{S.radio_ssh_port} ({type(e).__name__})")
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    def run(self, cmd: str, timeout: float) -> tuple[int, str]:
        """Run one command. Returns (exit_status, stdout+stderr). Raises SSHDropped if the
        session dies or times out before an exit status arrives."""
        try:
            _, stdout, _ = self.client.exec_command(cmd, timeout=timeout, get_pty=False)
            ch = stdout.channel
            ch.set_combine_stderr(True)
            out = stdout.read().decode("utf-8", "replace")
            if not ch.exit_status_ready() and not ch.status_event.wait(timeout):
                raise SSHDropped("no exit status")
            status = ch.recv_exit_status()
            if status == -1:
                raise SSHDropped("session closed without exit status")
            return status, out
        except SSHDropped:
            raise
        except (socket.timeout, TimeoutError, EOFError, OSError, paramiko.SSHException) as e:
            raise SSHDropped(type(e).__name__)


def _noise_free(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not BENIGN_LINE_RE.match(l.strip())]


def cpe_rename_job(ip: str, name: str, location: str | None, dry_run: bool) -> dict:
    """SSH in, read, diff, (edit, verify, save, apply). Returns a result dict; raises RenameError."""
    res: dict = {"saved": False, "applied": False, "apply_confirmed": False, "changed_keys": [],
                 "keys": {}, "state": ""}
    targets = cpe_targets(name, location)
    with RadioSSH(ip) as sh:
        def read_cfg() -> dict[str, list[str]]:
            try:
                st, out = sh.run(f"cat {CPE_CFG}", S.radio_ssh_command_timeout)
            except SSHDropped as e:
                raise RenameError(f"SSH session to {ip} dropped while reading config ({e})")
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

        try:
            st, out = sh.run(edit_command({k: targets[k] for k in changes}), S.radio_ssh_command_timeout)
        except SSHDropped as e:
            raise RenameError(f"SSH session to {ip} dropped while editing config ({e}); nothing saved")
        if st != 0:
            raise RenameError(f"config edit on {ip} failed (exit {st}): {' | '.join(_noise_free(out))[:200]}; nothing saved")

        after = read_cfg()
        res["keys"] = {k: {"before": b[k], "after": (after.get(k) or [None])[0], "target": targets[k]}
                       for k in targets}
        bad = cfg_diff(after, targets)
        if bad:
            try:  # put the working copy back so a later GUI save can't persist a half edit
                sh.run(f"cp {CPE_CFG_BAK} {CPE_CFG} && rm -f {CPE_CFG_BAK}", S.radio_ssh_command_timeout)
            except Exception:
                pass
            raise RenameError(f"verify failed on {ip} for {', '.join(bad)}; working config restored, nothing saved",
                              **res)

        try:
            sh.run(f"rm -f {CPE_CFG_BAK}", S.radio_ssh_command_timeout)
            st, out = sh.run(SAVE_CMD, S.radio_ssh_command_timeout)
        except SSHDropped as e:
            raise RenameError(f"SSH session to {ip} dropped during cfgmtd save ({e}); save state unknown", **res)
        if st != 0:
            raise RenameError(f"cfgmtd save on {ip} failed (exit {st}): {' | '.join(_noise_free(out))[:200]}", **res)
        res["saved"] = True

        # Soft restart drops the customer link for a few seconds and may drop this SSH session too.
        try:
            st, out = sh.run(APPLY_CMD, S.cpe_softrestart_timeout)
        except SSHDropped:
            res.update(applied=True, apply_confirmed=False, state="changed",
                       apply_note="SSH session dropped during soft restart (expected); config is saved")
            return res
        noise = _noise_free(out)
        if st != 0 and noise:
            raise RenameError(f"config saved on {ip} but soft restart reported exit {st}: {' | '.join(noise)[:200]}; "
                              "it will apply on next reboot", **res)
        res.update(applied=True, apply_confirmed=True, state="changed")
        return res


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

    warnings: list[str] = []
    loc_info = {"ap_name": "", "ap_site": ""}
    if override:
        location, location_source = override, "override"
    else:
        info = await anyio.to_thread.run_sync(uisp_location, ip, dev_id, mac)
        location, location_source = info["location"], info["source"]
        loc_info = {"ap_name": info["ap_name"], "ap_site": info["ap_site"]}
        if info["warning"]:
            warnings.append(info["warning"])
    entry.update(location=location, location_source=location_source)
    base = dict(name=name, ip=ip, dry_run=dry_run, location=location, location_source=location_source,
                **loc_info)

    if _busy(ip, True):
        msg = f"a rename is already running on {ip}"
        write_log({**entry, "result": "failed", "message": msg})
        return respond(False, msg, wid, 409, **base)
    try:
        res = await anyio.to_thread.run_sync(cpe_rename_job, ip, name, location, dry_run)
    except RenameError as e:
        extra = {**{"saved": False, "applied": False, "changed_keys": [], "keys": {}}, **e.extra}
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
    write_log({**entry, "result": "success", "message": msg, "state": st, "changed_keys": res["changed_keys"],
               "saved": res["saved"], "applied": res["applied"]})
    return respond(True, msg, wid, **base, warnings=warnings, **res)
