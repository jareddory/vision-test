"""
Tests for ssh_service.py against fake_airos.py on 127.0.0.1. No real radio is contacted.
Run: pytest -q tests/test_kick_service.py
"""
import http.server, importlib, json, os, re, sys, threading, urllib.parse
import pytest
from fastapi.testclient import TestClient

_TESTS = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TESTS)
sys.path.insert(0, _TESTS)
sys.path.insert(0, _ROOT)
from fake_airos import FakeAirOS

SECRET = "test-secret-0123456789abcdef"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    radio = FakeAirOS()
    log = tmp_path / "kicks.jsonl"
    for k, v in {"WEBHOOK_SECRET": SECRET, "RADIO_USERNAME": "testuser", "RADIO_PASSWORD": "testpass",
                 "RADIO_PORT": str(radio.port), "KICK_LOG": str(log),
                 "ALLOWED_NETWORKS": "127.0.0.0/8,10.0.0.0/8", "KICK_COOLDOWN_SECONDS": "30",
                 "ALLOW_QUERY_SECRET": "false"}.items():
        monkeypatch.setenv(k, v)
    import ssh_service
    importlib.reload(ssh_service)
    yield TestClient(ssh_service.app), radio, log
    radio.close()


H = {"X-Webhook-Secret": SECRET}


def lines(log):
    return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


def test_health(env):
    c, radio, _ = env
    assert c.get("/health").json()["status"] == "ok"
    assert radio.calls == []


def test_no_secret(env):
    c, radio, log = env
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
    assert r.status_code == 401 and r.json()["result"] == "failed"
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}, headers={"X-Webhook-Secret": "wrong"})
    assert r.status_code == 401
    r = c.post(f"/kick?secret={SECRET}", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
    assert r.status_code == 401  # query secret disabled by default
    assert radio.calls == []


def test_bearer_ok_dry_run(env):
    c, radio, log = env
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "AA-BB-CC-DD-EE-FF", "dry_run": True,
                              "workflow_id": "WFP-2611-0000001"},
               headers={"Authorization": f"Bearer {SECRET}"})
    j = r.json()
    assert r.status_code == 200 and j["result"] == "success" and j["success"] is True
    assert j["mac"] == "aa:bb:cc:dd:ee:ff" and j["dry_run"] is True and j["workflow_id"] == "WFP-2611-0000001"
    assert radio.calls == []  # dry run never contacts the radio
    assert lines(log)[-1]["dry_run"] is True


def test_validation(env):
    c, radio, _ = env
    bad = [
        {"ap_ip": "8.8.8.8", "mac": "aa:bb:cc:dd:ee:ff"},          # public IP
        {"ap_ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"},      # not in ALLOWED_NETWORKS for this test
        {"ap_ip": "notanip", "mac": "aa:bb:cc:dd:ee:ff"},
        {"mac": "aa:bb:cc:dd:ee:ff"},                              # missing ip
        {"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee"},           # short mac
        {"ap_ip": "127.0.0.1", "mac": "ff:ff:ff:ff:ff:ff"},        # broadcast
        {"ap_ip": "127.0.0.1", "mac": "01:00:5e:00:00:01"},        # multicast
        {"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"},
        {"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "ath0;reboot"},
    ]
    for b in bad:
        r = c.post("/kick", json=b, headers=H)
        assert r.status_code == 400 and r.json()["result"] == "failed", b
    assert radio.calls == []


def test_real_kick_against_fake(env):
    c, radio, log = env
    r = c.post("/kick", json={"radio_ip": "127.0.0.1/30", "mac": "aabb.ccdd.eeff", "workflow_id": "WF-1"}, headers=H)
    j = r.json()
    assert r.status_code == 200 and j["result"] == "success", j
    paths = [x["path"] for x in radio.calls]
    assert paths[:2] == ["/api/auth", "/stakick.cgi"]
    kick = radio.calls[1]
    assert kick["form"] == {"staif": "ath0", "staid": "aa:bb:cc:dd:ee:ff"}
    assert kick["headers"]["X-Csrf-Id"] == "csrf123"
    entry = lines(log)[-1]
    assert entry["result"] == "success" and entry["workflow_id"] == "WF-1" and entry["source_ip"]
    raw = log.read_text()
    assert "testpass" not in raw and SECRET not in raw and "csrf123" not in raw


def test_form_encoded_body(env):
    c, radio, _ = env
    r = c.post("/kick", data={"ap_ip": "127.0.0.1", "mac": "aabbccddeeff", "dry_run": "true"}, headers=H)
    assert r.json()["result"] == "success" and radio.calls == []


def test_cooldown(env):
    c, radio, _ = env
    b = {"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:01"}
    assert c.post("/kick", json=b, headers=H).json()["result"] == "success"
    r = c.post("/kick", json=b, headers=H)
    assert r.status_code == 429 and r.json()["result"] == "failed"


def test_bad_login(env, monkeypatch):
    c, radio, _ = env
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "radio_password", "wrong")
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:02"}, headers=H)
    assert r.status_code == 502 and "login rejected" in r.json()["message"]
    assert [x["path"] for x in radio.calls] == ["/api/auth"]
    # failed attempt must not trigger the cooldown
    monkeypatch.setattr(ssh_service.S, "radio_password", "testpass")
    assert c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:02"}, headers=H).json()["result"] == "success"


def test_unreachable(env, monkeypatch):
    c, radio, _ = env
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "radio_port", 1)  # nothing listening on 127.0.0.1:1
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:03"}, headers=H)
    assert r.status_code == 502 and "cannot reach" in r.json()["message"]


def test_kick_http_error(env):
    c, radio, _ = env
    radio.kick_status = 500
    r = c.post("/kick", json={"ap_ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:04"}, headers=H)
    assert r.status_code == 502 and "HTTP 500" in r.json()["message"]


def test_missing_settings(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "")
    import ssh_service
    with pytest.raises(RuntimeError):
        importlib.reload(ssh_service)


def test_vision_fields_body_secret(env):
    """Vision sends ip, mac, workflow_id, secret, name in the body."""
    c, radio, log = env
    r = c.post("/kick", json={"ip": "127.0.0.1", "mac": "AA-BB-CC-DD-EE-10", "workflow_id": "WFP-1",
                              "secret": SECRET, "name": "Jane Customer"})
    j = r.json()
    assert r.status_code == 200 and j["result"] == "success", j
    assert j["name"] == "Jane Customer" and j["ip"] == "127.0.0.1" and j["workflow_id"] == "WFP-1"
    entry = lines(log)[-1]
    assert entry["name"] == "Jane Customer" and entry["workflow_id"] == "WFP-1"
    assert SECRET not in log.read_text()


def test_vision_wrong_body_secret(env):
    c, radio, log = env
    r = c.post("/kick", json={"ip": "127.0.0.1", "mac": "aabbccddee11", "secret": "nope", "name": "X"})
    assert r.status_code == 401 and radio.calls == []


# ====================================================================== /rename-cpe (SSH)
from fake_airos import FakeAirOSSSH, SAMPLE_CFG

STD = {"resolv.host.1.name": "Mike Roberts", "snmp.status": "enabled", "snmp.community": "BTWI",
       "snmp.contact": "BTWI", "snmp.location": "HUT W", "syslog.status": "enabled",
       "syslog.remote.status": "enabled", "syslog.remote.ip": "10.55.12.244", "syslog.remote.port": "514"}

# Jared's "re-borked" config from 2026-11-11 (t90u)
BORKED_CFG = """aaa.status=disabled
resolv.host.1.name=MikeRobertszzsdff
syslog.status=disabled
syslog.remote.status=disabled
syslog.remote.port=5145
syslog.remote.ip=10.55.12.242
snmp.status=disabled
snmp.location=HUT Wasdfasdf
snmp.contact=BTWIzsdf
snmp.community=BTWId
users.1.name=BTTW
"""


def cfg_dict(text):
    d = {}
    for l in text.splitlines():
        if "=" in l:
            k, v = l.split("=", 1)
            d.setdefault(k, []).append(v)
    return d


def assert_standard(text, std=STD):
    d = cfg_dict(text)
    for k, v in std.items():
        assert d.get(k) == [v], (k, d.get(k))


@pytest.fixture()
def ssh_env(tmp_path, monkeypatch):
    holder = {}

    def make(cfg=SAMPLE_CFG, **kw):
        radio = FakeAirOSSSH(cfg=cfg, **kw)
        holder["radio"] = radio
        log = tmp_path / "kicks.jsonl"
        known_hosts = tmp_path / "known_hosts"
        for k, v in {"WEBHOOK_SECRET": SECRET, "RADIO_USERNAME": "testuser", "RADIO_PASSWORD": "testpass",
                     "KICK_LOG": str(log),
                     # /kick's allowlist. 127.0.0.1 is outside it on purpose.
                     "ALLOWED_NETWORKS": "10.0.0.0/8",
                     "RADIO_SSH_PORT": str(radio.port), "RADIO_SSH_USER": "BTTW", "RADIO_SSH_PASSWORD": "sshpass",
                     "RADIO_SSH_CONNECT_TIMEOUT": "5", "RADIO_SSH_COMMAND_TIMEOUT": "10",
                     "CPE_SOFTRESTART_TIMEOUT": "5", "UISP_API_TOKEN": "",
                     # Less-secure test opt-in so the fake's key can be saved on first connect.
                     "RADIO_SSH_HOST_KEY_POLICY": "accept-new",
                     "RADIO_SSH_KNOWN_HOSTS": str(known_hosts)}.items():
            monkeypatch.setenv(k, v)
        import ssh_service
        importlib.reload(ssh_service)
        # Production rejects loopback. The fake radio is on 127.0.0.1, so this
        # fixture permits that one address and no other special address.
        real_norm = ssh_service.norm_rename_ip

        def allow_fake_loopback(value):
            if str(value or "").strip() == "127.0.0.1":
                return "127.0.0.1"
            return real_norm(value)

        ssh_service.norm_rename_ip = allow_fake_loopback
        return TestClient(ssh_service.app), radio, log

    yield make
    if "radio" in holder:
        holder["radio"].close()


def rename(c, **body):
    body.setdefault("ip", "127.0.0.1")
    body.setdefault("name", "Mike Roberts")
    body.setdefault("snmp_location", "HUT W")
    return c.post("/rename-cpe", json=body, headers=H)


def test_rename_borked_config_fully_fixed(ssh_env):
    c, radio, log = ssh_env(BORKED_CFG)
    r = rename(c, workflow_id="WFP-R1")
    j = r.json()
    assert r.status_code == 200 and j["result"] == "success", j
    assert j["state"] == "changed" and j["saved"] and j["applied"] and j["apply_confirmed"]
    assert set(j["changed_keys"]) == set(STD)  # every key was wrong
    assert j["keys"]["snmp.status"] == {"before": "disabled", "after": "enabled", "target": "enabled"}
    assert j["keys"]["resolv.host.1.name"]["before"] == "MikeRobertszzsdff"
    assert j["location_source"] == "override" and j["location"] == "HUT W" and j["dry_run"] is False
    assert_standard(radio.cfg())
    assert_standard(radio.saved())  # cfgmtd saved the fixed config
    assert radio.restarts == 1
    assert "aaa.status=disabled" in radio.cfg() and "users.1.name=BTTW" in radio.cfg()  # untouched
    assert radio.commands[-2:] == ["cfgmtd -w -p /etc/", "/usr/etc/rc.d/rc.softrestart save"]
    raw = log.read_text()
    assert "sshpass" not in raw and SECRET not in raw
    e = lines(log)[-1]
    assert e["action"] == "rename-cpe" and e["result"] == "success" and e["saved"] and e["workflow_id"] == "WFP-R1"


def test_rename_missing_keys_appended(ssh_env):
    c, radio, _ = ssh_env("aaa.status=disabled\nresolv.host.1.name=old\nusers.1.name=BTTW\n")
    j = rename(c).json()
    assert j["result"] == "success", j
    assert j["keys"]["syslog.remote.ip"]["before"] is None
    assert_standard(radio.cfg())
    assert_standard(radio.saved())


def test_rename_already_compliant_no_save(ssh_env):
    c, radio, _ = ssh_env(SAMPLE_CFG.replace("snmp.location=HUT", "snmp.location=HUT W"))
    j = rename(c).json()
    assert j["result"] == "success" and j["state"] == "already_compliant" and j["already_compliant"] is True, j
    assert j["changed_keys"] == [] and j["saved"] is False and j["applied"] is False
    assert radio.saved() is None and radio.restarts == 0
    assert radio.commands == ["cat /tmp/system.cfg"]


def test_rename_dry_run_changes_nothing(ssh_env):
    c, radio, log = ssh_env(BORKED_CFG)
    j = rename(c, dry_run=True).json()
    assert j["result"] == "success" and j["state"] == "dry_run" and j["dry_run"] is True, j
    assert set(j["changed_keys"]) == set(STD) and j["saved"] is False and j["applied"] is False
    assert j["keys"]["syslog.remote.port"] == {"before": "5145", "after": "514", "target": "514"}
    assert radio.cfg() == BORKED_CFG and radio.saved() is None and radio.restarts == 0
    assert radio.commands == ["cat /tmp/system.cfg"]
    assert lines(log)[-1]["dry_run"] is True


def test_rename_verify_failure_no_save(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG, sabotage_key="snmp.location")
    r = rename(c)
    j = r.json()
    assert r.status_code == 502 and j["result"] == "failed" and "verify failed" in j["message"], j
    assert "restored and verified" in j["message"]
    assert "snmp.location" in j["message"] and j["saved"] is False and j["applied"] is False
    assert radio.saved() is None and radio.restarts == 0
    assert not any(cmd.startswith("cfgmtd") for cmd in radio.commands)
    assert radio.cfg() == BORKED_CFG  # working copy restored from the backup


def test_rename_save_failure(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG, save_exit=1)
    r = rename(c)
    assert r.status_code == 502 and "cfgmtd save" in r.json()["message"] and r.json()["saved"] is False
    assert radio.restarts == 0


def test_rename_ssh_drop_during_softrestart_ok(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG, drop_on_restart=True)
    j = rename(c).json()
    assert j["result"] == "success" and j["saved"] and j["applied"] and j["apply_confirmed"] is False, j
    assert any("dropped during soft restart" in w for w in j["warnings"])
    assert_standard(radio.saved())


def test_rename_softrestart_rtnetlink_noise_ok(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG, restart_exit=1)  # only RTNETLINK noise printed -> still fine
    j = rename(c).json()
    assert j["result"] == "success" and j["applied"], j


def test_rename_bad_ssh_password(ssh_env, monkeypatch):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "radio_ssh_password", "wrong")
    r = rename(c)
    assert r.status_code == 502 and "SSH login rejected" in r.json()["message"]
    assert radio.cfg() == BORKED_CFG
    assert "wrong" not in r.text


def test_rename_unreachable(ssh_env, monkeypatch):
    c, radio, _ = ssh_env()
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "radio_ssh_port", 1)
    r = rename(c)
    assert r.status_code == 502 and "SSH" in r.json()["message"]


def test_rename_auth_required(ssh_env):
    c, radio, log = ssh_env(BORKED_CFG)
    b = {"ip": "127.0.0.1", "name": "Mike Roberts", "snmp_location": "HUT W"}
    assert c.post("/rename-cpe", json=b).status_code == 401
    assert c.post("/rename-cpe", json=b, headers={"X-Webhook-Secret": "wrong"}).status_code == 401
    assert c.post("/rename-cpe", json={**b, "secret": "nope"}).status_code == 401
    assert c.get("/rename-cpe", params={**b, "secret": SECRET}).status_code == 401  # query secret off
    assert radio.commands == [] and radio.logins == 0
    assert lines(log)[-1]["message"] == "unauthorized"


def test_rename_get_query_and_bearer(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    r = c.get("/rename-cpe", params={"ip": "127.0.0.1", "name": "Mike Roberts", "snmp_location": "HUT W",
                                     "dry_run": "true"}, headers={"Authorization": f"Bearer {SECRET}"})
    assert r.status_code == 200 and r.json()["state"] == "dry_run"


def test_rename_body_secret_vision_style(ssh_env):
    c, radio, log = ssh_env(BORKED_CFG)
    r = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts", "snmp_location": "HUT W",
                                    "secret": SECRET, "dry_run": True})
    assert r.status_code == 200 and SECRET not in log.read_text()


def test_rename_connects_only_to_the_supplied_ip(ssh_env, monkeypatch):
    """The SSH client opens a session to the one IP in the call and to nothing else."""
    import ipaddress
    import socket
    import ssh_service

    c, radio, _ = ssh_env(BORKED_CFG)
    supplied = "127.0.0.1"
    assert not any(ipaddress.ip_address(supplied) in net for net in ssh_service.S.allowed_networks)
    assert not hasattr(ssh_service.S, "cpe_allowed_networks")

    destinations = []
    real_connect = socket.socket.connect

    def spy_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        destinations.append(str(host))
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", spy_connect)
    j = rename(c, ip=supplied).json()
    assert j["result"] == "success", j
    assert j["ip"] == supplied
    assert destinations, "expected an SSH connection to the supplied IP"
    assert set(destinations) == {supplied}
    assert radio.logins == 1


def test_rename_ip_has_no_allowlist(env):
    """Ordinary IPv4 addresses parse. Prefixes, junk, and special addresses do not."""
    import ssh_service
    assert not hasattr(ssh_service.S, "cpe_allowed_networks")
    # Documentation and private CPE addresses. Parsing does not connect.
    assert ssh_service.norm_rename_ip("203.0.113.50") == "203.0.113.50"
    assert ssh_service.norm_rename_ip("10.41.0.5") == "10.41.0.5"
    assert ssh_service.norm_rename_ip("172.20.1.2") == "172.20.1.2"
    for bad in ("203.0.113.0/24", "notanip", "127.0.0.1,10.1.2.3", "", "  ",
                "0.0.0.0", "0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1"):
        with pytest.raises(ValueError):
            ssh_service.norm_rename_ip(bad)


def test_rename_bad_input_rejected(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    bad = [
        {"name": "|||&&&"},                              # nothing left after sanitizing
        {"name": "   "},
        {"name": ""},
        {"snmp_location": "HUT|W"},                      # sed delimiter
        {"snmp_location": "HUT & W"},
        {"snmp_location": "HUT\\W"},
        {"snmp_location": "HUT\nW"},
        {"snmp_location": "HUT 'W'"},
        {"snmp_location": 'HUT "W"'},
        {"snmp_location": "HUT;reboot"},
        {"ip": "notanip"},
        {"ip": "127.0.0.1/30"},                          # a prefix is not a single address
        {"ip": "127.0.0.1,10.1.2.3"},                    # a list is not a single address
        {"ip": "10.0.0.0/8"},
        {"ip": ""},
        {"uisp_device_id": "../devices"},
        {"mac": "zz"},
    ]
    for b in bad:
        r = rename(c, **b)
        assert r.status_code == 400 and r.json()["result"] == "failed", b
    assert radio.commands == [] and radio.logins == 0


def test_rename_name_with_symbols_is_sanitized(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    j = rename(c, name="Mike & Sue O'Roberts | Farm", dry_run=True).json()
    assert j["name"] == "Mike Sue ORoberts Farm"


def test_rename_no_location_skips_key(ssh_env, monkeypatch):
    c, radio, _ = ssh_env(BORKED_CFG)
    j = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts"}, headers=H).json()
    assert j["result"] == "success" and j["location_source"] == "none" and j["location"] is None, j
    assert "snmp.location" not in j["keys"] and j["skipped_keys"] == ["snmp.location"]
    assert any("UISP_API_TOKEN" in w for w in j["warnings"]) and "NOT set" in j["message"]
    d = cfg_dict(radio.cfg())
    assert d["snmp.location"] == ["HUT Wasdfasdf"]  # left alone, never guessed
    assert_standard(radio.cfg(), {k: v for k, v in STD.items() if k != "snmp.location"})


def test_rename_location_from_uisp(ssh_env, monkeypatch):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "uisp_api_token", "tok")
    stations = [{"identification": {"id": "x", "mac": "70:a7:41:44:a8:b2"}, "ipAddress": "127.0.0.1/24",
                 "attributes": {"apDevice": {"id": "ap-1", "name": "BOTSECHUTW"}}}]
    ap = {"identification": {"site": {"name": "03_PRYHUT"}}}
    seen = []

    def fake_get(path, budget=None):
        seen.append(path)
        return stations if path.startswith("/devices?") else ap

    monkeypatch.setattr(ssh_service, "_uisp_get", fake_get)
    j = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts"}, headers=H).json()
    assert j["location"] == "HUT W" and j["location_source"] == "uisp_ap" and j["ap_name"] == "BOTSECHUTW", j
    assert j["ap_site"] == "03_PRYHUT" and seen == ["/devices?role=station", "/devices/ap-1"]
    assert_standard(radio.saved())
    # by mac
    seen.clear()
    j = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts", "mac": "70-A7-41-44-A8-B2",
                                    "dry_run": True}, headers=H).json()
    assert j["location"] == "HUT W"
    # by device id
    seen.clear()
    stations_by_id = stations[0]
    monkeypatch.setattr(ssh_service, "_uisp_get",
                        lambda p, budget=None: (seen.append(p), stations_by_id if p.endswith("8865782f-3e30-4822-a268-2e9d9e84016e") else ap)[1])
    j = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts", "dry_run": True,
                                    "uisp_device_id": "8865782f-3e30-4822-a268-2e9d9e84016e"}, headers=H).json()
    assert j["location"] == "HUT W" and seen[0] == "/devices/8865782f-3e30-4822-a268-2e9d9e84016e"


def test_rename_missing_ssh_password(ssh_env, monkeypatch):
    c, radio, _ = ssh_env()
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "radio_ssh_password", "")
    r = rename(c)
    assert r.status_code == 500 and "RADIO_SSH_PASSWORD" in r.json()["message"] and radio.logins == 0


def test_rename_edit_command_quoting(ssh_env):
    c, radio, _ = ssh_env()
    import ssh_service
    cmd = ssh_service.edit_command({"resolv.host.1.name": "Sam Hochstetler", "snmp.location": "HUT W"})
    assert "btwi-cfg-edit" in cmd and "s snmp.location 'HUT W'" in cmd
    assert "s resolv.host.1.name 'Sam Hochstetler'" in cmd
    assert "rename-bak.tmp" in cmd and "mv " in cmd
    assert "sed -i" not in cmd
    with pytest.raises(ValueError):
        ssh_service.edit_command({"snmp.location": "a|b"})


def test_rename_rejects_special_addresses(env, monkeypatch):
    """Special addresses are a 400 and never open a socket."""
    import socket
    blocked = []

    def spy(self, address):
        host = address[0] if isinstance(address, tuple) else address
        blocked.append(str(host))
        raise OSError("test blocked connect")

    monkeypatch.setattr(socket.socket, "connect", spy)
    c, _, _ = env
    cases = {
        "0.0.0.0": "0.x",
        "0.8.8.8": "0.x",
        "127.0.0.1": "loopback",
        "127.255.255.1": "loopback",
        "169.254.1.1": "link-local",
        "224.0.0.1": "multicast",
        "240.0.0.1": "reserved",
        "255.255.255.255": "reserved",
    }
    for ip, snippet in cases.items():
        r = c.post("/rename-cpe", json={"ip": ip, "name": "Mike Roberts", "snmp_location": "HUT W"}, headers=H)
        assert r.status_code == 400, (ip, r.status_code, r.text)
        body = r.json()
        assert body["result"] == "failed"
        assert snippet in body["message"], body
    assert blocked == []


def test_rename_host_key_default_refuses_password(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    ssh_service.S.radio_ssh_host_key_policy = "reject"
    ssh_service.S.radio_ssh_known_hosts = ""
    r = rename(c, dry_run=True)
    assert r.status_code == 400, r.text
    assert "Refusing to send the SSH password" in r.json()["message"]
    assert radio.logins == 0 and radio.commands == []


def test_rename_missing_known_hosts_file_is_clear(ssh_env, tmp_path):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    ssh_service.S.radio_ssh_host_key_policy = "reject"
    ssh_service.S.radio_ssh_known_hosts = str(tmp_path / "does-not-exist")
    r = rename(c, dry_run=True)
    assert r.status_code == 400, r.text
    assert "missing" in r.json()["message"].lower()
    assert "500" not in r.json()["message"]
    assert radio.logins == 0


def test_rename_bare_ip_known_hosts_is_not_cannot_reach(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    key = radio.host_key
    path = ssh_service.S.radio_ssh_known_hosts
    with open(path, "w") as fh:
        fh.write(f"127.0.0.1 {key.get_name()} {key.get_base64()}\n")
    ssh_service.S.radio_ssh_host_key_policy = "reject"
    r = rename(c, dry_run=True)
    j = r.json()
    assert r.status_code == 502, j
    assert "host key" in j["message"].lower()
    assert "not found" in j["message"].lower()
    assert "cannot reach" not in j["message"].lower()
    assert "[127.0.0.1]:" in j["message"]
    assert radio.logins == 0


def test_rename_pinned_host_key_allows_connect(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    key = radio.host_key
    path = ssh_service.S.radio_ssh_known_hosts
    with open(path, "w") as fh:
        fh.write(f"[127.0.0.1]:{radio.port} {key.get_name()} {key.get_base64()}\n")
    ssh_service.S.radio_ssh_host_key_policy = "reject"
    j = rename(c, dry_run=True).json()
    assert j["result"] == "success", j
    assert radio.logins == 1


def test_rename_accept_new_saves_then_rejects_changed_key(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    path = ssh_service.S.radio_ssh_known_hosts
    assert ssh_service.S.radio_ssh_host_key_policy == "accept-new"
    first = rename(c, dry_run=True).json()
    assert first["result"] == "success", first
    saved = open(path).read()
    assert f"[127.0.0.1]:{radio.port}" in saved
    second = rename(c, dry_run=True).json()
    assert second["result"] == "success", second
    radio.rotate_host_key()
    r = rename(c, dry_run=True)
    j = r.json()
    assert r.status_code == 502, j
    assert "does not match" in j["message"]
    assert radio.logins == 2  # the changed key is rejected before a third login


def test_rename_restore_is_honest_when_backup_is_gone(ssh_env):
    c, radio, _ = ssh_env(BORKED_CFG, sabotage_key="snmp.location", drop_backup=True)
    r = rename(c)
    j = r.json()
    assert r.status_code == 502, j
    assert "verify failed" in j["message"]
    assert "could not be verified" in j["message"]
    assert "restored and verified" not in j["message"]
    assert j["saved"] is False and j["applied"] is False
    assert radio.saved() is None and radio.restarts == 0
    assert "sabotaged" in radio.cfg()


def test_rename_does_not_clobber_lookalike_keys(ssh_env):
    cfg = "snmpXstatus=leave-me\nresolvXhost.1.name=leave-host\n" + BORKED_CFG
    c, radio, _ = ssh_env(cfg)
    j = rename(c).json()
    assert j["result"] == "success", j
    text = radio.cfg()
    assert "snmpXstatus=leave-me" in text
    assert "resolvXhost.1.name=leave-host" in text
    assert "\nsnmp.status=enabled\n" in f"\n{text}"


def test_uisp_redirect_is_not_followed(env, monkeypatch):
    import ssh_service
    calls = []

    class Resp:
        status_code = 302
        headers = {"Location": "https://evil.example/steal"}
        text = ""

        def json(self):
            raise AssertionError("redirect body must not be read")

    def fake_get(url, headers=None, timeout=None, allow_redirects=True, **kwargs):
        calls.append({"url": url, "allow_redirects": allow_redirects,
                      "token": (headers or {}).get("x-auth-token")})
        return Resp()

    monkeypatch.setattr(ssh_service.S, "uisp_api_token", "super-secret-token")
    monkeypatch.setattr(ssh_service.requests, "get", fake_get)
    with pytest.raises(RuntimeError) as caught:
        ssh_service._uisp_get("/devices?role=station")
    assert "redirect" in str(caught.value).lower()
    assert len(calls) == 1
    assert calls[0]["allow_redirects"] is False
    assert calls[0]["token"] == "super-secret-token"
    assert "evil.example" not in calls[0]["url"]


def test_rename_mac_must_match_supplied_ip(ssh_env, monkeypatch):
    c, radio, _ = ssh_env(BORKED_CFG)
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "uisp_api_token", "tok")
    seen = []
    stations = [{
        "identification": {"id": "x", "mac": "70:a7:41:44:a8:b2"},
        "ipAddress": "10.9.9.9",
        "attributes": {"apDevice": {"id": "ap-1", "name": "BOTSECHUTW"}},
    }]

    def fake_get(path, budget=None):
        seen.append(path)
        if path.startswith("/devices?"):
            return stations
        raise AssertionError(f"must not look up another device for a MAC on a different IP: {path}")

    monkeypatch.setattr(ssh_service, "_uisp_get", fake_get)
    j = c.post("/rename-cpe", json={"ip": "127.0.0.1", "name": "Mike Roberts",
                                    "mac": "70-A7-41-44-A8-B2", "dry_run": True}, headers=H).json()
    assert j["result"] == "success", j
    assert j["location"] is None and j["location_source"] == "none"
    assert any("does not use 127.0.0.1" in w for w in j["warnings"])
    assert seen == ["/devices?role=station"]
    assert "snmp.location" not in j["keys"]


def test_rename_redacts_snmp_community(ssh_env, monkeypatch):
    c, radio, log = ssh_env(BORKED_CFG)
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "cpe_snmp_community", "SuperSecretCommunity")
    r = rename(c)
    j = r.json()
    assert j["result"] == "success", j
    assert j["keys"]["snmp.community"] == {"before": "***", "after": "***", "target": "***"}
    assert "SuperSecretCommunity" not in r.text
    assert "SuperSecretCommunity" not in log.read_text()
    assert "snmp.community=SuperSecretCommunity" in radio.cfg()


def test_rename_time_budget_stops_before_save(ssh_env, monkeypatch):
    c, radio, _ = ssh_env(BORKED_CFG, command_delay=3)
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "rename_time_budget", 1)
    r = rename(c)
    j = r.json()
    assert r.status_code == 504, j
    assert "timed out" in j["message"].lower()
    assert "restart" in j["message"].lower()
    assert j["saved"] is False and j["applied"] is False
    assert radio.restarts == 0
    assert not any("cfgmtd" in cmd for cmd in radio.commands)
    assert radio.cfg() == BORKED_CFG


def test_kick_starts_when_syslog_ip_is_blank(tmp_path, monkeypatch):
    import importlib
    import socket
    monkeypatch.setenv("WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("RADIO_USERNAME", "testuser")
    monkeypatch.setenv("RADIO_PASSWORD", "testpass")
    monkeypatch.setenv("CPE_SYSLOG_IP", "")
    monkeypatch.setenv("RADIO_SSH_PASSWORD", "sshpass")
    monkeypatch.setenv("ALLOWED_NETWORKS", "127.0.0.0/8")
    monkeypatch.setenv("KICK_LOG", str(tmp_path / "kicks.jsonl"))
    import ssh_service
    importlib.reload(ssh_service)
    blocked = []

    def spy(self, address):
        host = address[0] if isinstance(address, tuple) else address
        blocked.append(str(host))
        raise OSError("test blocked connect")

    monkeypatch.setattr(socket.socket, "connect", spy)
    c = TestClient(ssh_service.app)
    kick = c.post("/kick", json={"ip": "127.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "dry_run": True}, headers=H)
    assert kick.status_code == 200, kick.text
    rename_r = c.post("/rename-cpe", json={"ip": "203.0.113.10", "name": "Mike Roberts",
                                           "snmp_location": "HUT W", "dry_run": True}, headers=H)
    assert rename_r.status_code == 400, rename_r.text
    assert "CPE_SYSLOG_IP" in rename_r.json()["message"]
    assert blocked == []


class FakeUisp:
    """Local stand-in for UISP NMS. Never points at a real controller."""

    def __init__(self, devices, site, put_status=200):
        self.devices = devices
        self.site = site
        self.put_status = put_status
        self.calls = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else None
                path = urllib.parse.urlsplit(self.path).path
                fake.calls.append({
                    "method": self.command,
                    "path": path,
                    "token": self.headers.get("x-auth-token"),
                    "body": body,
                })
                return path, body

            def do_GET(self):
                path, _ = self._record()
                if path.startswith("/devices"):
                    ident = path.rstrip("/").split("/")[-1]
                    if ident == "devices":
                        return self._send(200, fake.devices)
                    for dev in fake.devices:
                        if (dev.get("identification") or {}).get("id") == ident:
                            return self._send(200, dev)
                    return self._send(404, {"message": "not found"})
                if path.startswith("/sites/"):
                    site_id = path.rstrip("/").split("/")[-1]
                    got = (fake.site.get("identification") or {}).get("id")
                    if site_id == got:
                        return self._send(200, fake.site)
                    return self._send(404, {"message": "not found"})
                return self._send(404, {"message": "not found"})

            def do_PUT(self):
                path, body = self._record()
                if path.startswith("/sites/") and fake.put_status == 200 and isinstance(body, dict):
                    fake.site = body
                self._send(fake.put_status, {"message": "put"})

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _station(site_type="endpoint", site_id="site-1", site_name="Old Customer"):
    return {
        "identification": {
            "id": "dev-1",
            "mac": "70:a7:41:44:a8:b2",
            "site": {"id": site_id, "name": site_name, "type": site_type},
        },
        "ipAddress": "127.0.0.1",
    }


def _site(name="Old Customer", site_id="site-1", site_type="endpoint"):
    return {
        "identification": {
            "id": site_id,
            "name": name,
            "type": site_type,
            "parent": {"id": "tower-1"},
        },
        "description": {
            "address": "123 Farm Road",
            "location": {"latitude": 41.5, "longitude": -93.6},
            "height": 4,
        },
    }


def _arm_site_rename(monkeypatch, fake, write_token="write-token-test", api_token="", enabled=True):
    import ssh_service
    monkeypatch.setattr(ssh_service.S, "uisp_base_url", fake.base)
    monkeypatch.setattr(ssh_service.S, "uisp_rename_site", enabled)
    monkeypatch.setattr(ssh_service.S, "uisp_write_token", write_token)
    monkeypatch.setattr(ssh_service.S, "uisp_api_token", api_token)


def test_uisp_site_rename_endpoint(ssh_env, monkeypatch):
    fake = FakeUisp([_station()], _site())
    try:
        c, radio, log = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake, write_token="write-token-test", api_token="read-token-test")
        r = rename(c)
        j = r.json()
        assert j["result"] == "success" and j["saved"] and j["applied"], j
        assert j["site_rename"]["state"] == "renamed"
        assert j["site_rename"]["site_id"] == "site-1"
        assert j["site_rename"]["before"] == "Old Customer"
        assert j["site_rename"]["after"] == "Mike Roberts"
        puts = [call for call in fake.calls if call["method"] == "PUT"]
        assert len(puts) == 1
        assert puts[0]["path"] == "/sites/site-1"
        assert puts[0]["token"] == "write-token-test"
        body = puts[0]["body"]
        assert body["identification"]["name"] == "Mike Roberts"
        assert body["identification"]["parent"] == {"id": "tower-1"}
        assert body["description"]["address"] == "123 Farm Road"
        assert body["description"]["location"] == {"latitude": 41.5, "longitude": -93.6}
        assert not any(call["method"] == "PUT" and call["path"].startswith("/devices") for call in fake.calls)
        assert all(call["token"] == "write-token-test" for call in fake.calls)
        raw = r.text + log.read_text()
        assert "write-token-test" not in raw and "read-token-test" not in raw
        assert_standard(radio.cfg())
    finally:
        fake.close()


def test_uisp_site_rename_skips_tower(ssh_env, monkeypatch):
    fake = FakeUisp([_station(site_type="site", site_id="tower-9", site_name="03_PRYHUT")],
                    _site(name="03_PRYHUT", site_id="tower-9", site_type="site"))
    try:
        c, radio, _ = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake)
        j = rename(c).json()
        assert j["result"] == "success" and j["applied"], j
        assert j["site_rename"]["state"] == "skipped"
        assert j["site_rename"]["site_id"] == "tower-9"
        assert any("endpoint" in w for w in j["warnings"])
        assert not any(call["method"] == "PUT" for call in fake.calls)
        assert not any(call["path"].startswith("/sites/") for call in fake.calls)
        assert_standard(radio.cfg())
    finally:
        fake.close()


def test_uisp_site_rename_dry_run_does_not_put(ssh_env, monkeypatch):
    fake = FakeUisp([_station()], _site())
    try:
        c, radio, _ = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake)
        j = rename(c, dry_run=True).json()
        assert j["result"] == "success" and j["dry_run"] is True, j
        assert j["site_rename"]["before"] == "Old Customer"
        assert j["site_rename"]["after"] == "Mike Roberts"
        assert "would rename" in j["site_rename"]["message"]
        assert "no PUT" in j["site_rename"]["message"]
        assert not any(call["method"] == "PUT" for call in fake.calls)
        assert any(call["method"] == "GET" and call["path"] == "/sites/site-1" for call in fake.calls)
        assert radio.cfg() == BORKED_CFG
    finally:
        fake.close()


def test_uisp_site_rename_disabled_skips_without_calling(ssh_env, monkeypatch):
    fake = FakeUisp([_station()], _site())
    try:
        c, radio, _ = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake, enabled=False)
        j = rename(c).json()
        assert j["result"] == "success", j
        assert j["site_rename"]["state"] == "skipped"
        assert any("UISP_RENAME_SITE" in w for w in j["warnings"])
        assert fake.calls == []
        assert_standard(radio.cfg())
    finally:
        fake.close()


def test_uisp_site_rename_error_keeps_radio_success(ssh_env, monkeypatch):
    fake = FakeUisp([_station()], _site(), put_status=500)
    try:
        c, radio, _ = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake)
        r = rename(c)
        j = r.json()
        assert r.status_code == 200 and j["result"] == "success", j
        assert j["saved"] and j["applied"]
        assert j["site_rename"]["state"] == "failed"
        assert "500" in j["site_rename"]["message"]
        assert_standard(radio.cfg())
        assert fake.site["identification"]["name"] == "Old Customer"
    finally:
        fake.close()


def test_uisp_site_rename_unchanged_when_name_matches(ssh_env, monkeypatch):
    fake = FakeUisp([_station(site_name="Mike Roberts")], _site(name="Mike Roberts"))
    try:
        c, radio, log = ssh_env(BORKED_CFG)
        _arm_site_rename(monkeypatch, fake, write_token="", api_token="api-token-test")
        j = rename(c).json()
        assert j["result"] == "success" and j["applied"], j
        assert j["site_rename"]["state"] == "unchanged"
        assert j["site_rename"]["before"] == "Mike Roberts"
        assert j["site_rename"]["after"] == "Mike Roberts"
        assert not any(call["method"] == "PUT" for call in fake.calls)
        assert fake.calls and all(call["token"] == "api-token-test" for call in fake.calls)
        assert "api-token-test" not in log.read_text()
        assert_standard(radio.cfg())
    finally:
        fake.close()


SANITIZE_CASES = [
    ("Mike Roberts", "Mike Roberts"),
    ("Sam Hochstetler", "Sam Hochstetler"),
    ("  Mike   Roberts  ", "Mike Roberts"),
    ("Mike\tRoberts\nJr.", "Mike Roberts Jr."),
    ("O'Brien, Pat & Sue", "OBrien Pat Sue"),
    ("Smith -- Farm", "Smith - Farm"),
    ("--Edge--", "Edge"),
    ("José Núñez", "Jos Nez"),
    ("Under_score.ok", "Under_score.ok"),
    ("A" * 40, "A" * 32),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZ12345 X", "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"),  # trailing space trimmed after cut
]


@pytest.mark.parametrize("raw,expected", SANITIZE_CASES)
def test_sanitize_name(env, raw, expected):
    import ssh_service
    assert ssh_service.sanitize_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "|&\\'\"", "!!!", "---", None])
def test_sanitize_name_empty_is_error(env, raw):
    import ssh_service
    with pytest.raises(ValueError):
        ssh_service.sanitize_name(raw)


def test_check_sed_safe(env):
    import ssh_service
    for bad in ["a|b", "a&b", "a\\b", "a\nb", "a'b", 'a"b', "a`b"]:
        with pytest.raises(ValueError):
            ssh_service.check_sed_safe("x", bad)
    ssh_service.check_sed_safe("x", "HUT W")


LOCATION_CASES = [
    ("BOTSECPWT240", "17_PWT", "PWT 240"),
    ("BOTSECHUTW", "03_PRYHUT", "HUT W"),
    ("BOTSECTLSW", "20_TL", "TL SW"),
    ("BOTSECMB240", "13_MB", "MB 240"),
    ("BOTSECEWT120", "70_EWT", "EWT 120"),
    ("PWTWAVENNE", "17_PWT", "PWT WAVENNE"),
    ("botsechutw", "03_PRYHUT", "HUT W"),
    ("BOTSEC150E", "150TH.", "150 E"),
    ("BOTSECMBTSW", "16MBT", "MBT SW"),
    ("BOTSECI35NE", "74_I-35", "I35 NE"),
    ("BOTSECGJCWAVEN", "GJC 81", "GJC WAVEN"),
    ("BOTSECSH2.4NE", "76_SH", "SH 2.4NE"),
    ("BOTSECEB-LOCAL-AP", "36_EB", "EB LOCAL-AP"),
    # never guess:
    ("BOTBHPWT2MB", "17_PWT", None),        # backhaul
    ("BOTSECPWT", "17_PWT", None),          # no sector
    ("Onken_Local", "42_JON", None),        # only 'ON' overlaps; non-BOTSEC needs full code
    ("Lynch-Hop-AP", "Lynch, Dan", None),   # customer site
    ("BPS Fiber Feed AP", "43_BPS", None),  # spaces
    ("BOTSECXYZ1", "17_PWT", None),
    ("", "17_PWT", None),
    ("BOTSECPWT240", "", None),
]


@pytest.mark.parametrize("ap,site,expected", LOCATION_CASES)
def test_derive_location(env, ap, site, expected):
    import ssh_service
    loc, note = ssh_service.derive_location(ap, site)
    assert loc == expected, note
    if expected is None:
        assert note  # always a warning


def test_derive_location_real_uisp_names(env):
    """Snapshot of every AP a UISP station hangs off (read-only pull 2026-11-11)."""
    import ssh_service
    data = json.load(open(os.path.join(os.path.dirname(__file__), "uisp_ap_names.json")))["aps"]
    assert len(data) > 300
    mismatches = []
    for row in data:
        loc, _ = ssh_service.derive_location(row["ap_name"], row["site"])
        if loc != row["expected"]:
            mismatches.append((row["ap_name"], row["site"], loc, row["expected"]))
    assert not mismatches, mismatches[:10]
    botsec = [r for r in data if r["ap_name"].upper().startswith("BOTSEC")]
    assert botsec and all(r["expected"] for r in botsec)  # every BOTSEC sector parses
    for r in data:
        if r["expected"]:
            assert re.match(r"^[A-Z0-9]+ [A-Z0-9][A-Z0-9.\-]*$", r["expected"]), r
