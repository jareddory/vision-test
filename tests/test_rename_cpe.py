"""/rename-cpe: strict MAC+IP match, UISP alias rename, airOS hostname push, dry_run.

All UISP HTTP traffic is mocked; nothing here talks to a real UISP.
"""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["UISP_TOKEN"] = os.environ.get("UISP_TOKEN") or "test-token"
os.environ["WEBHOOK_SECRET"] = os.environ.get("WEBHOOK_SECRET") or "test-secret"

import uisp_service as mod
from fastapi import HTTPException


class FakeRequest:
    def __init__(self, method="GET", params=None, body=None):
        self.method = method
        self.query_params = params or {}
        self._body = {} if body is None else body

    async def json(self):
        return self._body


class Resp:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def cpe(mac="AA:BB:CC:DD:EE:FF", ip="10.1.2.3", name="Old Name", dtype="airMax", role="station", did="dev-1"):
    return {
        "identification": {"id": did, "mac": mac, "name": name, "displayName": name,
                           "type": dtype, "role": role, "site": {"id": "site-1"}},
        "ipAddress": ip,
    }


class Uisp:
    """Records every call. GET /system/unms and /airos/.../configuration return canned bodies."""

    def __init__(self, devices, alias="Old Name", hostname="Old Name", unms_extra=None,
                 put_unms=None, put_airos=None, get_status=200):
        self.devices = devices
        self.calls = []
        self.unms = {"overrideGlobal": False, "devicePingIntervalNormal": 30000,
                     "deviceTransmissionProfile": "auto",
                     "meta": {"alias": alias, "note": "keep me", "maintenance": False}}
        if unms_extra:
            self.unms.update(unms_extra)
        self.airos = {"system": {"hostname": hostname, "timezone": "America/Chicago",
                                 "ledsOff": False, "uiLanguage": "en_US"},
                      "wireless": {"ssid": "do-not-touch"}, "network": {"interfaces": []}}
        self.put_unms = put_unms or (lambda: Resp(200, {"meta": {"alias": "x"}}))
        self.put_airos = put_airos or (lambda: Resp(200, {"result": True, "message": "ok"}))
        self.get_status = get_status

    def get_devices(self):
        self.calls.append(("GET", "/devices", None, None))
        return self.devices

    def get(self, url, headers=None, timeout=None, params=None):
        path = url.replace(mod.UISP_BASE, "")
        self.calls.append(("GET", path, params, None))
        if self.get_status != 200:
            return Resp(self.get_status, text="nope")
        if path.endswith("/system/unms"):
            return Resp(200, self.unms)
        if path.startswith("/devices/airos/") and path.endswith("/configuration"):
            return Resp(200, self.airos)
        raise AssertionError(f"unexpected GET {path}")

    def put(self, url, headers=None, timeout=None, params=None, json=None):
        path = url.replace(mod.UISP_BASE, "")
        self.calls.append(("PUT", path, params, json))
        if path.endswith("/system/unms"):
            return self.put_unms()
        if path.startswith("/devices/airos/"):
            return self.put_airos()
        raise AssertionError(f"unexpected PUT {path}")

    def forbid(self, *a, **k):
        raise AssertionError(f"rename-cpe must not POST/DELETE: {a}")

    def puts(self):
        return [c for c in self.calls if c[0] == "PUT"]


class RenameCpeTests(unittest.TestCase):
    def invoke(self, request, uisp, secret=None):
        secret = mod.WEBHOOK_SECRET if secret is None else secret
        with patch.object(mod, "get_devices", uisp.get_devices), \
             patch.object(mod.requests, "get", uisp.get), \
             patch.object(mod.requests, "put", uisp.put), \
             patch.object(mod.requests, "post", uisp.forbid), \
             patch.object(mod.requests, "delete", uisp.forbid):
            resp = asyncio.run(mod.rename_cpe(request, secret))
        return resp, json.loads(resp.body)

    def params(self, **extra):
        d = {"mac": "aa-bb-cc-dd-ee-ff", "ip": "10.1.2.3", "name": "Cindy Sohn",
             "location": "", "workflow_id": "WF-9"}
        d.update(extra)
        return d

    # --- name building -------------------------------------------------
    def test_build_rename_blank_vs_present_location(self):
        self.assertEqual(mod.build_rename("  Cindy Sohn  ", ""), "Cindy Sohn")
        self.assertEqual(mod.build_rename("Cindy Sohn", "   "), "Cindy Sohn")
        self.assertEqual(mod.build_rename("Cindy Sohn", None), "Cindy Sohn")
        self.assertEqual(mod.build_rename("Cindy  Sohn", " Shop "), "Cindy  Sohn - Shop")  # inner spaces kept
        self.assertEqual(mod.build_rename("sohn, CINDY", ""), "sohn, CINDY")  # case kept

    def test_separator_is_configurable(self):
        with patch.object(mod, "RENAME_LOCATION_SEPARATOR", "-"):
            self.assertEqual(mod.build_rename("Doe", "Shop"), "Doe-Shop")

    # --- happy paths ---------------------------------------------------
    def test_renames_uisp_and_pushes_airos_hostname(self):
        u = Uisp([cpe()])
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 200, body)
        self.assertEqual(body["result"], "success")
        self.assertEqual(body["old_name"], "Old Name")
        self.assertEqual(body["new_name"], "Cindy Sohn")
        self.assertEqual(body["device_id"], "dev-1")
        self.assertEqual(body["match_method"], "mac+ip")
        self.assertEqual(body["changed"], {"uisp": True, "radio": True})
        self.assertEqual(body["radio_status"], "pushed")
        self.assertEqual(body["old_hostname"], "Old Name")
        puts = u.puts()
        self.assertEqual([p[1] for p in puts], ["/devices/dev-1/system/unms", "/devices/airos/dev-1/configuration"])
        unms_body = puts[0][3]
        self.assertEqual(unms_body["meta"]["alias"], "Cindy Sohn")
        self.assertEqual(unms_body["meta"]["note"], "keep me")  # preserved
        self.assertIs(unms_body["meta"]["maintenance"], False)
        self.assertIs(unms_body["overrideGlobal"], False)
        self.assertEqual(unms_body["devicePingIntervalNormal"], 30000)
        self.assertNotIn("deviceTransmissionProfile", unms_body)  # not in PayloadUnmsSettings
        self.assertEqual(puts[1][2], {"isComposeRequest": "false"})
        airos_body = puts[1][3]
        self.assertEqual(list(airos_body), ["system"])  # never resend wireless/network
        self.assertEqual(airos_body["system"]["hostname"], "Cindy Sohn")
        self.assertEqual(airos_body["system"]["timezone"], "America/Chicago")

    def test_location_present_is_appended(self):
        u = Uisp([cpe()])
        resp, body = self.invoke(FakeRequest(method="POST", body=self.params(location="Shop")), u)
        self.assertEqual(resp.status_code, 200, body)
        self.assertEqual(body["new_name"], "Cindy Sohn - Shop")
        self.assertEqual(u.puts()[0][3]["meta"]["alias"], "Cindy Sohn - Shop")

    def test_blank_location_is_absent(self):
        for loc in ("", "   ", None):
            with self.subTest(location=loc):
                u = Uisp([cpe()])
                p = self.params(location=loc)
                resp, body = self.invoke(FakeRequest(method="POST", body=p), u)
                self.assertEqual(body["new_name"], "Cindy Sohn")

    def test_unsupported_type_renames_uisp_only(self):
        u = Uisp([cpe(dtype="wave")])
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 200, body)
        self.assertEqual(body["changed"], {"uisp": True, "radio": False})
        self.assertEqual(body["radio_status"], "unsupported_device_type")
        self.assertEqual([p[1] for p in u.puts()], ["/devices/dev-1/system/unms"])
        self.assertFalse(any("/airos/" in c[1] for c in u.calls))

    def test_push_hostname_false_skips_radio(self):
        u = Uisp([cpe()])
        resp, body = self.invoke(FakeRequest(params=self.params(push_hostname="false")), u)
        self.assertEqual(body["radio_status"], "skipped_disabled")
        self.assertEqual(body["changed"], {"uisp": True, "radio": False})
        self.assertFalse(any("/airos/" in c[1] for c in u.calls))

    def test_env_master_switch_off_skips_radio(self):
        u = Uisp([cpe()])
        with patch.object(mod, "RENAME_PUSH_HOSTNAME", False):
            resp, body = self.invoke(FakeRequest(params=self.params(push_hostname="true")), u)
        self.assertEqual(body["radio_status"], "skipped_disabled")

    # --- dry run / already named --------------------------------------
    def test_dry_run_writes_nothing(self):
        u = Uisp([cpe()])
        resp, body = self.invoke(FakeRequest(params=self.params(dry_run="true", location="Shop")), u)
        self.assertEqual(resp.status_code, 200, body)
        self.assertIs(body["dry_run"], True)
        self.assertEqual(body["message"], "Dry run — no changes made")
        self.assertEqual(body["would_change"], {"uisp": True, "radio": True})
        self.assertEqual(body["changed"], {"uisp": False, "radio": False})
        self.assertEqual(body["radio_status"], "would_push")
        self.assertEqual(body["new_name"], "Cindy Sohn - Shop")
        self.assertEqual(u.puts(), [])

    def test_already_named_no_change(self):
        u = Uisp([cpe(name="Cindy Sohn")], alias="Cindy Sohn", hostname="Cindy Sohn")
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 200, body)
        self.assertEqual(body["message"], "Already named — no change")
        self.assertEqual(body["changed"], {"uisp": False, "radio": False})
        self.assertEqual(u.puts(), [])

    def test_already_named_no_alias_but_display_name_matches(self):
        u = Uisp([cpe(dtype="wave", name="Cindy Sohn")], alias="")
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(body["message"], "Already named — no change")
        self.assertEqual(u.puts(), [])

    def test_uisp_named_but_radio_hostname_differs_pushes_radio_only(self):
        u = Uisp([cpe(name="Cindy Sohn")], alias="Cindy Sohn", hostname="ubnt-old")
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(body["changed"], {"uisp": False, "radio": True})
        self.assertEqual([p[1] for p in u.puts()], ["/devices/airos/dev-1/configuration"])

    # --- matching -------------------------------------------------------
    def test_match_failures_write_nothing(self):
        cases = (
            ("no-mac", [], {}, 409, "found 0"),
            ("dup-mac", [cpe(), cpe(did="dev-2")], {}, 409, "found 2"),
            ("ip-mismatch", [cpe()], {"ip": "10.9.9.9"}, 409, "management IP did not match"),
            ("infra", [cpe(role="ap")], {}, 403, "infrastructure"),
        )
        for label, devices, over, status, snippet in cases:
            with self.subTest(case=label):
                u = Uisp(devices)
                resp, body = self.invoke(FakeRequest(params=self.params(**over)), u)
                self.assertEqual(resp.status_code, status)
                self.assertEqual(body["result"], "failed")
                self.assertIs(body["success"], False)
                self.assertIn(snippet, body["message"])
                self.assertEqual(body["workflow_id"], "WF-9")
                self.assertEqual(u.puts(), [])

    def test_input_validation(self):
        cases = (
            ({"mac": "nope"}, "Invalid or missing MAC"),
            ({"ip": ""}, "Invalid or missing IP"),
            ({"name": "   "}, "Invalid or missing name"),
            ({"name": "A" * 25, "location": "Shop Building"}, "UISP alias limit is 30"),
        )
        for over, msg in cases:
            with self.subTest(over=over):
                u = Uisp([cpe()])
                resp, body = self.invoke(FakeRequest(params=self.params(**over)), u)
                self.assertEqual(resp.status_code, 400)
                self.assertIn(msg, body["message"])
                self.assertEqual(u.calls, [])

    def test_missing_secret_rejected(self):
        u = Uisp([cpe()])
        with self.assertRaises(HTTPException) as caught:
            self.invoke(FakeRequest(params=self.params()), u, secret="")
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(u.calls, [])

    # --- UISP errors ----------------------------------------------------
    def test_uisp_rename_error_stops_before_radio(self):
        u = Uisp([cpe()], put_unms=lambda: Resp(400, text="alias invalid"))
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(body["result"], "failed")
        self.assertIn("UISP rename failed", body["message"])
        self.assertIn("alias invalid", body["message"])
        self.assertEqual(body["changed"], {"uisp": False, "radio": False})
        self.assertEqual([p[1] for p in u.puts()], ["/devices/dev-1/system/unms"])

    def test_radio_push_error_reports_partial(self):
        u = Uisp([cpe()], put_airos=lambda: Resp(500, text="Failed to save settings"))
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(body["result"], "failed")
        self.assertIn("Radio hostname push failed", body["message"])
        self.assertEqual(body["changed"], {"uisp": True, "radio": False})

    def test_radio_push_result_false_is_failure(self):
        u = Uisp([cpe()], put_airos=lambda: Resp(200, {"result": False, "message": "device offline"}))
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 502)
        self.assertIn("device offline", body["message"])
        self.assertEqual(body["changed"], {"uisp": True, "radio": False})

    def test_uisp_read_error_fails_without_writes(self):
        u = Uisp([cpe()], get_status=404)
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 502)
        self.assertIn("UISP GET /devices/dev-1/system/unms failed: 404", body["message"])
        self.assertEqual(u.puts(), [])

    def test_unexpected_exception_is_500(self):
        def boom():
            raise RuntimeError("connection reset")
        u = Uisp([cpe()], put_unms=boom)
        resp, body = self.invoke(FakeRequest(params=self.params()), u)
        self.assertEqual(resp.status_code, 500)
        self.assertIn("connection reset", body["message"])


if __name__ == "__main__":
    unittest.main()
