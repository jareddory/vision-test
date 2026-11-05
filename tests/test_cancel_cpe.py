"""Cancel-cpe is delete-only: identify, delete, then drop an empty site.

No reachability check and no reboot. Identity failures stay 409/403.
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

import uisp_service
import vision_logger
from fastapi import HTTPException

MODULES = {
    "uisp_service": uisp_service,
    "vision_logger": vision_logger,
}
_USE_MODULE_SECRET = object()


class FakeRequest:
    def __init__(self, method="GET", params=None, body=None):
        self.method = method
        self.query_params = params or {}
        self._body = {} if body is None else body

    async def json(self):
        return self._body


def response(status_code, text=""):
    class _Response:
        pass

    result = _Response()
    result.status_code = status_code
    result.text = text
    return result


def cpe(
    status="active",
    role="station",
    mac="AA:BB:CC:DD:EE:FF",
    ip="10.1.2.3",
    name="Cindy Sohn",
    did="dev-1",
    site_id="site-1",
    status_key="overview",
):
    device = {
        "identification": {
            "id": did,
            "mac": mac,
            "name": name,
            "role": role,
            "site": {"id": site_id} if site_id is not None else None,
        },
        "ipAddress": ip,
    }
    if status_key == "overview":
        device["overview"] = {"status": status}
    elif status_key == "top":
        device["status"] = status
    return device


class UispDouble:
    def __init__(self, listings, on_delete=None):
        self.listings = [list(batch) for batch in listings]
        self.calls = []
        self._on_delete = on_delete

    def get_devices(self):
        self.calls.append(("GET", "/devices"))
        if not self.listings:
            return []
        return self.listings.pop(0)

    def delete(self, url, headers=None, timeout=None):
        self.calls.append(("DELETE", url))
        if self._on_delete:
            return self._on_delete(url)
        return response(204)

    def post(self, url, headers=None, timeout=None):
        self.calls.append(("POST", url))
        raise AssertionError(f"cancel-cpe must not POST {url}")

    def sleep(self, seconds):
        self.calls.append(("SLEEP", seconds))


class CancelCpeTests(unittest.TestCase):
    def for_each_module(self, check):
        for name, mod in MODULES.items():
            with self.subTest(module=name):
                check(mod)

    def invoke(self, mod, request, double, secret=_USE_MODULE_SECRET):
        if secret is _USE_MODULE_SECRET:
            secret = mod.WEBHOOK_SECRET

        def forbid_get(url, *args, **kwargs):
            raise AssertionError(f"unexpected HTTP GET {url}")

        with patch.object(mod, "get_devices", double.get_devices), patch.object(
            mod.requests, "delete", double.delete
        ), patch.object(mod.requests, "post", double.post), patch.object(
            mod.requests, "get", forbid_get
        ), patch.object(
            mod.time, "sleep", double.sleep
        ):
            resp = asyncio.run(mod.cancel_cpe(request, secret))
        return resp, json.loads(resp.body)

    def params(self, **extra):
        data = {
            "mac": "aa-bb-cc-dd-ee-ff",
            "ip": "10.1.2.3",
            "name": "Cindy Sohn",
            "workflow_id": "WF-123",
        }
        data.update(extra)
        return data

    def assert_deleted_without_reboot(self, mod, body, double, method):
        device_url = f"{mod.UISP_BASE}/devices/dev-1"
        self.assertEqual(body["result"], "success")
        self.assertIs(body["success"], True)
        self.assertEqual(body["message"], "Cancel complete — device removed")
        self.assertEqual(body["action"], "device_deleted")
        self.assertEqual(body["workflow_id"], "WF-123")
        self.assertEqual(body["device_id"], "dev-1")
        self.assertEqual(body["mac"], "AABBCCDDEEFF")
        self.assertEqual(body["name"], "Cindy Sohn")
        self.assertEqual(body["match_method"], method)
        self.assertNotIn("reboot", body["message"].lower())
        self.assertNotIn("offline", body["message"].lower())
        self.assertNotIn("status", body)
        self.assertIn(("DELETE", device_url), double.calls)
        self.assertFalse(any(kind == "POST" or "reboot" in str(url) for kind, url in double.calls))

    def test_online_offline_and_blank_status_all_delete_without_reboot(self):
        cases = (
            ("active", "overview"),
            ("disconnected", "overview"),
            ("", "overview"),
            ("active", "top"),
            ("active", None),
        )

        def check(mod):
            for status, status_key in cases:
                with self.subTest(status=status or "<blank>", status_key=status_key):
                    device = cpe(status=status, status_key=status_key)
                    double = UispDouble([[device], []])
                    resp, body = self.invoke(
                        mod, FakeRequest(params=self.params()), double
                    )
                    self.assertEqual(resp.status_code, 200)
                    self.assert_deleted_without_reboot(mod, body, double, "mac+ip")
                    self.assertEqual(body["site_id"], "site-1")
                    self.assertIs(body["site_deleted"], True)
                    self.assertEqual(body["site_message"], "Empty site also removed")
                    self.assertEqual(
                        ("DELETE", f"{mod.UISP_BASE}/sites/site-1"), double.calls[-1]
                    )
                    self.assertIn(("SLEEP", mod.SITE_DELETE_DELAY), double.calls)

        self.for_each_module(check)

    def test_post_json_uses_same_delete_path(self):
        def check(mod):
            double = UispDouble([[cpe()], []])
            resp, body = self.invoke(
                mod, FakeRequest(method="POST", body=self.params()), double
            )
            self.assertEqual(resp.status_code, 200)
            self.assert_deleted_without_reboot(mod, body, double, "mac+ip")
            self.assertIs(body["site_deleted"], True)

        self.for_each_module(check)

    def test_query_secret_authenticates(self):
        def check(mod):
            double = UispDouble([[cpe()], []])
            params = self.params(secret=mod.WEBHOOK_SECRET)
            resp, body = self.invoke(
                mod, FakeRequest(params=params), double, secret=""
            )
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(body["result"], "success")

        self.for_each_module(check)

    def test_missing_secret_is_rejected_before_any_uisp_call(self):
        def check(mod):
            double = UispDouble([[cpe()]])
            with self.assertRaises(HTTPException) as caught:
                self.invoke(mod, FakeRequest(params=self.params()), double, secret="")
            self.assertEqual(caught.exception.status_code, 401)
            self.assertEqual(double.calls, [])

        self.for_each_module(check)

    def test_site_kept_when_other_devices_remain(self):
        def check(mod):
            other = cpe(did="dev-2", mac="11:22:33:44:55:66", ip="10.9.9.9", name="Other")
            double = UispDouble([[cpe()], [other]])
            resp, body = self.invoke(mod, FakeRequest(params=self.params()), double)
            self.assertEqual(resp.status_code, 200)
            self.assert_deleted_without_reboot(mod, body, double, "mac+ip")
            self.assertIs(body["site_deleted"], False)
            self.assertEqual(body["site_message"], "Site not empty (1 device(s) remain)")
            self.assertFalse(any("/sites/" in str(url) for _, url in double.calls))

        self.for_each_module(check)

    def test_no_site_skips_site_delete(self):
        def check(mod):
            double = UispDouble([[cpe(site_id=None)]])
            resp, body = self.invoke(mod, FakeRequest(params=self.params()), double)
            self.assertEqual(resp.status_code, 200)
            self.assertIsNone(body["site_id"])
            self.assertIs(body["site_deleted"], False)
            self.assertIsNone(body["site_message"])
            self.assertFalse(any(kind == "SLEEP" or "/sites/" in str(url) for kind, url in double.calls))
            self.assertEqual(
                [kind for kind, _ in double.calls],
                ["GET", "DELETE"],
            )

        self.for_each_module(check)

    def test_device_delete_failure_does_not_reboot_or_delete_site(self):
        def check(mod):
            double = UispDouble(
                [[cpe()]],
                on_delete=lambda url: response(500, "boom"),
            )
            resp, body = self.invoke(mod, FakeRequest(params=self.params()), double)
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(body["result"], "failed")
            self.assertIs(body["success"], False)
            self.assertIn("Device delete failed", body["message"])
            self.assertIn("boom", body["message"])
            self.assertEqual(body["workflow_id"], "WF-123")
            self.assertFalse(any(kind in ("POST", "SLEEP") or "/sites/" in str(url) for kind, url in double.calls))

        self.for_each_module(check)

    def test_empty_site_delete_failure_still_reports_device_removed(self):
        def check(mod):
            def on_delete(url):
                if "/sites/" in url:
                    return response(409, "busy")
                return response(200)

            double = UispDouble([[cpe()], []], on_delete=on_delete)
            resp, body = self.invoke(mod, FakeRequest(params=self.params()), double)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(body["result"], "success")
            self.assertEqual(body["action"], "device_deleted")
            self.assertIs(body["site_deleted"], False)
            self.assertIn("Site delete failed: 409", body["site_message"])

        self.for_each_module(check)

    def test_name_fallback_still_matches_reversed_name_without_ip(self):
        def check(mod):
            double = UispDouble([[cpe()], []])
            params = self.params(ip="", name="sohncindy")
            resp, body = self.invoke(mod, FakeRequest(params=params), double)
            self.assertEqual(resp.status_code, 200)
            self.assert_deleted_without_reboot(mod, body, double, "mac+name")

        self.for_each_module(check)

    def test_matching_ip_wins_when_name_does_not_match(self):
        def check(mod):
            double = UispDouble([[cpe()], []])
            params = self.params(name="completely-different")
            resp, body = self.invoke(mod, FakeRequest(params=params), double)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(body["match_method"], "mac+ip")

        self.for_each_module(check)

    def test_identity_failures_do_not_delete(self):
        cases = (
            ("duplicate-mac", [cpe(), cpe(did="dev-2")], {}, 409, "found 2"),
            ("missing-mac", [], {}, 409, "found 0"),
            (
                "infra",
                [cpe(role="ap")],
                {},
                403,
                "Potential infrastructure device",
            ),
            (
                "neither-ip-nor-name",
                [cpe()],
                {"ip": "10.9.9.9", "name": "xyzohnqq"},
                409,
                "neither IP nor name matched",
            ),
            (
                "name-too-short-to-fallback",
                [cpe()],
                {"ip": "", "name": "Bob"},
                409,
                "neither IP nor name matched",
            ),
        )

        def check(mod):
            for label, devices, overrides, status, snippet in cases:
                with self.subTest(case=label):
                    double = UispDouble([devices])
                    resp, body = self.invoke(
                        mod,
                        FakeRequest(params=self.params(**overrides)),
                        double,
                    )
                    self.assertEqual(resp.status_code, status)
                    self.assertEqual(body["result"], "failed")
                    self.assertIs(body["success"], False)
                    self.assertIn(snippet, body["message"])
                    self.assertEqual(body["workflow_id"], "WF-123")
                    self.assertFalse(any(kind != "GET" for kind, _ in double.calls))

        self.for_each_module(check)

    def test_invalid_mac_fails_before_lookup(self):
        def check(mod):
            double = UispDouble([[cpe()]])
            resp, body = self.invoke(
                mod,
                FakeRequest(params=self.params(mac="not-a-mac")),
                double,
            )
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(body["result"], "failed")
            self.assertIs(body["success"], False)
            self.assertEqual(body["message"], "Invalid or missing MAC")
            self.assertEqual(body["workflow_id"], "WF-123")
            self.assertEqual(double.calls, [])

        self.for_each_module(check)

    def test_name_window_is_not_loosened_below_four_characters(self):
        """A 3-character overlap must not match unless one full name contains the other."""

        def check(mod):
            with self.assertRaises(HTTPException) as caught:
                mod.find_device_cancel("AABBCCDDEEFF", "", "xyzohnqq")
            self.assertEqual(caught.exception.status_code, 409)
            matched, method = mod.find_device_cancel("AABBCCDDEEFF", "", "sohncindy")
            self.assertEqual(method, "mac+name")
            self.assertEqual(matched["identification"]["id"], "dev-1")

        def check_with_devices(mod):
            device = cpe()
            with patch.object(mod, "get_devices", return_value=[device]):
                check(mod)

        self.for_each_module(check_with_devices)


if __name__ == "__main__":
    unittest.main()
