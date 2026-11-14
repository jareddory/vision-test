"""POST /twilio/inbound: validate Twilio's signature and forward the SMS.

Outbound HTTP is mocked. Nothing here talks to Twilio or the chief webhook.
"""
import asyncio
import os
import shlex
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, urlencode

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["UISP_TOKEN"] = os.environ.get("UISP_TOKEN") or "test-token"
os.environ["WEBHOOK_SECRET"] = os.environ.get("WEBHOOK_SECRET") or "test-secret"

import uisp_service as mod
from fastapi import Request
from twilio.request_validator import RequestValidator

TOKEN = "test-twilio-auth-token"
CHIEF_URL = "https://chief.example/hook"
CHIEF_KEY = "UNIQUE_CHIEF_KEY_9f3c"
PUBLIC_HOST = "vision-test-yz19.onrender.com"
PUBLIC_URL = f"https://{PUBLIC_HOST}/twilio/inbound"
SMS_BODY = "UNIQUE_SMS_BODY_9f3c gate code"
TWIML = b'<?xml version="1.0" encoding="UTF-8"?><Response/>'
ENV_KEYS = (
    "TWILIO_AUTH_TOKEN",
    "TWILIO_WEBHOOK_PUBLIC_URL",
    "CHIEF_WEBHOOK_URL",
    "CHIEF_WEBHOOK_KEY",
    "CHIEF_WEBHOOK_KEY_HEADER",
    "CHIEF_WEBHOOK_KEY_FORMAT",
)


def sample_params(**overrides):
    params = {
        "MessageSid": "SM0123456789abcdef0123456789abcdef",
        "AccountSid": "ACexample",
        "From": "+15551212001",
        "To": "+15557654321",
        "Body": SMS_BODY,
        "NumMedia": "0",
    }
    params.update(overrides)
    return params


def sign(url, params, token=TOKEN):
    return RequestValidator(token).compute_signature(url, params)


def make_request(body, signature, proto="https", forwarded_host=PUBLIC_HOST, host="127.0.0.1:10000", query=""):
    headers = [
        (b"host", host.encode()),
        (b"content-type", b"application/x-www-form-urlencoded"),
    ]
    if signature is not None:
        headers.append((b"x-twilio-signature", signature.encode("utf-8")))
    if proto is not None:
        headers.append((b"x-forwarded-proto", proto.encode()))
    if forwarded_host is not None:
        headers.append((b"x-forwarded-host", forwarded_host.encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/twilio/inbound",
        "raw_path": b"/twilio/inbound",
        "query_string": query.encode(),
        "headers": headers,
        "client": ("10.0.0.8", 40000),
        "server": ("127.0.0.1", 10000),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class TwilioInboundTests(unittest.TestCase):
    def setUp(self):
        self._saved = {key: os.environ.get(key) for key in ENV_KEYS}
        os.environ["TWILIO_AUTH_TOKEN"] = TOKEN
        os.environ["CHIEF_WEBHOOK_URL"] = CHIEF_URL
        os.environ["CHIEF_WEBHOOK_KEY"] = CHIEF_KEY
        for key in ("TWILIO_WEBHOOK_PUBLIC_URL", "CHIEF_WEBHOOK_KEY_HEADER", "CHIEF_WEBHOOK_KEY_FORMAT"):
            os.environ.pop(key, None)
        self.calls = []

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _capture_post(self, status_code=200, error=None):
        def fake_post(url, json=None, headers=None, timeout=None, **kwargs):
            self.calls.append({
                "url": url, "json": json, "headers": headers, "timeout": timeout, "kwargs": kwargs,
            })
            if error is not None:
                raise error
            return _Resp(status_code)

        return fake_post

    def _assert_empty_twiml(self, resp, forward_status):
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.body, TWIML)
        self.assertEqual(resp.headers["content-type"], "text/xml")
        self.assertEqual(resp.headers["x-forward-status"], forward_status)

    def _assert_logs_omit_secrets(self, captured):
        text = "\n".join(captured.output)
        self.assertNotIn(SMS_BODY, text)
        self.assertNotIn(CHIEF_KEY, text)
        self.assertNotIn(TOKEN, text)

    def test_valid_signature_forwards_and_returns_empty_twiml(self):
        params = sample_params()
        for proto in ("https", "https, http"):
            with self.subTest(proto=proto):
                self.calls.clear()
                with self.assertLogs("uisp", level="INFO") as captured:
                    with patch.object(mod.requests, "post", self._capture_post()):
                        request = make_request(urlencode(params).encode(), sign(PUBLIC_URL, params), proto=proto)
                        resp = asyncio.run(mod.twilio_inbound(request))
                self._assert_empty_twiml(resp, "forwarded")
                self.assertEqual(len(self.calls), 1)
                call = self.calls[0]
                self.assertEqual(call["url"], CHIEF_URL)
                self.assertEqual(call["timeout"], 10)
                self.assertEqual(call["headers"], {"Authorization": f"Bearer {CHIEF_KEY}"})
                self.assertEqual(call["kwargs"], {})
                payload = call["json"]
                self.assertEqual(set(payload), {
                    "from", "to", "body", "num_media", "media_urls", "message_sid", "received_at",
                })
                self.assertEqual(payload["from"], "+15551212001")
                self.assertEqual(payload["to"], "+15557654321")
                self.assertEqual(payload["body"], SMS_BODY)
                self.assertEqual(payload["num_media"], 0)
                self.assertEqual(payload["media_urls"], [])
                self.assertEqual(payload["message_sid"], params["MessageSid"])
                self.assertNotIn("AccountSid", payload)
                received = datetime.fromisoformat(payload["received_at"].replace("Z", "+00:00"))
                self.assertEqual(received.utcoffset().total_seconds(), 0)
                self.assertLess(abs((datetime.now(timezone.utc) - received).total_seconds()), 60)
                self._assert_logs_omit_secrets(captured)

    def test_bad_signature_forbidden_and_does_not_forward(self):
        params = sample_params()
        cases = {
            "wrong": "not-a-valid-signature",
            "missing": None,
        }
        for name, signature in cases.items():
            with self.subTest(signature=name):
                self.calls.clear()

                def forbid(*args, **kwargs):
                    raise AssertionError("rejected webhook was forwarded")

                body = urlencode(params).encode()
                request = make_request(body, signature)
                with self.assertLogs("uisp", level="INFO") as captured:
                    with patch.object(mod.requests, "post", forbid):
                        resp = asyncio.run(mod.twilio_inbound(request))
                self.assertEqual(resp.status_code, 403)
                self.assertNotIn(b"<Response", resp.body)
                self.assertNotIn("x-forward-status", resp.headers)
                self._assert_logs_omit_secrets(captured)

    def test_missing_auth_token_forbidden(self):
        params = sample_params()
        os.environ.pop("TWILIO_AUTH_TOKEN", None)

        def forbid(*args, **kwargs):
            raise AssertionError("rejected webhook was forwarded")

        request = make_request(urlencode(params).encode(), sign(PUBLIC_URL, params))
        with patch.object(mod.requests, "post", forbid):
            resp = asyncio.run(mod.twilio_inbound(request))
        self.assertEqual(resp.status_code, 403)

        os.environ["TWILIO_AUTH_TOKEN"] = "   "
        with patch.object(mod.requests, "post", forbid):
            resp = asyncio.run(mod.twilio_inbound(request))
        self.assertEqual(resp.status_code, 403)

    def test_media_urls_are_collected(self):
        params = sample_params(
            NumMedia="2",
            MediaUrl0="https://api.twilio.com/media/ME111",
            MediaContentType0="image/jpeg",
            MediaUrl1="https://api.twilio.com/media/ME222",
            MediaContentType1="image/png",
        )
        with patch.object(mod.requests, "post", self._capture_post()):
            request = make_request(urlencode(params).encode(), sign(PUBLIC_URL, params))
            resp = asyncio.run(mod.twilio_inbound(request))
        self._assert_empty_twiml(resp, "forwarded")
        payload = self.calls[0]["json"]
        self.assertEqual(payload["num_media"], 2)
        self.assertEqual(payload["media_urls"], [
            {"url": "https://api.twilio.com/media/ME111", "content_type": "image/jpeg"},
            {"url": "https://api.twilio.com/media/ME222", "content_type": "image/png"},
        ])

    def test_forward_failure_still_returns_200(self):
        params = sample_params()
        request_body = urlencode(params).encode()
        signature = sign(PUBLIC_URL, params)

        with self.subTest(failure="http"):
            self.calls.clear()
            request = make_request(request_body, signature)
            with self.assertLogs("uisp", level="WARNING") as captured:
                with patch.object(mod.requests, "post", self._capture_post(status_code=502)):
                    resp = asyncio.run(mod.twilio_inbound(request))
            self._assert_empty_twiml(resp, "failed")
            self.assertEqual(len(self.calls), 1)
            self.assertTrue(any("status=502" in line for line in captured.output))
            self._assert_logs_omit_secrets(captured)

        with self.subTest(failure="timeout"):
            self.calls.clear()
            request = make_request(request_body, signature)
            with self.assertLogs("uisp", level="WARNING") as captured:
                with patch.object(
                    mod.requests, "post", self._capture_post(error=mod.requests.Timeout())
                ):
                    resp = asyncio.run(mod.twilio_inbound(request))
            self._assert_empty_twiml(resp, "failed")
            self.assertEqual(len(self.calls), 1)
            self.assertTrue(any("status=none" in line for line in captured.output))
            self._assert_logs_omit_secrets(captured)

    def test_key_header_format_is_honored(self):
        os.environ["CHIEF_WEBHOOK_KEY_HEADER"] = "X-Routine-Key"
        os.environ["CHIEF_WEBHOOK_KEY_FORMAT"] = "ApiKey {key}"
        params = sample_params()
        with patch.object(mod.requests, "post", self._capture_post()):
            request = make_request(urlencode(params).encode(), sign(PUBLIC_URL, params))
            resp = asyncio.run(mod.twilio_inbound(request))
        self._assert_empty_twiml(resp, "forwarded")
        self.assertEqual(self.calls[0]["headers"], {"X-Routine-Key": f"ApiKey {CHIEF_KEY}"})

    def test_public_url_override_is_what_gets_validated(self):
        configured = "https://hooks.example/twilio/inbound?src=twilio"
        os.environ["TWILIO_WEBHOOK_PUBLIC_URL"] = configured
        params = sample_params()
        with patch.object(mod.requests, "post", self._capture_post()):
            request = make_request(urlencode(params).encode(), sign(configured, params))
            resp = asyncio.run(mod.twilio_inbound(request))
        self._assert_empty_twiml(resp, "forwarded")

        def forbid(*args, **kwargs):
            raise AssertionError("rejected webhook was forwarded")

        # A signature for the reconstructed proxy URL must not pass once the public URL is set.
        request = make_request(urlencode(params).encode(), sign(PUBLIC_URL, params))
        with patch.object(mod.requests, "post", forbid):
            resp = asyncio.run(mod.twilio_inbound(request))
        self.assertEqual(resp.status_code, 403)

    def test_query_string_and_host_header_are_part_of_the_signed_url(self):
        params = sample_params()
        query = "src=twilio"
        signed = f"https://{PUBLIC_HOST}/twilio/inbound?{query}"
        with patch.object(mod.requests, "post", self._capture_post()):
            request = make_request(
                urlencode(params).encode(),
                sign(signed, params),
                proto="https",
                forwarded_host=None,
                host=PUBLIC_HOST,
                query=query,
            )
            resp = asyncio.run(mod.twilio_inbound(request))
        self._assert_empty_twiml(resp, "forwarded")

    def test_sign_script_signature_is_accepted(self):
        script = ROOT / "scripts" / "sign_twilio_sample.py"
        env = os.environ.copy()
        env["TWILIO_AUTH_TOKEN"] = TOKEN
        proc = subprocess.run(
            [sys.executable, str(script), PUBLIC_URL],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(TOKEN, proc.stdout)
        self.assertNotIn(TOKEN, proc.stderr)
        args = shlex.split(proc.stdout.strip())
        self.assertEqual(args[0], "curl")
        headers = {}
        data = None
        index = 1
        while index < len(args) - 1:
            if args[index] == "-H":
                name, value = args[index + 1].split(": ", 1)
                headers[name.lower()] = value
                index += 2
            elif args[index] == "--data":
                data = args[index + 1]
                index += 2
            else:
                index += 1
        self.assertEqual(args[-1], PUBLIC_URL)
        self.assertIsNotNone(data)
        os.environ["TWILIO_WEBHOOK_PUBLIC_URL"] = PUBLIC_URL
        posted = dict(parse_qsl(data, keep_blank_values=True))
        with patch.object(mod.requests, "post", self._capture_post()):
            request = make_request(data.encode(), headers["x-twilio-signature"])
            resp = asyncio.run(mod.twilio_inbound(request))
        self._assert_empty_twiml(resp, "forwarded")
        self.assertEqual(self.calls[0]["json"]["body"], posted["Body"])
        self.assertEqual(self.calls[0]["json"]["from"], "+15551212001")

        bare = os.environ.copy()
        bare.pop("TWILIO_AUTH_TOKEN", None)
        missing = subprocess.run(
            [sys.executable, str(script), PUBLIC_URL],
            env=bare,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(missing.returncode, 1)
        self.assertEqual(missing.stdout, "")
        self.assertIn("TWILIO_AUTH_TOKEN", missing.stderr)
