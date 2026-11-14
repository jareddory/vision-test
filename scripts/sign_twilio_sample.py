#!/usr/bin/env python3
"""Print a curl command for a signed Twilio inbound-SMS POST.

TWILIO_AUTH_TOKEN is read from the environment and is not printed.
The URL argument is the exact string the service validates: the public
webhook URL, including a query string when the Twilio URL has one.

Usage:
  TWILIO_AUTH_TOKEN=... python scripts/sign_twilio_sample.py https://vision-test-yz19.onrender.com/twilio/inbound
"""
import os
import shlex
import sys
from urllib.parse import urlencode

from twilio.request_validator import RequestValidator

SAMPLE_PARAMS = {
    "MessageSid": "SM0123456789abcdef0123456789abcdef",
    "SmsSid": "SM0123456789abcdef0123456789abcdef",
    "AccountSid": "ACexample",
    "From": "+15551212001",
    "To": "+15557654321",
    "Body": "Test inbound from sign_twilio_sample.py",
    "NumMedia": "0",
}


def curl_command(url: str, token: str) -> str:
    signature = RequestValidator(token).compute_signature(url, SAMPLE_PARAMS)
    body = urlencode(SAMPLE_PARAMS)
    return " ".join([
        "curl", "-sS", "-X", "POST",
        "-H", shlex.quote("Content-Type: application/x-www-form-urlencoded"),
        "-H", shlex.quote(f"X-Twilio-Signature: {signature}"),
        "--data", shlex.quote(body),
        shlex.quote(url),
    ])


def main(argv: list) -> int:
    if len(argv) != 2 or not argv[1].strip():
        print(
            "usage: python scripts/sign_twilio_sample.py <webhook-url>",
            file=sys.stderr,
        )
        return 2
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    if token is None or token.strip() == "":
        print("TWILIO_AUTH_TOKEN is not set", file=sys.stderr)
        return 1
    print(curl_command(argv[1].strip(), token.strip()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
