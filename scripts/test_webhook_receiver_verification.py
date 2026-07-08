#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from webhook_receiver_verification import webhook_signature, verify_webhook_signature


SECRET = "webhook-secret-0123456789abcdef"
NOW = datetime(2026, 6, 28, 12, 0, 0, tzinfo=timezone.utc)
TIMESTAMP = "2026-06-28T12:00:00Z"
BODY = b'{"schema_version":1,"event_type":"certificate.issued"}'


def test_accepts_valid_signature() -> None:
    signature = webhook_signature(SECRET, TIMESTAMP, BODY)

    assert verify_webhook_signature(SECRET, TIMESTAMP, signature, BODY, NOW)


def test_accepts_timestamp_at_replay_window_boundary() -> None:
    boundary_timestamp = "2026-06-28T11:55:00Z"
    signature = webhook_signature(SECRET, boundary_timestamp, BODY)

    assert verify_webhook_signature(SECRET, boundary_timestamp, signature, BODY, NOW)


def test_accepts_offset_timestamp() -> None:
    offset_timestamp = "2026-06-28T21:00:00+09:00"
    signature = webhook_signature(SECRET, offset_timestamp, BODY)

    assert verify_webhook_signature(SECRET, offset_timestamp, signature, BODY, NOW)


def test_rejects_empty_secret() -> None:
    signature = webhook_signature(SECRET, TIMESTAMP, BODY)

    assert not verify_webhook_signature("", TIMESTAMP, signature, BODY, NOW)


def test_rejects_invalid_hmac() -> None:
    signature = webhook_signature("wrong-secret", TIMESTAMP, BODY)

    assert not verify_webhook_signature(SECRET, TIMESTAMP, signature, BODY, NOW)


def test_rejects_tampered_body() -> None:
    signature = webhook_signature(SECRET, TIMESTAMP, BODY)

    assert not verify_webhook_signature(SECRET, TIMESTAMP, signature, b"{}", NOW)


def test_rejects_stale_timestamp() -> None:
    signature = webhook_signature(SECRET, TIMESTAMP, BODY)
    stale_now = NOW + timedelta(minutes=6)

    assert not verify_webhook_signature(SECRET, TIMESTAMP, signature, BODY, stale_now)


def test_rejects_future_replay_window() -> None:
    future_timestamp = "2026-06-28T12:06:00Z"
    signature = webhook_signature(SECRET, future_timestamp, BODY)

    assert not verify_webhook_signature(SECRET, future_timestamp, signature, BODY, NOW)


def test_rejects_malformed_timestamp() -> None:
    signature = webhook_signature(SECRET, "not-a-time", BODY)

    assert not verify_webhook_signature(SECRET, "not-a-time", signature, BODY, NOW)


def test_rejects_wrong_signature_scheme() -> None:
    signature = webhook_signature(SECRET, TIMESTAMP, BODY).removeprefix("sha256=")

    assert not verify_webhook_signature(SECRET, TIMESTAMP, signature, BODY, NOW)


def main() -> None:
    tests = [
        test_accepts_valid_signature,
        test_accepts_timestamp_at_replay_window_boundary,
        test_accepts_offset_timestamp,
        test_rejects_empty_secret,
        test_rejects_invalid_hmac,
        test_rejects_tampered_body,
        test_rejects_stale_timestamp,
        test_rejects_future_replay_window,
        test_rejects_malformed_timestamp,
        test_rejects_wrong_signature_scheme,
    ]
    for test in tests:
        test()
    print(f"webhook receiver verification tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
