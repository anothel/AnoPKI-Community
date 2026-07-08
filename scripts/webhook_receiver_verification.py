#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone


def webhook_signature(secret: str, timestamp: str, body: bytes) -> str:
    msg = timestamp.encode("utf-8") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return "sha256=" + digest


def verify_webhook_signature(
    secret: str,
    timestamp: str,
    signature: str,
    body: bytes,
    now: datetime,
    tolerance_seconds: int = 300,
) -> bool:
    if not secret or not signature.startswith("sha256="):
        return False
    parsed_timestamp = parse_rfc3339_utc(timestamp)
    if parsed_timestamp is None:
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    skew = abs((now.astimezone(timezone.utc) - parsed_timestamp).total_seconds())
    if skew > tolerance_seconds:
        return False
    expected = webhook_signature(secret, timestamp, body)
    return hmac.compare_digest(expected, signature)


def parse_rfc3339_utc(timestamp: str) -> datetime | None:
    candidate = timestamp
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)
