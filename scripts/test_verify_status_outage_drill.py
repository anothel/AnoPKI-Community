#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-tests for the Community CRL/OCSP outage drill runner."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-status-outage-drill.py"
SPEC = importlib.util.spec_from_file_location("verify_status_outage_drill", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def fake_go(path: Path, *, version: str = "go1.25.12", fail_test: str = "", omit_test: str = "") -> list[str]:
    events = []
    for package, test in MODULE.EXPECTED_TESTS:
        if test == omit_test:
            continue
        action = "fail" if test == fail_test else "pass"
        events.append(json.dumps({"Action": action, "Package": package, "Test": test}))
    code = f'''#!/usr/bin/env python3
import sys
if len(sys.argv) > 1 and sys.argv[1] == "version":
    print("go version {version} linux/amd64")
    raise SystemExit(0)
if len(sys.argv) > 1 and sys.argv[1] == "test":
    print({json.dumps(chr(10).join(events))})
    raise SystemExit({1 if fail_test else 0})
raise SystemExit(2)
'''
    path.write_text(code, encoding="utf-8")
    return [sys.executable, str(path)]


def test_success_writes_strict_redacted_evidence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        go = fake_go(root / "go")
        out = root / "out"
        evidence = MODULE.run_drill(ROOT, out, go, "a" * 40)
        payload = json.loads((out / "status-outage-verification.json").read_text(encoding="utf-8"))
        markdown = (out / "status-outage-verification.md").read_text(encoding="utf-8")
    assert evidence["result"] == "passed"
    assert payload["commit"] == "a" * 40
    assert [item["status"] for item in payload["tests"]] == ["pass"] * len(MODULE.EXPECTED_TESTS)
    assert [item["name"] for item in payload["checks"]] == list(MODULE.EXPECTED_CHECKS)
    serialized = json.dumps(payload, sort_keys=True).lower()
    for forbidden in ('"key_ref"', '"private_key"', '"password"', '"credential"'):
        assert forbidden not in serialized
    assert "-----begin private key-----" not in serialized
    assert "issuer-key-ref" not in (serialized + markdown.lower())


def test_unsupported_go_fails_before_tests() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        go = fake_go(root / "go", version="go1.23.2")
        out = root / "out"
        evidence = MODULE.run_drill(ROOT, out, go, "b" * 40)
    assert evidence["result"] == "failed"
    assert "minimum is 1.25.11" in evidence["blocker"]
    assert evidence["tests"] == []


def test_failed_test_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        failed = MODULE.EXPECTED_TESTS[1][1]
        go = fake_go(root / "go", fail_test=failed)
        evidence = MODULE.run_drill(ROOT, root / "out", go, "c" * 40)
    assert evidence["result"] == "failed"
    assert any(item["name"] == failed and item["status"] == "fail" for item in evidence["tests"])


def test_missing_test_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        missing = MODULE.EXPECTED_TESTS[2][1]
        go = fake_go(root / "go", omit_test=missing)
        evidence = MODULE.run_drill(ROOT, root / "out", go, "d" * 40)
    assert evidence["result"] == "failed"
    assert any(item["name"] == missing and item["status"] == "missing" for item in evidence["tests"])


def test_invalid_commit_is_rejected() -> None:
    try:
        MODULE.resolve_commit(ROOT, "not-a-commit")
    except MODULE.DrillFailure as exc:
        assert "40-character" in str(exc)
    else:
        raise AssertionError("invalid commit unexpectedly passed")


def main() -> None:
    tests = [
        test_success_writes_strict_redacted_evidence,
        test_unsupported_go_fails_before_tests,
        test_failed_test_fails_closed,
        test_missing_test_fails_closed,
        test_invalid_commit_is_rejected,
    ]
    for test in tests:
        test()
    print(f"status outage drill tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
