#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "security-baseline-scan.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("security_baseline_scan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_finds_private_key_pem() -> None:
    scanner = load_scanner()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.txt"
        path.write_text("-----BEGIN PRIVATE KEY-----\nabc\n", encoding="utf-8")  # secret-scan: allow
        findings = scanner.scan_root(Path(tmp))
    assert findings
    assert findings[0].kind == "private-key-pem"


def test_finds_high_confidence_service_tokens() -> None:
    scanner = load_scanner()
    cases = {
        "aws-access-key": "AKIA" + "1234567890ABCDEF",
        "github-token": "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEF",
        "slack-token": "xoxb-" + "12345678901234567890",
    }
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for kind, value in cases.items():
            (root / f"{kind}.txt").write_text(value + "\n", encoding="utf-8")
        findings = scanner.scan_root(root)

    assert {finding.kind for finding in findings} == set(cases)


def test_allow_marker_suppresses_finding() -> None:
    scanner = load_scanner()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "allowed.txt"
        path.write_text("AKIA" + "1234567890ABCDEF  # secret-scan: allow\n", encoding="utf-8")
        findings = scanner.scan_root(Path(tmp))
    assert findings == []


def test_allows_documentation_placeholders() -> None:
    scanner = load_scanner()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "README.md"
        path.write_text(
            'ANOPKI_API_KEY_PEPPER = "<32+ chars random secret>"\n',
            encoding="utf-8",
        )
        findings = scanner.scan_root(Path(tmp))
    assert findings == []


def main() -> None:
    test_finds_private_key_pem()
    test_finds_high_confidence_service_tokens()
    test_allow_marker_suppresses_finding()
    test_allows_documentation_placeholders()
    print("security baseline scan tests ok")


if __name__ == "__main__":
    main()
