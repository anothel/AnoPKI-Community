#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Fail-closed regression tests for release CycloneDX dependency inventory."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-release-sbom.py"
VALID = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {"type": "library", "purl": "pkg:golang/github.com/jackc/pgx/v5@v5.9.2"},
        {"type": "library", "purl": "pkg:golang/modernc.org/sqlite@v1.34.5"},
    ],
}


def run_case(payload: object, expected: int, diagnostic: str = "") -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "anopki.sbom.cdx.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
    assert result.returncode == expected, result.stderr
    if diagnostic:
        assert diagnostic in result.stderr, result.stderr


def test_valid_inventory_passes() -> None:
    run_case(VALID, 0)


def test_empty_inventory_fails() -> None:
    run_case({**VALID, "components": []}, 1, "no catalogued dependencies")


def test_non_go_inventory_fails() -> None:
    run_case(
        {**VALID, "components": [{"type": "library", "purl": "pkg:deb/ubuntu/openssl@3"}]},
        1, "missing shipped Go module inventory",
    )


def test_missing_pgx_fails() -> None:
    run_case({**VALID, "components": VALID["components"][1:]}, 1, "pkg:golang/github.com/jackc/pgx/v5@")


def test_missing_sqlite_fails() -> None:
    run_case({**VALID, "components": VALID["components"][:1]}, 1, "pkg:golang/modernc.org/sqlite@")


def test_invalid_format_fails() -> None:
    run_case({**VALID, "bomFormat": "not-CycloneDX"}, 1, "identity is invalid")


def test_invalid_shape_fails() -> None:
    run_case({**VALID, "components": ["invalid"]}, 1, "invalid shape")


def test_missing_file_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(Path(tmp) / "missing.json")],
            text=True,
            capture_output=True,
            check=False,
        )
    assert result.returncode == 1
    assert "missing or invalid release SBOM" in result.stderr


if __name__ == "__main__":
    test_valid_inventory_passes()
    test_empty_inventory_fails()
    test_non_go_inventory_fails()
    test_missing_pgx_fails()
    test_missing_sqlite_fails()
    test_invalid_format_fails()
    test_invalid_shape_fails()
    test_missing_file_fails()
    print("release SBOM validator tests ok")
