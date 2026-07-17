#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for Community release metadata generation."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate-release-metadata.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def backend_info() -> dict[str, object]:
    return {
        "product_profile": "community-openssl",
        "edition": "community",
        "selected_backend": "openssl",
        "fallback_enabled": False,
        "backend_id": "openssl",
        "backend_dependency": "OpenSSL",
        "backend_version": "3.5.5",
        "backend_readiness": "ready",
        "backend_capabilities": [
            "csr_inspect",
            "certificate_issue",
            "crl_generate",
            "crl_inspect",
            "ocsp_request_inspect",
            "ocsp_issuer_inspect",
            "ocsp_response_generate",
            "ocsp_responder_validate",
        ],
        "backend_abi_version": 1,
        "backend_build_fingerprint": "test-build",
    }


def run_generator(info: dict[str, object], *, commit: str = COMMIT) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        backend = root / "backend.json"
        output = root / "release.json"
        backend.write_text(json.dumps(info), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backend-info",
                str(backend),
                "--out",
                str(output),
                "--version",
                "0.1.0-alpha.0",
                "--commit",
                commit,
                "--build-time",
                "2026-07-17T01:02:03Z",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        payload = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else None
        return result, payload


def test_valid_metadata_passes() -> None:
    result, payload = run_generator(backend_info())
    assert result.returncode == 0, result.stderr or result.stdout
    assert payload is not None
    assert payload["product_profile"] == "community-openssl"
    assert payload["selected_backend"] == "openssl"
    assert payload["fallback_enabled"] is False
    assert payload["fallback_used"] is False
    assert payload["key_provider_policy"]["supported_classes"] == ["file"]
    assert payload["key_provider_policy"]["file_provider_allowed_in_production"] is False
    assert payload["production_ready"] is False


def test_unknown_backend_field_fails() -> None:
    info = backend_info()
    info["key_ref"] = "/secret/issuer.key"
    result, payload = run_generator(info)
    assert result.returncode == 1
    assert payload is None
    assert "unknown fields" in result.stderr


def test_fallback_enabled_fails() -> None:
    info = backend_info()
    info["fallback_enabled"] = True
    result, _ = run_generator(info)
    assert result.returncode == 1
    assert "fallback_enabled=false" in result.stderr


def test_missing_capability_fails() -> None:
    info = backend_info()
    info["backend_capabilities"] = ["csr_inspect"]
    result, _ = run_generator(info)
    assert result.returncode == 1
    assert "capabilities missing" in result.stderr


def test_wrong_profile_fails() -> None:
    info = backend_info()
    info["product_profile"] = "enterprise-openssl"
    result, _ = run_generator(info)
    assert result.returncode == 1
    assert "community-openssl" in result.stderr


def test_non_exact_commit_fails() -> None:
    result, _ = run_generator(backend_info(), commit="main")
    assert result.returncode == 1
    assert "40-character" in result.stderr


def main() -> None:
    test_valid_metadata_passes()
    test_unknown_backend_field_fails()
    test_fallback_enabled_fails()
    test_missing_capability_fails()
    test_wrong_profile_fails()
    test_non_exact_commit_fails()
    print("release metadata generator tests ok")


if __name__ == "__main__":
    main()
