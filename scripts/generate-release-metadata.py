#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Generate fail-closed Community release profile metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path


EXPECTED_BACKEND_FIELDS = {
    "product_profile",
    "edition",
    "selected_backend",
    "fallback_enabled",
    "backend_id",
    "backend_dependency",
    "backend_version",
    "backend_readiness",
    "backend_capabilities",
    "backend_abi_version",
    "backend_build_fingerprint",
}

REQUIRED_COMMUNITY_CAPABILITIES = {
    "csr_inspect",
    "certificate_issue",
    "crl_generate",
    "crl_inspect",
    "ocsp_request_inspect",
    "ocsp_issuer_inspect",
    "ocsp_response_generate",
    "ocsp_responder_validate",
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read_backend_info(path: Path) -> dict[str, object]:
    if not path.is_file():
        fail(f"missing backend info: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid backend info: {exc}")
    if not isinstance(value, dict):
        fail("backend info must be a JSON object")
    fields = set(value)
    missing = sorted(EXPECTED_BACKEND_FIELDS - fields)
    extra = sorted(fields - EXPECTED_BACKEND_FIELDS)
    if missing:
        fail("backend info missing fields:\n" + "\n".join(missing))
    if extra:
        fail("backend info has unknown fields:\n" + "\n".join(extra))
    return value


def require_nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"backend info field {field} must be a non-empty string")
    return value


def validate_backend_info(info: dict[str, object]) -> None:
    for field in (
        "product_profile",
        "edition",
        "selected_backend",
        "backend_id",
        "backend_dependency",
        "backend_version",
        "backend_readiness",
        "backend_build_fingerprint",
    ):
        require_nonempty_string(info[field], field)

    if info["product_profile"] != "community-openssl":
        fail("Community release metadata requires product_profile=community-openssl")
    if info["edition"] != "community":
        fail("Community release metadata requires edition=community")
    if info["selected_backend"] != "openssl" or info["backend_id"] != "openssl":
        fail("Community release metadata requires the OpenSSL adapter")
    if info["fallback_enabled"] is not False:
        fail("Community release metadata requires fallback_enabled=false")
    if info["backend_readiness"] != "ready":
        fail("Community release metadata requires backend_readiness=ready")
    abi = info["backend_abi_version"]
    if not isinstance(abi, int) or isinstance(abi, bool) or abi <= 0:
        fail("backend_abi_version must be a positive integer")
    capabilities = info["backend_capabilities"]
    if not isinstance(capabilities, list) or not all(isinstance(item, str) and item for item in capabilities):
        fail("backend_capabilities must be a list of non-empty strings")
    if len(capabilities) != len(set(capabilities)):
        fail("backend_capabilities contains duplicates")
    missing = sorted(REQUIRED_COMMUNITY_CAPABILITIES - set(capabilities))
    if missing:
        fail("Community backend capabilities missing:\n" + "\n".join(missing))


def validate_inputs(version: str, commit: str, build_time: str) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version):
        fail("version must be SemVer with an optional prerelease")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        fail("commit must be an exact 40-character hexadecimal SHA")
    try:
        parsed = datetime.fromisoformat(build_time.replace("Z", "+00:00"))
    except ValueError:
        fail("build-time must be RFC3339")
    if parsed.tzinfo is None:
        fail("build-time must include a timezone")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-info", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-time", required=True)
    args = parser.parse_args()

    validate_inputs(args.version, args.commit, args.build_time)
    backend = read_backend_info(args.backend_info)
    validate_backend_info(backend)

    metadata = {
        "schema_version": 1,
        "product": "AnoPKI",
        "version": args.version,
        "commit": args.commit.lower(),
        "build_time": args.build_time,
        "edition": backend["edition"],
        "product_profile": backend["product_profile"],
        "selected_backend": backend["selected_backend"],
        "fallback_enabled": False,
        "fallback_used": False,
        "backend": {
            "id": backend["backend_id"],
            "dependency": backend["backend_dependency"],
            "version": backend["backend_version"],
            "readiness": backend["backend_readiness"],
            "capabilities": backend["backend_capabilities"],
            "abi_version": backend["backend_abi_version"],
            "build_fingerprint": backend["backend_build_fingerprint"],
        },
        "key_provider_policy": {
            "supported_classes": ["file"],
            "file_provider_exportability": "exportable",
            "file_provider_allowed_in_production": False,
            "core_signing_evidence_required": True,
            "automatic_provider_fallback": False,
        },
        "production_ready": False,
        "kcmvp_status": "not_applicable",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"release metadata written: {args.out}")


if __name__ == "__main__":
    main()
