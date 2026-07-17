#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Smoke-check release archives and profile metadata before upload/signing."""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
BACKEND_INFO_NAME = "anopki-backend-info.json"
RELEASE_METADATA_NAME = "anopki-release-metadata.json"


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_archive(dist: Path, name: str, member: str) -> Path:
    path = dist / name
    if not path.is_file():
        fail(f"missing release archive: {path}")
    try:
        with tarfile.open(path, "r:gz") as archive:
            names = set(archive.getnames())
    except tarfile.TarError as exc:
        fail(f"invalid tar archive {path}: {exc}")
    if member not in names:
        fail(f"{path.name} missing member: {member}")
    unexpected = sorted(names - {member})
    if unexpected:
        fail(f"{path.name} unexpected archive members:\n" + "\n".join(unexpected))
    return path


def read_checksums(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing checksum file: {path}")
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if not digest or not name:
            fail(f"invalid checksum line: {line}")
        if name in checksums:
            fail(f"duplicate checksum entry: {name}")
        checksums[name] = digest
    return checksums


def read_json_object(path: Path, label: str) -> dict[str, object]:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_exact_fields(value: dict[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        fail(f"{label} missing fields:\n" + "\n".join(missing))
    if extra:
        fail(f"{label} has unknown fields:\n" + "\n".join(extra))


def validate_backend_info(info: dict[str, object]) -> None:
    require_exact_fields(
        info,
        {
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
        },
        "backend info",
    )
    if info["product_profile"] != "community-openssl" or info["edition"] != "community":
        fail("backend info does not describe Community/OpenSSL")
    if info["selected_backend"] != "openssl" or info["backend_id"] != "openssl":
        fail("backend info does not select the OpenSSL adapter")
    if info["fallback_enabled"] is not False:
        fail("backend info enables fallback")
    if info["backend_readiness"] != "ready":
        fail("backend info is not ready")
    if not isinstance(info["backend_abi_version"], int) or isinstance(info["backend_abi_version"], bool) or info["backend_abi_version"] <= 0:
        fail("backend info ABI version is invalid")
    capabilities = info["backend_capabilities"]
    if not isinstance(capabilities, list) or not capabilities or not all(isinstance(item, str) and item for item in capabilities):
        fail("backend info capabilities are invalid")
    if len(capabilities) != len(set(capabilities)):
        fail("backend info capabilities contain duplicates")


def validate_release_metadata(metadata: dict[str, object], backend: dict[str, object]) -> None:
    require_exact_fields(
        metadata,
        {
            "schema_version",
            "product",
            "version",
            "commit",
            "build_time",
            "edition",
            "product_profile",
            "selected_backend",
            "fallback_enabled",
            "fallback_used",
            "backend",
            "key_provider_policy",
            "production_ready",
            "kcmvp_status",
        },
        "release metadata",
    )
    if metadata["schema_version"] != 1 or metadata["product"] != "AnoPKI" or metadata["version"] != VERSION:
        fail("release metadata identity/version mismatch")
    if metadata["edition"] != backend["edition"] or metadata["product_profile"] != backend["product_profile"]:
        fail("release metadata profile mismatch")
    if metadata["selected_backend"] != backend["selected_backend"]:
        fail("release metadata selected backend mismatch")
    if metadata["fallback_enabled"] is not False or metadata["fallback_used"] is not False:
        fail("release metadata fallback state is invalid")
    if metadata["production_ready"] is not False or metadata["kcmvp_status"] != "not_applicable":
        fail("release metadata maturity claim is invalid")

    backend_metadata = metadata["backend"]
    if not isinstance(backend_metadata, dict):
        fail("release metadata backend must be an object")
    require_exact_fields(
        backend_metadata,
        {"id", "dependency", "version", "readiness", "capabilities", "abi_version", "build_fingerprint"},
        "release metadata backend",
    )
    expected_backend = {
        "id": backend["backend_id"],
        "dependency": backend["backend_dependency"],
        "version": backend["backend_version"],
        "readiness": backend["backend_readiness"],
        "capabilities": backend["backend_capabilities"],
        "abi_version": backend["backend_abi_version"],
        "build_fingerprint": backend["backend_build_fingerprint"],
    }
    if backend_metadata != expected_backend:
        fail("release metadata backend evidence does not match core backend info")

    policy = metadata["key_provider_policy"]
    if not isinstance(policy, dict):
        fail("release metadata key provider policy must be an object")
    expected_policy = {
        "supported_classes": ["file"],
        "file_provider_exportability": "exportable",
        "file_provider_allowed_in_production": False,
        "core_signing_evidence_required": True,
        "automatic_provider_fallback": False,
    }
    if policy != expected_policy:
        fail("release metadata key provider policy mismatch")

    serialized = json.dumps(metadata, sort_keys=True).lower()
    for forbidden in ("key_ref", "private_key", "issuer_key", "credential", "session_token", "pin_value"):
        if forbidden in serialized:
            fail(f"release metadata contains forbidden sensitive field: {forbidden}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate-release-artifacts.py <dist-dir>")
    dist = Path(sys.argv[1])
    service = require_archive(
        dist,
        f"anopki-service-v{VERSION}-linux-amd64.tar.gz",
        "anopki-service",
    )
    core = require_archive(
        dist,
        f"anopki-core-v{VERSION}-linux-amd64.tar.gz",
        "anopki-core",
    )
    backend_path = dist / BACKEND_INFO_NAME
    metadata_path = dist / RELEASE_METADATA_NAME
    backend = read_json_object(backend_path, "backend info")
    validate_backend_info(backend)
    metadata = read_json_object(metadata_path, "release metadata")
    validate_release_metadata(metadata, backend)

    checksums = read_checksums(dist / "SHA256SUMS")
    artifacts = (service, core, backend_path, metadata_path)
    expected_names = {artifact.name for artifact in artifacts}
    extra_names = sorted(set(checksums) - expected_names)
    missing_names = sorted(expected_names - set(checksums))
    if extra_names:
        fail("unexpected checksum entries:\n" + "\n".join(extra_names))
    if missing_names:
        fail("missing checksum entries:\n" + "\n".join(missing_names))
    for artifact in artifacts:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if checksums.get(artifact.name) != digest:
            fail(f"checksum mismatch: {artifact.name}")
    print("release artifacts ok")


if __name__ == "__main__":
    main()
