#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for release artifact smoke validation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def write_archive(path: Path, member_name: str) -> None:
    payload = path.parent / member_name
    payload.write_text("binary", encoding="utf-8")
    with tarfile.open(path, "w:gz") as archive:
        archive.add(payload, arcname=member_name)


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


def release_metadata(backend: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "product": "AnoPKI",
        "version": VERSION,
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "build_time": "2026-07-17T01:02:03Z",
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


def rewrite_checksums(dist: Path) -> None:
    artifacts = [
        path
        for path in dist.iterdir()
        if path.name != "SHA256SUMS" and (path.suffix == ".json" or path.name.endswith(".tar.gz"))
    ]
    sums = []
    for artifact in sorted(artifacts, key=lambda path: path.name):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        sums.append(f"{digest}  {artifact.name}")
    (dist / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def write_valid_dist(dist: Path) -> tuple[Path, Path]:
    service = dist / f"anopki-service-v{VERSION}-linux-amd64.tar.gz"
    core = dist / f"anopki-core-v{VERSION}-linux-amd64.tar.gz"
    write_archive(service, "anopki-service")
    write_archive(core, "anopki-core")
    backend = backend_info()
    (dist / "anopki-backend-info.json").write_text(json.dumps(backend), encoding="utf-8")
    (dist / "anopki-release-metadata.json").write_text(json.dumps(release_metadata(backend)), encoding="utf-8")
    rewrite_checksums(dist)
    return service, core


def run_validator(dist: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/validate-release-artifacts.py", str(dist)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_valid_release_artifacts_pass() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        result = run_validator(dist)

    assert result.returncode == 0, result.stderr or result.stdout


def test_missing_release_archive_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        service, _ = write_valid_dist(dist)
        service.unlink()
        result = run_validator(dist)

    assert result.returncode == 1
    assert "missing release archive" in result.stderr


def test_invalid_release_archive_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        service, _ = write_valid_dist(dist)
        service.write_text("not a tar archive", encoding="utf-8")
        result = run_validator(dist)

    assert result.returncode == 1
    assert "invalid tar archive" in result.stderr


def test_missing_archive_member_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        service, _ = write_valid_dist(dist)
        service.unlink()
        write_archive(service, "anopki-service-drift")
        result = run_validator(dist)

    assert result.returncode == 1
    assert "missing member" in result.stderr


def test_extra_archive_member_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        service, _ = write_valid_dist(dist)
        extra = dist / "unexpected.txt"
        extra.write_text("extra", encoding="utf-8")
        with tarfile.open(service, "w:gz") as archive:
            archive.add(dist / "anopki-service", arcname="anopki-service")
            archive.add(extra, arcname="unexpected.txt")
        result = run_validator(dist)

    assert result.returncode == 1
    assert "unexpected archive members" in result.stderr


def test_missing_checksum_file_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        (dist / "SHA256SUMS").unlink()
        result = run_validator(dist)

    assert result.returncode == 1
    assert "missing checksum file" in result.stderr


def test_invalid_checksum_line_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        (dist / "SHA256SUMS").write_text("not-a-checksum-line\n", encoding="utf-8")
        result = run_validator(dist)

    assert result.returncode == 1
    assert "invalid checksum line" in result.stderr


def test_checksum_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        sums = dist / "SHA256SUMS"
        text = sums.read_text(encoding="utf-8")
        sums.write_text(("0" if text[0] != "0" else "1") + text[1:], encoding="utf-8")
        result = run_validator(dist)

    assert result.returncode == 1
    assert "checksum mismatch" in result.stderr


def test_extra_checksum_entry_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        sums = dist / "SHA256SUMS"
        sums.write_text(
            sums.read_text(encoding="utf-8") + ("0" * 64) + "  unexpected.tar.gz\n",
            encoding="utf-8",
        )
        result = run_validator(dist)

    assert result.returncode == 1
    assert "unexpected checksum entries" in result.stderr


def test_duplicate_checksum_entry_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        service, _ = write_valid_dist(dist)
        sums = dist / "SHA256SUMS"
        sums.write_text(
            sums.read_text(encoding="utf-8") + ("0" * 64) + f"  {service.name}\n",
            encoding="utf-8",
        )
        result = run_validator(dist)

    assert result.returncode == 1
    assert "duplicate checksum entry" in result.stderr



def test_missing_release_metadata_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        (dist / "anopki-release-metadata.json").unlink()
        rewrite_checksums(dist)
        result = run_validator(dist)

    assert result.returncode == 1
    assert "missing release metadata" in result.stderr


def test_backend_profile_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        path = dist / "anopki-backend-info.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["product_profile"] = "enterprise-openssl"
        path.write_text(json.dumps(value), encoding="utf-8")
        rewrite_checksums(dist)
        result = run_validator(dist)

    assert result.returncode == 1
    assert "Community/OpenSSL" in result.stderr


def test_release_metadata_backend_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        path = dist / "anopki-release-metadata.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["backend"]["version"] = "drift"
        path.write_text(json.dumps(value), encoding="utf-8")
        rewrite_checksums(dist)
        result = run_validator(dist)

    assert result.returncode == 1
    assert "does not match core backend info" in result.stderr


def test_release_metadata_sensitive_field_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        path = dist / "anopki-release-metadata.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["key_ref"] = "/secret/issuer.key"
        path.write_text(json.dumps(value), encoding="utf-8")
        rewrite_checksums(dist)
        result = run_validator(dist)

    assert result.returncode == 1
    assert "unknown fields" in result.stderr


def main() -> None:
    test_valid_release_artifacts_pass()
    test_missing_release_archive_fails()
    test_invalid_release_archive_fails()
    test_missing_archive_member_fails()
    test_extra_archive_member_fails()
    test_missing_checksum_file_fails()
    test_invalid_checksum_line_fails()
    test_checksum_mismatch_fails()
    test_extra_checksum_entry_fails()
    test_duplicate_checksum_entry_fails()
    test_missing_release_metadata_fails()
    test_backend_profile_mismatch_fails()
    test_release_metadata_backend_mismatch_fails()
    test_release_metadata_sensitive_field_fails()
    print("release artifact tests ok")


if __name__ == "__main__":
    main()
