#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for release artifact smoke validation."""

from __future__ import annotations

import hashlib
import json
import shutil
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



def write_go_evidence_archive(
    path: Path,
    *,
    result: str = "passed",
    missing_log: str = "",
    commit: str = "0123456789abcdef0123456789abcdef01234567",
    extra_field: bool = False,
    extra_member: bool = False,
) -> None:
    root = path.parent / "go-evidence"
    if root.exists():
        shutil.rmtree(root)
    logs = root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    step_names = [
        "go-test",
        "go-vet",
        "go-build",
        "go-race",
        "staticcheck",
        "gosec",
        "govulncheck",
    ]
    commands = [
        ["go", "test", "./..."],
        ["go", "vet", "./..."],
        ["go", "build", "-trimpath", "-o", "<evidence-dir>/anopki-service", "./cmd/anopki-service"],
        ["go", "test", "-race", "./..."],
        ["go", "run", "honnef.co/go/tools/cmd/staticcheck@2026.1", "./..."],
        ["go", "run", "github.com/securego/gosec/v2/cmd/gosec@v2.25.0", "./..."],
        ["go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.1.4", "./..."],
    ]
    evidence = {
        "schema_version": 1,
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "profile": "full",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "platform": "linux/amd64",
        "started_at": "2026-07-17T01:00:00Z",
        "completed_at": "2026-07-17T01:01:00Z",
        "result": result,
        "go_version": "go version go1.25.12 linux/amd64",
        "go_environment": {
            "GOOS": "linux",
            "GOARCH": "amd64",
            "GOVERSION": "go1.25.12",
            "CGO_ENABLED": "1",
        },
        "tool_versions": {
            "staticcheck": "2026.1",
            "gosec": "v2.25.0",
            "govulncheck": "v1.1.4",
        },
        "steps": [
            {
                "name": name,
                "command": command,
                "status": "passed",
                "exit_code": 0,
                "duration_seconds": 1.0,
                "log_file": f"logs/{index:02d}-{name}.log",
            }
            for index, (name, command) in enumerate(zip(step_names, commands), start=1)
        ],
    }
    if extra_field:
        evidence["unexpected"] = "drift"
    (root / "go-verification.json").write_text(json.dumps(evidence), encoding="utf-8")
    (root / "go-verification.md").write_text("# Go evidence\n", encoding="utf-8")
    for index, name in enumerate(step_names, start=1):
        log_name = f"{index:02d}-{name}.log"
        if log_name != missing_log:
            (logs / log_name).write_text("pass\n", encoding="utf-8")
    if extra_member:
        (root / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with tarfile.open(path, "w:gz") as archive:
        archive.add(root / "go-verification.json", arcname="go-verification.json")
        archive.add(root / "go-verification.md", arcname="go-verification.md")
        archive.add(logs, arcname="logs")
        if extra_member:
            archive.add(root / "unexpected.txt", arcname="unexpected.txt")

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
    write_go_evidence_archive(dist / "anopki-go-verification.tar.gz")
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



def test_missing_go_evidence_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        (dist / "anopki-go-verification.tar.gz").unlink()
        rewrite_checksums(dist)
        result = run_validator(dist)
    assert result.returncode == 1
    assert "missing Go verification evidence" in result.stderr


def test_failed_go_evidence_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        write_go_evidence_archive(dist / "anopki-go-verification.tar.gz", result="failed")
        rewrite_checksums(dist)
        result = run_validator(dist)
    assert result.returncode == 1
    assert "full profile did not pass" in result.stderr


def test_incomplete_go_evidence_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        write_go_evidence_archive(dist / "anopki-go-verification.tar.gz", missing_log="03-go-build.log")
        rewrite_checksums(dist)
        result = run_validator(dist)
    assert result.returncode == 1
    assert "missing Go evidence members" in result.stderr


def test_go_evidence_commit_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        write_go_evidence_archive(
            dist / "anopki-go-verification.tar.gz",
            commit="f" * 40,
        )
        rewrite_checksums(dist)
        result = run_validator(dist)
    assert result.returncode == 1
    assert "commit does not match" in result.stderr



def test_unexpected_go_evidence_member_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        write_go_evidence_archive(dist / "anopki-go-verification.tar.gz", extra_member=True)
        rewrite_checksums(dist)
        result = run_validator(dist)
    assert result.returncode == 1
    assert "unexpected Go evidence members" in result.stderr


def test_unknown_go_evidence_field_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp)
        write_valid_dist(dist)
        write_go_evidence_archive(dist / "anopki-go-verification.tar.gz", extra_field=True)
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
    test_missing_go_evidence_fails()
    test_failed_go_evidence_fails()
    test_incomplete_go_evidence_fails()
    test_go_evidence_commit_mismatch_fails()
    test_unexpected_go_evidence_member_fails()
    test_unknown_go_evidence_field_fails()
    print("release artifact tests ok")


if __name__ == "__main__":
    main()
