#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for release artifact smoke validation."""

from __future__ import annotations

import hashlib
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


def write_valid_dist(dist: Path) -> tuple[Path, Path]:
    service = dist / f"anopki-service-v{VERSION}-linux-amd64.tar.gz"
    core = dist / f"anopki-core-v{VERSION}-linux-amd64.tar.gz"
    write_archive(service, "anopki-service")
    write_archive(core, "anopki-core")
    sums = []
    for artifact in (core, service):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        sums.append(f"{digest}  {artifact.name}")
    (dist / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
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
        sums.write_text(sums.read_text(encoding="utf-8").replace("0", "1", 1), encoding="utf-8")
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
    print("release artifact tests ok")


if __name__ == "__main__":
    main()
