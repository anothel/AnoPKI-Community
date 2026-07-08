#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Smoke-check release archives before upload/signing."""

from __future__ import annotations

import hashlib
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


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
    checksums = read_checksums(dist / "SHA256SUMS")
    expected_names = {service.name, core.name}
    extra_names = sorted(set(checksums) - expected_names)
    if extra_names:
        fail("unexpected checksum entries:\n" + "\n".join(extra_names))
    for artifact in (service, core):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if checksums.get(artifact.name) != digest:
            fail(f"checksum mismatch: {artifact.name}")
    print("release artifacts ok")


if __name__ == "__main__":
    main()
