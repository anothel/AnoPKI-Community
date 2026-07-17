#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate release version source-of-truth wiring."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_text(root: Path, path: Path, values: list[str]) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(root)}")
    text = path.read_text(encoding="utf-8")
    missing = [value for value in values if value not in text]
    if missing:
        fail(f"{path.relative_to(root)} missing:\n" + "\n".join(missing))
    return text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=ROOT, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    version = require_text(root, root / "VERSION", []).strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version):
        fail("VERSION must be MAJOR.MINOR.PATCH with an optional SemVer prerelease")

    require_text(
        root,
        root / "CMakeLists.txt",
        [
            'file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ANOPKI_VERSION)',
            'string(REGEX MATCH "^[0-9]+\\\\.[0-9]+\\\\.[0-9]+" ANOPKI_PROJECT_VERSION "${ANOPKI_VERSION}")',
            "project(anopki VERSION ${ANOPKI_PROJECT_VERSION} LANGUAGES CXX)",
            "src/version_config.hpp.in",
        ],
    )
    require_text(
        root,
        root / "src/version.cpp",
        [
            "ANOPKI_VERSION_MAJOR",
            "ANOPKI_VERSION_STRING",
        ],
    )
    require_text(
        root,
        root / ".github/workflows/release.yml",
        [
            'VERSION="$(cat VERSION)"',
            'test "${GITHUB_REF_NAME#v}" = "$VERSION"',
            "-X main.serviceVersion=${VERSION}",
            "anopki-service-v${VERSION}-linux-amd64.tar.gz",
            "anopki-core-v${VERSION}-linux-amd64.tar.gz",
            "anopki-backend-info.json",
            "anopki-release-metadata.json",
            "scripts/generate-release-metadata.py",
        ],
    )
    print("version metadata ok")


if __name__ == "__main__":
    main()
