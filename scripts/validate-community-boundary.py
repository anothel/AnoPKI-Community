#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate that the public Community tree does not contain Enterprise overlay material."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PATHS = [
    "enterprise",
    "docs/enterprise",
    "service/internal/enterprise",
    "include/anopki/enterprise",
    "src/enterprise",
    "src/core/crypto/anocrypto_backend.cpp",
    "src/core/crypto/anocrypto_backend.hpp",
]

FORBIDDEN_TOKENS = [
    "LicenseRef-AnoPKI-Enterprise",
    "ANOPKI_ENTERPRISE_EDITION",
    "ANOPKI_ENTERPRISE_ANOCRYPTO",
]

def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)

def main() -> None:
    hits = [p for p in FORBIDDEN_PATHS if (ROOT / p).exists()]
    if hits:
        fail("Community tree contains Enterprise-only paths:\n" + "\n".join(hits))

    token_hits = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(ROOT).parts
        if any(part in {".git", "build", "docs-pack"} for part in rel_parts):
            continue
        if path.name == "validate-community-boundary.py":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for token in FORBIDDEN_TOKENS:
            if token in content:
                token_hits.append(f"{path.relative_to(ROOT)}: {token}")
    if token_hits:
        fail("Community tree contains Enterprise-only tokens:\n" + "\n".join(sorted(token_hits)))

    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    if "find_package(OpenSSL REQUIRED COMPONENTS Crypto)" not in cmake:
        fail("Community CMakeLists.txt must keep OpenSSL as the active backend")
    print("community boundary ok")

if __name__ == "__main__":
    main()
