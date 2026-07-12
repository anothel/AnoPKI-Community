#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate that the public Community tree does not contain Enterprise overlay material."""

from __future__ import annotations

import sys
import subprocess
import re
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_PATHS = [
    "enterprise",
    "docs/enterprise",
    "service/internal/enterprise",
    "include/anopki/enterprise",
    "src/enterprise",
    "src/core/crypto/anocrypto_backend.cpp",
    "src/core/crypto/anocrypto_backend.hpp",
    "src/backends/anocrypto_c",
]

FORBIDDEN_TOKENS = [
    "LicenseRef-AnoPKI-Enterprise",
    "ENTERPRISE-LICENSE-NOTICE",
    "ANOPKI_ENTERPRISE_EDITION",
    "ANOPKI_ENTERPRISE_ANOCRYPTO",
]

SKIP_DIRS = {
    ".git",
    ".tmp",
    ".tmp-gocache",
    ".pytest_cache",
    "build",
    "build-fuzz",
    "docs-pack",
    "node_modules",
    "vendor",
    "__pycache__",
}


OPENSSL_ADAPTER_FILES = [
    "src/backends/openssl/openssl_backend.hpp",
    "src/backends/openssl/openssl_backend.cpp",
    "src/backends/openssl/csr.cpp",
    "src/backends/openssl/issue.cpp",
    "src/backends/openssl/crl.cpp",
    "src/backends/openssl/ocsp.cpp",
]

SELF_TEST_FILES = {
    "validate-community-boundary.py",
    "test_validate_community_boundary.py",
}

ANOCRYPTO_CLAIM_WORDS = ("implemented", "implementation", "active", "current", "default", "production", "ready")
KCMVP_CLAIM_WORDS = ("certified", "validated")
ALLOW_QUALIFIERS = (
    "planned",
    "intended",
    "pending",
    "future",
    "target",
    "ready architecture",
    "not implemented",
    "does not implement",
    "do not",
    "must not claim",
    "not claim",
    "not mark",
    "excluded",
    "until",
    "before switching",
    "begins",
    "when the first",
    "work as an",
    "adoption",
    "source or binaries",
    "certification evidence",
    "until code",
    "earlier planning",
    "production expansion",
    "production-releasable",
    "external enterprise",
    "production release blocked",
    "full parity",
    "if any",
    "exact validated",
)


def fail(message: str) -> None:
    raise SystemExit(message)

def should_skip(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    return path.name in SELF_TEST_FILES or path.name.startswith("test_") or any(part in SKIP_DIRS for part in rel_parts)


def text_files(root: Path) -> Iterable[Path]:
    git_dir = root / ".git"
    if git_dir.exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            for rel in result.stdout.splitlines():
                path = root / rel
                if path.is_file() and not should_skip(path, root):
                    yield path
            return

    for path in root.rglob("*"):
        if path.is_file() and not should_skip(path, root):
            yield path


def has_allow_qualifier(line: str) -> bool:
    lowered = line.lower()
    return any(qualifier in lowered for qualifier in ALLOW_QUALIFIERS)


def validate(root: Path = ROOT) -> None:
    hits = [p for p in FORBIDDEN_PATHS if (root / p).exists()]
    hits.extend(str(p.relative_to(root)) for p in (root / "src/core/crypto").glob("anocrypto_backend.*"))
    if hits:
        fail("Community tree contains Enterprise-only paths:\n" + "\n".join(hits))

    token_hits = []
    anocrypto_hits = []
    kcmvp_hits = []
    for path in text_files(root):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root)
        for token in FORBIDDEN_TOKENS:
            if token in content:
                token_hits.append(f"{rel}: {token}")
        for number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if "anocrypto" in lowered and any(word in lowered for word in ANOCRYPTO_CLAIM_WORDS) and not has_allow_qualifier(line):
                anocrypto_hits.append(f"{rel}:{number}: {line.strip()}")
            if "kcmvp" in lowered and any(word in lowered for word in KCMVP_CLAIM_WORDS) and not has_allow_qualifier(line):
                kcmvp_hits.append(f"{rel}:{number}: {line.strip()}")
    if token_hits:
        fail("Community tree contains Enterprise-only tokens:\n" + "\n".join(sorted(token_hits)))
    if anocrypto_hits:
        fail("Community tree contains premature AnoCrypto claims:\n" + "\n".join(sorted(anocrypto_hits)))
    if kcmvp_hits:
        fail("Community tree contains KCMVP certification claims:\n" + "\n".join(sorted(kcmvp_hits)))

    cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    if "find_package(OpenSSL REQUIRED COMPONENTS Crypto)" not in cmake:
        fail("Community CMakeLists.txt must keep OpenSSL as the active backend")
    required_profile_markers = [
        'set(ANOPKI_PRODUCT_PROFILE "community-openssl"',
        'ANOPKI_SELECTED_BACKEND_ID="openssl"',
        'ANOPKI_PROFILE_REQUIRES_FULL_OPERATIONS=1',
        'add_custom_target(anopki-community-openssl',
    ]
    missing = [marker for marker in required_profile_markers if marker not in cmake]
    if missing:
        fail("Community CMakeLists.txt missing explicit product profile markers:\n" + "\n".join(missing))

    source_root = root / "src"
    if source_root.exists():
        missing_adapter_files = [path for path in OPENSSL_ADAPTER_FILES if not (root / path).is_file()]
        if missing_adapter_files:
            fail("Community OpenSSL adapter files are missing:\n" + "\n".join(missing_adapter_files))

        direct_openssl_hits = []
        core_root = root / "src" / "core"
        if core_root.exists():
            for path in core_root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    content = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                for number, line in enumerate(content.splitlines(), start=1):
                    if "#include <openssl/" in line or "#include \"openssl/" in line:
                        direct_openssl_hits.append(f"{path.relative_to(root)}:{number}: {line.strip()}")
        if direct_openssl_hits:
            fail("Backend-neutral Core contains direct OpenSSL includes:\n" + "\n".join(direct_openssl_hits))

        cli_path = root / "src" / "cli" / "main.cpp"
        if cli_path.is_file() and "#include <openssl/" in cli_path.read_text(encoding="utf-8"):
            fail("CLI must obtain dependency diagnostics through the selected adapter")


        backend_header = (root / "include/anopki/crypto/backend.hpp").read_text(encoding="utf-8")
        required_backend_tokens = ["BackendInfo", "BackendCapability", "BackendReadiness", "BackendErrorCode"]
        missing = [token for token in required_backend_tokens if token not in backend_header]
        if missing:
            fail("Community backend control contract missing:\n" + "\n".join(missing))

        if "add_library(anopki_openssl_adapter" not in cmake:
            fail("Community CMakeLists.txt must define the OpenSSL adapter target")
        if "target_link_libraries(anopki_openssl_adapter" not in cmake or "OpenSSL::Crypto" not in cmake:
            fail("Community OpenSSL adapter target must link OpenSSL::Crypto")

        for target in ("anopki_core", "anopki-core"):
            pattern = re.compile(
                rf"target_link_libraries\(\s*{re.escape(target)}(?=\s|\))(?P<body>.*?)\)",
                re.DOTALL,
            )
            for match in pattern.finditer(cmake):
                if "OpenSSL::Crypto" in match.group("body"):
                    fail(f"{target} must not link OpenSSL::Crypto directly")


def main() -> None:
    validate(ROOT)
    print("community boundary ok")

if __name__ == "__main__":
    main()
