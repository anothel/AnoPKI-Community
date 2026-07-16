#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROVIDER_HEADER = Path("src/backends/openssl/key_providers/file_key_provider.hpp")
PROVIDER_SOURCE = Path("src/backends/openssl/key_providers/file_key_provider.cpp")
ISSUE_SOURCE = Path("src/backends/openssl/issue.cpp")
PROVIDER_TEST = Path("tests/file_key_provider_test.cpp")

FORBIDDEN_ISSUE_TOKENS = (
    "BIO_new_file",
    "PEM_read_bio_PrivateKey",
    "PEM_read_PrivateKey",
    "parse_issuer_key",
    "std::ifstream",
    "std::fopen",
    "fopen(",
)

REQUIRED_ISSUE_TOKENS = (
    '#include "key_providers/file_key_provider.hpp"',
    "resolve_certificate_signing_key",
    "provider_policy_from_environment",
    ".native_handle()",
    "throw_provider_sign_failed",
)

REQUIRED_PROVIDER_TOKENS = (
    "provider.invalid_reference",
    "provider.unavailable",
    "provider.not_ready",
    "provider.key_not_found",
    "provider.key_parse_failed",
    "provider.algorithm_mismatch",
    "provider.key_binding_mismatch",
    "provider.exportability_violation",
    "provider.profile_mismatch",
    "provider.sign_failed",
    "fallback_used = false",
    "X509_check_private_key",
    "reject_private_key_password",
    "PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_private_key_password, nullptr)",
)

REQUIRED_PROVIDER_TEST_TOKENS = (
    "write_encrypted_private_key",
    "EVP_aes_256_cbc",
    "encrypted.pem",
    "test-only-password",
)


def fail(message: str) -> None:
    raise RuntimeError(message)


def read_required(root: Path, relative: Path) -> str:
    path = root / relative
    if not path.is_file():
        fail(f"missing KeyProvider boundary file: {relative.as_posix()}")
    return path.read_text(encoding="utf-8")


def validate(root: Path) -> None:
    header = read_required(root, PROVIDER_HEADER)
    provider = read_required(root, PROVIDER_SOURCE)
    issue = read_required(root, ISSUE_SOURCE)
    provider_test = read_required(root, PROVIDER_TEST)
    cmake = read_required(root, Path("CMakeLists.txt"))

    forbidden_hits = [token for token in FORBIDDEN_ISSUE_TOKENS if token in issue]
    if forbidden_hits:
        fail(
            "certificate issuance directly loads a private key:\n"
            + "\n".join(forbidden_hits)
        )

    missing_issue = [token for token in REQUIRED_ISSUE_TOKENS if token not in issue]
    if missing_issue:
        fail(
            "certificate issuance does not use the FileKeyProvider boundary:\n"
            + "\n".join(missing_issue)
        )

    missing_provider = [token for token in REQUIRED_PROVIDER_TOKENS if token not in provider]
    if missing_provider:
        fail(
            "FileKeyProvider implementation is missing required semantics:\n"
            + "\n".join(missing_provider)
        )

    missing_provider_tests = [
        token for token in REQUIRED_PROVIDER_TEST_TOKENS if token not in provider_test
    ]
    if missing_provider_tests:
        fail(
            "FileKeyProvider tests do not cover non-interactive encrypted PEM rejection:\n"
            + "\n".join(missing_provider_tests)
        )

    for marker in (
        "class SigningKeyProvider",
        "class FileKeyProvider",
        "class SigningKeyHandle",
        "ProviderMetadata",
        "RedactedProviderDiagnostics",
    ):
        if marker not in header:
            fail(f"adapter-private provider interface missing: {marker}")

    if "src/backends/openssl/key_providers/file_key_provider.cpp" not in cmake:
        fail("OpenSSL adapter target does not compile FileKeyProvider")
    if "tests/file_key_provider_test.cpp" not in cmake:
        fail("CMake does not register FileKeyProvider tests")

    for relative_root in (Path("include"), Path("src/core")):
        scan_root = root / relative_root
        if not scan_root.exists():
            continue
        for path in scan_root.rglob("*"):
            if not path.is_file() or path.suffix not in {".h", ".hpp", ".c", ".cc", ".cpp"}:
                continue
            content = path.read_text(encoding="utf-8")
            if "#include <openssl/" in content or "#include \"openssl/" in content or "EVP_PKEY" in content:
                fail(
                    "OpenSSL provider type/include escaped adapter-private paths: "
                    + path.relative_to(root).as_posix()
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("key provider boundary ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
