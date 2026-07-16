#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-key-provider-boundary.py")
SPEC = importlib.util.spec_from_file_location("validate_key_provider_boundary", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def clean_fixture(root: Path) -> None:
    write(
        root,
        "src/backends/openssl/key_providers/file_key_provider.hpp",
        """class SigningKeyProvider {};
class FileKeyProvider {};
class SigningKeyHandle {};
struct ProviderMetadata {};
struct RedactedProviderDiagnostics {};
""",
    )
    write(
        root,
        "src/backends/openssl/key_providers/file_key_provider.cpp",
        """provider.invalid_reference provider.unavailable provider.not_ready
provider.key_not_found provider.key_parse_failed provider.algorithm_mismatch
provider.key_binding_mismatch provider.exportability_violation
provider.profile_mismatch provider.sign_failed
fallback_used = false
X509_check_private_key
int reject_private_key_password(char *, int, int, void *) noexcept
PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_private_key_password, nullptr)
""",
    )
    write(
        root,
        "src/backends/openssl/issue.cpp",
        """#include "key_providers/file_key_provider.hpp"
auto key = resolve_certificate_signing_key(ref, algorithm, cert, provider_policy_from_environment());
X509_sign(cert, key.native_handle(), digest);
throw_provider_sign_failed(key);
""",
    )
    write(
        root,
        "tests/file_key_provider_test.cpp",
        """write_encrypted_private_key
EVP_aes_256_cbc
encrypted.pem
test-only-password
""",
    )
    write(
        root,
        "CMakeLists.txt",
        """add_library(adapter
src/backends/openssl/key_providers/file_key_provider.cpp)
add_executable(test tests/file_key_provider_test.cpp)
""",
    )
    write(root, "include/anopki/core.hpp", "// neutral\n")
    write(root, "src/core/issue.cpp", "// neutral\n")


def expect_failure(root: Path, fragment: str) -> None:
    try:
        VALIDATOR.validate(root)
    except RuntimeError as error:
        assert fragment in str(error), str(error)
        return
    raise AssertionError(f"expected validator failure containing {fragment!r}")


def test_clean_fixture_passes() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        VALIDATOR.validate(root)


def test_direct_bio_open_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        issue = root / "src/backends/openssl/issue.cpp"
        issue.write_text(issue.read_text(encoding="utf-8") + "BIO_new_file(path, \"rb\");\n", encoding="utf-8")
        expect_failure(root, "directly loads a private key")


def test_direct_pem_read_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        issue = root / "src/backends/openssl/issue.cpp"
        issue.write_text(issue.read_text(encoding="utf-8") + "PEM_read_bio_PrivateKey(bio, 0, 0, 0);\n", encoding="utf-8")
        expect_failure(root, "directly loads a private key")


def test_interactive_password_callback_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        provider = root / "src/backends/openssl/key_providers/file_key_provider.cpp"
        provider.write_text(
            provider.read_text(encoding="utf-8").replace(
                "reject_private_key_password, nullptr", "nullptr, nullptr"
            ),
            encoding="utf-8",
        )
        expect_failure(root, "missing required semantics")


def test_missing_encrypted_pem_rejection_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        provider_test = root / "tests/file_key_provider_test.cpp"
        provider_test.write_text(
            provider_test.read_text(encoding="utf-8").replace(
                "write_encrypted_private_key", "write_private_key"
            ),
            encoding="utf-8",
        )
        expect_failure(root, "do not cover non-interactive encrypted PEM rejection")


def test_missing_resolution_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        issue = root / "src/backends/openssl/issue.cpp"
        issue.write_text(issue.read_text(encoding="utf-8").replace("resolve_certificate_signing_key", "legacy_key_loader"), encoding="utf-8")
        expect_failure(root, "does not use the FileKeyProvider boundary")


def test_missing_cmake_source_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("src/backends/openssl/key_providers/file_key_provider.cpp", ""), encoding="utf-8")
        expect_failure(root, "does not compile FileKeyProvider")


def test_openssl_type_escape_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        write(root, "include/anopki/leak.hpp", "EVP_PKEY *leaked;\n")
        expect_failure(root, "escaped adapter-private paths")


def main() -> None:
    test_clean_fixture_passes()
    test_direct_bio_open_fails()
    test_direct_pem_read_fails()
    test_interactive_password_callback_fails()
    test_missing_encrypted_pem_rejection_test_fails()
    test_missing_resolution_fails()
    test_missing_cmake_source_fails()
    test_openssl_type_escape_fails()
    print("key provider boundary validator tests ok")


if __name__ == "__main__":
    main()
