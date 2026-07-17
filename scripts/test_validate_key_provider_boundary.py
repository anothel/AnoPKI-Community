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
        """enum class ProviderClass { file, software_token };
class SigningKeyProvider {};
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
provider.profile_mismatch provider.sign_failed provider.evidence_failed
ANOPKI_CORE_SIGNING_EVIDENCE_FILE
evidence_source\\":\\"core_signing result_code\\":\\"ok
fallback_used = false
X509_check_private_key
int reject_private_key_password(char *, int, int, void *) noexcept
PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_private_key_password, nullptr)
crl_generate_sign
ocsp_response_sign
resolve_signing_key_with_provider
""",
    )
    write(
        root,
        "src/backends/openssl/key_providers/provider_resolver.hpp",
        """SigningKeyHandle resolve_signing_key_with_provider(
const SigningKeyProvider &provider,
const SigningKeyRequest &request);
""",
    )
    write(
        root,
        "src/backends/openssl/key_providers/provider_resolver.cpp",
        """SigningKeyHandle resolve_signing_key_with_provider(
const SigningKeyProvider &provider,
const SigningKeyRequest &request) {
auto metadata = provider.metadata();
provider.accepts(request.key_ref);
ProviderReadiness::ready;
metadata.exportable;
auto handle = provider.acquire(request);
auto evidence = handle.evidence();
evidence.requested_signature_algorithm;
evidence.key_algorithm.empty();
evidence.issuer_binding_verified;
evidence.fallback_used;
ProviderErrorCode::profile_mismatch;
"evidence";
return handle;
}
""",
    )
    write(
        root,
        "src/backends/openssl/issue.cpp",
        """#include "key_providers/file_key_provider.hpp"
auto key = resolve_certificate_signing_key(ref, algorithm, cert, provider_policy_from_environment());
X509_sign(cert, key.native_handle(), digest);
write_signing_evidence_if_requested(key);
throw_provider_sign_failed(key);
""",
    )
    write(
        root,
        "src/backends/openssl/crl.cpp",
        """#include "key_providers/file_key_provider.hpp"
auto key = resolve_crl_signing_key(ref, cert, provider_policy_from_environment());
X509_CRL_sign(crl, key.native_handle(), EVP_sha256());
write_signing_evidence_if_requested(key);
throw_provider_sign_failed(key);
""",
    )
    write(
        root,
        "src/backends/openssl/ocsp.cpp",
        """#include "key_providers/file_key_provider.hpp"
auto key = resolve_ocsp_signing_key(ref, cert, provider_policy_from_environment());
OCSP_basic_sign(response, cert, key.native_handle(), EVP_sha256(), nullptr, 0);
write_signing_evidence_if_requested(key);
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
resolve_crl_signing_key
crl_generate_sign
resolve_ocsp_signing_key
ocsp_response_sign
test_signing_evidence_sidecar
ANOPKI_CORE_SIGNING_EVIDENCE_FILE
core_signing
provider.evidence_failed
""",
    )
    write(
        root,
        "tests/crl_file_key_provider_test.cpp",
        """file:
kms:
provider.key_not_found
provider.key_parse_failed
provider.key_binding_mismatch
provider.exportability_violation
X509_CRL_verify
deterministic CRL DER
""",
    )
    write(
        root,
        "tests/ocsp_file_key_provider_test.cpp",
        """file:
kms:
provider.invalid_reference
provider.key_not_found
provider.key_parse_failed
provider.algorithm_mismatch
provider.key_binding_mismatch
provider.exportability_violation
OCSP_basic_verify
provider-signed OCSP response verification failed
""",
    )
    write(
        root,
        "tests/software_token_key_provider_test.cpp",
        """class SoftwareTokenKeyProvider {};
ProviderClass::software_token;
"softtoken:issuer";
policy.production_mode = true;
provider.acquire_count() == 1;
ProviderErrorCode::profile_mismatch;
mismatched_algorithm;
unverified_binding;
empty_key_algorithm;
fallback_claim;
resolve_signing_key_with_provider;
X509_verify;
""",
    )
    write(
        root,
        "service/internal/corecli/runner.go",
        """ANOPKI_CORE_SIGNING_EVIDENCE_FILE
createSigningEvidenceFile
withSigningEvidenceEnvironment
DisallowUnknownFields
ValidateSigningEvidence
EvidenceSource != "core_signing"
IssuerBindingVerified
FallbackUsed
ResultCode != "ok"
SigningEvidence SigningEvidence `json:"-"`
""",
    )
    write(
        root,
        "service/internal/lifecycle/service.go",
        """ValidateSigningEvidence(result.SigningEvidence, "certificate_issue"
ValidateSigningEvidence(result.SigningEvidence, "crl_generate_sign", "sha256")
ValidateSigningEvidence(result.SigningEvidence, "ocsp_response_sign", "sha256")
SigningEvidenceJSON
coreSigningAuditFields(result.SigningEvidence
fields["key_provider_evidence_source"] = evidence.EvidenceSource
fields["key_provider_signing_proven"] = true
fields["key_provider_evidence_source"] = "legacy_key_ref_classification"
fields["key_provider_signing_proven"] = false
""",
    )
    write(root, "service/internal/domain/types.go", "SigningEvidenceJSON signing_evidence_json\n")
    write(root, "service/internal/store/migrate.go", "SigningEvidenceJSON signing_evidence_json\n")
    write(root, "service/internal/store/sqlstore_certificate.go", "SigningEvidenceJSON signing_evidence_json\n")
    write(
        root,
        "CMakeLists.txt",
        """add_library(adapter
src/backends/openssl/key_providers/file_key_provider.cpp
src/backends/openssl/key_providers/provider_resolver.cpp)
add_executable(test tests/file_key_provider_test.cpp)
add_executable(crl_test tests/crl_file_key_provider_test.cpp)
add_executable(ocsp_test tests/ocsp_file_key_provider_test.cpp)
add_executable(software_token_test tests/software_token_key_provider_test.cpp)
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


def test_crl_direct_bio_open_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        crl = root / "src/backends/openssl/crl.cpp"
        crl.write_text(crl.read_text(encoding="utf-8") + 'BIO_new_file(path, "rb");\n', encoding="utf-8")
        expect_failure(root, "CRL signing directly loads a private key")


def test_crl_direct_pem_read_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        crl = root / "src/backends/openssl/crl.cpp"
        crl.write_text(crl.read_text(encoding="utf-8") + "PEM_read_bio_PrivateKey(bio, 0, 0, 0);\n", encoding="utf-8")
        expect_failure(root, "CRL signing directly loads a private key")


def test_missing_crl_resolution_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        crl = root / "src/backends/openssl/crl.cpp"
        crl.write_text(crl.read_text(encoding="utf-8").replace("resolve_crl_signing_key", "legacy_crl_key_loader"), encoding="utf-8")
        expect_failure(root, "CRL signing does not use the FileKeyProvider boundary")


def test_missing_crl_provider_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        test = root / "tests/crl_file_key_provider_test.cpp"
        test.write_text(test.read_text(encoding="utf-8").replace("provider.exportability_violation", "missing"), encoding="utf-8")
        expect_failure(root, "CRL FileKeyProvider tests are missing required coverage")


def test_ocsp_direct_bio_open_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        ocsp = root / "src/backends/openssl/ocsp.cpp"
        ocsp.write_text(ocsp.read_text(encoding="utf-8") + 'BIO_new_file(path, "rb");\n', encoding="utf-8")
        expect_failure(root, "OCSP signing directly loads a private key")


def test_ocsp_direct_pem_read_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        ocsp = root / "src/backends/openssl/ocsp.cpp"
        ocsp.write_text(ocsp.read_text(encoding="utf-8") + "PEM_read_bio_PrivateKey(bio, 0, 0, 0);\n", encoding="utf-8")
        expect_failure(root, "OCSP signing directly loads a private key")


def test_missing_ocsp_resolution_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        ocsp = root / "src/backends/openssl/ocsp.cpp"
        ocsp.write_text(ocsp.read_text(encoding="utf-8").replace("resolve_ocsp_signing_key", "legacy_ocsp_key_loader"), encoding="utf-8")
        expect_failure(root, "OCSP signing does not use the FileKeyProvider boundary")


def test_missing_ocsp_provider_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        test = root / "tests/ocsp_file_key_provider_test.cpp"
        test.write_text(test.read_text(encoding="utf-8").replace("provider.algorithm_mismatch", "missing"), encoding="utf-8")
        expect_failure(root, "OCSP FileKeyProvider tests are missing required coverage")


def test_missing_ocsp_cmake_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("tests/ocsp_file_key_provider_test.cpp", ""), encoding="utf-8")
        expect_failure(root, "does not register OCSP FileKeyProvider tests")


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


def test_missing_crl_cmake_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("tests/crl_file_key_provider_test.cpp", ""), encoding="utf-8")
        expect_failure(root, "does not register CRL FileKeyProvider tests")


def test_missing_resolver_source_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        (root / "src/backends/openssl/key_providers/provider_resolver.cpp").unlink()
        expect_failure(root, "missing KeyProvider boundary file")


def test_provider_specific_resolver_coupling_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        resolver = root / "src/backends/openssl/key_providers/provider_resolver.cpp"
        resolver.write_text(resolver.read_text(encoding="utf-8") + "FileKeyProvider fallback;\n", encoding="utf-8")
        resolver.write_text(resolver.read_text(encoding="utf-8") + "FileKeyProvider fallback;\n", encoding="utf-8")
        expect_failure(root, "fallback/provider-specific coupling")


def test_missing_software_token_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        test = root / "tests/software_token_key_provider_test.cpp"
        test.write_text(test.read_text(encoding="utf-8").replace("fallback_claim", "missing"), encoding="utf-8")
        expect_failure(root, "software-token provider contract tests are missing required coverage")


def test_missing_software_token_cmake_test_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("tests/software_token_key_provider_test.cpp", ""), encoding="utf-8")
        expect_failure(root, "does not register software-token provider contract tests")


def test_missing_resolver_cmake_source_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        cmake = root / "CMakeLists.txt"
        cmake.write_text(cmake.read_text(encoding="utf-8").replace("src/backends/openssl/key_providers/provider_resolver.cpp", ""), encoding="utf-8")
        expect_failure(root, "does not compile the single-provider resolver")


def test_evidence_written_before_signing_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        issue = root / "src/backends/openssl/issue.cpp"
        content = issue.read_text(encoding="utf-8")
        content = content.replace(
            "X509_sign(cert, key.native_handle(), digest);\nwrite_signing_evidence_if_requested(key);",
            "write_signing_evidence_if_requested(key);\nX509_sign(cert, key.native_handle(), digest);",
        )
        issue.write_text(content, encoding="utf-8")
        expect_failure(root, "writes provider evidence before cryptographic signing succeeds")


def test_missing_runner_sidecar_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        runner = root / "service/internal/corecli/runner.go"
        runner.write_text(
            runner.read_text(encoding="utf-8").replace("ANOPKI_CORE_SIGNING_EVIDENCE_FILE", "missing"),
            encoding="utf-8",
        )
        expect_failure(root, "does not require actual signing sidecar evidence")


def test_lifecycle_readiness_only_claim_fails() -> None:
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        clean_fixture(root)
        lifecycle = root / "service/internal/lifecycle/service.go"
        lifecycle.write_text(
            lifecycle.read_text(encoding="utf-8").replace(
                "coreSigningAuditFields(result.SigningEvidence", "legacyKeyProviderAuditFields(keyRef"
            ),
            encoding="utf-8",
        )
        expect_failure(root, "does not correlate actual core signing evidence")


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
    test_crl_direct_bio_open_fails()
    test_crl_direct_pem_read_fails()
    test_missing_crl_resolution_fails()
    test_missing_crl_provider_test_fails()
    test_ocsp_direct_bio_open_fails()
    test_ocsp_direct_pem_read_fails()
    test_missing_ocsp_resolution_fails()
    test_missing_ocsp_provider_test_fails()
    test_missing_ocsp_cmake_test_fails()
    test_interactive_password_callback_fails()
    test_missing_encrypted_pem_rejection_test_fails()
    test_missing_resolution_fails()
    test_missing_cmake_source_fails()
    test_missing_crl_cmake_test_fails()
    test_missing_resolver_source_fails()
    test_provider_specific_resolver_coupling_fails()
    test_missing_software_token_test_fails()
    test_missing_software_token_cmake_test_fails()
    test_missing_resolver_cmake_source_fails()
    test_evidence_written_before_signing_fails()
    test_missing_runner_sidecar_fails()
    test_lifecycle_readiness_only_claim_fails()
    test_openssl_type_escape_fails()
    print("key provider boundary validator tests ok")


if __name__ == "__main__":
    main()
