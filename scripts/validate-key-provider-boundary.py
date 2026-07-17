#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROVIDER_HEADER = Path("src/backends/openssl/key_providers/file_key_provider.hpp")
PROVIDER_SOURCE = Path("src/backends/openssl/key_providers/file_key_provider.cpp")
PROVIDER_RESOLVER_HEADER = Path("src/backends/openssl/key_providers/provider_resolver.hpp")
PROVIDER_RESOLVER_SOURCE = Path("src/backends/openssl/key_providers/provider_resolver.cpp")
ISSUE_SOURCE = Path("src/backends/openssl/issue.cpp")
CRL_SOURCE = Path("src/backends/openssl/crl.cpp")
OCSP_SOURCE = Path("src/backends/openssl/ocsp.cpp")
PROVIDER_TEST = Path("tests/file_key_provider_test.cpp")
CRL_PROVIDER_TEST = Path("tests/crl_file_key_provider_test.cpp")
OCSP_PROVIDER_TEST = Path("tests/ocsp_file_key_provider_test.cpp")
SOFTWARE_TOKEN_PROVIDER_TEST = Path("tests/software_token_key_provider_test.cpp")
CORE_RUNNER_SOURCE = Path("service/internal/corecli/runner.go")
LIFECYCLE_SOURCE = Path("service/internal/lifecycle/service.go")
DOMAIN_TYPES_SOURCE = Path("service/internal/domain/types.go")
STORE_MIGRATION_SOURCE = Path("service/internal/store/migrate.go")
STORE_CERTIFICATE_SOURCE = Path("service/internal/store/sqlstore_certificate.go")

FORBIDDEN_SIGNING_PATH_TOKENS = (
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
    "throw_provider_sign_failed",    "write_signing_evidence_if_requested",
)

REQUIRED_CRL_TOKENS = (
    '#include "key_providers/file_key_provider.hpp"',
    "resolve_crl_signing_key",
    "provider_policy_from_environment",
    ".native_handle()",
    "throw_provider_sign_failed",    "write_signing_evidence_if_requested",
)

REQUIRED_OCSP_TOKENS = (
    '#include "key_providers/file_key_provider.hpp"',
    "resolve_ocsp_signing_key",
    "provider_policy_from_environment",
    ".native_handle()",
    "throw_provider_sign_failed",    "write_signing_evidence_if_requested",
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
    "provider.evidence_failed",
    "ANOPKI_CORE_SIGNING_EVIDENCE_FILE",
    r'evidence_source\":\"core_signing',
    r'result_code\":\"ok',
    "fallback_used = false",
    "X509_check_private_key",
    "reject_private_key_password",
    "PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_private_key_password, nullptr)",
    "crl_generate_sign",
    "ocsp_response_sign",
)

REQUIRED_PROVIDER_TEST_TOKENS = (
    "write_encrypted_private_key",
    "EVP_aes_256_cbc",
    "encrypted.pem",
    "test-only-password",
    "ecdsa_with_sha256",
    'key_algorithm == "ecdsa"',
    "NID_ecdsa_with_SHA256",
    "resolve_crl_signing_key",
    "crl_generate_sign",
    "resolve_ocsp_signing_key",
    "ocsp_response_sign",
    "test_signing_evidence_sidecar",
    "ANOPKI_CORE_SIGNING_EVIDENCE_FILE",
    "core_signing",
    "provider.evidence_failed",
)

REQUIRED_CRL_PROVIDER_TEST_TOKENS = (
    "file:",
    "kms:",
    "provider.key_not_found",
    "provider.key_parse_failed",
    "provider.key_binding_mismatch",
    "provider.exportability_violation",
    "write_encrypted_private_key",
    "encrypted.pem",
    "generate_ec_key",
    "NID_ecdsa_with_SHA256",
    "ECDSA CRL TBS DER",
    "X509_CRL_verify",
    "deterministic CRL DER",
)

REQUIRED_OCSP_PROVIDER_TEST_TOKENS = (
    "file:",
    "kms:",
    "provider.invalid_reference",
    "provider.key_not_found",
    "provider.key_parse_failed",
    "provider.algorithm_mismatch",
    "provider.key_binding_mismatch",
    "provider.exportability_violation",
    "write_encrypted_private_key",
    "encrypted.pem",
    "generate_ec_key",
    "NID_ecdsa_with_SHA256",
    "test_ecdsa_success",
    "OCSP_basic_verify",
    "provider-signed OCSP response verification failed",
)
REQUIRED_RESOLVER_TOKENS = (
    "resolve_signing_key_with_provider",
    "const SigningKeyProvider &provider",
    "provider.metadata()",
    "provider.accepts(request.key_ref)",
    "ProviderReadiness::ready",
    "metadata.exportable",
    "provider.acquire(request)",
    "evidence.requested_signature_algorithm",
    "evidence.key_algorithm.empty()",
    "evidence.issuer_binding_verified",
    "evidence.fallback_used",
    "ProviderErrorCode::profile_mismatch",
    '"evidence"',
)

FORBIDDEN_RESOLVER_TOKENS = (
    "FileKeyProvider",
    "std::vector<SigningKeyProvider",
    "std::vector<const SigningKeyProvider",
)

REQUIRED_SOFTWARE_TOKEN_TEST_TOKENS = (
    "class SoftwareTokenKeyProvider",
    "ProviderClass::software_token",
    '"softtoken:issuer"',
    "policy.production_mode = true",
    "provider.acquire_count() == 1",
    "ProviderErrorCode::profile_mismatch",
    "mismatched_algorithm",
    "unverified_binding",
    "empty_key_algorithm",
    "fallback_claim",
    "resolve_signing_key_with_provider",
    "X509_verify",
)



REQUIRED_RUNNER_TOKENS = (
    "ANOPKI_CORE_SIGNING_EVIDENCE_FILE",
    "createSigningEvidenceFile",
    "withSigningEvidenceEnvironment",
    "DisallowUnknownFields",
    "ValidateSigningEvidence",
    'EvidenceSource != "core_signing"',
    "IssuerBindingVerified",
    "FallbackUsed",
    'ResultCode != "ok"',
    'SigningEvidence SigningEvidence `json:"-"`',
)

REQUIRED_LIFECYCLE_TOKENS = (
    'ValidateSigningEvidence(result.SigningEvidence, "certificate_issue"',
    'ValidateSigningEvidence(result.SigningEvidence, "crl_generate_sign", "sha256")',
    'ValidateSigningEvidence(result.SigningEvidence, "ocsp_response_sign", "sha256")',
    "SigningEvidenceJSON",
    "coreSigningAuditFields(result.SigningEvidence",
    'fields["key_provider_evidence_source"] = evidence.EvidenceSource',
    'fields["key_provider_signing_proven"] = true',
    'fields["key_provider_evidence_source"] = "legacy_key_ref_classification"',
    'fields["key_provider_signing_proven"] = false',
)

REQUIRED_STORE_TOKENS = (
    "signing_evidence_json",
    "SigningEvidenceJSON",
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
    resolver_header = read_required(root, PROVIDER_RESOLVER_HEADER)
    resolver = read_required(root, PROVIDER_RESOLVER_SOURCE)
    issue = read_required(root, ISSUE_SOURCE)
    crl = read_required(root, CRL_SOURCE)
    ocsp = read_required(root, OCSP_SOURCE)
    provider_test = read_required(root, PROVIDER_TEST)
    crl_provider_test = read_required(root, CRL_PROVIDER_TEST)
    ocsp_provider_test = read_required(root, OCSP_PROVIDER_TEST)
    software_token_provider_test = read_required(root, SOFTWARE_TOKEN_PROVIDER_TEST)
    core_runner = read_required(root, CORE_RUNNER_SOURCE)
    lifecycle = read_required(root, LIFECYCLE_SOURCE)
    domain_types = read_required(root, DOMAIN_TYPES_SOURCE)
    store_migration = read_required(root, STORE_MIGRATION_SOURCE)
    store_certificate = read_required(root, STORE_CERTIFICATE_SOURCE)
    cmake = read_required(root, Path("CMakeLists.txt"))

    for operation, content in (
        ("certificate issuance", issue),
        ("CRL signing", crl),
        ("OCSP signing", ocsp),
    ):
        forbidden_hits = [
            token for token in FORBIDDEN_SIGNING_PATH_TOKENS if token in content
        ]
        if forbidden_hits:
            fail(
                f"{operation} directly loads a private key:\n"
                + "\n".join(forbidden_hits)
            )

    for operation, content, sign_token in (
        ("certificate issuance", issue, "X509_sign("),
        ("CRL signing", crl, "X509_CRL_sign("),
        ("OCSP signing", ocsp, "OCSP_basic_sign("),
    ):
        if content.find("write_signing_evidence_if_requested") < content.find(sign_token):
            fail(f"{operation} writes provider evidence before cryptographic signing succeeds")

    missing_issue = [token for token in REQUIRED_ISSUE_TOKENS if token not in issue]
    if missing_issue:
        fail(
            "certificate issuance does not use the FileKeyProvider boundary:\n"
            + "\n".join(missing_issue)
        )

    missing_crl = [token for token in REQUIRED_CRL_TOKENS if token not in crl]
    if missing_crl:
        fail(
            "CRL signing does not use the FileKeyProvider boundary:\n"
            + "\n".join(missing_crl)
        )

    missing_ocsp = [token for token in REQUIRED_OCSP_TOKENS if token not in ocsp]
    if missing_ocsp:
        fail(
            "OCSP signing does not use the FileKeyProvider boundary:\n"
            + "\n".join(missing_ocsp)
        )

    missing_provider = [token for token in REQUIRED_PROVIDER_TOKENS if token not in provider]
    if missing_provider:
        fail(
            "FileKeyProvider implementation is missing required semantics:\n"
            + "\n".join(missing_provider)
        )

    missing_resolver = [token for token in REQUIRED_RESOLVER_TOKENS if token not in resolver]
    if missing_resolver:
        fail(
            "single-provider resolver is missing required fail-closed semantics:\n"
            + "\n".join(missing_resolver)
        )

    forbidden_resolver = [token for token in FORBIDDEN_RESOLVER_TOKENS if token in resolver]
    if forbidden_resolver:
        fail(
            "single-provider resolver contains fallback/provider-specific coupling:\n"
            + "\n".join(forbidden_resolver)
        )

    if "resolve_signing_key_with_provider" not in resolver_header:
        fail("adapter-private single-provider resolver contract missing")
    if "resolve_signing_key_with_provider" not in provider:
        fail("FileKeyProvider operation wrappers bypass the single-provider resolver")

    missing_provider_tests = [
        token for token in REQUIRED_PROVIDER_TEST_TOKENS if token not in provider_test
    ]
    if missing_provider_tests:
        fail(
            "FileKeyProvider tests do not cover non-interactive encrypted PEM rejection:\n"
            + "\n".join(missing_provider_tests)
        )

    missing_crl_provider_tests = [
        token for token in REQUIRED_CRL_PROVIDER_TEST_TOKENS if token not in crl_provider_test
    ]
    if missing_crl_provider_tests:
        fail(
            "CRL FileKeyProvider tests are missing required coverage:\n"
            + "\n".join(missing_crl_provider_tests)
        )

    missing_software_token_tests = [
        token for token in REQUIRED_SOFTWARE_TOKEN_TEST_TOKENS if token not in software_token_provider_test
    ]
    if missing_software_token_tests:
        fail(
            "software-token provider contract tests are missing required coverage:\n"
            + "\n".join(missing_software_token_tests)
        )

    missing_ocsp_provider_tests = [
        token for token in REQUIRED_OCSP_PROVIDER_TEST_TOKENS if token not in ocsp_provider_test
    ]
    if missing_ocsp_provider_tests:
        fail(
            "OCSP FileKeyProvider tests are missing required coverage:\n"
            + "\n".join(missing_ocsp_provider_tests)
        )

    missing_runner = [token for token in REQUIRED_RUNNER_TOKENS if token not in core_runner]
    if missing_runner:
        fail(
            "Go core runner does not require actual signing sidecar evidence:\n"
            + "\n".join(missing_runner)
        )

    missing_lifecycle = [token for token in REQUIRED_LIFECYCLE_TOKENS if token not in lifecycle]
    if missing_lifecycle:
        fail(
            "lifecycle audit does not correlate actual core signing evidence:\n"
            + "\n".join(missing_lifecycle)
        )

    for relative, content, required_tokens in (
        (DOMAIN_TYPES_SOURCE, domain_types, ("SigningEvidenceJSON",)),
        (STORE_MIGRATION_SOURCE, store_migration, ("signing_evidence_json",)),
        (STORE_CERTIFICATE_SOURCE, store_certificate, REQUIRED_STORE_TOKENS),
    ):
        missing_store = [token for token in required_tokens if token not in content]
        if missing_store:
            fail(
                f"signing evidence persistence is incomplete in {relative.as_posix()}:\n"
                + "\n".join(missing_store)
            )

    for marker in (
        "class SigningKeyProvider",
        "class FileKeyProvider",
        "class SigningKeyHandle",
        "ProviderMetadata",
        "RedactedProviderDiagnostics",
        "software_token",
    ):
        if marker not in header:
            fail(f"adapter-private provider interface missing: {marker}")

    if "src/backends/openssl/key_providers/file_key_provider.cpp" not in cmake:
        fail("OpenSSL adapter target does not compile FileKeyProvider")
    if "src/backends/openssl/key_providers/provider_resolver.cpp" not in cmake:
        fail("OpenSSL adapter target does not compile the single-provider resolver")
    if "tests/file_key_provider_test.cpp" not in cmake:
        fail("CMake does not register FileKeyProvider tests")
    if "tests/crl_file_key_provider_test.cpp" not in cmake:
        fail("CMake does not register CRL FileKeyProvider tests")
    if "tests/ocsp_file_key_provider_test.cpp" not in cmake:
        fail("CMake does not register OCSP FileKeyProvider tests")
    if "tests/software_token_key_provider_test.cpp" not in cmake:
        fail("CMake does not register software-token provider contract tests")

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
