# Changelog

All notable changes to this project will be recorded here.

This project is pre-1.0. Release candidates must record exact verification
commands and known gaps before tagging.

## Unreleased (`v0.1.0-alpha.0` candidate)

### Added

- A tamper-evident `sha256-v1` Audit chain with monotonic sequence, legacy migration backfill, Memory/SQLite/PostgreSQL verification, fail-closed append and retention, prune checkpoints, integrity API, and recovery-state evidence.
- An exact-commit Audit integrity evidence runner and release artifact covering canonical hashing, legacy backfill, Memory/SQLite/PostgreSQL parity, row/checkpoint tampering, full-prune protection, integrity API reporting, retention checkpoints and strict redaction.
- Multi-node single-writer reliability evidence for certificate issuance, CRL generation and Outbox dispatch, including CRL claim compare-and-swap semantics, contiguous numbering, active lease protection, exact-commit CI/release artifacts and strict redaction.
- A PostgreSQL 16 backup/restore and migration-rollback evidence runner using isolated databases, real Go migrations, custom-format `pg_dump`/`pg_restore`, source-damage detection, exact state digests, CI/release artifact binding, and strict secret/DSN exclusion.
- An atomic certificate-profile intermediate issuer rollover and rollback contract with same-root validation, stale-transition rejection, overlap preservation, audit/outbox evidence, and an exact-commit verification runner.
- A fail-closed audit-repair and dead-letter replay drill that proves current signing/policy evidence reconstruction, idempotent repair, scoped replay, preserved attempt history, recovered delivery completion, redaction and exact-commit release binding.
- A fail-closed CRL/OCSP outage-and-recovery drill covering lifecycle atomicity, public 502 mapping, no phantom CRL publication, no success audit during failure, recovery numbering, completed signing evidence, CI artifact upload, and strict release archive validation.
- Stable allow/reject/unknown policy-decision audit metadata with redacted validation-evidence references for enrollment creation, replacement enrollment, certificate issuance, failure auditing, retry, and legacy audit repair.
- A deterministic fail-closed SQLite backup/restore drill with strict redacted evidence, CI artifact upload, release archive validation, and regression tests for dirty migrations, lost CRL state and private-key material.
- ECDSA P-256 signing regression coverage for certificate issuance, CRL generation, and OCSP responses, plus non-interactive encrypted-PEM rejection at all three Community FileKeyProvider operation boundaries.
- A fail-closed Community Go release verification runner that requires Go 1.25.11 or newer, pins race/static-analysis/security tool versions, emits redacted JSON/Markdown/log evidence, and is consumed by local verification, CI, and release artifacts.
- Strict Go parsing of `anopki-core backend info`, additive `/version` backend
  and KeyProvider policy metadata, and release artifacts that bind the exact
  Community/OpenSSL profile to backend capabilities without exposing key refs.
- ADR 0007 deliberately scoped hybrid signing boundary and Community/OpenSSL certificate-issuance, CRL-signing, and OCSP-response-signing `FileKeyProvider` vertical slices.
- Adapter-private file-provider tests and a source-boundary validator covering certificate/CRL/OCSP direct key loading, production rejection, algorithm/binding failures, and no fallback.
- A generic single-provider resolver plus a test-only software-token provider contract covering one-time acquisition, non-exportable policy shape, provider failure propagation, evidence mismatch rejection, and `fallback_used=false`.
- Private redacted C++ signing-result sidecar correlation for certificate, CRL,
  and OCSP operations, including durable certificate issuance-attempt evidence
  and explicit legacy-unproven audit semantics.
- Backend identity, capability, readiness, stable error, and explicit product-profile metadata with `anopki-core backend info`.
- CI workflow for docs validation, service contract parity, secret baseline
  scan, Go service tests/build, PostgreSQL migration integration, and C++
  CMake/CTest.
- MPL-2.0 license file and docs-as-code validation.
- Release readiness, security, contribution, architecture, policy, operation,
  runbook, compliance, and ACME conformance documentation.
- Lifecycle service foundations for identity, issuer, certificate profile,
  enrollment, issuance, revocation, suspension, renewal, reissue, audit,
  outbox, webhook delivery, CRL, OCSP, and ACME adapter flows.
- Issued-certificate DER golden coverage for SAN, KU, EKU, Basic Constraints,
  AIA, CRL Distribution Points, SKI, and AKI.
- Profile algorithm policy for CSR public key algorithm, minimum key size, and
  selected signing algorithm.
- Release evidence manifest for artifact, SBOM, signing, scan, and
  compatibility decisions, validated in CI.
- Tagged release workflow for Linux amd64 service/core archives, checksums,
  CycloneDX SBOM, and cosign signatures.
- Documentation index and documentation governance rules that separate maintained
  public repository docs from internal or GPT project source material.
- Crypto backend strategy and ADR 0006 recording AnoCrypto as the intended
  backend direction while OpenSSL-backed core operations remain the current
  implementation.
- Release evidence fields for recording the active crypto backend and the
  intended AnoCrypto migration direction per release candidate.
- Docs validator guard for previous-name identifiers outside migration,
  compatibility, or historical documentation contexts.
- Backend-neutral crypto parity fixtures and OpenSSL parity reporting for CSR,
  issuance, CRL, and OCSP operations.
- Draft local release evidence for the `v0.1.0-alpha.0` candidate.
- Physically separated backend-neutral core dispatch from the Community OpenSSL adapter while preserving all existing CLI and golden contracts.

### Changed

- The optional generic request authorizer now has a bounded two-second default deadline with fail-closed timeout semantics, and `GET /debug/vars` requires operator scope in API-key mode.
- Release-evidence validation now pins the canonical audit-replay minimum-Go tuple spelling and includes a regression test for formatting drift.
- The full C++ repository now builds cleanly with `-Wall -Wextra -Wpedantic -Werror`; the OpenSSL parity harness no longer emits range-loop temporary-binding or unused-helper warnings.
- `src/backends/openssl/issue.cpp`, `src/backends/openssl/crl.cpp`, and `src/backends/openssl/ocsp.cpp` no longer open or parse signing private-key files directly; each resolves one adapter-private provider and signs through the returned handle without changing the Core CLI JSON contract.
- Go `keyref.Provider.CheckReady` remains readiness preflight and is not described as actual cryptographic signing evidence.
- Runtime FileKeyProvider operation wrappers now pass through one provider-neutral resolver that rejects provider/operation evidence drift and any fallback claim.
- Lifecycle signing audits now use completed C++ `core_signing` evidence rather
  than presenting `CheckReady` or key-reference classification as signing proof.
- Roadmap is future-only; completed work belongs in reference docs, runbooks,
  or this changelog.
- Public docs are curated around the AnoPKI name, `ANOPKI_*` environment
  variables, `anopki-service`, `anopki-core`, `X-AnoPKI-*`, and `MPL-2.0`
  license wording.
- Root README now delegates the detailed documentation map to `docs/INDEX.md`
  to reduce duplicate documentation drift.
- Version metadata accepts SemVer prerelease identifiers while CMake uses the
  numeric `0.1.0` project version and binaries report `0.1.0-alpha.0`.
- `anopki_core` no longer links OpenSSL directly; `anopki_openssl_adapter` owns OpenSSL operations and dependency diagnostics.

### Known Gaps

- Certbot live smoke remains environment-gated on Linux or elevated Windows.
- Local ZIP baseline verification does not close Go service tests/builds when
  the host Go toolchain is older than the repository requirement and cannot
  download the requested toolchain.
- Git working-tree status, GitHub Actions CI URLs, tagged release artifacts,
  SBOM output, cosign signatures, and Go lint/security scanner evidence must be
  recorded from the real repository before tagging a release candidate.
- Full compatibility evidence, production non-exportable HSM/KMS provider, external Audit anchor/SIEM integration, EAB, and DNS-01 remain future work.
