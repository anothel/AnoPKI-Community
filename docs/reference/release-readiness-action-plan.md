# Release Readiness Action Plan

This file turns the 2026-06-28 repository analysis into a project
execution plan. It keeps [ROADMAP](../ROADMAP.md) future-only and prevents
analysis findings from becoming scattered TODO lists.

## Current Thesis

`AnoPKI` should not expand feature surface first. The next major work is to
make the existing lifecycle service trustworthy as a pre-1.0 security utility:
verified builds, route/API/doc parity, negative tests, compatibility evidence,
and release-repeatable operations.

## Evidence Already Present

| Area | Current evidence |
| --- | --- |
| Baseline docs | README, SECURITY, CONTRIBUTING, roadmap, OpenAPI, API surface status, runbooks, threat model, architecture, policy, ADR, and alignment docs. |
| Docs-as-code | `scripts/validate-docs.py` checks required docs, README links, OpenAPI JSON, license state, README local-verification command coverage, and CI docs self-check wiring. |
| Service contract parity | `scripts/validate-service-contracts.py` checks route/OpenAPI parity, operation ID parity, path/list query parameter and common schema parity, service README endpoint/curl example parity, config/env docs parity, public error message/status docs parity, and ACME problem type docs parity; `scripts/validate-core-cli-contracts.py` checks Go-to-core CLI JSON field parity against the contract reference, including structured OpenSSL diagnostic details, malformed JSON handling, and context deadline handling on core CLI failures; env-gated core boundary integration tests run the Go runner against the real C++ CLI. |
| Secret baseline | `scripts/security-baseline-scan.py` checks high-confidence committed secret patterns. |
| Release trust | README quickstart smoke checklist, `CHANGELOG.md`, CI run/badge strategy in the release process, release evidence manifest validation, and tagged release artifact workflow with GitHub Release publishing. |
| Core robustness | CI and optional local libFuzzer targets cover CSR PEM inspection, OCSP request DER inspection, and CRL DER inspection with AddressSanitizer smoke runs. |
| Maintainability | HTTP API ACME protocol code and SQL store certificate, audit, outbox/webhook, and ACME aggregates are split into focused files after contract and regression coverage existed. |
| Issuance failure-mode coverage | Lifecycle tests cover duplicate issuer serial rejection without issuing the second enrollment; memory, SQLite, and PostgreSQL parity tests cover duplicate certificate finalization keys, stale issuance-attempt updates, CRL/OCSP signer failures, transaction rollback, outbox, audit, migration, and ACME nonce behavior. |
| Certificate correctness | Core issue profile tests parse issued DER and assert SAN, KU, EKU, Basic Constraints, AIA, CRL Distribution Points, SKI, and AKI; core CSR fixtures include real weak-key metadata coverage; profile policy enforces CSR key algorithm/size, selected signing algorithm, invalid KU/EKU combinations, forbidden CSR-requested extensions, SAN presence, wildcard policy, IP SAN policy, oversized SAN rejection, and a fail-closed public TLS pre-signing lint hook; core issuance rejects expired or not-yet-valid issuer certificates and DNS SANs outside issuer DNS name constraints before signing. |
| CI shape | Workflow includes docs validation, version metadata, release artifact, release evidence, secret baseline, Go tests/race/vet/staticcheck/gosec/govulncheck/build, PostgreSQL integration, C++ CMake, and CTest. |
| Lifecycle scope | Identity, issuer, profile, enrollment, approval, issuance, renewal, reissue, revocation, suspension, CRL, OCSP, audit, outbox, webhook, and ACME foundations exist. Non-ACME enrollment and issuance policy rejections record stable audit reason codes. |
| Public TLS guardrails | Validity ceilings, validation evidence age, CAA DNSSEC/RFC 8657 policy, ACME validation audit metadata, and mass-revocation planning docs exist. |
| ACME baseline | Deterministic ACME smoke harness tests plus lego and WSL certbot HTTP-01 smoke evidence exist. |
| HTTP-01 guardrails | Tests cover unsafe private, loopback, redirect, resolver, and IPv6 targets before validator boundary changes. |

## Execution Order

### Batch 1: Release And Supply Chain

Make release artifacts auditable:

- Compatibility matrix evidence for client, OS, Go, OpenSSL,
  SQLite/PostgreSQL, and smoke result.

Exit criteria:

- A release candidate includes provenance, dependency, compatibility, and
  security-scan evidence.

### Batch 2: Operations And Key Boundary

Raise production-operating confidence:

- HSM/KMS/PKCS#11 semantics and file-provider split.
- Non-exportable-key API and audit behavior.
- Key ceremony and intermediate rollover drill evidence.
- Independent Audit-chain anchoring/export after an operator integration is selected.
- First-class role/ABAC enforcement after an operator directory exists.
- Synthetic CRL/OCSP/ACME/deployment health checks after a deploy target exists.

Exit criteria:

- Production signing keys, audit records, operator roles, and recovery drills
  have explicit evidence paths.

## Deferred Unless Triggered

| Item | Trigger |
| --- | --- |
| EAB | Real subscriber/account integration requires it. |
| DNS-01 | Operator-owned DNS provider is selected. |
| Broad discovery scanners | One concrete import source proves inventory and ownership fields. |
| UI | Operator APIs, filters, pagination, and workflows stabilize. |
| Kubernetes/deploy adapters | First deployment target is chosen. |
| PQC/hybrid production | Dependencies and relying-party support are real; lab-only until then. |
| Large file split | Tests cover behavior and repeated changes prove a stable boundary. |

## Mapping From 2026-06-28 Analysis

| Analysis recommendation | Project action |
| --- | --- |
| Build a trustworthy release candidate first. | README quickstart smoke checklist, CHANGELOG, CI workflow shape, and release-process evidence strategy exist. |
| Automate API/docs/code parity. | Route/OpenAPI, operation ID, path/query parameter/schema, service README endpoint/curl example, config/doc, error-envelope, ACME problem type, and Go-to-core CLI JSON contract parity checks. |
| Add Go/C++ boundary contract tests. | Fake-command Go runner tests, C++ CLI contract tests, JSON contract drift validation, and env-gated real CLI integration tests exist. |
| Strengthen ACME compatibility. | Certbot and lego smoke plus fixture conversion and compatibility matrix. |
| Strengthen CSR/certificate correctness. | DER golden tests, profile algorithm policy, invalid KU/EKU checks, real weak-key CSR metadata coverage, CSR linting for forbidden extensions and SAN policy cases, public TLS pre-signing lint hook, and issuer validity/name-constraint negative fixtures exist. |
| Strengthen issuance consistency tests. | Signer/DB failure, lease race, serial collision, and PostgreSQL parity coverage exist. |
| Add parser fuzzing. | CI and optional local libFuzzer targets exist for CSR, OCSP, and CRL parser boundaries. |
| Strengthen webhook/outbox safety tests. | Receiver replay/signature, timeout, unsafe redirect/egress, retry, and dead-letter coverage exist. |
| Add audit tamper-evidence. | `sha256-v1` sequence/hash chaining, v2 legacy backfill, checkpoints, fail-closed append/prune, integrity API, and recovery snapshots are implemented. |
| Add HSM/KMS/PKCS#11 boundary. | P2 Key Boundary. |
| Add SBOM/release signing/SAST/SCA. | Release evidence selects syft, cosign, go vet, staticcheck, gosec, Go race detector, and govulncheck; tagged release workflow builds archives, checksums, SBOM, and cosign signatures. |
| Do not refactor large files prematurely. | HTTP API and SQL store splits now follow tested ACME, certificate, audit, outbox/webhook, and ACME persistence boundaries. |
