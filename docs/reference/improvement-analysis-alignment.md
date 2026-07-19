# Improvement Analysis Alignment

This file maps prior improvement analyses to current repo evidence and
future-only gaps. It prevents external reports from becoming parallel roadmaps.

Inputs currently folded in:

- 2026-06-27 PKI improvement analysis.
- 2026-06-28 repository code/documentation analysis.

Execution order is tracked in
[Release readiness action plan](release-readiness-action-plan.md). Future work
is tracked in [ROADMAP](../ROADMAP.md).

## P0 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Code and doc baseline | README, SECURITY, CONTRIBUTING, CI, OpenAPI, runbooks, compliance matrix, this alignment file, docs validator. | Keep docs validation in CI and update this file when major architecture changes land. |
| Certificate inventory | Identity ownership metadata, certificate inventory API, expiry SLO, list filters, SQL indexes. | First real discovery/import source still deferred until operators choose it. |
| Shorter certificate lifetime | Expiration scan, expiry SLO, public TLS 200/100/47-day ceilings, ACME HTTP-01 flow. | Deployment adapters and full automated deployment/reload checks remain future work. |
| Certificate profiles | Profile-as-code fields for validity, Basic Constraints, KU, EKU, SAN, SKI, AKI, key algorithm, key size, and signing algorithm; issued DER golden tests assert SAN, KU, EKU, Basic Constraints, AIA, CRL Distribution Points, SKI, and AKI. | Keep profile policy current when new algorithms are enabled. |
| Key protection | `key_ref` model, production docs require external key provider, DB excludes private key material, HSM/KMS/PKCS#11 semantics selected. | Provider implementation, ceremony evidence, and non-exportable-key audit behavior remain future work. |
| Audit log | Structured metadata, request context, API key fingerprint, query/retention/repair, `sha256-v1` chain, v2 legacy backfill, integrity API, prune checkpoints, recovery evidence, and SIEM examples. | Independently anchored chain export and SIEM exporter integration remain future work. |
| Documentation | Architecture, policy, operations, security, ADR, runbook, compliance docs now have baseline files. | Keep detailed procedures current with implementation changes. |

## 2026-06-28 P0/P1 Findings

| Analysis finding | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Build and test trust must come before feature expansion. | README quickstart smoke checklist, CI workflow shape, release process CI evidence/badge strategy, docs validation, secret baseline scan, and CHANGELOG. | Record latest CI evidence for each release candidate. |
| OpenAPI and actual routes need automated parity. | `scripts/validate-service-contracts.py` compares service routes, operation IDs, path/query parameters, and service README endpoint/curl examples to OpenAPI and runs in CI. | Keep intentional OpenAPI exclusions limited to operational and public ACME protocol endpoints. |
| Config/env docs need automated parity. | `scripts/validate-service-contracts.py` compares env vars used by the service to the `service/README.md` config table. | Keep new config env vars documented in the table before merging. |
| API error schema should be fixed. | `scripts/validate-service-contracts.py` compares mapped public domain errors and ACME problem types to `docs/reference/api-errors.md`; handler tests cover JSON envelopes and ACME problem details. | Add focused handler tests when new error envelopes or ACME problem types are introduced. |
| README quickstart must be verified. | README quickstart smoke checklist lists deterministic commands and expected outputs. | Keep the checklist current when validation commands change. |
| Issuance consistency needs failure injection. | `docs/reference/issuance-consistency.md` documents signer claim, retry, and repair behavior; tests cover signer success plus DB finalization failure, retry without second signing, lease races, duplicate issuer serial rejection, duplicate certificate finalization keys, stale issuance-attempt updates, CRL/OCSP signer failures, core CLI context deadlines and malformed JSON output, and PostgreSQL parity for lifecycle/outbox/audit/migration behavior. | Keep PostgreSQL parity current when repository contracts change. |
| Webhook/outbox safety needs negative tests. | HMAC signing, timestamp, receiver invalid-HMAC/replay validation, timeout failure recording, unsafe redirect/egress rejection, retry, and dead-letter behavior are implemented and documented. | Keep coverage current when webhook delivery semantics change. |
| ACME nonce/replay/key binding tests should expand. | ACME malformed JWS, nonce reuse, badNonce retry, KID base URL, key mismatch, account key, key rollover, SQL nonce PostgreSQL parity, rate limit, HTTP-01 unsafe target guards, certbot-derived protocol fixtures, and lego/certbot smoke coverage exist. | Keep compatibility fixtures current when live clients expose new differences. |
| CSR/certificate correctness needs stronger tests. | Profile policy, profile algorithm policy, CSR linting, public TLS policy and pre-signing lint hook, negative policy fixtures, and issued DER golden tests exist. | Add external public TLS lint fixtures when a tool is selected. |
| Release readiness needs supply-chain evidence. | CI, MPL-2.0 license, CHANGELOG, docs validation, service contract parity, release evidence validation, version metadata validation, artifact smoke validation, tagged release archives, checksums, SBOM, cosign signing, Go race detector, staticcheck, gosec, govulncheck, C++ parser fuzz/sanitizer smoke, and high-confidence secret scan exist. | Keep compatibility matrix evidence current. |
| Large files should not be split prematurely. | Roadmap defer/delete rules reject speculative refactors; HTTP API and SQL store splits now follow tested ACME, certificate, audit, outbox/webhook, and ACME persistence boundaries. | Continue splitting only when future repeated changes prove another stable boundary. |

## P1 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Issuance validation | Identity SAN allow-lists, public TLS CAA/DNSSEC/RFC 8657 checks, HTTP-01 ACME validation. | DNS-01 and EAB wait for real integrations; tls-alpn-01 is not selected. |
| Access control | API key auth, scopes, bootstrap runbook, access model, break-glass rules, and audit metadata. | First-class role/ABAC enforcement waits for an operator directory. |
| Revocation/status service | Revocation API, CRL publication, OCSP endpoint, public TLS mass-revocation checklist. | HA deployment validation and scheduled tabletop evidence remain future work. |
| Observability | Structured logs, expvar metrics, operation metrics, readiness checks, observability reference. | Exporter/backend integration, synthetic checks, CT monitoring remain future work. |
| DevSecOps | CI builds/tests Go, C++, PostgreSQL migration integration, docs validation, high-confidence secret baseline scan, govulncheck, SBOM, and release signing workflow. | Full SAST/SCA plus container/IaC scans remain future work after tool choices. |

## P2/P3 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Crypto agility and PQC | Project scope and roadmap keep production PQC deferred; profile policy exists. | Crypto inventory, algorithm migration plan, PQC readiness, and vendor tracking remain future work. |
| Repository structure | Current repo uses `docs/reference` and `docs/runbooks` plus new architecture/policy/operations/security/ADR baselines. | Do not reshuffle files only to match the analysis tree; links and validation carry the contract. |
