# AnoPKI roadmap

Only future work belongs here. Completed items must be removed after the
verification evidence is recorded in the relevant reference or runbook.

This roadmap folds in prior PKI improvement analyses, including the
2026-06-28 and 2026-06-30 repository analyses. Those reports are inputs, not
parallel backlogs. Current execution guidance lives in
[Release readiness action plan](reference/release-readiness-action-plan.md).

## Operating Rules

- Prefer reliability, parity checks, and negative tests before feature surface.
- Keep work grouped by risk area; do not stop at tiny slices when one coherent
  risk area can be closed.
- Do not split large files only because they are large. Add contract and
  failure-mode coverage first, then split along repeated change boundaries.
- Keep discovery, deploy adapters, EAB, DNS-01, UI, and PQC gated on real
  operator demand.
- Add abstractions only when they protect a concrete boundary. The backend
  interface is justified by the OpenSSL adapter and the planned external
  AnoCrypto-C adapter.
- Reject new dependencies unless stdlib/native code is materially worse or the
  dependency is a selected release/security tool.
- Keep README, SECURITY, release evidence, and this roadmap aligned on maturity:
  pre-1.0, not production-stable, and internal-pilot oriented until release
  evidence proves otherwise.

## External Timeline Drivers

Publicly trusted TLS work must track the CA/Browser Forum Baseline
Requirements. As of BR 2.2.8, public Subscriber Certificate validity and
Domain/IP validation reuse shrink on this schedule. Source:
https://cabforum.org/working-groups/server/baseline-requirements/requirements/

| Date | Public TLS max validity | Domain/IP validation reuse |
| --- | ---: | ---: |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | 47 days | 10 days |

Private PKI is not forced to follow public Web PKI timelines, but the same
timeline is a useful pressure test: manual renewal and deployment must disappear
before 100-day and 47-day public certificate operations become normal.

## P1: ACME Client Compatibility

Goal: convert real-client differences into stable protocol fixtures.

- Keep the ACME compatibility matrix current by client, OS, account key type,
  challenge type, and result.
- Add External Account Binding only after a real subscriber/account integration
  requires it.
- Add DNS-01 only after an operator-owned DNS provider integration is selected.

## P1: Release Operations

Goal: make pre-1.0 release candidates repeatable.

- Keep compatibility matrix evidence current for OS, Go, OpenSSL, SQLite,
  PostgreSQL, lego, and certbot.
- Add generated API example validation if example drift becomes visible.

## P1: Refactor Safety Coverage

Goal: split large service files only after behavior is pinned down.

- Split `service/internal/httpapi/server.go` by resource or middleware only
  after contract tests prove route behavior.
- Split `service/internal/lifecycle/service.go` by repeated use-case change
  boundaries only after failure-mode tests prove lifecycle behavior.
- Split `service/cmd/anopki-service/main.go` only when config loading,
  validation, bootstrap, and server lifecycle change independently.

## P2: Backend Adapters And Key Boundary

Goal: make AnoPKI Core backend-neutral while preserving the complete
Community/OpenSSL baseline and keeping key providers separate.

- Expose selected product profile and backend metadata through the Go service/version and release manifests.
- Keep Community/OpenSSL golden, CLI-contract, and failure-mode tests passing after each adapter change.
- Pin a real immutable AnoCrypto-C SDK artifact in trusted Enterprise CI.
- Expand the external AnoCrypto-C adapter only as supported SDK operations become available.
- Keep Enterprise/AnoCrypto-C production release blocked until required CSR,
  issuance, CRL, and OCSP parity is complete.
- Add negative tests proving that unsupported AnoCrypto-C operations never call
  OpenSSL.
- Extend the proven provider contract to CRL signing and then OCSP signing.
- Add a mock/software-token provider before selecting a real PKCS#11/HSM implementation.
- Define actual C++ provider-result audit correlation without treating Go `CheckReady` as cryptographic proof.
- Prototype and separately approve remote KMS retry/idempotency and signing semantics before adding a vendor SDK.
- Add executable key ceremony evidence and intermediate rollover drills.
- Add an offline-root operating model if this project owns CA hierarchy operations.
- Add a PKCS#11 mock or software-token test path.

## P2: Audit, Access, And Operations

Goal: raise operator accountability and recovery confidence.

- Add policy decision reason and validation evidence ref.
- Add synthetic checks for CRL, OCSP, ACME order/finalize, and post-deployment
  certificate health after a deployment target is selected.
- Add issuer key rotation, intermediate rollover, CRL/OCSP outage, audit repair,
  webhook dead-letter, migration rollback, and restore drill evidence updates
  to runbooks as implementations change.
- Add executable migration rollback and backup/restore tests when SQL migration
  compatibility becomes release-gating.

## P2: Inventory And Discovery

Goal: prove one import model before broad scanning.

- Keep discovery/import scoped to the first real source requested by operators.
- Add owner-missing and 30/60/90-day expiry exception reports once the first
  real import source exists.
- Move any remaining service-side inventory filtering into SQL only when large
  inventory tests show response time risk.

## P4: Product Expansion

- Add certificate rotation automation that includes deploy target update,
  post-deploy health check, rollback, and operator notification.
- Add deploy adapters only after an operator picks concrete first targets;
  likely first targets are Kubernetes Secret and load balancer.
- Add Kubernetes workload identity.
- Add CT or external certificate monitoring for public DNS names.
- Add crypto inventory for TLS, mTLS, JWT/JWS, S/MIME, code signing, SSH,
  database encryption, and backup encryption.
- Add crypto agility registry for key algorithm, signature algorithm, provider,
  and profile compatibility.
- Add algorithm migration plan and 47-day renewal/retry/load simulation report.
- Add PQC/hybrid experiments with clear non-production labeling.
- Track HSM, KMS, TLS library, service mesh, ingress, load balancer, and client
  PQC readiness before any production PQC/hybrid rollout.
- Add UI only after operator API shape and filters stabilize.

## SLO And KPI Targets

| Measure | Target |
| --- | ---: |
| Inventory coverage | 90% first pass, 99% after stabilization |
| Owner assignment | 100% for newly managed certificates |
| Automated renewal coverage | 70% first pass, 95% for public/critical certs |
| Certificates unhandled inside 14-day expiry window | 0 |
| Renewal success rate | 99%+ |
| Revocation request traceability | 100% |
| Missing audit events for issue/renew/revoke/policy change | 0 |
| New weak-algorithm certificates | 0 |
| OCSP/CRL freshness violations | 0 |
| Policy-violating issuance | 0 |

## Defer Or Delete

- Defer broad discovery scanners until one concrete source proves inventory
  fields and ownership workflow.
- Defer deploy adapters beyond the first selected target.
- Defer UI until API filters, pagination, and operator flows stabilize.
- Defer PQC from production; keep lab-only until dependencies and relying-party
  support are real.
- Defer EAB and DNS-01 until real integrations require them.
- Defer Docker Compose or devcontainer support until the local verification
  wrapper and smoke harness are still materially hard for new contributors.
- Reject large file splitting until tests prove behavior and repeated changes
  prove a stable boundary.
- Reject new product surface while release trust, contract parity, failure-mode
  coverage, key-boundary, and recovery evidence remain incomplete.
