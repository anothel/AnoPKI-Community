# AnoPKI Documentation Index

This index is the public entry point for repository documentation. Keep it short enough to scan and use it to prevent the root README from becoming a second documentation tree.

## Start Here

| Document | Use when |
| --- | --- |
| [Project scope](reference/project-scope.md) | You need to understand what AnoPKI is, what it is not, and where the current service boundaries are. |
| [Project identity and license](reference/project-identity-and-license.md) | You need canonical naming, technical identifiers, or MPL-2.0 license wording. |
| [Roadmap](ROADMAP.md) | You need future-only priorities and deferred work. |
| [Security policy](../SECURITY.md) | You need security status, reporting guidance, production expectations, or known constraints. |
| [Contributing guide](../CONTRIBUTING.md) | You need local verification commands and contribution expectations. |
| [Service README](../service/README.md) | You need service behavior, endpoints, configuration, auth, workers, or ACME details. |

## Architecture

| Document | Purpose |
| --- | --- |
| [PKI context](architecture/pki-context.md) | Overview of CA hierarchy, trust boundary, issuance, renewal, and revocation flows. |
| [Target architecture](reference/target-architecture.md) | Community service, backend-neutral Core, OpenSSL adapter, FileKeyProvider, audit, CRL, and OCSP boundaries. |
| [CA hierarchy](architecture/ca-hierarchy.md) | Trust anchor, intermediate, and issuer structure. |
| [Issuance flow](architecture/issuance-flow.md) | Enrollment and signing path. |
| [Renewal flow](architecture/renewal-flow.md) | Renewal and reissue behavior. |
| [Revocation flow](architecture/revocation-flow.md) | Revocation and status publication behavior. |
| [State transitions](reference/state-transitions.md) | Valid and invalid lifecycle transitions. |

## API And Integration

| Document | Purpose |
| --- | --- |
| [OpenAPI spec](reference/openapi.json) | Machine-readable lifecycle, operator, distribution, and ACME management API contract. |
| [API surface status](reference/api-surface-status.md) | Endpoint maturity, stability labels, and duplicate-request semantics. |
| [API error codes](reference/api-errors.md) | Public HTTP errors, ACME problem types, and audit error codes. |
| [Core CLI contract](reference/core-cli-contract.md) | JSON contract between the Go service and C++ core CLI. |
| [Core boundary integration](reference/core-boundary-integration.md) | How service/core responsibilities are separated. |
| [ACME RFC 8555 conformance](acme-rfc8555-conformance.md) | Implemented ACME protocol behavior and fixture evidence. |
| [ACME client compatibility](acme-client-compatibility.md) | Real-client smoke states and known compatibility gaps. |
| [Webhook receivers](reference/webhook-receivers.md) | Receiver verification and examples. |

## Policy And Security

| Document | Purpose |
| --- | --- |
| [Certificate profiles](policy/certificate-profiles.md) | Profile-as-code policy fields and remaining profile gaps. |
| [Algorithm policy](policy/algorithm-policy.md) | Current algorithm baseline, PQC stance, and algorithm migration expectations. |
| [Crypto backend strategy](reference/crypto-backend-strategy.md) | Community/OpenSSL baseline, explicit profile selection, provider separation, and no-fallback rules. |
| [Crypto backend parity](reference/crypto-backend-parity.md) | Shared fixture format, parity result states, commands, and release evidence. |
| [Key provider semantics](security/key-provider-semantics.md) | Signing key reference, selected hybrid provider boundary, non-exportability, and audit semantics. |
| [Threat model](security/threat-model.md) | Main assets, threats, current controls, and gaps. |
| [Access model](security/access-model.md) | Operator and API-key access assumptions. |
| [Audit log schema](security/audit-log-schema.md) | Audit properties, retention, tamper-evidence, and SIEM export baseline. |
| [Audit tamper evidence](security/audit-tamper-evidence.md) | Hash-chain and tamper-evidence direction. |
| [SIEM detections](security/siem-detections.md) | Detection examples for security-relevant events. |
| [CP/CPS map](policy/cp-cps-map.md) | Evidence-oriented CP/CPS coverage map. |
| [Compliance matrix](reference/compliance-matrix.md) | RFC, CA/B Forum, Mozilla, and NIST coverage. |

## Operations And Runbooks

| Document | Purpose |
| --- | --- |
| [Manual demo](runbooks/manual-demo.md) | Local end-to-end enrollment lifecycle demo. |
| [Production deployment](runbooks/production-deployment.md) | Production architecture, secure sample config, startup checks, and rollback link. |
| [Production hardening checklist](runbooks/production-hardening-checklist.md) | Required checks before production-like deployment. |
| [Production recovery](runbooks/production-recovery.md) | Backup, rollback, restore, and disaster-recovery drill rules. |
| [Bootstrap API key](runbooks/bootstrap-api-key.md) | First operator provisioning, bootstrap removal, key rotation, and disable flow. |
| [Release process](runbooks/release-process.md) | Release candidate checklist, verification, metadata, and approval gates. |
| [Release evidence](reference/release-evidence.md) | Artifact, SBOM, signing, scan, and compatibility evidence baseline. |
| [Incident response](runbooks/incident-response.md) | Mis-issuance, key exposure, CA outage, renewal, revocation, and webhook incidents. |
| [Webhook outbox safety](runbooks/webhook-outbox-safety.md) | Receiver verification, replay cache, schema versioning, and dead-letter replay. |
| [Public TLS readiness](runbooks/public-tls-readiness.md) | Validity ceilings, validation reuse, CAA checks, and mass-revocation drill. |
| [Issuance runbook](operations/issuance-runbook.md) | Normal and emergency issuance procedure. |
| [Renewal runbook](operations/renewal-runbook.md) | Renewal, failure handling, and deployment gap baseline. |
| [Revocation runbook](operations/revocation-runbook.md) | Revocation reasons and response procedure. |
| [Mass revocation plan](operations/mass-revocation-plan.md) | Mass incident drill steps and evidence. |
| [Key ceremony](operations/key-ceremony.md) | Key ceremony baseline and HSM/KMS gaps. |
| [Backup and restore](operations/backup-restore-runbook.md) | Restore drill checklist tied to production recovery. |

## Release And Maintenance

| Document | Purpose |
| --- | --- |
| [Release readiness action plan](reference/release-readiness-action-plan.md) | Current grouped execution plan from repository analysis. |
| [v0.1.0-alpha.0 candidate evidence](reference/release-candidate-v0.1.0-alpha.0.md) | Local draft checks, known gaps, and blockers; no publication status. |
| [Release evidence](reference/release-evidence.md) | Release artifact and supply-chain evidence requirements. |
| [Observability](reference/observability.md) | Structured logs, expvar counters, request IDs, and remaining observability gaps. |
| [Fuzzing](reference/fuzzing.md) | Parser fuzzing scope and local invocation. |
| [Issuance consistency](reference/issuance-consistency.md) | Signing claim, retry, and audit repair behavior. |
| [Audit metadata](reference/audit-metadata.md) | Audit metadata fields and stable result codes. |
| [Documentation governance](reference/documentation-governance.md) | What belongs in Git, what belongs in internal/GPT project sources, and how to retire docs. |
| [Source file header policy](reference/source-file-header-policy.md) | SPDX header policy for first-party files. |

## ADRs

| ADR | Decision |
| --- | --- |
| [0001](adr/0001-ca-backend-selection.md) | CA backend selection. |
| [0002](adr/0002-acme-adoption.md) | ACME adoption. |
| [0003](adr/0003-hsm-kms-strategy.md) | HSM/KMS strategy. |
| [0004](adr/0004-license-change-to-mpl-2.0.md) | MPL-2.0 license change. |
| [0005](adr/0005-project-rename-to-anopki.md) | Project rename to AnoPKI. |
| [0006](adr/0006-crypto-backend-direction-anocrypto.md) | Backend-neutral Core, Community/OpenSSL ownership, and external-adapter repository boundary. |
| [0007](adr/0007-key-provider-signing-boundary.md) | Deliberately scoped hybrid key-provider signing boundary. |

## Internal Or Archived Material

Implementation plans, generated analysis packs, AI-assistant scratch notes, and dated planning artifacts do not belong in the public documentation index unless they are promoted into one of the stable documents above.

The previous `docs/superpowers/` planning tree is treated as internal project-source material. Keep it outside the committed public docs tree unless a specific plan is still active and has been converted into a maintained roadmap item or ADR.
