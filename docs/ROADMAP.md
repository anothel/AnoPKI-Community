# AnoPKI Community Roadmap — Future Work Only

Date: 2026-07-17

Completed backend and FileKeyProvider work is intentionally omitted.

## Operating rules

- Preserve public API, Core CLI JSON contracts, golden fixtures and stable error semantics.
- Keep Community/OpenSSL as the only runtime profile in this project.
- Reject automatic provider, backend and product-profile fallback.
- Prefer release evidence, failure-mode tests and operational recovery over feature breadth.
- Do not add Enterprise commercial features or AnoCrypto-C implementation work here.

## P1 — Release operations

- Run and review `verify-go-release.py --profile full` with a supported Go toolchain on the exact Community commit.
- Review remote CI for the exact cumulative Community commit.
- Generate and review service/core archives, `anopki-go-verification.tar.gz`, backend metadata, release metadata, checksums, SBOM and signing status.
- Keep compatibility evidence current for OS, Go, OpenSSL, SQLite, PostgreSQL, lego and certbot.

## P1 — KeyProvider boundary maintenance

- Keep certificate, CRL and OCSP direct-key-loading regression guards active.
- Keep `FileKeyProvider` local/development only and production-rejected.
- Keep signing evidence strict, redacted and tied to actual C++ signing results.
- Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision.

## P1 — ACME compatibility

- Maintain real-client compatibility evidence by client, OS, account key type and challenge type.
- Add DNS-01 only after a concrete Community operator integration is selected.
- Add External Account Binding only after a concrete subscriber/account integration requires it.

## P2 — Audit and recovery

- Keep policy-decision reasons and redacted validation-evidence references stable across enrollment, issuance, retry and audit repair.
- Keep the executable SQLite backup/restore drill and release evidence contract current.
- Keep the executable CRL/OCSP outage-and-recovery drill and release evidence contract current.
- Keep the audit-repair and dead-letter replay drill and release evidence contract current.
- Keep the Audit hash-chain integrity drill and exact-commit release evidence current across Memory, SQLite and PostgreSQL.
- Keep the generic authorization boundary drill and exact-commit release evidence current across authentication, scope, timeout, redaction, Audit correlation and race semantics.
- Keep the intermediate issuer rollover and rollback drill and release evidence contract current.
- Keep the PostgreSQL 16 backup/restore and migration-rollback drill and release evidence contract current.
- Keep multi-node issuance, CRL and Outbox single-writer evidence current.
- Keep PostgreSQL multi-node lease-expiry failover and traffic-shift evidence current across issuance, CRL and Outbox.
- Add infrastructure-level PostgreSQL primary failover, network-partition and load-balancer traffic-shift evidence after a concrete deployment target exists.
- Add independently anchored Audit-chain export evidence when a concrete SIEM or release-custody integration is selected.

## P2 — Refactor safety

- Split large Go service files only where repeated independent change boundaries exist and contract/failure tests already pin behavior.
- Move inventory filtering into SQL only when realistic scale tests justify it.

## Deferred or separate-project work

- Production non-exportable vendor providers: Enterprise project.
- Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project.
- OIDC/SAML, enterprise RBAC, UI, SIEM packaging and deployment adapters: Enterprise project.
- Production PQC/hybrid certificates.
- Public CA/root-store business.
