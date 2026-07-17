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
- Add ECDSA and encrypted-key negative fixtures when they materially improve coverage.
- Keep signing evidence strict, redacted and tied to actual C++ signing results.
- Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision.

## P1 — ACME compatibility

- Maintain real-client compatibility evidence by client, OS, account key type and challenge type.
- Add DNS-01 only after a concrete Community operator integration is selected.
- Add External Account Binding only after a concrete subscriber/account integration requires it.

## P2 — Audit and recovery

- Add policy-decision reason and validation-evidence references.
- Expand issuer rotation, intermediate rollover, CRL/OCSP outage, audit repair, dead-letter, migration rollback and restore drill evidence.
- Complete tamper-evident audit storage only after event-schema stability is sufficient.

## P2 — Refactor safety

- Split large Go service files only where repeated independent change boundaries exist and contract/failure tests already pin behavior.
- Move inventory filtering into SQL only when realistic scale tests justify it.

## Deferred or separate-project work

- Production non-exportable vendor providers: Enterprise project.
- Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project.
- OIDC/SAML, enterprise RBAC, UI, SIEM packaging and deployment adapters: Enterprise project.
- Production PQC/hybrid certificates.
- Public CA/root-store business.
