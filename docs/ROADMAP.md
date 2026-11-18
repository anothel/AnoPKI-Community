# AnoPKI Community Roadmap

Updated: 2026-11-18

Future work only. Delivered changes and release history belong in the
[changelog](../CHANGELOG.md) and [release evidence](reference/release-evidence.md).

## Remaining evaluation work

- [Issue #21](https://github.com/anothel/AnoPKI-Community/issues/21): remaining
  real-client interoperability scope beyond the
  [verified scenarios](acme-client-compatibility.md); keep open.
- [Issue #29](https://github.com/anothel/AnoPKI-Community/issues/29): reproduce
  and classify audit hash-chain intermittency. Diagnostics do not establish a fix.
- [Issue #5](https://github.com/anothel/AnoPKI-Community/issues/5): classify
  PostgreSQL intermittency; later passing runs do not establish remediation.
- [Issue #31](https://github.com/anothel/AnoPKI-Community/issues/31): separately
  design cross-account ACME revocation authority for all certificate identifiers.
  This authority remains deferred and denied.

## Community boundary

- Preserve public API, Core CLI JSON contracts, golden fixtures, and stable
  error semantics.
- Community/OpenSSL remains the only implemented runtime profile in this
  project; this does not declare a supported OpenSSL version range.
- Do not add Enterprise commercial features or AnoCrypto-C implementation work
  here.
- Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project.
- Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision.

## Deferred / not selected

These areas remain outside the selected stabilization and alpha scope:

- HSM, KMS, PKCS#11, and other production non-exportable vendor providers.
- DNS-01 and External Account Binding.
- Independent Audit-chain anchoring and SIEM integration.
- PQC or hybrid production certificates.
- Infrastructure-level PostgreSQL primary failover, network partition, and
  load-balancer traffic-shift evidence.
- OIDC/SAML, enterprise RBAC, UI, deployment adapters, and public CA/root-store
  business.
