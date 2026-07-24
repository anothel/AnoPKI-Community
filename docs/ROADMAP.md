# AnoPKI Community Roadmap — Closed And Frozen

Date: 2026-07-24

There is no active roadmap. Engineering is closed and frozen at
`5348a478ff1117482a8d168b655dad290367b188`; reopening requires a new product
decision.

```text
ACTIVE_NEXT_WORK=NONE
FUTURE_WORK=DEFERRED_NOT_SELECTED
REOPEN_REQUIRES_NEW_PRODUCT_DECISION
```

## Frozen boundary

- Preserve public API, Core CLI JSON contracts, golden fixtures, and stable
  error semantics.
- Community/OpenSSL remains the only implemented runtime profile in this
  project; this does not declare a supported OpenSSL version range.
- Do not add Enterprise commercial features or AnoCrypto-C implementation work
  here.
- Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project.
- Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision.

## Deferred / not selected

The following are not defects, commitments, or active work:

- HSM, KMS, PKCS#11, and other production non-exportable vendor providers.
- DNS-01 and External Account Binding.
- Independent Audit-chain anchoring and SIEM integration.
- PQC or hybrid production certificates.
- Infrastructure-level PostgreSQL primary failover, network partition, and
  load-balancer traffic-shift evidence.
- OIDC/SAML, enterprise RBAC, UI, deployment adapters, and public CA/root-store
  business.
- Additional compatibility, release, packaging, or publication work.

Existing local validators, self-tests, runbooks, and evidence documents remain
historical engineering evidence. Their presence does not select future work,
authorize a public release, or claim production readiness.
