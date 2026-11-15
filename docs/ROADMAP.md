# AnoPKI Community Roadmap — Active Alpha Readiness

Updated: 2026-11-15

The owner resumed AnoPKI-Community engineering on 2026-11-15 after the
historical 2026-07-24 freeze. The old baseline is preserved in repository
history but no longer represents the current development status.

```text
ENGINEERING_STATUS=ACTIVE_STABILIZATION
ACTIVE_NEXT_WORK=PHASE_4_ALPHA_READINESS
PUBLIC_RELEASE=NOT_PUBLISHED
PRODUCTION_READY=NO
```

## Completed stabilization

- Phase 1: CI stabilization, PostgreSQL lease fixes and runner portability — PR #2.
- Phase 2: loopback-only development defaults and production ACME smoke guards — PR #3.
- Phase 3: behavior-preserving HTTP DTO, ACME verifier/SSRF and MemoryStore
  helper extraction — PRs #6, #8 and #11.
- PostgreSQL failover diagnostics — PR #9. Five additional PostgreSQL 16
  reruns passed, but the historical intermittent failure remains open in #5.

## Active alpha readiness

- Issue #12 tracks Community/OpenSSL `v0.1.0-alpha.1` release recovery:
  exact-commit CI, recovery and security evidence, SBOM, checksums, release
  signing, environment approvals, and an explicit go/no-go.
- The GitHub-verified signed `v0.1.0-alpha.0` tag is preserved as evidence:
  its artifact build passed, but the tag-only publish job failed because
  checkout rewrote the local annotated tag ref to its peeled commit.
  No GitHub Release was published. Do not rewrite or delete that signed tag.
- Windows runtime and live ACME-client interoperability still require evidence.
- The alpha target is evaluation-only. No stable compatibility or production
  readiness guarantee is being made.
- Publication is permitted only after all release checks and cryptographic
  signing gates pass. No bypass or production deployment is authorized.

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

Archived closeout records still describe the previous freeze. Test evidence
alone neither authorizes publication nor establishes production readiness.
