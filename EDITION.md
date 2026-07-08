# AnoPKI Community Edition

This repository is the public **AnoPKI Community** codebase.

Community is the MPL-2.0, OpenSSL-backed edition. It should stay suitable for
public GitHub development, security review, issue discussion, and community
contribution.

## Included

- Go lifecycle API service.
- C++ `anopki-core` CLI.
- OpenSSL-backed CSR inspection, issuance, CRL generation, and OCSP DER handling.
- Public documentation, API contract, runbooks, security policy, release evidence,
  and ADRs.
- Compatibility and contract validation scripts.

## Excluded

- AnoCrypto implementation source or binaries.
- KCMVP submission material and customer-specific compliance packages.
- Enterprise SSO/RBAC/ABAC, deployment adapters, UI, SIEM exporters, and commercial
  support material.
- Real HSM/KMS/PKCS#11 provider implementations.

## Rule

Community may document AnoCrypto as the intended direction, but it must not claim
that AnoCrypto is implemented or active until code, parity fixtures, and release
evidence prove it.
