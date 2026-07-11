# AnoPKI Community Edition Policy

AnoPKI Community Edition은 공개 GitHub에서 유지되는 완전한 Community
제품입니다.

## 제품 조립

```text
Community/OpenSSL
  = AnoPKI Core + OpenSSL adapter
```

## 포함 범위

- backend-neutral AnoPKI Core contract
- Community OpenSSL adapter
- PKI lifecycle API
- identity, issuer, profile, enrollment, approval, issuance
- inventory, renewal, reissue, revocation, suspension, expiration scan
- CRL and OCSP
- ACME HTTP-01 compatibility baseline
- API key authentication
- audit metadata and lifecycle outbox baseline
- OpenAPI, CLI contracts, golden fixtures, release evidence

## 제외 범위

- AnoCrypto-C adapter
- AnoCrypto-C SDK/source
- KCMVP submission/test/validation material
- Enterprise UI and access-control integration
- production HSM/KMS/PKCS#11 vendor providers
- production deployment adapters
- Enterprise audit/SIEM/reporting
- commercial license enforcement and customer support streams

## Backend Contract Rule

Core code should be backend-neutral. OpenSSL-specific calls belong in the
Community OpenSSL adapter. The contract should allow Enterprise to add an
adapter without importing Enterprise code into Community.

Community does not need to build or test the Enterprise AnoCrypto-C adapter.

## Public Claim Rule

Community docs and release metadata must say that the Community product uses the
OpenSSL profile. They may describe a backend-neutral extension contract but must
not claim that AnoCrypto-C is active, bundled, validated, or supported by the
Community release.
