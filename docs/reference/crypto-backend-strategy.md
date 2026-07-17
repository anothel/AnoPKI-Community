# Community Crypto Backend Strategy

## Current profile

AnoPKI Community builds exactly one runtime product profile:

```text
community-openssl
  = AnoPKI Core + Community OpenSSL adapter
```

The backend-neutral Core does not include OpenSSL headers or link OpenSSL directly. The adapter under `src/backends/openssl` owns OpenSSL-specific CSR, certificate, CRL, OCSP and diagnostic behavior.

## Backend control

The selected artifact reports backend identity, dependency/version, readiness, capabilities, ABI and build fingerprint. `fallback_enabled` is false. Unsupported or failed operations do not switch to another provider, backend or product profile.

## KeyProvider relation

Backend selection and key-provider selection are separate boundaries.

Community currently ships only an adapter-private file provider for local/development certificate, CRL and OCSP signing. It is exportable and rejected in production. The test-only software-token implementation is contract evidence only and is not shipped.

## External extension boundary

Other product profiles and external cryptographic adapters are outside this Community project's implementation scope. Community retains only the neutral contracts and boundary rules needed to prevent proprietary or external adapter code from entering the public repository.

## Release evidence

Every Community candidate records:

- `community-openssl` product profile,
- OpenSSL dependency and exact version,
- backend capabilities, ABI and build fingerprint,
- Community file-provider policy,
- `fallback_used=false`,
- certificate/CRL/OCSP golden and negative-test results,
- service/core artifacts, checksums and SBOM.
