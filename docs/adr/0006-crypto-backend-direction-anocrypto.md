# ADR 0006: Backend-Neutral Core And External AnoCrypto-C Adapter

## Status

Accepted revised direction; Community/OpenSSL extraction implemented, profile and parity work pending.

## Context

AnoPKI Community now has a backend-neutral operation dispatch layer and a physically separate OpenSSL adapter for CSR inspection, certificate issuance, CRL generation, and OCSP processing. AnoCrypto-C is a
separate C99 project and SDK. It is not developed inside the Community or
Enterprise AnoPKI repositories.

Earlier planning described AnoCrypto as if it would be implemented inside the
Enterprise repository or used with automatic OpenSSL fallback. That is not the
selected design.

## Decision

AnoPKI will use a backend-neutral core with explicit adapter composition.

```text
AnoPKI Core
  |- OpenSSL adapter -----> OpenSSL::Crypto
  `- AnoCrypto-C adapter -> AnoCryptoC::AnoCryptoC
```

Repository ownership is:

- Community owns the backend-neutral core contract and OpenSSL adapter.
- Enterprise reuses Community and owns the AnoCrypto-C adapter and Enterprise
  layer.
- AnoCrypto-C owns its cryptographic algorithms, module lifecycle, self-tests,
  secure memory behavior, and validation evidence.

The supported product targets are:

- Community/OpenSSL: core + OpenSSL adapter.
- Enterprise/OpenSSL: core + OpenSSL adapter + Enterprise layer.
- Enterprise/AnoCrypto-C: core + AnoCrypto-C adapter + Enterprise layer.

Backend selection must be explicit. An AnoCrypto-C profile must return a stable
capability-unavailable error or fail startup when a required capability is
missing. It must not silently call OpenSSL.

## Consequences

- Community/OpenSSL remains the complete public and releaseable baseline.
- Enterprise/OpenSSL covers all Community functions but must not be marketed as
  AnoCrypto-backed or KCMVP-related.
- Enterprise/AnoCrypto-C remains a development/integration profile until all
  required Community operation parity and release gates pass.
- OpenSSL compatibility is a separately selected product profile, not a runtime
  fallback path.
- Release and audit evidence must identify edition, adapter, backend dependency,
  version, capabilities, and whether fallback was used.
- Crypto adapter work remains separate from HSM/KMS/PKCS#11 key-provider work.

## Follow-Up Work

- Extend the backend contract with identity, version, capability, readiness, and stable error metadata.
- Keep all Community/OpenSSL golden fixtures passing through the separated OpenSSL adapter.
- Add explicit build targets for Community/OpenSSL, Enterprise/OpenSSL, and
  Enterprise/AnoCrypto-C.
- Implement the Enterprise adapter only against supported external AnoCrypto-C
  APIs; do not reimplement AnoCrypto-C inside AnoPKI.
- Add capability discovery, stable unsupported errors, and negative tests that
  prove OpenSSL is not called from the AnoCrypto-C profile.
- Keep Enterprise/AnoCrypto-C production release blocked until required parity
  and exact-module evidence are complete.
