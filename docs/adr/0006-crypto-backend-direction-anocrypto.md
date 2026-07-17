# ADR 0006: Backend-Neutral Core And External Adapter Boundary

## Status

Accepted. Community/OpenSSL extraction, explicit profile selection, backend
metadata, capability/readiness checks, and no-fallback controls are implemented.
External adapter implementation and product execution are outside this Community
project.

## Context

AnoPKI Community uses a backend-neutral operation dispatch layer and a physically
separate OpenSSL adapter for CSR inspection, certificate issuance, CRL generation,
and OCSP processing. AnoCrypto-C is a separate external project and SDK; it is
not implemented, bundled, or validated by the Community repository.

## Decision

Community assembles exactly one runtime profile:

```text
AnoPKI Core -> Community OpenSSL adapter -> OpenSSL::Crypto
```

The Core contract remains backend-neutral so a separate product may implement an
external adapter without importing proprietary or external SDK code into
Community. Backend selection is explicit. Missing capability or adapter failure
must fail closed and must not invoke another backend automatically.

Repository ownership is:

- Community owns backend-neutral Core, the OpenSSL adapter, the Go service,
  public contracts, golden tests, and Community release evidence.
- External adapters and SDK integration remain outside the Community repository.
- Shared generic contract changes are implemented and reviewed Community-first.

## Consequences

- `community-openssl` is the only runtime profile managed here.
- Community release metadata reports OpenSSL, its exact version, capabilities,
  readiness, ABI/build fingerprint, and `fallback_enabled=false`.
- Community does not claim AnoCrypto-C support, KCMVP status, external SDK
  evidence, or Enterprise product readiness.
- Backend selection remains separate from KeyProvider selection.
- Public API and Core CLI JSON contracts remain stable across internal refactors.

## Follow-Up Work

- Keep Community/OpenSSL golden, CLI-contract, provider-boundary, and
  failure-mode tests passing.
- Keep external adapter code, SDK artifacts, credentials, product plans, and
  private evidence out of Community.
- Make future shared contract changes in Community before any separate product
  synchronizes them.
