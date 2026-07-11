# Crypto Backend Strategy

This document records the current crypto implementation and the intended direction for adopting **AnoCrypto**.

## Current State

AnoPKI currently builds the C++ core against OpenSSL `Crypto` through CMake. The current core CLI uses that implementation for CSR inspection, certificate issuance, CRL generation, OCSP request decoding, and OCSP response signing.

The backend contract covers CSR parsing, certificate issuance, CRL generation,
OCSP request decoding, OCSP response signing, and responder validation. Community
routes those operations through its OpenSSL implementation.

## Intended Direction

The intended direction is to use **AnoCrypto** as the project-owned crypto backend layer after the current OpenSSL-backed behavior is fully pinned by contract tests and fixture evidence.

Use these names consistently:

| Context | Name |
| --- | --- |
| Public project/backend name | `AnoCrypto` |
| Technical package or module name | `anocrypto` |
| Documentation phrase | `AnoCrypto backend` |

## Non-Goals For The First AnoCrypto Step

- Do not replace all crypto behavior in one broad rewrite.
- Do not remove OpenSSL until CSR, issuance, CRL, OCSP, ACME, and release evidence parity are proven.
- Do not mix crypto backend work with HSM/KMS key-provider work in one change.
- Do not introduce PQC or hybrid certificate production support as part of the backend migration.

## Migration Gates

Before switching the default backend to AnoCrypto, the project needs:

1. a backend contract for CSR parse, certificate issue, CRL sign, OCSP decode, and OCSP sign operations,
2. fixture parity using the [shared backend parity harness](crypto-backend-parity.md),
3. stable error mapping so raw backend errors do not become public API contracts,
4. release evidence that records OS, compiler, dependency, and artifact behavior,
5. a fallback or compatibility plan for existing OpenSSL-based deployments,
6. security review of key handling, parser behavior, signature algorithm handling, and failure modes.

## Relationship To Key Providers

Crypto backend selection and key-provider selection are related but separate.

- The crypto backend owns parsing, encoding, signing primitives, and certificate/status artifact construction.
- The key provider owns private-key boundary, non-exportability, readiness checks, and provider audit metadata.

AnoCrypto adoption should not weaken the rule that production private keys are referenced by `key_ref` and must not be stored in the service database.

## Documentation Impact

When AnoCrypto implementation begins, update:

- `CMakeLists.txt` and build docs,
- `include/anopki/crypto/backend.hpp` and core CLI contract docs,
- `docs/policy/algorithm-policy.md`,
- `docs/security/key-provider-semantics.md`,
- `docs/reference/core-cli-contract.md`,
- `docs/reference/release-evidence.md`,
- `docs/reference/compliance-matrix.md`,
- release notes and migration notes.
