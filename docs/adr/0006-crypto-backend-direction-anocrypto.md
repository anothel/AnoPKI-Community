# ADR 0006: Crypto Backend Direction To AnoCrypto

## Status

Accepted direction; implementation pending.

## Context

AnoPKI currently uses OpenSSL through the C++ core build. This is practical for the current pre-1.0 implementation because CSR parsing, certificate issuance, CRL generation, and OCSP DER handling already have tests and local build coverage.

The project owner has stated the intended direction to use `anocrypto` / **AnoCrypto**. That direction was not yet recorded in repository documentation, and no existing file mentioned AnoCrypto before this ADR.

## Decision

AnoPKI will treat **AnoCrypto** as the intended project-owned crypto backend direction.

OpenSSL remains the current implementation until AnoCrypto parity is proven through backend contracts, golden fixtures, release evidence, and security review.

## Consequences

- The codebase should evolve toward a real crypto backend boundary instead of spreading OpenSSL calls across unrelated layers.
- The AnoCrypto migration must be incremental and test-first.
- Documentation must distinguish crypto backend work from HSM/KMS/PKCS#11 key-provider work.
- Release evidence must explicitly record which backend was used for each release candidate.
- Public docs must not claim AnoCrypto is implemented until code and tests prove it.

## Follow-Up Work

- Expand `include/anopki/crypto/backend.hpp` into a concrete backend contract.
- Add backend parity fixtures for CSR, issuance, CRL, OCSP decode, and OCSP sign behavior.
- Add release-evidence fields for crypto backend name and version.
- Add implementation docs when the first AnoCrypto-backed path exists.
