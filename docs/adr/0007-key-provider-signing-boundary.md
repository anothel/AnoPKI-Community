# ADR 0007: Key Provider Signing Boundary

## Status

Accepted architecture; certificate-issuance file-provider vertical slice pending.

## Context

AnoPKI already separates the backend-neutral Core from backend adapters and
selects one product profile per artifact. Key-provider selection is a separate
axis, but actual signing is not yet provider-neutral.

The Go lifecycle service currently:

- classifies `key_ref` values,
- checks provider readiness,
- records provider class and exportability in audit metadata,
- passes the unchanged key reference to `anopki-core`.

The Community OpenSSL adapter currently:

- opens file-backed private keys directly,
- parses them into OpenSSL `EVP_PKEY` objects,
- performs certificate, CRL, and OCSP signing synchronously inside one core
  operation.

A production provider must support non-exportable key references without
weakening duplicate-signing protection, audit traceability, profile selection,
or no-fallback rules.

Three designs were considered.

### Option A: One in-process C++ provider model

Every provider runs in the core process and supplies an adapter-compatible
signing handle.

This preserves the current atomic operation shape and public CLI contracts, and
fits local file and PKCS#11/OpenSSL-provider integrations. However, forcing every
remote KMS into the C++ process would add cloud SDK, network, credential, and
retry behavior to the Community core runtime.

### Option B: Go prepare/sign/finalize protocol

The C++ codec prepares exact TBS material, Go invokes a provider, and C++
finalizes the certificate, CRL, or OCSP response.

This fits remote KMS integrations, but it changes the Go/C++ contract and
creates new persistence and retry requirements. Issuance must persist prepared
material and the returned signature to prevent duplicate signing. CRL and OCSP
would need equivalent operation state or explicitly bounded retry semantics.

### Option C: Deliberately scoped hybrid

Use an in-process adapter-compatible provider for local file and PKCS#11/HSM
paths first. Treat remote KMS as a separate Enterprise protocol problem that may
later use prepare/sign/finalize after an evidence-backed prototype.

## Decision

AnoPKI adopts **Option C: a deliberately scoped hybrid**.

### Common policy contract

The service and release evidence use backend-neutral provider concepts:

- provider ID and class,
- key reference,
- readiness,
- algorithm and public-key binding metadata,
- exportability,
- stable provider error code,
- actual signing result/audit evidence,
- compatibility with the selected backend profile.

No public API or backend-neutral Core contract exposes OpenSSL, PKCS#11, cloud
SDK, or AnoCrypto-C native types.

### Community/OpenSSL implementation model

The first implementation is an **in-process OpenSSL signing-provider seam**.

- The OpenSSL adapter owns its provider-compatible native signing handle.
- `EVP_PKEY` and OpenSSL provider types remain private to
  `src/backends/openssl`.
- A `FileKeyProvider` replaces direct file opening in certificate issuance.
- The provider opens and validates the key, verifies its certificate/public-key
  binding, and returns an adapter-private signing handle.
- `X509_sign` remains the signing mechanism for the first slice so existing
  certificate DER/golden behavior and the one-operation CLI contract remain
  unchanged.
- CRL and OCSP migrate only after certificate issuance is stable.

The Go `CheckReady` call remains a policy and early-failure check, but it is not
cryptographic proof. The C++ provider repeats actual readiness, key parsing, and
binding checks at the signing boundary.

### PKCS#11 and local HSM direction

PKCS#11 or local HSM implementations may provide a non-exportable
OpenSSL-compatible signing handle through a selected OpenSSL 3 provider or an
Enterprise adapter. They must not return private key bytes to Go, the database,
or backend-neutral Core code.

### Remote KMS direction

Remote KMS integration is not forced into the first C++ provider interface.
Before implementation, Enterprise must prototype and separately approve either:

- an adapter-compatible provider implementation with clear network/retry
  semantics, or
- a versioned prepare/sign/finalize protocol with persisted prepared material,
  signature result, idempotency, and audit correlation.

Remote KMS support must not be represented as implemented by this ADR.

### Backend compatibility

Provider compatibility is explicit.

- Community/OpenSSL and Enterprise/OpenSSL initially use OpenSSL-compatible
  providers.
- Enterprise/AnoCrypto-C may use a provider only when the external SDK exposes
  the necessary signing/key-handle API and compatibility tests exist.
- An incompatible provider/profile combination fails with a stable error.
- Provider failure never triggers another provider, file key, OpenSSL adapter,
  or product-profile fallback.

## Stable provider errors

The internal provider contract uses stable categories such as:

- `provider.invalid_reference`
- `provider.unavailable`
- `provider.not_ready`
- `provider.key_not_found`
- `provider.key_parse_failed`
- `provider.algorithm_mismatch`
- `provider.key_binding_mismatch`
- `provider.exportability_violation`
- `provider.profile_mismatch`
- `provider.sign_failed`

Dependency-native messages may be emitted only as redacted operator
diagnostics. Stable codes remain the service and audit contract.

## First vertical slice

The next implementation patch is limited to certificate issuance in
Community/OpenSSL.

1. Add OpenSSL adapter-private signing-provider interfaces and metadata.
2. Implement `FileKeyProvider` using the current file-key behavior.
3. Route certificate issuance key loading through that provider.
4. Remove direct issuer-key file opening from the issuance implementation.
5. Preserve CLI request/result fields and certificate golden fixtures.
6. Add positive and negative provider tests:
   - file reference and bare-path compatibility,
   - missing or unreadable key,
   - malformed key,
   - key/certificate binding mismatch,
   - algorithm mismatch,
   - unavailable provider,
   - production policy rejecting exportable file providers,
   - no undeclared provider or backend fallback.
7. Record provider identity/result as actual signing evidence before claiming
   provider-backed production operation.

CRL, OCSP, PKCS#11, HSM, KMS, and AnoCrypto-C signing are non-goals for that
first patch.

## Consequences

- Existing public lifecycle and core CLI operation contracts remain stable for
  the first slice.
- Community avoids cloud SDK and remote-signing state complexity.
- The design gives PKCS#11/local HSM a practical path without claiming that
  remote KMS is solved.
- A later prepare/sign/finalize design remains possible, but requires a separate
  ADR amendment and operation-state evidence.
- Production remains blocked while file providers perform actual signing.
- ADR 0003 remains the high-level HSM/KMS policy and is refined by this
  implementation decision.
