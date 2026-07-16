# ADR 0007: Key Provider Signing Boundary

## Status

Accepted. The Community/OpenSSL certificate-issuance `FileKeyProvider` vertical
slice is implemented. CRL, OCSP, non-exportable providers, and remote KMS remain
pending and are not implied by this status.

## Context

AnoPKI separates backend-neutral Core operations from selected backend adapters.
Key-provider selection is a separate axis. Before this slice, the Go service
classified `key_ref`, performed policy/readiness preflight through
`keyref.Provider.CheckReady`, and passed the reference to `anopki-core`, while
the C++ OpenSSL certificate-issuance adapter opened and parsed the issuer key
file directly.

The Go readiness seam is useful defense in depth, but it is not cryptographic
proof that the expected provider key performed the signature. The signing
boundary must perform its own key resolution, parsing, algorithm compatibility,
issuer-certificate binding, and signing checks.

Three designs were considered:

1. one in-process C++ provider model,
2. a Go prepare/sign/finalize protocol,
3. a deliberately scoped hybrid.

## Decision

AnoPKI uses a **deliberately scoped hybrid**.

- Local file and future local PKCS#11/HSM paths may use an in-process,
  adapter-compatible provider seam.
- Remote KMS is a separate Enterprise protocol problem. It requires a later
  evidence-backed decision and may use either an adapter-compatible provider or
  a versioned prepare/sign/finalize protocol.
- No public API or Core CLI JSON field is added for this first slice.
- Backend selection and provider selection remain explicit and independent.
- Provider failure never retries through another provider, a file key, another
  backend, or another product profile.

## Implemented Community/OpenSSL Slice

The first vertical slice is limited to certificate issuance.

```text
src/backends/openssl/key_providers/
  file_key_provider.hpp
  file_key_provider.cpp
```

The adapter-private provider contract supplies:

- provider ID and class,
- readiness and exportability metadata,
- stable `provider.*` errors,
- redacted diagnostic stage metadata,
- `file:` and bare-path normalization,
- private-key parsing,
- requested signature-algorithm compatibility checks,
- issuer-certificate/private-key binding checks,
- an OpenSSL-private signing-key handle for `X509_sign`,
- evidence that fallback was not used.

`src/backends/openssl/issue.cpp` no longer opens a file or calls a PEM private-key
reader. It resolves one provider once and signs with the returned private
adapter handle. OpenSSL types remain below `src/backends/openssl`.

The file provider is explicitly:

- provider class `file`,
- local/development only,
- exportable,
- rejected when `ANOPKI_ENV=production`,
- never a fallback target for another provider reference.

## Stable Provider Errors

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

The stable code is the exception message consumed by the existing CLI error
mapping. Raw OpenSSL errors and raw paths are cleared or omitted from provider
diagnostics.

## Evidence Semantics

`keyref.Provider.CheckReady` remains a policy and preflight signal only.
Certificate-signing evidence requires the selected C++ provider path to:

1. resolve the requested reference without fallback,
2. acquire and parse the actual key,
3. verify requested algorithm compatibility,
4. verify issuer certificate/key binding,
5. complete `X509_sign` with the returned handle,
6. preserve the certificate golden result.

A release candidate records those test and validator results. A successful Go
readiness check alone cannot mark cryptographic signing evidence as passed.

## Non-goals Of This Slice

- CRL signing migration,
- OCSP signing migration,
- real PKCS#11/HSM implementation,
- real cloud KMS implementation,
- prepare/sign/finalize protocol,
- Enterprise/AnoCrypto-C changes,
- a production non-exportability claim.

## Consequences

- Community/OpenSSL certificate issuance has one explicit key-provider path.
- Existing public lifecycle and Core CLI JSON contracts remain unchanged.
- Existing RSA certificate DER behavior remains pinned by golden-equivalence
  testing.
- Production still rejects the exportable file provider.
- CRL and OCSP still have their previous direct file-key behavior and must not be
  represented as migrated.
- Enterprise synchronizes this reviewed Community change only after the
  Community commit SHA is known.
