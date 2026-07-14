# Key Provider Semantics

This document defines provider policy and the selected phased signing boundary.
ADR 0007 owns the architecture decision. No production HSM, KMS, or PKCS#11
provider is implemented yet.

## Selected Boundary

All issuer and OCSP responder signing uses a `key_ref`.

- `file:` and bare filesystem references are local/dev only.
- Production providers use non-exportable references.
- The service and Core must not request, store, log, or return private key bytes.
- Provider selection is explicit and separate from backend-adapter selection.
- Provider failure never triggers an implicit file-key, provider, adapter, or
  product-profile fallback.

## Selected Architecture

AnoPKI uses a deliberately scoped hybrid.

- Community/OpenSSL first uses an in-process OpenSSL-compatible provider seam.
- The first provider is a file provider that preserves current synchronous
  certificate issuance and golden behavior.
- PKCS#11/local HSM may later use an OpenSSL-compatible non-exportable handle.
- Remote KMS requires a separate Enterprise prototype and approval; it may use
  an adapter-compatible implementation or prepare/sign/finalize protocol.
- OpenSSL native types remain private to the OpenSSL adapter/provider path.

## Provider Classes

| Class | Intended use | Exportability | Example reference |
| --- | --- | --- | --- |
| File | Local development and smoke tests only | Exportable | `file:/var/lib/anopki/issuer.key` |
| PKCS#11/local HSM | Production signing after implementation/evidence | Non-exportable | `pkcs11:token=ca;object=issuer-a` |
| Cloud KMS | Future Enterprise remote signing | Non-exportable | `kms:provider/key/version` |

## Common Provider Metadata

Provider policy and evidence record:

- provider ID and class,
- normalized key reference or redacted reference fingerprint,
- readiness and result,
- algorithm and public-key binding,
- exportability,
- selected product profile and backend adapter,
- operation type and request/trace ID,
- stable provider error code,
- whether any compatibility mode was explicitly selected.

Audit metadata must not include private keys, raw credentials, PINs, session
tokens, or dependency-native errors that may contain secrets.

## Stable Errors

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

## Go And C++ Responsibilities

### Go lifecycle service

- classifies references,
- applies production policy,
- performs early readiness checks,
- records expected provider class/exportability metadata,
- correlates lifecycle, signing, and audit requests.

### C++ selected adapter/provider

- resolves the actual signing provider,
- opens or reaches the actual key,
- checks cryptographic readiness and key binding,
- performs or delegates signing,
- returns stable result/error evidence.

The Go readiness check is defense in depth, not proof that the cryptographic
signing operation used the expected provider.

## Current Implementation State

- The Go service has `keyref.Provider.CheckReady`, class/exportability helpers,
  and audit metadata seams.
- The C++ OpenSSL adapter still opens file keys directly for certificate, CRL,
  and OCSP signing.
- Actual provider isolation and actual-signing evidence are not complete.

## First Implementation Gate

Certificate issuance migrates first to an OpenSSL adapter-private
`FileKeyProvider` while preserving the current JSON contract and golden
certificate behavior. CRL and OCSP remain unchanged until that slice is stable.

Production mode continues to reject exportable file providers. No production
non-exportability claim is allowed until actual signing-provider evidence exists.
