# Key Provider Semantics

This document defines provider policy and the implemented certificate-issuance
slice. ADR 0007 owns the deliberately scoped hybrid architecture decision.

## Selected Boundary

All signing keys are addressed by `key_ref`.

- `file:` and bare filesystem references are local/development only.
- Production providers must be non-exportable.
- Provider selection is separate from backend-adapter selection.
- Provider failure never triggers an implicit file, provider, adapter, or
  product-profile fallback.
- Private key bytes must not cross into the Go service, database,
  backend-neutral Core, public API, logs, or diagnostics.

## Provider Classes

| Class | Intended use | Exportability | Current implementation |
| --- | --- | --- | --- |
| File | Local development and smoke | Exportable | Certificate issuance only |
| PKCS#11/local HSM | Future production signing | Non-exportable | Not implemented |
| Cloud KMS | Future Enterprise remote signing | Non-exportable | Not implemented |

## Implemented Certificate-Issuance Path

Community/OpenSSL certificate issuance resolves a single adapter-private
`FileKeyProvider`.

The provider:

- normalizes `file:` and bare paths,
- reports provider identity/class/readiness/exportability,
- opens and parses the actual private key,
- checks requested RSA/ECDSA/Ed25519 compatibility,
- verifies issuer certificate/key binding,
- returns an OpenSSL-private signing handle,
- reports `fallback_used=false`,
- emits stable, redacted `provider.*` failures.

`src/backends/openssl/issue.cpp` does not open the key file or invoke a PEM
private-key reader. `X509_sign` remains in the OpenSSL adapter to preserve the
one-operation CLI contract and existing certificate result.

## Go And C++ Evidence Responsibilities

### Go lifecycle service

- classifies references,
- applies service policy,
- performs early `CheckReady` preflight,
- records expected provider class/exportability metadata,
- correlates lifecycle and audit requests.

### C++ selected adapter/provider

- resolves the actual provider,
- reaches and parses the actual key,
- checks algorithm compatibility and certificate binding,
- performs signing with the returned handle,
- produces the actual operation result or stable failure.

The Go `CheckReady` result is not cryptographic signing evidence. A release or
audit claim about actual signing must be backed by the C++ provider path and its
positive/negative tests.

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

Only stable codes and redacted stages such as `resolve`, `open`, `parse`,
`algorithm`, `binding`, `policy`, and `sign` may leave the provider boundary.
Raw paths, PEM data, credentials, PINs, session tokens, and raw provider/OpenSSL
errors are prohibited.

## Production Gates

Production mode fails closed when:

- the selected provider is the exportable file provider,
- provider availability/readiness fails,
- the key cannot be found or parsed,
- the requested algorithm is incompatible,
- issuer certificate/key binding fails,
- the selected backend/profile is incompatible,
- configuration would require fallback.

`ANOPKI_ENV=production` causes certificate issuance through the file provider to
return `provider.exportability_violation` before the key file is opened.

## Current Scope Limits

- Certificate issuance: provider-isolated through `FileKeyProvider`.
- CRL signing: unchanged; direct file-key path remains.
- OCSP signing: unchanged; direct file-key path remains.
- Non-exportable provider: not implemented.
- Remote KMS prepare/sign/finalize: not implemented.
- Enterprise/AnoCrypto-C provider compatibility: not implemented.

No production HSM/KMS/PKCS#11 or non-exportability claim is allowed from this
slice.
