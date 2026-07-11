# Key Provider Semantics

This document selects the production signing semantics for issuer and OCSP
responder keys. It does not implement an HSM, KMS, or PKCS#11 provider.

## Selected Boundary

All issuer and OCSP responder signing uses a `key_ref`.

- `file:` or bare filesystem references are local/dev only.
- Production providers use non-exportable references.
- The service may ask a provider to sign, identify a public key, and report key
  metadata.
- The service must not request, read, store, log, or return private key bytes.

## Adapter And Provider Separation

A backend adapter and a key provider are different boundaries.

- Backend adapter: implements the selected PKI operation profile through
  OpenSSL or external AnoCrypto-C.
- Key provider: owns key location, exportability, readiness, signing
  authorization, and provider audit metadata.

The product profile explicitly selects OpenSSL or AnoCrypto-C. Key-provider
selection is configured separately. Missing AnoCrypto-C capability or provider
failure must not trigger an implicit OpenSSL/file-key fallback.

## Provider Classes

| Class | Intended use | Key export | Example reference shape |
| --- | --- | --- | --- |
| File | Local development and smoke tests only | Exportable by OS file access | `file:/var/lib/anopki/issuer.key` |
| HSM or PKCS#11 | Production CA and responder signing | Non-exportable | `pkcs11:token=ca;object=issuer-a` |
| Cloud KMS | Production signing where cloud controls fit policy | Non-exportable | `kms:provider/key/version` |

Provider resolution must be explicit so production mode can reject local file
providers.

## Required Operations

- `DescribeKey(key_ref)` returns provider class, algorithm, public key or
  certificate binding material, and exportability.
- `Sign(key_ref, algorithm, digest_or_tbs)` signs without exposing private key
  bytes.
- `CheckReady(key_ref)` proves provider and key reachability before issuance,
  CRL publication, or OCSP response signing.

Provider errors remain stable at the API boundary. Raw provider errors may go
to operator logs only after secret redaction.

## Audit Semantics

Provider-backed signing audit metadata records:

- product profile and backend adapter,
- provider class,
- non-exportable/exportable status,
- operation type and algorithm,
- request or trace id,
- provider result code,
- whether any compatibility mode was selected.

Audit metadata must not record private keys, raw file paths, credentials,
session tokens, PINs, or raw provider error strings that may contain secrets.

## Production Gates

Production mode fails closed when:

- an issuer or active responder uses a local file provider,
- provider readiness cannot be checked,
- provider metadata says the key is exportable,
- algorithm metadata does not match the requested profile,
- selected backend capability is unavailable,
- configuration would require an undeclared fallback.

## Implementation Notes

Current signing still uses local file references in the OpenSSL-backed path.
The next boundary work is to move signing behind provider and backend adapter
contracts, add mock/software-token tests, and preserve Community/OpenSSL
behavior before wiring real providers.
