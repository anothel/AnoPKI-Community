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


## Crypto Backend Separation

Key providers are not the same as crypto backends. A key provider answers where the private key lives and whether it is exportable. A crypto backend answers which implementation performs parsing, encoding, and cryptographic operations.

AnoPKI currently uses OpenSSL-backed core operations. The intended crypto backend direction is **AnoCrypto**, tracked in [Crypto backend strategy](../reference/crypto-backend-strategy.md) and ADR 0006. AnoCrypto adoption must not weaken `key_ref` boundaries or production non-exportability requirements.

## Provider Classes

| Class | Intended use | Key export | Example reference shape |
| --- | --- | --- | --- |
| File | Local development and smoke tests only | Exportable by OS file access | `file:/var/lib/AnoPKI/issuer.key` |
| HSM or PKCS#11 | Production CA and responder signing | Non-exportable | `pkcs11:token=ca;object=issuer-a` |
| Cloud KMS | Production signing where cloud controls fit policy | Non-exportable | `kms:provider/key/version` |

Do not infer provider class from a database column alone. Provider resolution
must be explicit in configuration so production mode can reject local file
providers.

## Required Operations

- `DescribeKey(key_ref)` returns provider class, algorithm, public key or
  certificate binding material, and exportability.
- `Sign(key_ref, algorithm, digest_or_tbs)` signs certificate, CRL, or OCSP
  material without exposing private key bytes.
- `CheckReady(key_ref)` proves the provider and key are reachable before
  issuance, CRL publication, or OCSP response signing.

The service should keep provider errors stable at the API boundary. Raw provider
errors can go to operator logs only after secret redaction.

## Audit Semantics

Audit metadata for provider-backed signing must record:

- provider class,
- non-exportable/exportable status,
- operation type,
- caller request id or trace id,
- provider result code.

Issuer registration, certificate issuance with available issuer metadata, OCSP
responder registration, CRL publication, and OCSP response audit now record
provider class and exportability expectation without recording raw `key_ref`
values.

Audit metadata must not record private key material, raw `key_ref` file paths,
provider credentials, session tokens, PINs, or raw provider error strings that
may contain secrets.

## Production Gates

Production mode must fail closed when:

- an issuer or active OCSP responder uses a local file provider,
- provider readiness cannot be checked,
- provider metadata says the key is exportable,
- algorithm metadata does not match the requested profile or responder
  certificate.

## Implementation Notes

Issuer and OCSP responder creation currently reject `kms:` and `pkcs11:` key
references until provider-backed signing exists. Issuer and OCSP responder
creation reject local file key references in production mode. A minimal
`keyref.Provider` readiness contract exists with a file provider for local
tests, and certificate issuance, CRL publication, and OCSP response signing gate
core signer calls on provider readiness. The current signing path still uses
file key references. Successful key-provider audit metadata records provider
operation result code without raw `key_ref` values.
