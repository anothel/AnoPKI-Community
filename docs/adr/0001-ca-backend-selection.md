# ADR 0001: CA Backend Selection

## Status

Accepted baseline; refined for adapter separation.

## Decision

Use the C++ `anopki-core` CLI as the signing, CSR inspection, CRL, and OCSP
operation boundary. Keep the Go service as lifecycle, policy, API, persistence,
and audit owner.

The C++ side must evolve into:

```text
AnoPKI Core -> selected backend adapter -> backend dependency
```

The Community product assembles the backend-neutral core with the OpenSSL
adapter. Enterprise reuses the same core contract and may assemble either the
Community OpenSSL adapter or an Enterprise AnoCrypto-C adapter.

## Consequences

- The Go service does not own low-level cryptographic-library behavior.
- The core operation and JSON contracts remain stable across adapters.
- Direct OpenSSL calls must move out of backend-neutral core code and into the
  OpenSSL adapter as the refactor proceeds.
- Enterprise adapters must not require public API changes merely to select a
  backend.
- Core CLI contract and golden tests guard the Go-to-C++ boundary and adapter
  parity.
- Crypto adapter selection remains separate from HSM/KMS/PKCS#11 key-provider
  selection.
