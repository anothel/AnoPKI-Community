# ADR 0003: HSM/KMS Strategy

## Status

Accepted policy; implementation architecture refined by ADR 0007.

## Decision

Production issuers and responders should use non-exportable key references
through HSM, KMS, or PKCS#11 providers. File-backed keys are local/dev only.

## Consequences

- API and audit should prove private key material was not exported.
- Key ceremony and dual-control evidence are required before production use.
- Provider implementation is deferred until one deployment target is selected.



## Refinement

[ADR 0007](0007-key-provider-signing-boundary.md) selects a deliberately scoped hybrid: an in-process OpenSSL-compatible provider seam for the first file/PKCS#11 path, with remote KMS requiring a separately approved integration protocol.
