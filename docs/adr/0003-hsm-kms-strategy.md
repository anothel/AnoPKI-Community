# ADR 0003: HSM/KMS Strategy

## Status

Proposed.

## Decision

Production issuers and responders should use non-exportable key references
through HSM, KMS, or PKCS#11 providers. File-backed keys are local/dev only.

## Consequences

- API and audit should prove private key material was not exported.
- Key ceremony and dual-control evidence are required before production use.
- Provider implementation is deferred until one deployment target is selected.

