# ADR 0001: CA Backend Selection

## Status

Accepted baseline.

## Decision

Use the existing C++ core CLI as the first signing, CSR inspection, CRL, and
OCSP DER boundary. Keep the Go service as lifecycle, policy, API, and audit
owner.

## Consequences

- Go service avoids owning low-level OpenSSL behavior.
- Core CLI contract tests and JSON field parity validation guard the
  Go-to-C++ boundary.
- Production key-provider boundary still needs HSM/KMS/PKCS#11 design.
