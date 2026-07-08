# PKI Context

`AnoPKI` is a lifecycle control plane around a signing core. It is not a
standalone certificate generator.

## Trust Boundary

- Operators and ACME clients enter through the Go HTTP API.
- Lifecycle policy and audit live in the Go service.
- Signing, CSR inspection, CRL generation, and OCSP DER work live behind the
  core CLI boundary.
- Private keys are referenced by `key_ref`; key material must stay outside the
  service database and API responses.

## Primary Flows

- Issuance: [issuance-flow.md](issuance-flow.md)
- Renewal: [renewal-flow.md](renewal-flow.md)
- Revocation: [revocation-flow.md](revocation-flow.md)
- CA hierarchy: [ca-hierarchy.md](ca-hierarchy.md)

## Current Evidence

- [Target architecture](../reference/target-architecture.md)
- [Project scope](../reference/project-scope.md)
- [State transitions](../reference/state-transitions.md)
- [Compliance matrix](../reference/compliance-matrix.md)

