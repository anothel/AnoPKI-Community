# Key Ceremony

## Current Boundary

The service stores issuer and responder `key_ref` values. It must not store
private key material. Selected provider behavior is documented in
[Key provider semantics](../security/key-provider-semantics.md).

## Ceremony Baseline

1. Assign roles: ceremony lead, security approver, operator, witness.
2. Record CA purpose, environment, and profile scope.
3. Generate or import key in selected provider.
4. Record non-exportable key reference.
5. Create issuer or responder record with `key_ref`.
6. Verify backup/recovery process for provider metadata.
7. Store signed evidence outside application DB.

## Gaps

- HSM/KMS/PKCS#11 provider implementation.
- Dual-control implementation.
- Intermediate rollover runbook.
