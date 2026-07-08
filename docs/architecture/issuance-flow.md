# Issuance Flow

1. Caller creates or selects an identity.
2. Caller creates an enrollment with CSR and requested identifiers.
3. Service validates identity DNS/IP allow-lists and certificate profile policy.
4. Operator approves or rejects the enrollment.
5. Service claims issuance by enrollment ID to prevent duplicate signing.
6. Core CLI inspects and signs.
7. Service stores certificate state, audit event, and outbox event.

## Safety Properties

- Issuance requires an approved enrollment.
- Retries are idempotent through `certificate_issuance_attempts`.
- API responses must not expose private key material.
- Missing issuance audit can be repaired from persisted certificate state.

## References

- [Issuance consistency](../reference/issuance-consistency.md)
- [State transitions](../reference/state-transitions.md)
- [Issuance runbook](../operations/issuance-runbook.md)

