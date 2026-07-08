# Issuance Runbook

## Normal Issuance

1. Confirm identity owner, service, environment, and allowed DNS/IP values.
2. Select a certificate profile.
3. Create enrollment with CSR and requested identifiers.
4. Approve enrollment only after profile and ownership checks pass.
5. Issue certificate from the approved enrollment.
6. Check audit event and outbox delivery.

## Emergency Issuance

- Treat as break-glass.
- Record actor, reason, affected service, and follow-up review.
- Prefer short validity and planned replacement.

## References

- [Issuance flow](../architecture/issuance-flow.md)
- [API errors](../reference/api-errors.md)
- [Manual demo](../runbooks/manual-demo.md)

