# Revocation Flow

1. Operator requests revocation for a valid or suspended certificate.
2. Service validates transition and reason.
3. Service creates revocation state and audit event.
4. CRL publication uses revocation records to produce signed CRL artifacts.
5. OCSP response maps revoked serials to `revoked`.
6. Incident runbooks decide whether replacement issuance is needed.

## Current Evidence

- [Incident response runbook](../runbooks/incident-response.md)
- [Public TLS readiness runbook](../runbooks/public-tls-readiness.md)
- [State transitions](../reference/state-transitions.md)

## Gaps

- Scheduled mass-revocation tabletop evidence.
- Revocation SLA dashboard.
- Automated replacement workflow after revocation.

