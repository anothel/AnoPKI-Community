# Renewal Flow

1. Expiration scan marks expired certificates and creates one renewal warning
   per eligible certificate inside the warning window.
2. Operator or automation requests renewal for an existing certificate.
3. Service creates a new enrollment tied to the existing identity and profile.
4. Existing profile and identity SAN policy apply again.
5. Approval and issuance follow the normal issuance flow.

## Current Evidence

- `renewal_notified_at` prevents duplicate renewal warnings.
- Expiry SLO tracks valid or suspended certificates inside the 14-day window.
- Renewal/reissue APIs preserve lifecycle history.

## Gaps

- Deployment reload/rollout verification.
- Automated rollback after failed replacement.
- External notification escalation policy per owner/team.

