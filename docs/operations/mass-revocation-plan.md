# Mass Revocation Plan

This plan points to existing public TLS and incident runbooks and names required
evidence.

## Drill Steps

1. Identify affected issuer/profile/domain/service set.
2. Freeze risky issuance.
3. Prioritize public TLS, production mTLS, and high-impact services.
4. Notify service owners.
5. Revoke affected certificates.
6. Publish CRLs and verify OCSP.
7. Issue replacements.
8. Verify deployment health.
9. Capture timeline, gaps, and signoff.

## Evidence

- affected certificate list
- owner notifications
- revocation request timestamps
- CRL/OCSP verification timestamps
- replacement certificate IDs
- post-drill action items

