# Revocation Runbook

## Reasons

- key compromise
- CA compromise
- affiliation changed
- superseded
- cessation of operation
- privilege withdrawn

## Procedure

1. Confirm certificate ID, owner, issuer, serial, and blast radius.
2. Pick revocation reason.
3. Revoke certificate.
4. Publish CRL if issuer distribution requires it.
5. Test OCSP response for affected serial.
6. Start replacement issuance when service must continue.
7. Record incident link and follow-up action.

## References

- [Incident response](../runbooks/incident-response.md)
- [Revocation flow](../architecture/revocation-flow.md)

