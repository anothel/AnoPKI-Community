# Backup And Restore Runbook

Use [production recovery](../runbooks/production-recovery.md) as the detailed
restore procedure.

## Restore Drill Checklist

- schema version clean
- issuer records and `key_ref` values present
- active OCSP responders present
- latest CRL artifacts present
- outbox and webhook state present
- audit events queryable
- issuance attempts consistent
- readiness endpoints pass
- non-production issuance smoke passes

## Rule

Backups must not include private key bytes unless the selected external key
provider explicitly owns encrypted key backup outside this service.

