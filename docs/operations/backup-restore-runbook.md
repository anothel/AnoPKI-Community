# Backup And Restore Runbook

Use [production recovery](../runbooks/production-recovery.md) as the detailed
restore procedure.

## Restore Drill Checklist

Run `python scripts/verify-recovery-drill.py --out-dir .tmp/recovery-evidence/manual` for the maintained SQLite state-preservation baseline.

- schema version clean
- issuer records and `key_ref` values present
- active OCSP responders present
- latest CRL artifacts present
- outbox and webhook state present
- audit events queryable
- issuance attempts consistent
- readiness endpoints pass
- non-production issuance smoke passes

## Evidence Boundary

The maintained SQLite drill verifies migration state, issuer/responder key
references, CRL artifacts, signed issuance attempts, audit records, outbox/job
attempts and webhook delivery state. Its evidence contains hashes and counts,
not the database or raw sensitive values.

## Rule

Backups must not include private key bytes unless the selected external key
provider explicitly owns encrypted key backup outside this service.

