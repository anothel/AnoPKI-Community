# Backup And Restore Runbook

Use [production recovery](../runbooks/production-recovery.md) as the detailed
restore procedure.

## Restore Drill Checklist

Run `python scripts/verify-recovery-drill.py --out-dir .tmp/recovery-evidence/manual` for the maintained SQLite state-preservation baseline. For PostgreSQL 16, set `ANOPKI_POSTGRES_RECOVERY_DSN` to a disposable control database and run `python scripts/verify-postgres-recovery-drill.py --out-dir .tmp/postgres-recovery-evidence/manual`.

- schema version clean
- issuer records and `key_ref` values present
- active OCSP responders present
- latest CRL artifacts present
- outbox and webhook state present
- audit events queryable
- issuance attempts consistent
- readiness endpoints pass
- non-production issuance smoke passes

## PostgreSQL Drill Requirements

- PostgreSQL server major 16
- `psql`, `pg_dump`, and `pg_restore` from a PostgreSQL 16 client package
- a role allowed to create and drop isolated recovery databases
- a disposable control DSN, never a production database
- Go 1.25.11 or newer

The drill uses a custom-format dump, intentionally damages the source database,
restores into a separate fresh database, and deletes the temporary databases and
dump after verification.

## Evidence Boundary

The maintained SQLite and PostgreSQL drills verify migration state,
issuer/responder key-reference preservation, CRL artifacts, signed issuance
attempts, audit records, outbox/job attempts and webhook delivery state. The
PostgreSQL drill additionally proves transactional rollback for a failed
migration and fail-closed dirty-migration detection. Evidence contains hashes,
counts and tool versions, not database dumps, DSNs or raw sensitive values.

## Rule

Backups must not include private key bytes unless the selected external key
provider explicitly owns encrypted key backup outside this service.

