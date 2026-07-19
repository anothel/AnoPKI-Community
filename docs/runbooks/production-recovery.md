# Production Recovery Runbook

## Backup Rules

- Back up the database before every schema migration and before issuer, OCSP responder, CRL, or lifecycle-job bulk changes.
- Back up `schema_migrations`, `audit_events`, `issuers`, `ocsp_responders`, `crl_publications`, `outbox_messages`, `job_attempts`, `webhook_deliveries`, `certificate_issuance_attempts`, `certificates`, `revocations`, and `api_keys` in one consistent database snapshot.
- Store issuer and responder private keys in the configured key provider. Database backups must preserve only key references, never private key material.
- Keep the latest published CRL PEMs from `crl_publications` with the database backup so distribution can be restored without regenerating a different artifact.
- Keep restore credentials and key-provider recovery credentials outside the restored database.

## Rollback Rules

- Do not roll back by editing `schema_migrations` directly.
- If migration startup fails before `schema_migrations.dirty=false`, restore the pre-migration database snapshot.
- If migration startup fails after `dirty=false`, treat the new schema as active and roll forward unless a restore test proves rollback preserves audit, CRL, OCSP, and outbox state.
- Rollback must preserve audit events. Missing audit for issuance can be repaired with `POST /audit-events/repair/issuance`; other missing audit requires incident review.
- Rollback must preserve issuer `key_ref` and OCSP responder `key_ref`. If a referenced key is unavailable, disable issuance and OCSP responder rotation until key-provider recovery finishes.
- Rollback must preserve lifecycle outbox state. Do not replay all outbox rows blindly; use dead-letter retry rules below.

## Restore Rules

- Restore database first, then verify key-provider access for every active issuer and active OCSP responder.
- Run `GET /readyz`, `GET /trust/anchors`, `GET /issuers/{id}/crl`, and a known-good `POST /ocsp` request before re-enabling issuance.
- Verify `schema_migrations` has version `1`, expected checksum, and `dirty=false`.
- Verify the newest CRL per issuer is still available and has the expected CRL number.
- Verify `certificate_issuance_attempts` before retrying failed issuance finalization. If an attempt is `signed`, retry issuance for the same enrollment; the service should finalize from stored signed material.
- Restart lifecycle workers only after restore checks pass.

## Disaster-Recovery Drills

### Database Loss

1. Stop service nodes and lifecycle workers.
2. Restore the latest consistent DB backup.
3. Check `schema_migrations`, active issuers, active OCSP responders, latest CRLs, outbox status, and issuance attempts.
4. Start one service node.
5. Run `GET /readyz`, `GET /trust/anchors`, `GET /certificates?expires_within_days=14`, and `GET /operator/expiry-slo`.
6. Start remaining nodes and workers.

### Signer Or Key-Provider Loss

1. Disable issuance traffic at the gateway.
2. Verify which issuer and OCSP responder `key_ref` values are unavailable.
3. Restore key-provider access or rotate affected responders.
4. Run a test issuance against a non-production profile.
5. Re-enable issuance only after audit event creation and outbox delivery work.

### CRL Publication Failure

1. Check latest `crl_publications` row for the issuer.
2. Republish the latest stored PEM if generation failed after persistence.
3. If no valid CRL exists, fix signer access and call `POST /crls`.
4. Verify `GET /issuers/{id}/crl` returns the latest CRL number.

### OCSP Responder Failure

1. Check active responder for the issuer.
2. If responder key is unavailable, rotate with `POST /issuers/{id}/ocsp-responders/rotate`.
3. If no responder is active, issuer-direct signing remains compatibility fallback; use it only while responder recovery runs.
4. Verify `POST /ocsp` for valid, revoked, and unknown serials.

### Failed Issuance Finalization

1. Inspect `certificate_issuance_attempts` for the enrollment.
2. If status is `signed`, retry `POST /certificates` with the same enrollment ID.
3. Confirm no second signer call occurred.
4. Run `POST /audit-events/repair/issuance` if the certificate exists but the issued audit event is missing.
## Executable Recovery And Status-Outage Evidence

Run the deterministic Community drill from the repository root:

```powershell
python scripts\test_verify_recovery_drill.py
python scripts\verify-recovery-drill.py --out-dir .tmp\recovery-evidence\manual
python scripts\test_verify_status_outage_drill.py
python scripts\verify-status-outage-drill.py --out-dir .tmp\status-outage-evidence\manual
python scripts\test_verify_audit_replay_drill.py
python scripts\verify-audit-replay-drill.py --out-dir .tmp\audit-replay-evidence\manual
python scripts\test_verify_issuer_rollover_drill.py
python scripts\verify-issuer-rollover-drill.py --out-dir .tmp\issuer-rollover-evidence\manual
python scripts\test_verify_postgres_recovery_drill.py
$env:ANOPKI_POSTGRES_RECOVERY_DSN = "postgres://anopki:anopki@localhost:5432/anopki_recovery_control?sslmode=disable"
python scripts\verify-postgres-recovery-drill.py --out-dir .tmp\postgres-recovery-evidence\manual
```

The drill creates the current SQLite schema, seeds issuer and OCSP responder
references, a signed issuance attempt, certificate/revocation state, a published
CRL, audit events, dead-letter outbox state, webhook delivery state and API-key
metadata. It then creates a consistent SQLite backup, deliberately damages the
live copy, restores from the backup and verifies:

- clean migration version and checksum,
- SQLite integrity and foreign-key integrity,
- exact restored-state digest and table counts,
- issuer/responder key-reference preservation without exposing their values,
- latest CRL artifact preservation,
- durable no-fallback signing evidence,
- audit, outbox, job-attempt and webhook-delivery state,
- absence of private-key PEM markers from the database and evidence.

The JSON and Markdown recovery evidence contain hashes and counts only. They do
not package database files, raw `key_ref` values, webhook secrets, API-key hashes
or private-key material. The separate status-outage drill executes the exact
lifecycle and HTTP CRL/OCSP failure-and-recovery regressions. It proves no
phantom CRL publication or success audit is created during signer failure, public
failures map correctly, CRL numbering resumes without a skipped publication and
recovered operations return through the normal signing-evidence contract. The audit/replay drill separately proves idempotent issuance-audit reconstruction, scoped dead-letter selection, preserved job/webhook history, and successful completion only after receiver recovery. The issuer-rollover drill proves an atomic same-root intermediate transition, overlap operation for old certificates and CRLs, stale-retry rejection, and explicit rollback without duplicate audit or outbox events.

These drills cover deterministic SQLite and PostgreSQL 16 backup/restore,
transactional migration rollback, intermediate rollover, single-node CRL/OCSP
signer-outage semantics, and shared-PostgreSQL lease-expiry takeover with stale-node
rejection for issuance, CRL and Outbox. Infrastructure-level primary failover,
network-partition traffic and real key-provider recovery remain separate operational
evidence.
