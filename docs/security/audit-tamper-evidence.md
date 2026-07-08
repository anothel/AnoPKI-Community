# Audit Tamper-Evidence Plan

This plan adds tamper evidence without changing the current pre-1.0 storage
contract yet.

## Selected Model

- Keep `audit_events` append-only at the application boundary.
- Add a deterministic hash chain when audit storage becomes release-gating:
  `event_hash = SHA-256(previous_event_hash || canonical_event_json)`.
- Store `previous_event_hash` and `event_hash` with each audit row.
- Anchor the latest hash in each release candidate evidence pack or operator
  export before pruning old rows.
- Verify the chain during backup/restore drills and SIEM export jobs.

## Canonical Event JSON

The canonical payload includes:

- audit event ID,
- actor,
- action,
- resource type,
- resource ID,
- metadata JSON,
- created timestamp.

It excludes database-local row IDs and mutable export envelope fields.

## Failure Handling

- Reject writes when the previous event hash cannot be read.
- Treat chain verification failure as an incident.
- Do not repair hashes in place. Create an incident record and preserve the
  broken rows for investigation.

## Implementation Trigger

Implement the hash columns, migration, and verifier when audit retention or SIEM
export becomes release-gating. Until then, keep this as the selected storage
plan and rely on existing append-only service behavior plus backup controls.
