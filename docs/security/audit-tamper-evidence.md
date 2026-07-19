# Audit Tamper Evidence

AnoPKI Community stores Audit events in a deterministic `sha256-v1` hash chain.
The Memory, SQLite, and PostgreSQL repositories share the same append, verify,
checkpoint, and retention contract.

## Chain Model

Each row stores:

- `sequence`: a monotonic integer beginning at 1,
- `hash_algorithm`: `sha256-v1`,
- `previous_event_hash`: the previous row hash, or empty for the genesis row,
- `event_hash`: the current row hash.

The hash is:

```text
event_hash = SHA-256(previous_event_hash || canonical_event_json)
```

The canonical JSON commits the algorithm, sequence, event ID, actor, action,
resource type, resource ID, parsed-and-remarshaled metadata JSON, and UTC
RFC3339Nano timestamp. Database-local fields and export envelopes are excluded.

## Migration

Schema migration v2 adds the chain columns and `audit_chain_state`. Existing
Audit rows are read in deterministic `created_at, id` order and backfilled
before the unique sequence index is created. A dirty, malformed, or
non-canonical legacy row fails migration closed.

`audit_chain_state` stores the latest sequence/hash and the retention checkpoint.
PostgreSQL append and prune operations lock this singleton state row in the same
transaction; SQLite serializes the same update through its transaction.

## Verification And Query

`GET /audit-events/integrity` recomputes the retained chain and verifies it
against the latest state and checkpoint. The response reports the algorithm,
event count, first/last sequence, latest hash, checkpoint, and a stable failure
reason when invalid.

Append and retention prune verify the chain before changing state. A damaged
row, sequence, latest state, or checkpoint returns `audit_integrity_failed` and
no append or prune is committed.

## Retention Checkpoint

Retention deletes only a contiguous oldest prefix. Before deletion, the last
removed row becomes the checkpoint. The first retained row must reference that
checkpoint hash. The separate latest sequence/hash also detects checkpoint
mutation when no retained rows remain.

The checkpoint preserves chain continuity across pruning; it is not an external
notary. Operators that require independent proof should export or anchor the
latest sequence/hash in controlled release or SIEM evidence.

## Incident Handling

- Treat any invalid integrity report as an incident.
- Do not rewrite hashes or silently repair the chain.
- Preserve the database and relevant backup evidence.
- Stop append and retention operations until the cause is understood.
- Recover only from a reviewed, integrity-verified source.
