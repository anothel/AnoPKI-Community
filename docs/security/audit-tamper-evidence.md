# Audit Tamper Evidence

AnoPKI stores audit events in a `sha256-v1` chain that is append-only between
checkpointed retention operations.

## Stored Fields

Each event stores:

- monotonic `chain_index`,
- `hash_algorithm=sha256-v1`,
- `previous_event_hash`,
- `event_hash`.

The canonical payload includes the chain index, previous hash, event ID, actor,
action, resource type and ID, canonical JSON metadata, and UTC timestamp. A
domain separator prevents reuse as an unrelated SHA-256 payload.

## Write Semantics

SQL writes update the event and singleton chain-tail state in one transaction.
The tail update uses compare-and-swap semantics; concurrent or stale writers fail
closed with an audit-chain conflict and the transaction rolls back. Invalid
metadata JSON is rejected before hashing. Memory storage uses the same canonical
hash implementation under its transaction lock.

## Retention Checkpoints

Retention removes only a contiguous expired prefix. Before deletion, the store
writes an immutable checkpoint containing the last removed chain index, event ID,
event hash, cutoff, and creation time. Retained events continue from that hash.
The chain tail and total event count are not reset by pruning.

## Verification

`GET /audit-events/integrity` verifies:

- supported hash algorithm,
- contiguous chain indexes,
- previous-hash linkage,
- recomputed event hashes,
- latest checkpoint continuity,
- persisted chain-tail state.

Verification never repairs hashes. A failure is an incident and the rows must be
preserved for investigation. Retention pruning also verifies the chain first, so
a damaged prefix cannot be deleted and replaced with a checkpoint that appears
healthy.

## Security Boundary

The in-database chain detects accidental corruption and edits that are not
coordinated with the chain state. It does not by itself defeat a privileged
attacker who can rewrite events, checkpoints, and chain-tail state and then
recompute every hash. Database access controls, backup evidence, and an external
immutable anchor are still required for stronger tamper resistance.

## Remaining Work

Release evidence records the exact-commit verification result. Exporting the
latest checkpoint or tail hash to a third-party immutable anchor remains pending
until a concrete operator or SIEM integration is selected.
