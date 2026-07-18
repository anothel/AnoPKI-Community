# Audit Log Schema

Audit details are defined in [audit metadata](../reference/audit-metadata.md).
Tamper-evidence storage is defined in
[audit tamper-evidence](audit-tamper-evidence.md).
SIEM export format and starter detections are defined in
[SIEM detections](siem-detections.md).

## Required Properties

- actor
- action
- resource type
- resource ID
- request ID or trace ID when available
- authentication context
- state transition metadata
- redacted secret handling
- failure result code for rejected API requests

## Retention And Query

The service supports audit query filters, pagination, sorting, and retention
pruning. Production deployments must define retention duration and export
requirements.

## Gaps

- external immutable anchoring or signed SIEM export for the latest checkpoint
  and chain tail


## Tamper-Evidence Fields

- `chain_index`: monotonic insertion order independent of event timestamp.
- `hash_algorithm`: currently `sha256-v1`.
- `previous_event_hash`: the prior retained or checkpointed event hash.
- `event_hash`: canonical event digest.

Retention checkpoints preserve the last removed event hash so verification can
continue after pruning. Hashes are evidence fields and must not be rewritten in
place.
