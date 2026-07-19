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

## Chain, Retention, And Query

Every row carries a monotonic `sequence`, `hash_algorithm=sha256-v1`,
`previous_event_hash`, and `event_hash`. `GET /audit-events/integrity` verifies
the retained chain, latest state, and prune checkpoint. Retention verifies first,
deletes only a contiguous prefix, advances the checkpoint, and fails closed on
tamper.

Production deployments must define retention duration, independent chain-anchor
or export requirements, and incident handling for an invalid integrity report.

## Gaps

- independently anchored export or SIEM custody integration
- evidence pack for policy changes
