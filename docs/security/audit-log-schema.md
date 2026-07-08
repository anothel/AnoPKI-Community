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

- evidence pack for policy changes
