# SIEM Export And Detection Examples

This is the selected release-candidate format for exporting audit events to a
SIEM. It is a contract for future exporters, not a live integration.

## Export Event Shape

Emit one JSON object per audit event:

```json
{
  "event_type": "anopki.audit",
  "event_id": "audit-1",
  "actor": "operator",
  "action": "certificate.issued",
  "resource_type": "certificate",
  "resource_id": "certificate-1",
  "result_code": "ok",
  "error_code": "",
  "created_at": "2026-07-05T00:00:00Z",
  "metadata": {
    "issuer_id": "issuer-1",
    "certificate_id": "certificate-1",
    "serial_number": "01"
  }
}
```

Keep raw secrets, tokens, passwords, and private key material out of the export;
the source audit metadata redacts those fields before export.

## Detection Examples

| Detection | Match |
| --- | --- |
| Failed issuance spike | `action = api.request_failed` and `error_code = certificate_issuance_failed` more than 3 times in 10 minutes |
| Unexpected revocation | `action in (certificate.revoked, certificate.force_revoked)` outside approved maintenance window |
| Policy churn | `action = certificate_profile.created` by non-standard operator or repeated more than 5 times per day |
| Key-provider use | `action in (issuer.created, ocsp_responder.created, ocsp_responder.disabled)` |
| Audit repair | `action = certificate.issuance_audit_repaired` |
| Break-glass candidate | `actor = break-glass` or `api_key_scopes` contains `operator` outside change window |
| Authorization deny/error | `authorization_outcome in (deny, approval_required, error, invalid)` grouped by `authorization_reason_code`, `authorization_policy_revision`, or route |

## Export Rules

- Preserve `request_id`, `traceparent`, `client_ip`, `user_agent`, and
  `auth_method` when present.
- Preserve `api_key_id`, `api_key_actor`, `api_key_fingerprint`, and
  `api_key_scopes`; never export API key tokens or token hashes.
- Preserve bounded `authorization_outcome`, `authorization_evaluator_status`, `authorization_decision_id`, `authorization_reason_code`, and `authorization_policy_revision` when present; never export raw evaluator errors or policy input claims.
- Include Audit `sequence`, `hash_algorithm`, `previous_event_hash`, `event_hash`, and integrity/checkpoint state in controlled exports.
- Treat exporter failure as an operator alert, not as a reason to block the
  lifecycle write path.
