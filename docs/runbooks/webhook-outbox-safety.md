# Webhook And Outbox Safety Runbook

## Receiver Verification

Receivers must verify:

- `X-AnoPKI-Timestamp` is within 5 minutes of receiver time.
- `X-AnoPKI-Delivery` has not been accepted before.
- `X-AnoPKI-Signature` equals `sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw_body)>`.
- `outbox_message_id`, `event_type`, `payload`, `created_at`, and `schema_version` are present.

Minimal Go verification:

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write([]byte(timestamp))
mac.Write([]byte("."))
mac.Write(rawBody)
want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(got), []byte(want)) {
	return errors.New("bad signature")
}
```

Replay cache rule: store `X-AnoPKI-Delivery` for at least the timestamp skew window plus retry jitter. Reject duplicates after a successful 2xx response.

## Payload Schema Versioning

- Current schema version: `1`.
- Producers must include `schema_version` on new webhook payloads.
- Consumers must ignore unknown fields.
- Breaking payload changes require a new schema version and parallel delivery support during migration.

## Dead-Letter Replay

- List dead letters: `GET /outbox/messages?status=dead_letter`.
- Retry one message: `POST /outbox/messages/{id}/retry`.
- Replay only after the downstream receiver is fixed and idempotency is confirmed.
- Renewal, revocation, CRL, and OCSP events are state notifications. Receivers must re-read current certificate/CRL/OCSP state before applying side effects.
- Do not bulk replay mixed event types during incident recovery. Replay by event type and time window.
