# API Surface Status

This reference labels the exposed API surface for pre-1.0 use. It is not a
compatibility promise; it tells operators which surfaces are implemented,
partial, planned, smoke-only, or not-production-stable.

## Status Labels

| Label | Meaning |
| --- | --- |
| Implemented | Handler, persistence, docs, and regression coverage exist. |
| Partial | Core path exists, but production evidence or edge coverage is incomplete. |
| Planned | Roadmap item; do not build clients against it yet. |
| Smoke-only | Intended for local compatibility or release-candidate smoke tests. |
| Not-production-stable | Pre-1.0 behavior can still change before release evidence closes. |

## Feature Status Matrix

| Area | Status | Evidence | Remaining gap |
| --- | --- | --- | --- |
| Identity, issuer, profile, enrollment, approval, issuance | Implemented, not-production-stable | Service README, OpenAPI, state transitions, Go/C++ boundary tests. | Public API compatibility freeze. |
| Certificate inventory, renewal, reissue, revocation, suspension, expiration scan | Implemented, not-production-stable | Service README, state transitions, lifecycle tests. | Deployment-target automation remains planned. |
| CRL publication and OCSP response | Implemented, not-production-stable | Service README, core CLI contract, CRL/OCSP tests. | HA deployment and outage drill evidence. |
| Delegated OCSP responder registration and rotation | Implemented, not-production-stable | Service README, OpenAPI, lifecycle tests. | Production key-provider boundary. |
| Audit events, outbox, webhook delivery | Partial, not-production-stable | Service README, webhook receiver reference, outbox tests, audit tamper-evidence plan, SIEM detection examples. | Tamper-evident hash-chain implementation and SIEM exporter integration. |
| API key auth and operational probes | Implemented, not-production-stable | Service README, production startup guard tests, access model. | First-class role/ABAC enforcement waits for an operator directory. |
| Public RFC 8555 ACME protocol adapter | Partial, smoke-only, not-production-stable | RFC 8555 conformance matrix plus lego and WSL certbot smoke evidence. | EAB and DNS-01 remain gated. |
| Internal ACME state management endpoints | Implemented, not-production-stable | Service README, OpenAPI, store tests. | Operator-facing shape can change before 1.0. |
| Release artifact provenance | Partial | Release evidence, version metadata validation, artifact smoke validation, and release workflow docs. | Compatibility matrix evidence per release candidate. |
| HSM/KMS/PKCS#11 signing boundary | Planned | Roadmap, ADR, key provider semantics, production file-provider readiness tests, issuer/responder/certificate-issuance key-provider audit metadata, CRL/OCSP signing audit metadata, and unsupported provider ref rejection for issuer/responder creation. | Provider implementation, signing-path split, and non-exportable provider support. |

## Endpoint Stability Labels

| Label | Endpoint groups |
| --- | --- |
| Stable | Public distribution endpoints: `GET /crls/{id}`, `GET /issuers/{id}/crl`, `POST /ocsp`. |
| Experimental | Lifecycle and operator APIs: identities, issuers, profiles, enrollments, certificates, CRLs, OCSP responders, audit, outbox, webhooks, API keys, trust anchors, inventory, and expiry SLO. |
| Internal | `GET /debug/vars`, operational probes, and internal ACME state endpoints: `/acme/accounts`, `/acme/orders`, `/acme/authorizations`, `/acme/challenges`. |
| Smoke-only | Local ACME bootstrap behavior controlled by `ANOPKI_ACME_BOOTSTRAP_DEFAULTS` and `ANOPKI_ACME_HTTP01_BASE_URL`. |
| Experimental, smoke-only | Public ACME protocol endpoints: `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/account/{id}`, `/acme/new-order`, `/acme/key-change`, `/acme/order/{id}`, `/acme/authz/{id}`, `/acme/challenge/{id}`, `/acme/order/{id}/finalize`, `/acme/revoke-cert`, `/acme/cert/{id}`. |

Internal ACME state endpoints are service management APIs. Public ACME protocol
endpoints are RFC 8555 client-facing endpoints. Keep them documented separately
even though they share `/acme` routing.

## Duplicate Request Semantics

No public lifecycle endpoint accepts a caller-supplied idempotency key today.
Clients must treat unsafe retries as potentially creating a new resource unless
the row below says otherwise.

| Operation | Duplicate or retry behavior |
| --- | --- |
| Issuance: `POST /certificates` | The service uses an issuance attempt to prevent duplicate signing. If signing succeeded but DB finalization failed, retry finalizes from stored signed material instead of signing again. |
| Revocation: `POST /certificates/{id}/revoke` | Revocation is a state transition. A second revoke after the certificate is no longer `valid` or force-revocable returns invalid transition semantics. |
| Renewal: `POST /certificates/{id}/renew` | Each accepted request creates a new pending enrollment. No idempotency key exists. |
| Reissue: `POST /certificates/{id}/reissue` | Each accepted request creates a new pending enrollment. No idempotency key exists. |
| Outbox retry: `POST /outbox/messages/{id}/retry` | Retry resets a failed or dead-letter message to `pending`; callers should read message state before repeating. |
| Outbox replay: `POST /outbox/messages/dead-letter/replay` | Replay requeues matching dead-letter messages in the requested scope. Repeating the same replay can affect messages still matching that scope. |
| Webhook delivery retry | Delivery attempts carry `X-AnoPKI-Delivery` and `outbox_message_id`; receivers should deduplicate with those fields. |

## Optimistic Concurrency

No lifecycle endpoint accepts caller-supplied entity versions, `ETag`, or
`If-Match` today. State-transition handlers protect lifecycle order with
conditional repository updates; stale transitions return invalid-transition
conflict semantics instead of overwriting current state.

`created_at` and `updated_at` are response metadata, not compare-and-swap tokens.
Add public optimistic concurrency only when a real edit workflow needs concurrent
write protection; until then, clients should read current state before unsafe
state-changing retries.

## Parity Rules

- OpenAPI remains the source of truth for lifecycle, operator, distribution,
  and internal ACME management routes.
- Public RFC 8555 ACME behavior is tracked in the RFC 8555 conformance matrix
  because protocol details are not fully represented by OpenAPI.
- `scripts/validate-service-contracts.py` blocks route/OpenAPI, operation ID,
  path/query parameter/schema, service README endpoint/curl example, config
  docs, public error message/status, and ACME problem type drift.
