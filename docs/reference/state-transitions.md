# State Transition Reference

This reference documents externally visible lifecycle states. Transitions not
listed here should be treated as invalid and return `invalid lifecycle
transition`.

## Identity

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /identities` | `active` |

`disabled` exists in the domain model, but no public disable endpoint exists
yet.

## Issuer

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /issuers` | `active` |

`disabled` exists in the domain model, but no public disable endpoint exists
yet.

## OCSP Responder

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /issuers/{id}/ocsp-responders` | `active` |
| `active` | `POST /issuers/{id}/ocsp-responders/{responderID}/disable` | `disabled` |
| `active` | `POST /issuers/{id}/ocsp-responders/rotate` | old responder `disabled`, new responder `active` |

Only one active responder is allowed per issuer.

## Notification Endpoint

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /notification-endpoints` | `active` |
| `active` | `POST /notification-endpoints/{id}/disable` | `disabled` |

## Enrollment

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /enrollments` | `pending` |
| none | `POST /certificates/{id}/renew` | `pending` |
| none | `POST /certificates/{id}/reissue` | `pending` |
| `pending` | `POST /enrollments/{id}/approve` | `approved` |
| `pending` | `POST /enrollments/{id}/reject` | `rejected` |
| `approved` | `POST /certificates` | `issued` |

`canceled` exists in the domain model, but no public cancel endpoint exists
yet.

## Issuance Attempt

| Current | Trigger | Next |
| --- | --- | --- |
| none | issuance claim accepted | `signing` |
| `signing` | signer returns certificate material | `signed` |
| `signing` | lease expires and retry claims work | `signing` |
| `signed` | certificate row and enrollment update persist | `finalized` |
| `failed` | retry claims work | `signing` |

The issuance attempt table prevents duplicate signing across service nodes.
If signing succeeds but finalization fails, retry finalizes from stored signed
material.

## Certificate

| Current | Trigger | Next |
| --- | --- | --- |
| none | enrollment issuance finalizes | `valid` |
| `valid` | `POST /certificates/{id}/suspend` | `suspended` |
| `suspended` | `POST /certificates/{id}/resume` | `valid` |
| `valid` | `POST /certificates/{id}/revoke` | `revoked` |
| `suspended` | `POST /certificates/{id}/revoke` with `{"force": true}` | `revoked` |
| `valid` or `suspended` | expiration scan sees `not_after` in the past | `expired` |

Renewal and reissue do not mutate the source certificate. They create a new
pending enrollment from a valid certificate and retain its ID as
`source_certificate_id`.

## CRL Publication

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /crls` | `published` |

Each publication stores a signed PEM artifact and CRL number.

## Outbox Message

| Current | Trigger | Next |
| --- | --- | --- |
| none | lifecycle event creates outbox message | `pending` |
| `pending` | worker claims delivery | `processing` |
| `processing` | webhook succeeds | `completed` |
| `processing` | webhook fails with retries left | `failed` |
| `failed` | worker retries delivery | `processing` |
| `failed` | max attempts reached | `dead_letter` |
| `failed` or `dead_letter` | manual retry | `pending` |
| `dead_letter` | scoped bulk replay | `pending` |

## API Key

| Current | Trigger | Next |
| --- | --- | --- |
| none | bootstrap ensure or `POST /api-keys` | `active` |
| `active` | `POST /api-keys/{id}/disable` | `disabled` |
| `active` | `POST /api-keys/{id}/rotate` | old key `disabled`, new key `active` |

Expired active keys remain stored as `active`, but authentication rejects them.

## ACME Account

| Current | Trigger | Next |
| --- | --- | --- |
| none | `POST /acme/new-account` or internal ACME account API | `valid` |
| `valid` | account update with `status: deactivated` | `deactivated` |
| `valid` | `POST /acme/key-change` | `valid` with new account key |

Deactivated accounts cannot create or access ACME orders, authorizations,
challenges, finalize, or certificate resources.

## ACME Order, Authorization, And Challenge

| Resource | Current | Trigger | Next |
| --- | --- | --- | --- |
| order | none | new order | `pending` |
| authorization | none | new order creates authz per identifier | `pending` |
| challenge | none | new order creates HTTP-01 challenge per identifier | `pending` |
| challenge | `pending` | client submits challenge response | `processing` |
| challenge | `processing` | HTTP-01 validation succeeds | `valid` |
| authorization | `pending` | all challenges for authorization valid | `valid` |
| order | `pending` | all authorizations valid | `ready` |
| order | `ready` | finalize creates and issues certificate | `valid` |
| order | `ready` | finalize after order expiry | `invalid` |

HTTP-01 validation failures leave the challenge in `processing` and return
`Retry-After` so clients can poll and retry.
