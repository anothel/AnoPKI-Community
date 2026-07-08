# API Error Code Reference

Non-ACME API errors return JSON:

```json
{"error":"invalid request"}
```

Public ACME protocol endpoints return `application/problem+json` with ACME
problem types, status, and detail. ACME errors also include a fresh
`Replay-Nonce` when nonce issuance succeeds.

## HTTP Mapping

| Domain error | Public message | HTTP status |
| --- | --- | ---: |
| `ErrInvalidRequest` | `invalid request` | 400 |
| ACME bad nonce | `invalid request` | 400 |
| `ErrUnsupportedMediaType` | `unsupported media type` | 415 |
| `ErrUnauthorized` | `unauthorized` | 401 |
| `ErrForbidden` | `forbidden` | 403 |
| `ErrRateLimited` | `rate limited` | 429 |
| `ErrACMEAccountDeactivated` | `acme account deactivated` | 401 |
| `ErrInvalidTransition` | `invalid lifecycle transition` | 409 |
| `ErrIdentityNotFound` | `identity not found` | 404 |
| `ErrIssuerNotFound` | `issuer not found` | 404 |
| `ErrOCSPResponderNotFound` | `ocsp responder not found` | 404 |
| `ErrNotificationEndpointNotFound` | `notification endpoint not found` | 404 |
| `ErrCertificateProfileNotFound` | `certificate profile not found` | 404 |
| `ErrEnrollmentNotFound` | `enrollment not found` | 404 |
| `ErrCertificateNotFound` | `certificate not found` | 404 |
| `ErrCRLPublicationNotFound` | `crl publication not found` | 404 |
| `ErrOutboxMessageNotFound` | `outbox message not found` | 404 |
| `ErrAPIKeyNotFound` | `api key not found` | 404 |
| `ErrACMEAccountNotFound` | `acme account not found` | 404 |
| `ErrACMEOrderNotFound` | `acme order not found` | 404 |
| `ErrACMEAuthorizationNotFound` | `acme authorization not found` | 404 |
| `ErrACMEChallengeNotFound` | `acme challenge not found` | 404 |
| `ErrCSRParseFailed` | `csr parse failed` | 422 |
| `ErrCertificateIssuanceFailed` | `certificate issuance failed` | 502 |
| `ErrCRLGenerationFailed` | `crl generation failed` | 502 |
| `ErrOCSPDecodeFailed` | `ocsp decode failed` | 400 |
| `ErrOCSPResponderValidationFailed` | `ocsp responder validation failed` | 422 |
| `ErrOCSPResponseFailed` | `ocsp response failed` | 502 |
| `ErrStorageFailure` | `storage failure` | 500 |
| unknown error | `internal server error` | 500 |

`ErrIssuanceAttemptNotFound` and `ErrWebhookDeliveryNotFound` are internal
domain errors today. They are not mapped to public HTTP responses.

## ACME Problem Types

| Condition | ACME problem type |
| --- | --- |
| bad nonce | `urn:ietf:params:acme:error:badNonce` |
| rate limited | `urn:ietf:params:acme:error:rateLimited` |
| unauthorized, forbidden, or deactivated account | `urn:ietf:params:acme:error:unauthorized` |
| all other mapped errors | `urn:ietf:params:acme:error:malformed` |

Rate-limited ACME responses include `Retry-After`.

## Audit Error Codes

Failed API request audit events use these stable `error_code` values:

| Error code | Source |
| --- | --- |
| `invalid_request` | invalid payload, validation failure, bad nonce |
| `unsupported_media_type` | unsupported request content type |
| `unauthorized` | missing, invalid, expired, or disabled credentials |
| `forbidden` | authenticated principal lacks required scope |
| `rate_limited` | request exceeded fixed-window rate limit |
| `invalid_lifecycle_transition` | request does not match current resource state |
| `identity_not_found` | identity lookup failed |
| `issuer_not_found` | issuer lookup failed |
| `ocsp_responder_not_found` | OCSP responder lookup failed |
| `notification_endpoint_not_found` | notification endpoint lookup failed |
| `certificate_profile_not_found` | profile lookup failed |
| `enrollment_not_found` | enrollment lookup failed |
| `certificate_not_found` | certificate lookup failed |
| `crl_publication_not_found` | CRL publication lookup failed |
| `outbox_message_not_found` | outbox message lookup failed |
| `api_key_not_found` | API key lookup failed |
| `acme_account_not_found` | ACME account lookup failed |
| `acme_account_deactivated` | ACME account exists but is deactivated |
| `acme_order_not_found` | ACME order lookup failed |
| `acme_authorization_not_found` | ACME authorization lookup failed |
| `acme_challenge_not_found` | ACME challenge lookup failed |
| `csr_parse_failed` | core CLI rejected CSR parse |
| `certificate_issuance_failed` | core CLI failed certificate issuance |
| `crl_generation_failed` | core CLI failed CRL generation |
| `ocsp_decode_failed` | core CLI failed OCSP request decode |
| `ocsp_responder_validation_failed` | core CLI rejected OCSP responder certificate |
| `ocsp_response_failed` | core CLI failed OCSP response signing |
| `storage_failure` | persistence failure |
| `internal` | unmapped internal failure |
