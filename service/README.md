# AnoPKI service

Go API service for the manual enrollment lifecycle MVP. It exposes HTTP endpoints for identities, certificate profiles, enrollments, certificate issuance, revocation, CRL publication, OCSP response, and audit events, backed by the SQL store and the `anopki-core` CLI for CSR inspection, certificate issuance, CRL generation, and OCSP DER processing.

Enrollment creation inspects the CSR and stores CSR SANs separately from requested SANs. The current policy requires requested DNS/IP SANs to exactly match CSR DNS/IP SANs, ignoring order.

Identities support machine lifecycle metadata through `owner`, `team`, `service`, `environment`, `deployment_target`, `last_seen_at`, `metadata_json`, `allowed_dns_names`, and `allowed_ip_addresses`. When an identity allow-list is non-empty, enrollment, renewal/reissue enrollment creation, and final signing reject requested SANs outside that identity policy. Empty allow-lists preserve the existing unrestricted identity behavior.

The HTTP service applies operational request safety limits. The process uses explicit server timeouts and a 1 MiB default request body limit. OCSP requests are capped at 16 KiB.

Certificate profiles are first-class service records at:

- `POST /certificate-profiles`
- `GET /certificate-profiles`
- `GET /certificate-profiles/{id}`

Profiles currently model typed policy fields for validity, subject templates, allowed DNS/IP constraints, key usage, extended key usage, basic constraints, subject key identifiers, and authority key identifiers. Profile-driven X.509 extension emission is wired through the core CLI for basic constraints, key usage, extended key usage, subject key identifier, authority key identifier, and subject alternative name.

Profile policy is enforced when creating enrollments, creating renewal/reissue enrollments, and immediately before signing approved enrollments. Requested expiration cannot exceed `validity_period_seconds` from the current service clock. Requested DNS names must match allowed exact names or `*.example.test`-style suffix patterns when `allowed_dns_patterns` is set. Requested IP addresses must fall inside configured CIDR ranges when `allowed_ip_ranges` is set. CSR public key algorithm and size must satisfy `allowed_key_algorithms` and `min_key_size_bits` when set; issuance uses the first `allowed_signature_algorithms` value when present.

CRL publications are service-owned artifacts generated from certificate inventory and revocation records. The service selects revoked certificates for an issuer, assigns the next CRL number, calls the core CLI to build and sign the CRL, stores the PEM artifact, and publishes the latest issuer CRL over HTTP.

- `POST /crls`
- `GET /crls/{id}`
- `GET /issuers/{id}/crl`

Issuers can record parent issuer links, AIA URLs, CRL distribution points, and trust anchor status. Root CAs are trust anchors by default. Operator and clients can export issuer chains and active trust anchors:

- `GET /issuers/{id}/chain`
- `GET /trust/anchors`

ACME enrollment state is modeled as accounts, orders, authorizations, and challenges. Creating an order records requested DNS/IP identifiers and creates one pending authorization and challenge per identifier. Completing all challenges moves the order to `ready`. Finalizing a ready order creates an enrollment, approves it, issues the certificate, and marks the order `valid`.

- `POST /acme/accounts`
- `GET /acme/accounts`
- `POST /acme/orders`
- `GET /acme/orders/{id}`
- `GET /acme/orders/{id}/authorizations`
- `GET /acme/authorizations/{id}/challenges`
- `POST /acme/challenges/{id}/complete`
- `POST /acme/orders/{id}/finalize`

The service also exposes an ACME-shaped protocol adapter with directory discovery, nonce issuance, JWS envelope decoding, and one-time nonce replay protection:

- `GET /acme/directory`
- `HEAD /acme/new-nonce`
- `GET /acme/new-nonce`
- `POST /acme/new-account`
- `POST /acme/account/{id}`
- `POST /acme/new-order`
- `POST /acme/key-change`
- `GET /acme/order/{id}`
- `POST /acme/order/{id}`
- `GET /acme/authz/{id}`
- `POST /acme/authz/{id}`
- `POST /acme/challenge/{id}`
- `POST /acme/order/{id}/finalize`
- `POST /acme/revoke-cert`
- `GET /acme/cert/{id}`
- `POST /acme/cert/{id}`

Protocol adapter requests use `Content-Type: application/jose+json` and JSON JWS fields `protected`, `payload`, and `signature`. The protected header must include `alg: ES256`, `RS256`, or `EdDSA`, a fresh `nonce` from `/acme/new-nonce`, and the exact request `url`. ACME nonces are single-use, expire after 10 minutes, and use a bounded in-memory cache of 1024 entries by default for local/single-node mode; set `ANOPKI_ACME_NONCE_STORE=sql` for multi-node or production deployments. New-account requests bind the account to the submitted P-256, RSA, or OKP/Ed25519 JWK thumbprint and canonical JWK; repeated new-account requests with the same account key return the existing account. Later `kid`-based requests verify the account URL belongs to the configured ACME base URL, verify the JWS signature against the stored account key, and reject mismatched account IDs or invalid signatures. Account POST requests update contacts or deactivate the account, and key rollover is available through `/acme/key-change`. Deactivated accounts cannot create orders or access order, authorization, challenge, finalize, or certificate resources. ACME POST responses include a fresh `Replay-Nonce` and directory `Link`; protocol errors use `application/problem+json` with malformed JWS and badNonce retry coverage. Orders and authorizations expose `identifiers` and `expires`, and expired ready orders are rejected and marked invalid. POST-as-GET is supported for order, authorization, and certificate resources. HTTP-01 challenge validation fetches `http://{identifier}/.well-known/acme-challenge/{token}` and expects `{token}.{account_key_thumbprint}`. Default HTTP-01 validation rejects unsafe targets before fetch and redirect follow, including localhost names, loopback, private, link-local, multicast, unspecified, and metadata/link-local addresses. The dial path resolves DNS itself, filters unsafe resolver results, dials only those resolved IPs, caps redirects at 10, and uses explicit 5s connect/response-header and 10s overall request timeouts. Challenge validation failures keep the authorization and order pending, move the challenge to `processing`, and return `Retry-After` so clients can poll the authorization until validation succeeds. Finalize accepts the standard RFC8555 `csr` base64url DER payload and the internal `csr_pem` compatibility payload. Finalized orders expose `GET` and POST-as-GET `/acme/cert/{id}` for `application/pem-certificate-chain` download with the issued leaf followed by issuer chain PEMs. The adapter has passed local live lego and WSL certbot HTTP-01 smokes. Remaining compatibility gaps include external account binding and DNS-01.

ACME protocol account, order, challenge, and finalize POST paths use fixed-window per-client rate limits and return ACME `rateLimited` problems with `Retry-After` when exceeded.

Live client status is tracked in [ACME client compatibility](../docs/acme-client-compatibility.md). RFC 8555 coverage is tracked in [ACME RFC 8555 conformance](../docs/acme-rfc8555-conformance.md).

For local ACME smoke tests, `ANOPKI_ACME_HTTP01_BASE_URL` can override the HTTP-01 fetch base URL. It is empty by default. When set, the verifier ignores the requested identifier host and fetches `/.well-known/acme-challenge/{token}` from the configured base URL. This override is trusted operator configuration and can target loopback for local smoke runs; keep it disabled around real infrastructure. `ANOPKI_ACME_BOOTSTRAP_DEFAULTS` is also available for the smoke harness; it creates a local machine identity, issuer, certificate profile, and temporary CA key material. Keep it disabled outside local smoke runs. See the root [security policy](../SECURITY.md) before using smoke-only settings around real infrastructure.

Certificate lifecycle operations include revocation, suspension, and resumption:

- `POST /certificates/{id}/revoke`
- `POST /certificates/{id}/suspend`
- `POST /certificates/{id}/resume`
- `POST /certificates/{id}/renew`
- `POST /certificates/{id}/reissue`
- `POST /certificates/expiration-scan`

Certificate inventory and expiry views are available for operators:

- `GET /certificates?expires_within_days=30`
- `GET /certificates?expires_within_days=14`
- `GET /certificates?expires_within_days=7`
- `GET /certificates?expires_within_days=3`
- `GET /certificates?expires_within_days=1`
- `GET /certificates?expires_within_days=30&limit=50&offset=0`
- `GET /operator/certificate-inventory`
- `GET /operator/certificate-inventory?owner=platform&service=payments&environment=prod&issuer_id=issuer-1&profile_id=profile-1&sort=asc&limit=50&offset=0`
- `GET /operator/expiry-slo`

Issuance uses a DB-backed enrollment claim to prevent duplicate signing across service nodes. If signing succeeds but DB finalization fails, retry finalizes from stored signed material without calling the signer again. If `certificate.issued` audit repair is needed after finalized state is stored, operators can call:

- `POST /audit-events/repair/issuance`
- `GET /audit-events?actor=operator&resource_type=certificate&sort=desc&limit=50&offset=0`
- `GET /audit-events/integrity`
- `POST /audit-events/retention/prune`

Normal revocation accepts only `valid` certificates. Forced revocation accepts `valid` and `suspended` certificates by posting `{"force": true}` with the revocation reason.
Renewal creates a new pending enrollment from a valid certificate, copying identity, issuer, profile, subject, and SANs while accepting a new CSR and requested expiration.
Reissue creates a new pending enrollment from a valid certificate with a new CSR while preserving the original certificate expiration.
Expiration scans mark `valid` and `suspended` certificates as `expired` when `not_after` is in the past. They emit one renewal warning for each `valid` certificate inside the requested warning window, tracked by `renewal_notified_at`.
The expiration scan worker is disabled by default. Set `ANOPKI_EXPIRATION_SCAN_ENABLED=true` to run scans automatically on startup and then at the configured interval.
The operator expiry SLO reports zero success only when no valid or suspended certificates inside the 14-day window are still missing a renewal notification.
The inventory view joins certificate, identity, issuer, and profile references. It exposes owner, team, service, environment, deployment target, issuer, profile, issuer key reference, revocation state, last seen timestamp, and ownership completeness warnings. It supports exact filters for owner, team, service, environment, issuer_id, profile_id, and revocation_state, plus ascending/descending sort and limit/offset pagination.

Certificate profile issuer transitions emit `certificate_profile.issuer_rolled_over` or `certificate_profile.issuer_rolled_back` outbox events. The transition is allowed only between active intermediates sharing the same active root trust anchor; stale expected-issuer retries fail closed.

Notification endpoints deliver lifecycle outbox events to operator webhooks:

- `POST /notification-endpoints`
- `GET /notification-endpoints`
- `POST /notification-endpoints/{id}/disable`

Webhook endpoints require a shared secret when created. In production mode, webhook endpoint URLs must use HTTPS and webhook secrets must be at least 32 characters and not common defaults. Deliveries receive JSON with `schema_version`, `outbox_message_id`, `event_type`, `payload`, and `created_at`. Empty `event_types` subscribes to all lifecycle outbox event types. Delivery requests include `X-AnoPKI-Event`, `X-AnoPKI-Delivery`, `X-AnoPKI-Timestamp`, and `X-AnoPKI-Signature`. The signature is `sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw_body)>`; receivers should reject stale timestamps to reduce replay risk. Receiver examples are in `docs/reference/webhook-receivers.md`. Failed webhook delivery creates a failed job attempt and reschedules the outbox message for retry after one minute.

Outbox operations expose delivery state for operators:

- `GET /outbox/messages`
- `GET /outbox/messages?status=dead_letter`
- `POST /outbox/messages/{id}/retry`
- `POST /outbox/messages/dead-letter/replay`

Webhook delivery uses bounded retry with capped backoff: 1 minute, 5 minutes, 15 minutes, then 1 hour. Messages move to `dead_letter` after the configured max attempts. Manual retry resets a failed or dead-letter message to `pending`. Bulk dead-letter replay requires `event_type`, `created_from`, `created_to`, and `limit`, and only replays matching dead-letter messages inside that time window.

OCSP responders can be registered with `POST /issuers/{id}/ocsp-responders`, listed with `GET /issuers/{id}/ocsp-responders`, disabled with `POST /issuers/{id}/ocsp-responders/{responderID}/disable`, and atomically rotated with `POST /issuers/{id}/ocsp-responders/rotate`.

OCSP response is available at `POST /ocsp`. Requests must use `Content-Type: application/ocsp-request`; successful responses use `Content-Type: application/ocsp-response`. The service selects the responder issuer from the OCSP CertID hash algorithm plus issuer name/key hash, maps requested serials to `good`, `revoked`, or `unknown` from certificate inventory and revocation records, preserves OCSP nonce extensions in signed responses, and delegates OCSP response signing to the core CLI.

Only one active OCSP responder is allowed per issuer. Registering a replacement requires disabling the current active responder first, or using rotate to disable the current active responder and create the replacement in one transaction. Rotate fails with a lifecycle conflict when no active responder exists.

When a matched issuer has an active responder, `POST /ocsp` signs with that responder certificate and key reference. When no active responder exists, the service falls back to issuer direct signing for compatibility.

Responder certificates are validated by the core CLI before storage and must be issued by the issuer, be non-CA certificates, and carry the OCSP Signing EKU.

Audit events include structured `metadata_json` for lifecycle resource IDs and successful result codes. Enrollment and issuance policy events record an allow/reject/unknown decision, a stable reason, and redacted validation-evidence references bound to identity/issuer/profile IDs plus SHA-256 CSR and policy-input references; raw CSR, SAN, key, and credential values are not copied into the references. HTTP requests can attach `X-Request-ID`; the service records it with the client IP for mutating operations. Every row receives a monotonic sequence and `sha256-v1` previous/current hash link. `GET /audit-events` returns those fields and supports exact filters for actor, action, resource type, resource ID, RFC3339 created time range, ascending/descending sort, and limit/offset pagination. `GET /audit-events/integrity` verifies the retained chain and prune checkpoint. Retention pruning verifies the chain first, advances the checkpoint to the last deleted prefix row, deletes only a contiguous prefix before the supplied RFC3339 cutoff, and records an `audit.retention_pruned` event. Append and prune operations fail closed when a row or checkpoint is damaged.
`X-Forwarded-For` is trusted only when the direct peer IP matches `ANOPKI_TRUSTED_PROXIES`; otherwise audit metadata uses the direct peer address.

API authentication defaults to `dev` mode for local compatibility. In `dev` mode, the service uses `X-Actor` as the audit actor and allows requests without credentials. Set `ANOPKI_AUTH_MODE=api_key` to require `Authorization: Bearer <token>` for lifecycle and operator APIs. `POST /ocsp`, `GET /crls/{id}`, and `GET /issuers/{id}/crl` remain public distribution endpoints. Bootstrap an initial operator key by setting `ANOPKI_BOOTSTRAP_API_KEY`. Set `ANOPKI_API_KEY_PEPPER` to store new API key token hashes as HMAC-SHA256 values. Existing SHA-256 token hashes remain accepted so operators can enable a pepper before rotating legacy keys.

Community authorization remains based on the existing API key `read`, `write`, and `operator` scopes. `httpapi.RequestAuthorizer` is an optional internal extension seam: when injected, it runs only after authentication and legacy scope checks on protected routes, and the default Community HTTP behavior is unchanged when it is absent. Community does not implement RBAC/ABAC, OIDC/SAML, or an approval workflow, and does not include Enterprise commercial policy or role catalogs. Authorization calls receive a two-second deadline by default, may use a shorter positive `AuthConfig.AuthorizationTimeout`, and fail closed on timeout, cancellation, evaluator error, empty outcome, or any non-`allow` result. Implementations must honor the request context and must not retry through another policy engine or bypass the existing scope decision. `GET /debug/vars` requires `operator` scope in API-key mode. When an authorizer is present, lifecycle and failure audit events correlate the normalized outcome, evaluator status, and optional bounded `decision_id`, `reason_code`, and `policy_revision`; raw evaluator errors, credentials, claims, request bodies, query values, and path parameter values are not audit fields. The default Community path emits no authorization-evidence claim when the seam is absent.

Set `ANOPKI_ENV=production` for production startup checks. Production mode rejects `dev` auth mode, requires a strong `ANOPKI_API_KEY_PEPPER`, rejects configured bootstrap API keys shorter than 32 characters or matching common defaults such as `change-me`, and enforces HTTPS plus strong secrets for new webhook notification endpoints.

Operational probes are public:

- `GET /healthz` returns process liveness.
- `GET /readyz` checks database reachability.
- `GET /version` returns service build metadata plus the immutable Core product profile/backend control metadata and Community KeyProvider policy. It reports supported provider classes and production/exportability policy, not a per-operation signing success claim or any raw `key_ref`.

API keys are managed by operator-scoped keys:

- `POST /api-keys`
- `GET /api-keys`
- `POST /api-keys/{id}/rotate`
- `POST /api-keys/{id}/disable`

Scopes are ordered as `operator`, `write`, and `read`. `operator` can access all protected APIs, including API key management, outbox operations, audit events, operator inventory, expiry SLOs, and expiration scans. `write` can read and mutate lifecycle resources. `read` can only read non-operator APIs. Created API keys return the generated token once in the creation response. List and disable responses never include token material.

API keys can include an optional `expires_at` timestamp. Expired keys are rejected during Bearer authentication. Successful API key authentication records `last_used_at`, which is visible to operator key listing. API key responses include a short `token_fingerprint` derived from the stored token hash so operators can identify keys without exposing token material. Rotating an active key disables the old key and returns the replacement token once.

Example:

```powershell
$env:ANOPKI_AUTH_MODE = "api_key"
$env:ANOPKI_BOOTSTRAP_API_KEY = "change-me"
$env:ANOPKI_BOOTSTRAP_API_KEY_ACTOR = "ops-admin"
$env:ANOPKI_API_KEY_PEPPER = "local-dev-pepper-0123456789abcdef"
go run ./cmd/anopki-service

curl.exe -H "Authorization: Bearer change-me" http://localhost:8080/identities

curl.exe -H "Authorization: Bearer change-me" "http://localhost:8080/identities?owner=platform&service=payments&environment=prod&sort=desc&limit=50"

curl.exe -H "Authorization: Bearer change-me" "http://localhost:8080/enrollments?identity_id=identity-1&issuer_id=issuer-1&profile_id=profile-1&status=pending&sort=asc&limit=50"

curl.exe -H "Authorization: Bearer change-me" "http://localhost:8080/certificates?owner=platform&service=payments&issuer_id=issuer-1&profile_id=profile-1&san=api.example.com&revocation_state=valid&renewal_state=unnotified&expires_within_days=30&sort=asc&limit=50"

curl.exe -H "Authorization: Bearer change-me" "http://localhost:8080/outbox/messages?status=pending&type=certificate.revoked&from=2026-07-01T00:00:00Z&to=2026-07-02T00:00:00Z&sort=asc&limit=50"

curl.exe -X POST http://localhost:8080/api-keys `
  -H "Authorization: Bearer change-me" `
  -H "Content-Type: application/json" `
  -d '{"name":"reader","actor":"read-client","scopes":["read"],"expires_at":"2026-07-23T00:00:00Z"}'
```

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `ANOPKI_ADDR` | `:8080` | HTTP listen address. |
| `ANOPKI_DB_DRIVER` | `sqlite` | Database driver name. Use `sqlite` locally or `pgx` for PostgreSQL. |
| `ANOPKI_DB_DSN` | `anopki.db` | Database DSN passed to `database/sql`. |
| `ANOPKI_CORE_BIN` | `anopki-core` | Path or command name for the core CLI. |
| `ANOPKI_ENV` | empty | Set to `production` to enable production startup checks. |
| `ANOPKI_AUTH_MODE` | `dev` | Auth mode. Use `dev` for local `X-Actor`; use `api_key` for Bearer token auth. |
| `ANOPKI_TRUSTED_PROXIES` | empty | Comma-separated proxy IPs or CIDR ranges allowed to supply `X-Forwarded-For` for audit client IP metadata. Leave empty unless the service is behind a trusted reverse proxy. |
| `ANOPKI_BOOTSTRAP_API_KEY` | empty | Optional initial API key token. Stored with `ANOPKI_API_KEY_PEPPER` when configured. In production, configured bootstrap tokens must be at least 32 characters and not common defaults. |
| `ANOPKI_BOOTSTRAP_API_KEY_NAME` | `bootstrap` | Name stored for the bootstrap API key. |
| `ANOPKI_BOOTSTRAP_API_KEY_ACTOR` | `bootstrap` | Audit actor assigned to the bootstrap API key. |
| `ANOPKI_API_KEY_PEPPER` | empty | Optional API key HMAC pepper. When set, new API key token hashes use `hmac-sha256`. Required in production API key mode. |
| `ANOPKI_OUTBOX_ENABLED` | `true` | Enables lifecycle outbox dispatch worker. |
| `ANOPKI_OUTBOX_INTERVAL` | `5s` | Outbox dispatch worker interval. |
| `ANOPKI_OUTBOX_BATCH_SIZE` | `10` | Max outbox messages dispatched per worker run. |
| `ANOPKI_EXPIRATION_SCAN_ENABLED` | `false` | Enables automatic certificate expiration scans. |
| `ANOPKI_EXPIRATION_SCAN_INTERVAL` | `1h` | Expiration scan worker interval. |
| `ANOPKI_EXPIRATION_WARNING_WINDOW` | `720h` | Renewal warning window for valid certificates. |
| `ANOPKI_EXPIRATION_SCAN_BATCH_SIZE` | `100` | Max certificates processed per expiration scan. |
| `ANOPKI_PUBLIC_TLS_MAX_VALIDITY` | empty | Optional override for public TLS profile max validity. Empty uses 200/100/47-day BR-era defaults. |
| `ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN` | empty | Enables public TLS CAA policy checks for `public_tls` profiles when set. |
| `ANOPKI_PUBLIC_TLS_CAA_ACCOUNT_URI` | empty | Account URI expected by RFC 8657 `accounturi` CAA parameters. |
| `ANOPKI_PUBLIC_TLS_CAA_VALIDATION_METHOD` | `http-01` | Validation method expected by RFC 8657 `validationmethods` CAA parameters. |
| `ANOPKI_PUBLIC_TLS_CAA_RESOLVER` | empty | DNS resolver host or `host:port` used for CAA lookups. Required when CAA issuer domain is set. |
| `ANOPKI_PUBLIC_TLS_CAA_LOOKUP_TIMEOUT` | `5s` | DNS CAA lookup timeout. |
| `ANOPKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE` | `false` | Explicit exception to allow CAA answers without a DNSSEC AD bit. Keep false for fail-closed public TLS issuance. |
| `ANOPKI_ACME_HTTP01_BASE_URL` | empty | Optional local smoke override for HTTP-01 challenge fetches. |
| `ANOPKI_ACME_NONCE_STORE` | `memory` | `memory` for local/single-node use, `sql` for shared multi-node nonce replay protection. Required as `sql` when `ANOPKI_ENV=production`. |
| `ANOPKI_ACME_BOOTSTRAP_DEFAULTS` | `false` | Local smoke-only bootstrap for default ACME identity, issuer, and profile. |
| `ANOPKI_ACME_DEFAULT_VALIDITY` | `24h` | Validity used by ACME smoke defaults. |
| `ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF` | `.tmp/acme-smoke/acme-smoke-issuer.key` | Local smoke CA private key path used only when ACME defaults bootstrap is enabled. |

Initial schema migration runs on startup before the HTTP server starts. SQLite uses `internal/store/migrations/0001_init_sqlite.sql`; `pgx` uses `internal/store/migrations/0001_init.sql`.

## Manual Verification

Repository owner runs tests and builds. Suggested commands:

```powershell
cd service
go test ./...
go build ./cmd/anopki-service
$env:ANOPKI_ADDR = ":8080"
$env:ANOPKI_DB_DRIVER = "sqlite"
$env:ANOPKI_DB_DSN = "anopki.db"
go run ./cmd/anopki-service
```

Optional PostgreSQL migration integration test:

```powershell
cd service
$env:ANOPKI_POSTGRES_TEST_DSN = "postgres://user:pass@localhost:5432/anopki_test?sslmode=disable"
go test ./internal/store -run TestApplyInitialMigrationPostgresIntegration -v
```
