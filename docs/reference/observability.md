# Observability Reference

`anopki-service` exposes low-cardinality process metrics and emits
structured JSON startup logs using only the Go standard library.

## Metrics

Metrics are exposed at:

```text
GET /debug/vars
```

The endpoint is registered on the service mux. Protect it at the deployment
gateway if the service is reachable outside a trusted operator network.

### Counters

`anopki_http_requests_total` is an expvar map keyed by:

```text
<boundary>:<http_status>
```

Current boundary values include:

```text
identity
issuer
profile
enrollment
issuance
certificate
revocation
renewal
reissue
suspension
crl
ocsp
acme
webhook
outbox
auth
audit
operator
expiration_scan
observability
```

`anopki_http_events_total` records event counters:

```text
auth:failure
rate_limit:acme_account
rate_limit:acme_order
rate_limit:acme_challenge
rate_limit:acme_finalize
```

`anopki_operations_total` records non-HTTP operation counters keyed by:

```text
<boundary>:<operation>:<status>
```

`anopki_operation_latency_ms_total` records the matching cumulative
operation latency in milliseconds. Current boundary and operation values
include:

```text
db:migration
db:readiness
core_cli:readiness
signer:validate_ocsp_responder
signer:inspect_csr
signer:issue
signer:generate_crl
signer:inspect_ocsp
signer:generate_ocsp_response
signer:inspect_ocsp_issuer
```

Status values are:

```text
success
error
```

These counters are process-local. Use the deployment platform or metrics
collector to scrape every service node.

## Structured Logs

Startup and worker lifecycle logs are JSON objects with an `event` field.
Examples:

```json
{"event":"service.listening","addr":":8080"}
{"event":"outbox_worker.enabled","interval":"5s","batch":10}
```

The structured log helper redacts fields whose names contain:

```text
secret
token
password
pepper
private_key
```

Do not rely on this as the only secret control. Never pass raw key material,
API tokens, webhook secrets, database passwords, or private keys to logs.

## Request Correlation

HTTP responses include `X-Request-ID`. If the request supplies `X-Request-ID`,
the service preserves it. Otherwise the service generates one. Audit metadata
records `request_id`, `traceparent`, `client_ip`, `user_agent`, `auth_method`,
and `elapsed_ms` when request context is available.

`X-Forwarded-For` is trusted only when the direct peer matches
`ANOPKI_TRUSTED_PROXIES`.

## Remaining Gaps

- Metrics are process-local expvar maps, not exported Prometheus/OpenTelemetry
  histograms.
- Distributed trace/span propagation is limited to preserving inbound
  `traceparent` in audit metadata.
- Audit hash-chain storage and integrity verification are implemented; SIEM export examples live in the security docs, while independent anchoring and exporter/backend integration remain future work.
