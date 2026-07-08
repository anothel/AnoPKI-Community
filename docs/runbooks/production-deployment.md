# Production Deployment Guide

This guide is the minimum production shape for `AnoPKI`. It assumes a
trusted operator controls the database, key provider, reverse proxy, and backup
system.
Use the [production hardening checklist](production-hardening-checklist.md)
before any production-like deployment.

## Required Architecture

- Run the Go service behind a TLS-terminating reverse proxy or private service
  mesh.
- Use PostgreSQL for shared production state.
- Keep issuer and OCSP responder private keys outside the database. Store only
  `key_ref` values in `AnoPKI`.
- Run every service node with the same database, API key pepper, ACME base URL
  behavior, public TLS CAA settings, and key-provider access.
- Use SQL ACME nonce storage for multi-node deployments.
- Back up the database and key-provider metadata before migrations and issuer,
  responder, CRL, or lifecycle-job bulk changes.

## Secure Sample Environment

Use placeholders only. Do not commit real values.

```powershell
$env:ANOPKI_ENV = "production"
$env:ANOPKI_ADDR = ":8080"

$env:ANOPKI_DB_DRIVER = "pgx"
$env:ANOPKI_DB_DSN = "postgres://anopki:<password>@db.example.internal:5432/anopki?sslmode=require"

$env:ANOPKI_CORE_BIN = "C:\AnoPKI\bin\anopki-core.exe"

$env:ANOPKI_AUTH_MODE = "api_key"
$env:ANOPKI_API_KEY_PEPPER = "<32+ chars random secret from secret manager>"

$env:ANOPKI_ACME_NONCE_STORE = "sql"
$env:ANOPKI_ACME_BOOTSTRAP_DEFAULTS = "false"
$env:ANOPKI_ACME_HTTP01_BASE_URL = ""

$env:ANOPKI_OUTBOX_ENABLED = "true"
$env:ANOPKI_OUTBOX_INTERVAL = "5s"
$env:ANOPKI_OUTBOX_BATCH_SIZE = "10"

$env:ANOPKI_EXPIRATION_SCAN_ENABLED = "true"
$env:ANOPKI_EXPIRATION_SCAN_INTERVAL = "1h"
$env:ANOPKI_EXPIRATION_WARNING_WINDOW = "720h"
$env:ANOPKI_EXPIRATION_SCAN_BATCH_SIZE = "100"

$env:ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN = "ca.example"
$env:ANOPKI_PUBLIC_TLS_CAA_ACCOUNT_URI = "https://ca.example/acct/operator"
$env:ANOPKI_PUBLIC_TLS_CAA_VALIDATION_METHOD = "http-01"
$env:ANOPKI_PUBLIC_TLS_CAA_RESOLVER = "resolver.example.internal:53"
$env:ANOPKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE = "false"
```

Only set `ANOPKI_TRUSTED_PROXIES` when the service sits behind a trusted
proxy that sets `X-Forwarded-For`. Use exact proxy IPs or CIDR ranges.

## Startup Checks

Before allowing traffic, verify:

1. `ANOPKI_ENV=production` starts without rejecting auth, pepper,
   bootstrap, or nonce config.
2. `GET /readyz` succeeds.
3. `GET /version` returns the expected build metadata.
4. `GET /trust/anchors` returns expected trust anchors.
5. `GET /issuers/{id}/crl` returns the latest CRL for every active issuer.
6. A known-good OCSP request returns `successful`.
7. `POST /audit-events/repair/issuance` returns zero repairs after restore or
   migration checks.

## Deployment Steps

1. Build and test the release artifact.
2. Back up the database and verify key-provider access.
3. Apply service deployment with production env vars from a secret manager.
4. Start one node and wait for `GET /readyz`.
5. Run smoke checks for health, readiness, trust anchors, CRL, OCSP, and one
   non-production issuance profile.
6. Start remaining nodes.
7. Confirm outbox and expiration scan workers are running on the intended nodes.
8. Remove any temporary bootstrap API key from runtime config after operator
   keys exist.

## Do Not Enable In Production

- `ANOPKI_AUTH_MODE=dev`
- `ANOPKI_ACME_BOOTSTRAP_DEFAULTS=true`
- `ANOPKI_ACME_HTTP01_BASE_URL`
- weak or checked-in API keys, API peppers, webhook secrets, DB passwords, or
  issuer key material
- memory ACME nonce store on multi-node or production deployments

## Rollback

Prefer roll-forward. If rollback is required, follow
[Production Recovery Runbook](production-recovery.md). Do not edit
`schema_migrations` manually and do not replay all outbox rows blindly.
