# Production Hardening Checklist

Use this before any production-like deployment. `AnoPKI` remains pre-1.0;
this checklist does not make a deployment production-stable by itself.

## Required Settings

- `ANOPKI_ENV=production`
- `ANOPKI_AUTH_MODE=api_key`
- `ANOPKI_API_KEY_PEPPER` set to a long random value.
- `ANOPKI_BOOTSTRAP_API_KEY` empty after durable operator keys exist.
- `ANOPKI_ACME_BOOTSTRAP_DEFAULTS` empty.
- `ANOPKI_ACME_HTTP01_BASE_URL` empty outside local smoke tests.
- `ANOPKI_ACME_NONCE_STORE=sql` for multi-node ACME.

## Access And Secrets

- At least two active operator API keys held by separate trusted operators.
- Break-glass API keys have short `expires_at` and incident-scoped actor names.
- No API key tokens, peppers, webhook secrets, DB passwords, private keys, or
  production certificates in git, logs, release artifacts, or backups without
  encryption.
- Webhook endpoints use HTTPS and strong secrets.
- Reverse proxy forwards only trusted client IP headers listed in
  `ANOPKI_TRUSTED_PROXIES`.

## Storage And Keys

- PostgreSQL used for shared production state.
- Database backups encrypted and restore-tested.
- Issuer and OCSP local file keys are absent; production readiness rejects local
  file providers until HSM/KMS or PKCS#11 signing exists.
- File-key paths excluded from audit metadata, SIEM export, and support bundles.

## Verification

- `GET /readyz` passes after migration.
- `GET /version` reports expected release metadata.
- `python scripts/security-baseline-scan.py` passes before release.
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-local.ps1`
  passes on the release candidate host or equivalent CI evidence exists.
- Restore drill evidence names DB backup, key backup, service version, and
  verification timestamp.

## Open Gaps To Accept

- HSM/KMS/PKCS#11 signing boundary is not implemented.
- Tamper-evident audit hash-chain is planned, not implemented.
- DNS-01 and EAB are deferred until real integrations exist.
- Deploy adapters and post-deployment synthetic checks wait for selected targets.
