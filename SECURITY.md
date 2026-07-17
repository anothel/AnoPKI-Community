# Security Policy

## Project Security Status

`AnoPKI` is pre-1.0 and still in active development. It has security controls for local development and early operational hardening, but it is not yet a stable supported production release.

Current security-relevant controls include API key authentication, scoped API keys, API key HMAC peppering, API key expiry and rotation, an operator [access model](docs/security/access-model.md), audit metadata, bounded request bodies, HTTP server timeouts, ACME nonce replay protection, ACME HTTP-01 unsafe target blocking, CRL publication, OCSP handling, and a production startup guard.

Production deployments must set:

```powershell
$env:ANOPKI_ENV = "production"
$env:ANOPKI_AUTH_MODE = "api_key"
$env:ANOPKI_API_KEY_PEPPER = "<long-random-secret>"
```

Do not use `dev` auth mode or ACME smoke bootstrap defaults in production. `ANOPKI_ACME_BOOTSTRAP_DEFAULTS` is for local smoke tests only.

## Reporting Vulnerabilities

Report suspected vulnerabilities privately. Open a private advisory or contact maintainers through project owner channels.

Do not open a public issue for an unpatched vulnerability unless maintainers ask you to do so.

## What To Include

Please include:

- Affected component, endpoint, command, or workflow.
- Impact and expected attacker capability.
- Reproduction steps or proof-of-concept details.
- Relevant configuration, environment variables, and platform details.
- Logs, request samples, or stack traces with secrets removed.
- Whether the issue is already public or known to be exploited.

## Supported Versions

| Version | Status |
| --- | --- |
| Pre-1.0 `main` | Active development; no stable supported release. |
| Older branches or forks | Not supported by this project unless maintainers state otherwise. |

Security fixes are handled on the active development line until a supported release policy exists.

## Security Expectations

- Run production services with `ANOPKI_ENV=production`.
- Use `ANOPKI_AUTH_MODE=api_key` for production API access.
- Set a long, random `ANOPKI_API_KEY_PEPPER`; production startup rejects missing or weak peppers.
- Keep bootstrap API keys long, unique, and secret. Production startup rejects weak configured bootstrap keys.
- Disable local smoke bootstrap settings outside local test runs.
- Treat issuer private keys, API keys, database files, webhook secrets, and ACME account keys as secrets.
- Restrict service, database, key storage, and backup access to trusted operators.
- Rotate exposed credentials and keys after suspected compromise.
- Use the [production hardening checklist](docs/runbooks/production-hardening-checklist.md) before any production-like deployment.

## Secret Handling

Never commit real private keys, API keys, webhook secrets, database dumps, or production certificates. Redact secrets from logs and reports. Use local throwaway material for tests and smoke runs.

If a secret is committed or exposed, assume compromise. Remove it from active use, rotate it, and review audit logs and dependent systems.

## Known Constraints

The following areas are not complete yet:

- No production non-exportable HSM or PKCS#11 provider; current file-provider signing is local/development only.
- Certbot live coverage still has a known local Windows non-admin gap.
- DNS-01 and External Account Binding are planned later.

These constraints matter for production architecture and threat modeling.

## Disclosure Process

Maintainers will acknowledge private reports, assess severity and scope, prepare a fix or mitigation, and coordinate disclosure timing with the reporter when practical. Public disclosure should wait until a fix or clear mitigation is available, unless active exploitation or user safety requires faster notice.
