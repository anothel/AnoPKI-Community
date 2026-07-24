# Security Policy

## Project Security Status

`AnoPKI-Community` is pre-1.0 and engineering is closed and frozen at the
documented baseline. It has security controls for local development and early
operational hardening, but it is not a published or supported production
release.

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
| Pre-1.0 frozen baseline | No published or supported production release. |
| Older branches or forks | Not supported by this project unless maintainers state otherwise. |

There is no active development line or supported-release policy. Reopening
engineering, including security maintenance work, requires a new product
decision. Private vulnerability reports remain welcome for assessment.

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

The following areas are deferred and not selected:

- HSM, KMS, and PKCS#11 production providers are `DEFERRED / NOT_SELECTED`;
  current file-provider signing is local/development only.
- Signing-result audit correlation uses a redacted private C++ sidecar. It is not
  a public API/CLI payload and must never contain raw key references, paths,
  credentials, PINs, PEM data, or private-key material.
- Certbot live coverage still has a known local Windows non-admin gap.
- DNS-01 and External Account Binding are `DEFERRED / NOT_SELECTED`.
- Independent SIEM anchoring/export, PQC, and infrastructure-level failover are
  `DEFERRED / NOT_SELECTED`.

These constraints matter for production architecture and threat modeling.

## Disclosure Process

Maintainers will acknowledge private reports, assess severity and scope, prepare a fix or mitigation, and coordinate disclosure timing with the reporter when practical. Public disclosure should wait until a fix or clear mitigation is available, unless active exploitation or user safety requires faster notice.
