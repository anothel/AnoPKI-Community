# Threat Model

## Assets

- issuer and responder key references
- certificate inventory
- identities and owner metadata
- enrollment approvals
- revocation state
- audit events
- ACME account/order/challenge state

## Main Threats

| Threat | Control now | Gap |
| --- | --- | --- |
| Mis-issuance | Profile policy, identity allow-lists, approval flow, ACME validation, CSR linting, public TLS pre-signing lint hook, and issued DER golden tests. | Expand public TLS lint fixtures when external tool is selected. |
| Key exposure | Certificate issuance, CRL generation, and OCSP response signing use adapter-private providers, keep private key bytes inside the OpenSSL adapter, redact provider errors, and reject the exportable file provider in production. | No real non-exportable provider. |
| Provider confusion or fallback | One selected provider is acquired once; resolver checks readiness, production exportability, provider/operation evidence, and `fallback_used=false`. Test-only software-token coverage exercises failure and mismatch paths. | Provider-result audit correlation is implemented for the Community file-provider path; a real non-exportable provider remains pending outside the Community runtime scope. |
| Privilege abuse | API key scopes, access model, break-glass rules, and audit metadata. | First-class role/ABAC enforcement waits for an operator directory. |
| Audit tampering | Monotonic `sha256-v1` chain, latest/checkpoint state, fail-closed append and prune, integrity API, migration backfill, and recovery verification. | Independent external anchoring and SIEM custody remain deployment-specific. |
| Replay/duplicate issuance | Issuance attempts, active signing claims, ACME nonce handling and focused multi-node single-writer evidence. | Real PostgreSQL multi-node failover and partition smoke coverage. |
| Status outage | CRL/OCSP backed by service state, fail-closed signer-outage recovery, and leased multi-node CRL publication that prevents duplicate signing. | Real multi-node HA and traffic-shift drills. |
| Supply chain compromise | CI builds/tests, secret baseline scan, govulncheck, SBOM, and release signing workflow. | Full SAST/SCA plus container/IaC scans after tool choices. |

## Review Triggers

- new key provider or signing protocol
- new discovery/import source
- new deployment adapter
- public TLS integration change
- new algorithm policy
