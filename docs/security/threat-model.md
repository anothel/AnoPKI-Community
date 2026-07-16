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
| Key exposure | Certificate issuance uses one adapter-private provider, keeps private key bytes inside the OpenSSL adapter, redacts provider errors, and rejects the exportable file provider in production. | CRL/OCSP still use direct file-key paths; no real non-exportable provider. |
| Privilege abuse | API key scopes, access model, break-glass rules, and audit metadata. | First-class role/ABAC enforcement waits for an operator directory. |
| Replay/duplicate issuance | Issuance attempts and ACME nonce handling. | More multi-node smoke coverage. |
| Status outage | CRL/OCSP backed by service state. | HA deployment drills. |
| Supply chain compromise | CI builds/tests, secret baseline scan, govulncheck, SBOM, and release signing workflow. | Full SAST/SCA plus container/IaC scans after tool choices. |

## Review Triggers

- new key provider or signing protocol
- new discovery/import source
- new deployment adapter
- public TLS integration change
- new algorithm policy
