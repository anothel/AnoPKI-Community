# Compliance Matrix

This matrix tracks how `AnoPKI` maps current implementation to common PKI
standards and operational expectations. It is evidence-oriented, not a legal
or audit attestation.

| Source | Area | Status | Evidence | Gap |
| --- | --- | --- | --- | --- |
| RFC 5280 | X.509 certificate profiles and extensions | Partial | Certificate profiles model validity, Basic Constraints, Key Usage, Extended Key Usage, SAN, SKI, AKI, key policy, CSR linting, public TLS pre-signing lint hook, issued-certificate DER golden tests, and negative profile tests. | Add external lint tool fixtures when selected. |
| RFC 5280 | Revocation and CRL publication | Partial | `POST /crls`, issuer latest CRL endpoint, CRL number storage, revocation lifecycle, and recovery runbook. | Add deeper CRL conformance vectors and distribution-point policy tests. |
| RFC 5280 | Certificate path and trust anchors | Partial | Issuer parent links, issuer chain export, trust anchor export. | No full path validation engine or name-constraints policy yet. |
| RFC 6960 | OCSP request/response handling | Partial | `POST /ocsp`, nonce preservation, delegated responder support, issuer-direct fallback, responder validation. | Add more OCSP DER golden vectors and responder rollover integration drills. |
| RFC 8555 | ACME protocol | Partial | [RFC 8555 conformance matrix](../acme-rfc8555-conformance.md) tracks directory, nonce, JWS, account, order, HTTP-01, finalize, certificate download, revocation, rate limits, and live lego/certbot smoke. | EAB and DNS-01 deferred until real integrations are selected. |
| CA/B Forum Baseline Requirements | Public TLS validity ceilings | Implemented | Public TLS profile validity ceilings for 200/100/47-day eras; [Public TLS readiness runbook](../runbooks/public-tls-readiness.md). | Keep future BR versions reviewed before dates or limits change. |
| CA/B Forum Baseline Requirements | Domain/IP validation reuse age | Implemented | Validation evidence age tracked separately from certificate validity and checked for public TLS issuance. | Add external validation source integration when selected. |
| CA/B Forum Baseline Requirements | CAA handling | Implemented | Public TLS CAA DNSSEC and RFC 8657 `accounturi`/`validationmethods` policy checks. | Production resolver behavior must be validated in deployment environment. |
| CA/B Forum Baseline Requirements | Mass revocation readiness | Partial | Public TLS readiness runbook includes mass-revocation drill; incident response runbook covers mis-issuance. | Add scheduled tabletop evidence and operator signoff artifacts. |
| Mozilla root-store expectations | Public CA operational maturity | Deferred | Project scope names root-store inclusion automation and public CA audit automation as non-goals. | Required only if project becomes a public CA candidate. |
| NIST SP 800-57 | Key-management lifecycle | Partial | Issuer/responder `key_ref` model, production docs require external key provider, backups exclude private key material, key provider semantics selected. | HSM/KMS/PKCS#11 signing implementation and ceremony evidence remain future work. |
| NIST SP 800-57 | Cryptoperiod and rotation | Partial | Certificate profiles enforce validity and key algorithm/size policy; OCSP responder rotation exists; API key rotation exists. | Add issuer/intermediate rollover operating model. |
| NIST SP 1800-16 | Machine identity inventory | Partial | Identity ownership metadata, certificate inventory, expiry SLO, renewal/reissue, expiration scan, webhook notifications. | Discovery/import intentionally scoped to first real operator-selected source. |
| NIST SP 1800-16 | Automated certificate lifecycle | Partial | Enrollment, approval, issuance, renewal, reissue, revocation, outbox, and ACME HTTP-01 flows exist. | Add deployment adapters and broader inventory integrations after one real source proves the model. |
| NIST SP 1800-16 | Monitoring and response | Partial | Audit metadata with request, trace, auth, API key fingerprint, state transition, redacted secret handling, query pagination, retention pruning, `sha256-v1` chain, integrity/checkpoint verification and recovery evidence; SIEM detection examples, structured startup logs, HTTP boundary metrics, DB/signer/core CLI operation metrics, recovery runbook, incident response runbook, webhook/outbox safety runbook. | Metrics exporter, distributed span backend, independently anchored chain export, and SIEM exporter integration remain roadmap items. |

## Status Meanings

- `Implemented`: the feature exists with local automated or documented
  verification.
- `Partial`: core behavior exists, but conformance depth, integration coverage,
  or operational evidence is incomplete.
- `Deferred`: intentionally out of scope until a real integration or owner
  decision selects it.
