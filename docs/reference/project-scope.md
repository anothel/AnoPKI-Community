# Project Scope

`AnoPKI` is an operational PKI lifecycle service. It is not only a
certificate generator. The service owns identity, enrollment, issuance policy,
renewal, revocation, status publication, audit, notifications, and ACME
automation around the core signing CLI.

## In Scope

### Private CA

- Root and intermediate issuer records.
- Issuer chain export and active trust-anchor export.
- Profile-driven issuance for internal CA use.
- CRL publication and OCSP response generation from service inventory.
- Delegated OCSP responder registration, disable, and rotation.

### Internal mTLS And Service Certificates

- Machine, service, workload, and device identities.
- Owner, team, service, environment, deployment target, and last-seen metadata.
- Identity DNS/IP allow-lists enforced at enrollment, renewal, reissue, and
  final signing.
- Renewal and reissue flows that preserve lifecycle history.

### Device Certificates

- Device identities through the `iot_device` identity type.
- Certificate profile constraints shared with other identity classes.
- Audit and inventory fields needed to tie issued material back to owner and
  deployment metadata.

### Public TLS

- Public-TLS profile flag.
- CA/Browser Forum validity ceilings for the 200/100/47-day eras.
- Domain/IP validation evidence age tracking separate from certificate
  validity.
- CAA DNSSEC and RFC 8657 `accounturi` and `validationmethods` policy checks
  when public TLS issuance is enabled.
- Pre-signing public TLS lint hook that fails closed when no hook is configured.
- ACME HTTP-01 order, challenge, finalize, certificate download, revocation,
  nonce, account, and account-key rollover flows.

### Code Signing

Code-signing certificate issuance is in scope only as a future profile and
policy shape. No code-signing workflow, timestamping service, signing key
ceremony, or artifact signing API exists yet.

## Explicit Non-Goals

- Root-store inclusion automation.
- Public CA audit automation.
- Broad discovery scanners before one operator-selected import integration
  proves the inventory model.
- DNS-01 before an operator-owned DNS provider integration is selected.
- External Account Binding before a real subscriber/account integration
  requires it.
- UI, self-service portals, and human approval workflows beyond current APIs.
- HSM/KMS/PKCS#11 production provider implementation until key-boundary design
  is selected.
- Certificate Transparency log submission.
- Code-signing timestamp authority.

## Current Boundaries

- The Go service owns lifecycle state, policy decisions, API auth, audit,
  workers, ACME protocol behavior, and persistence.
- The C++ core CLI owns CSR inspection, certificate issuance, CRL generation,
  OCSP request decoding, OCSP response signing, and responder certificate
  validation.
- Private keys are referenced by `key_ref`; the database must not store private
  key material.
- SQLite is local/default. PostgreSQL is the production-oriented SQL path.
