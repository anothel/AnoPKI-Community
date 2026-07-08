# Target Architecture

This document describes the intended service boundaries. It mirrors the current
implementation where one exists and names future boundaries without inventing
new components.

## Components

### RA/API

The Go HTTP API is the registration authority boundary. It authenticates
operator requests, validates payloads, applies production-mode request safety,
records audit metadata, and calls lifecycle services. Public distribution
endpoints expose CRLs, OCSP, health, readiness, version, and ACME protocol
resources.

### Policy Engine

Policy is currently implemented inside the lifecycle service. It validates:

- profile validity ceilings and X.509 extension policy,
- public TLS validity and validation reuse age,
- public TLS CAA DNSSEC and RFC 8657 parameters,
- identity DNS/IP allow-lists,
- production completeness rules for identity ownership,
- webhook endpoint URL and secret strength in production mode.

This can remain in-process until policies need independent ownership or
external decision logs.

### Lifecycle Service

The lifecycle service owns domain transitions for identities, issuers,
profiles, enrollments, certificates, revocations, ACME accounts/orders,
notifications, API keys, CRLs, OCSP responders, expiration scans, and audit
repair. It is the only layer that should create audit events for lifecycle
state changes.

### Issuer Adapter

The service delegates signing operations to the C++ core CLI through the core
runner. The adapter maps core failures to stable domain errors and never
returns raw crypto backend output as the API contract.

### Crypto Backend

The current C++ core implementation is OpenSSL-backed. The intended backend direction is **AnoCrypto**, but OpenSSL remains the current implementation until AnoCrypto parity is proven through contract tests, fixture evidence, and release evidence. Backend selection must stay below the public API contract.

### Key Providers

Issuer and responder keys are addressed by `key_ref`. The current file key
reference is suitable for local/dev use. Production key providers should be
non-exportable HSM/KMS/PKCS#11-backed providers with audit behavior that proves
private key material was not read or recorded by the service.

### Deploy Adapters

No deployment adapter exists yet. Deploy adapters should consume issued
certificate lifecycle events or operator APIs and must not bypass lifecycle
state, audit, or revocation policy.

### Audit

Audit events are append-only operational records with structured
`metadata_json`. Mutating APIs record successful lifecycle actions and failed
API requests. Missing issuance audit can be repaired from persisted
certificates with `POST /audit-events/repair/issuance`.

### CRL

CRL publication is service-owned. The service selects revoked certificates for
an issuer, assigns a CRL number, asks the core CLI to sign the CRL, stores the
PEM artifact, and serves the latest CRL by issuer.

### OCSP

OCSP request handling is service-owned with core CLI DER processing. The
service maps requested serials to `good`, `revoked`, or `unknown`, preserves
nonce extensions, prefers an active delegated responder, and falls back to
issuer-direct signing when no responder is active.

## Data Flow

1. Operator or ACME client sends a request.
2. HTTP layer authenticates, rate-limits where configured, decodes input, and
   calls lifecycle service.
3. Lifecycle service validates state and policy against SQL-backed data.
4. Signing/status operations call the core CLI through the issuer adapter.
5. Lifecycle service persists state changes and audit records in one
   transaction where possible.
6. Outbox messages are created for lifecycle events that need webhook delivery.
7. Workers process expiration scans and outbox delivery from stored state.

## Production Shape

- Multiple service nodes share one SQL database.
- ACME nonce storage must be SQL-backed in production.
- Issuer/responder private keys live outside the database.
- Restore drills verify schema, audit, issuer key references, CRL artifacts,
  OCSP responder state, outbox state, and lifecycle jobs before traffic returns.
