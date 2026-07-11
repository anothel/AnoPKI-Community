# Target Architecture

This document describes the intended service and product boundaries. It mirrors
current behavior where possible and marks adapter separation as an active
refactor target.

## Components

### RA/API

The Go HTTP API is the registration authority boundary. It authenticates
operator requests, validates payloads, applies production-mode request safety,
records audit metadata, and calls lifecycle services. Public distribution
endpoints expose CRLs, OCSP, health, readiness, version, and ACME resources.

### Policy Engine

Policy currently runs inside the lifecycle service. It validates profile
validity, X.509 extension policy, public TLS restrictions, identity DNS/IP
allow-lists, ownership completeness, and production webhook safety.

### Lifecycle Service

The lifecycle service owns identities, issuers, profiles, enrollments,
certificates, revocations, ACME state, notifications, API keys, CRLs, OCSP
responders, expiration scans, and audit repair. It owns lifecycle audit events.

### Core Runner

The Go service invokes the C++ `anopki-core` CLI. The runner maps core failures
to stable domain errors and does not expose dependency-specific errors as the
public API contract.

### AnoPKI Core

AnoPKI Core owns backend-neutral operation contracts for CSR inspection,
certificate issuance, CRL, OCSP, responder validation, capability reporting,
and stable error semantics.

After refactoring, backend-neutral core code must not directly call OpenSSL or
AnoCrypto-C APIs.

### Backend Adapters

```text
                         +-> OpenSSL adapter -----> OpenSSL::Crypto
AnoPKI Core ------------|
                         `-> AnoCrypto-C adapter -> AnoCryptoC::AnoCryptoC
```

- Community owns the OpenSSL adapter.
- Enterprise owns the AnoCrypto-C adapter.
- AnoCrypto-C is an external SDK and separate repository.
- Adapter selection is explicit; there is no automatic runtime fallback.

### Enterprise Layer

The Enterprise layer adds commercial capabilities such as enterprise access
control, operational UI, deployment adapters, enhanced audit/reporting,
provider integrations, packaging, and support evidence. It does not replace or
fork the Community lifecycle contracts unnecessarily.

### Key Providers

Issuer and responder keys are addressed by `key_ref`. File references are
local/dev only. Production providers should be non-exportable HSM/KMS/PKCS#11
providers with readiness and audit evidence. Key-provider selection remains
separate from backend-adapter selection.

### Deploy Adapters

Deploy adapters consume issued-certificate lifecycle events or operator APIs.
They must not bypass lifecycle state, audit, or revocation policy.

### Audit

Audit events are append-only operational records with structured metadata.
Mutating APIs record lifecycle changes and failed requests. Backend and provider
metadata must be recorded without exposing private keys, credentials, or raw
sensitive dependency errors.

### CRL And OCSP

The service owns CRL publication and OCSP status decisions. The selected core
adapter performs the required artifact operation. Unsupported operations in an
AnoCrypto-C profile fail explicitly and never invoke OpenSSL automatically.

## Product Assembly

```text
Community/OpenSSL
  = AnoPKI Core + OpenSSL adapter

Enterprise/OpenSSL
  = AnoPKI Core + OpenSSL adapter + Enterprise layer

Enterprise/AnoCrypto-C
  = AnoPKI Core + AnoCrypto-C adapter + Enterprise layer
```

Community/OpenSSL and Enterprise/OpenSSL are full-function profiles when their
normal release evidence passes. Enterprise/AnoCrypto-C remains a partial
development profile until all required Community operation parity is complete.

## Data Flow

1. Operator or ACME client sends a request.
2. HTTP layer authenticates, rate-limits, decodes input, and calls lifecycle
   services.
3. Lifecycle service validates state and policy against SQL-backed data.
4. Signing/status operations call `anopki-core` through the core runner.
5. AnoPKI Core dispatches to the adapter selected by the product profile.
6. The adapter either completes the operation or returns a stable explicit
   error; it does not silently switch dependencies.
7. Lifecycle service persists state changes and audit records.
8. Workers process expiration scans and outbox delivery.

## Production Shape

- Multiple service nodes share one SQL database.
- ACME nonce storage is SQL-backed in production.
- Issuer/responder private keys live outside the database.
- Product profile and adapter identity are immutable release metadata.
- Restore drills verify schema, audit, key references, CRL artifacts, OCSP
  responder state, outbox state, and lifecycle jobs before traffic returns.
