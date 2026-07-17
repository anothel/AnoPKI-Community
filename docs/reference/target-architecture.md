# AnoPKI Community Target Architecture

## Components

```text
Operator or ACME client
        |
        v
Go lifecycle service
  - API/auth/policy/state/audit
        |
        v
anopki-core CLI
        |
        v
backend-neutral Core
        |
        v
Community OpenSSL adapter
        |
        +-- adapter-private FileKeyProvider (local/dev only)
        |
        v
OpenSSL::Crypto
```

## Rules

- Go owns lifecycle, persistence, policy, API behavior and audit.
- C++ Core owns backend-neutral PKI operation dispatch and stable operation errors.
- OpenSSL-specific types remain under `src/backends/openssl`.
- Certificate, CRL and OCSP signing resolve one provider exactly once.
- Production rejects the exportable file provider before opening the key.
- Actual signing evidence is produced only after the cryptographic operation succeeds.
- Go readiness preflight cannot substitute for signing evidence.
- No automatic provider, backend or product-profile fallback exists.
- Public lifecycle and Core CLI JSON contracts remain stable.

## Current production limitation

Community has no production non-exportable signing provider. Production-like operation requiring issuer signing remains blocked unless a separately approved provider implementation exists outside the current Community runtime scope.
