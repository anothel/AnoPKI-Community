# ADR 0007: Key Provider Signing Boundary

## Status

Accepted. The Community/OpenSSL certificate-issuance, CRL-signing, and
OCSP-response-signing `FileKeyProvider` vertical slices are implemented. A
single-provider resolver, test-only software-token contract, and private
provider-result sidecar now pin provider selection, actual signing correlation,
production exportability checks, and no-fallback semantics. Real non-exportable providers and remote KMS remain pending and are
not implied by this status.

## Context

AnoPKI separates backend-neutral Core operations from selected backend adapters.
Key-provider selection is a separate axis. Before this slice, the Go service
classified `key_ref`, performed policy/readiness preflight through
`keyref.Provider.CheckReady`, and passed the reference to `anopki-core`, while
the C++ OpenSSL signing paths opened and parsed issuer or responder key files
directly.

The Go readiness seam is useful defense in depth, but it is not cryptographic
proof that the expected provider key performed the signature. The signing
boundary must perform its own key resolution, parsing, algorithm compatibility,
issuer-certificate binding, and signing checks.

Three designs were considered:

1. one in-process C++ provider model,
2. a Go prepare/sign/finalize protocol,
3. a deliberately scoped hybrid.

## Decision

AnoPKI uses a **deliberately scoped hybrid**.

- Local file and future local PKCS#11/HSM paths may use an in-process,
  adapter-compatible provider seam.
- Remote KMS is a separate Enterprise protocol problem. It requires a later
  evidence-backed decision and may use either an adapter-compatible provider or
  a versioned prepare/sign/finalize protocol.
- No public API or Core CLI JSON field is added for this first slice.
- Backend selection and provider selection remain explicit and independent.
- Provider failure never retries through another provider, a file key, another
  backend, or another product profile.

## Implemented Community/OpenSSL Slices

The implemented local file-provider slices cover certificate issuance, CRL signing,
and OCSP response signing.

```text
src/backends/openssl/key_providers/
  file_key_provider.hpp
  file_key_provider.cpp
  provider_resolver.hpp
  provider_resolver.cpp
```

The adapter-private provider contract supplies:

- provider ID and class,
- readiness and exportability metadata,
- stable `provider.*` errors,
- redacted diagnostic stage metadata,
- `file:` and bare-path normalization,
- private-key parsing,
- requested signature-algorithm compatibility checks,
- issuer-certificate/private-key binding checks,
- an OpenSSL-private signing-key handle for `X509_sign`, `X509_CRL_sign`, or
  `OCSP_basic_sign`,
- evidence that fallback was not used,
- a redacted private sidecar written only after successful signing when requested
  by the Go core runner.

`src/backends/openssl/issue.cpp`, `src/backends/openssl/crl.cpp`, and
`src/backends/openssl/ocsp.cpp` no longer open signing-key files or call PEM
private-key readers. Each operation resolves one provider once and signs with
the returned private adapter handle. OpenSSL types remain below
`src/backends/openssl`.

Provider evidence records the exact operation as `certificate_issue`,
`crl_generate_sign`, or `ocsp_response_sign`. All three paths preserve the
existing Core CLI JSON contract and fail without provider, file, backend, or
product-profile fallback.

The file provider is explicitly:

- provider class `file`,
- local/development only,
- exportable,
- rejected when `ANOPKI_ENV=production`,
- never a fallback target for another provider reference.

## Single-Provider Resolver And Test Contract

The adapter-private resolver accepts exactly one already-selected provider. It
has no provider list, does not know about `FileKeyProvider`, and cannot search
for an alternative implementation. Before acquisition it rejects invalid or
unsupported references, unavailable providers, and exportable providers in
production. After acquisition it verifies that provider metadata, operation identity, requested algorithm, key algorithm,
binding verification, and `fallback_used=false` evidence match the selected provider and
request.

A software-token provider exists only inside the C++ test target. It exercises a
non-exportable metadata shape, actual OpenSSL signing through the returned
handle, provider failure propagation, evidence mismatch rejection, and
single-acquire behavior. It is not linked into `anopki-core`, is not selectable
by Community runtime configuration, and is not evidence of production
non-exportability or PKCS#11/HSM support.

## Stable Provider Errors

- `provider.invalid_reference`
- `provider.unavailable`
- `provider.not_ready`
- `provider.key_not_found`
- `provider.key_parse_failed`
- `provider.algorithm_mismatch`
- `provider.key_binding_mismatch`
- `provider.exportability_violation`
- `provider.profile_mismatch`
- `provider.sign_failed`
- `provider.evidence_failed`

The stable code is the exception message consumed by the existing CLI error
mapping. Raw OpenSSL errors and raw paths are cleared or omitted from provider
diagnostics.

## Evidence Semantics

`keyref.Provider.CheckReady` remains a policy and preflight signal only.
Certificate, CRL, and OCSP signing evidence requires the selected C++ provider path to:

1. resolve the requested reference without fallback,
2. acquire the selected provider exactly once and reject mismatched provider
   evidence or any `fallback_used=true` result,
3. acquire and parse the actual key,
4. verify requested algorithm compatibility,
5. verify issuer certificate/key binding,
6. complete `X509_sign`, `X509_CRL_sign`, or `OCSP_basic_sign` with the
   returned handle,
7. preserve the certificate, CRL, and OCSP golden results.

The Go runner requests the sidecar with
`ANOPKI_CORE_SIGNING_EVIDENCE_FILE`, parses it with unknown-field rejection, and
validates provider identity/class/readiness/exportability, operation, algorithm,
binding, `fallback_used=false`, and `result_code=ok`. Certificate evidence is
stored with the durable issuance attempt so retry/finalization and audit repair
reuse the same completed signing result. CRL and OCSP audit events use the
operation result directly. Legacy issuance attempts without evidence are marked
classification-only and unproven.

This sidecar is adapter-private process coordination, not a public Core CLI JSON
wire field. Failure to write requested evidence returns
`provider.evidence_failed` and fails the operation closed. A successful Go
readiness check alone cannot mark cryptographic signing evidence as passed.

Because evidence is written after the cryptographic primitive succeeds, an
`provider.evidence_failed` result can leave an unreturned local signature that
is not accepted or persisted by the lifecycle service. This local file-provider
slice deliberately prefers fail-closed evidence over presenting an unproven
success. A remote or billed/non-idempotent signer must not reuse this assumption;
its retry and duplicate-signing semantics require separate prepare/sign/finalize
approval before implementation.

## Non-goals Of This Slice

- real PKCS#11/HSM implementation,
- real cloud KMS implementation,
- prepare/sign/finalize protocol,
- Enterprise/AnoCrypto-C changes,
- a production non-exportability claim.

## Consequences

- Community/OpenSSL certificate issuance, CRL generation, and OCSP response
  signing have one explicit key-provider path per operation.
- Existing public lifecycle and Core CLI JSON contracts remain unchanged.
- Existing certificate, CRL, and OCSP behavior remains pinned by the Community
  golden and integration tests.
- A test-only software-token provider pins the generic resolver contract without
  becoming a runtime or production provider.
- Production still rejects the exportable file provider.
- Enterprise synchronizes this reviewed Community change only after the
  Community commit SHA is known.
