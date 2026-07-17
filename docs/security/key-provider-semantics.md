# Key Provider Semantics

This document defines provider policy and the implemented Community/OpenSSL
local signing slices. ADR 0007 owns the deliberately scoped hybrid architecture
decision.

## Selected Boundary

All signing keys are addressed by `key_ref`.

- `file:` and bare filesystem references are local/development only.
- Production providers must be non-exportable.
- Provider selection is separate from backend-adapter selection.
- Provider failure never triggers an implicit file, provider, adapter, or
  product-profile fallback.
- Private key bytes must not cross into the Go service, database,
  backend-neutral Core, public API, logs, or diagnostics.

## Provider Classes

| Class | Intended use | Exportability | Current implementation |
| --- | --- | --- | --- |
| File | Local development and smoke | Exportable | Certificate issuance, CRL generation, and OCSP response signing |
| Software token | Contract testing only | Simulated non-exportable metadata | Test target only; not a runtime provider or production evidence |
| PKCS#11/local HSM | Future production signing | Non-exportable | Not implemented |
| Cloud KMS | Future Enterprise remote signing | Non-exportable | Not implemented |

## Implemented Certificate, CRL, And OCSP Paths

Community/OpenSSL certificate issuance, CRL generation, and OCSP response
signing each resolve a single adapter-private `FileKeyProvider`.

The provider:

- normalizes `file:` and bare paths,
- reports provider identity/class/readiness/exportability,
- opens and parses the actual private key,
- rejects encrypted private-key PEM non-interactively because the current
  provider contract has no password-input channel,
- checks requested RSA/ECDSA/Ed25519 compatibility,
- verifies the exact issuer or responder signing certificate/key binding,
- returns an OpenSSL-private signing handle,
- reports `fallback_used=false`,
- emits stable, redacted `provider.*` failures.

`src/backends/openssl/issue.cpp`, `src/backends/openssl/crl.cpp`, and
`src/backends/openssl/ocsp.cpp` do not open signing-key files or invoke PEM
private-key readers. `X509_sign`, `X509_CRL_sign`, and `OCSP_basic_sign` remain
in the OpenSSL adapter to preserve the one-operation CLI contract and existing
certificate, CRL, and OCSP results.

The provider evidence identifies `certificate_issue`, `crl_generate_sign`, and
`ocsp_response_sign` separately. A successful result for one operation is not
evidence for another.

## Resolver Contract Test

The adapter-private resolver receives exactly one selected provider. It rejects
invalid references, unsupported references, unavailable readiness, and
exportable production providers before acquisition. It acquires once, then
fails closed if returned provider metadata, operation identity, requested algorithm, key algorithm, or
binding result differs from the selection or if the provider claims
`fallback_used=true`.

The test-only software-token resolver contract lives only under `tests/`.
Its non-exportable flag is simulated contract metadata, not evidence that
AnoPKI currently controls a real non-exportable device or token.

## Go And C++ Evidence Responsibilities

### Go lifecycle service

- classifies references,
- applies service policy,
- performs early `CheckReady` preflight,
- requests one private redacted signing-evidence sidecar from `anopki-core`,
- rejects missing, malformed, mismatched, or fallback-claiming sidecar evidence,
- persists certificate-issuance evidence with the durable issuance attempt,
- records CRL and OCSP audit metadata from the returned signing evidence,
- marks legacy rows without sidecar evidence as classification-only and
  `key_provider_signing_proven=false`.

### C++ selected adapter/provider

- resolves the actual provider,
- reaches and parses the actual key,
- checks algorithm compatibility and certificate binding,
- performs signing with the returned handle,
- produces the actual operation result or stable failure.

The Go `CheckReady` result is not cryptographic signing evidence. After a
successful `X509_sign`, `X509_CRL_sign`, or `OCSP_basic_sign`, the selected C++
provider writes a redacted internal sidecar only when the runner supplies
`ANOPKI_CORE_SIGNING_EVIDENCE_FILE`. The sidecar is not a public CLI JSON field.
If the requested sidecar cannot be written, the signing operation fails closed.
A release or audit claim about actual signing must come from this completed
C++ path, not from readiness or key-reference classification.
The file-provider slice may therefore perform a local cryptographic primitive
whose result is not returned when post-sign evidence writing fails. The service
must not treat that failed command as issued material or successful audit
evidence. Remote or non-idempotent providers require a separately approved
retry/duplicate-signing protocol before integration.

## Stable Errors

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

Only stable codes and redacted stages such as `resolve`, `open`, `parse`,
`algorithm`, `binding`, `policy`, `sign`, and `evidence` may leave the provider boundary.
Raw paths, PEM data, credentials, PINs, session tokens, and raw provider/OpenSSL
errors are prohibited.

## Production Gates

Production mode fails closed when:

- the selected provider is the exportable file provider,
- provider availability/readiness fails,
- the key cannot be found or parsed,
- the requested algorithm is incompatible,
- issuer certificate/key binding fails,
- the selected backend/profile is incompatible,
- configuration would require fallback.

`ANOPKI_ENV=production` causes certificate, CRL, and OCSP signing through the
file provider to return `provider.exportability_violation` before the key file
is opened.

## Current Scope Limits

- Certificate issuance: provider-isolated through `FileKeyProvider`.
- CRL signing: provider-isolated through `FileKeyProvider`.
- OCSP response signing: provider-isolated through `FileKeyProvider`.
- Test-only software-token resolver contract: implemented; not shipped.
- Actual signing-result correlation: implemented through an internal redacted
  sidecar for certificate issuance, CRL signing, and OCSP response signing.
- Certificate evidence persistence: implemented on the durable issuance attempt.
- Legacy issuance rows without evidence remain explicitly unproven.
- `GET /version` and `anopki-release-metadata.json` report immutable product
  profile, backend, and Community provider-policy metadata. They are
  release/configuration evidence only, not per-operation signing proof, and
  never contain a raw `key_ref` or filesystem path.
- Real non-exportable provider: not implemented.
- Remote KMS prepare/sign/finalize: not implemented.
- Other product-profile provider integrations are outside this Community project.

No production HSM/KMS/PKCS#11 or non-exportability claim is allowed from this
slice.
