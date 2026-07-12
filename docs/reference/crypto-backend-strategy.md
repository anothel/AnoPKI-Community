# Crypto Backend Strategy

This document defines the backend-neutral core, adapter ownership, product
composition, and release rules for OpenSSL and external AnoCrypto-C builds.

## Current State

Community/OpenSSL remains the complete implementation. Backend-neutral dispatch lives under `src/core`, while CSR inspection, certificate issuance, CRL generation, OCSP request decoding, OCSP response signing, and OpenSSL diagnostics live under `src/backends/openssl`. The `anopki_core` target no longer links OpenSSL directly; the OpenSSL adapter target owns that dependency.

Backend identity, dependency version, capability, readiness, stable error metadata, and explicit product-profile selection are implemented in the C++ control contract.

The project does not develop AnoCrypto inside AnoPKI. AnoCrypto-C is a
separate external C99 project and SDK. Enterprise consumes it through an
AnoPKI-owned adapter.

## Target Architecture

```text
                         +-> OpenSSL adapter -----> OpenSSL::Crypto
AnoPKI Core ------------|
                         `-> AnoCrypto-C adapter -> AnoCryptoC::AnoCryptoC
```

`AnoPKI Core` owns backend-neutral operation contracts and domain-safe error
semantics. Each adapter owns dependency-specific calls and translation.

## Repository Ownership

### Community Repository

- backend-neutral AnoPKI Core contract,
- OpenSSL adapter,
- Community/OpenSSL golden and contract tests,
- public CLI and service contracts.

Community does not contain AnoCrypto-C source, an AnoCrypto-C adapter, private
SDK artifacts, KCMVP submissions, or Enterprise release evidence.

### Enterprise Repository

- synchronized Community core and OpenSSL adapter,
- Enterprise layer,
- AnoCrypto-C adapter,
- external SDK acquisition and version/fingerprint policy,
- Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles,
- private parity, packaging, and compliance evidence.

### AnoCrypto-C Repository

- cryptographic algorithm implementation,
- public C API and CMake package `AnoCryptoC::AnoCryptoC`,
- module lifecycle and state,
- self-tests and secure memory behavior,
- algorithm implementation tests,
- exact-module KCMVP evidence when available.

## Product Profiles

| Profile | Composition | Functional expectation | Release position |
| --- | --- | --- | --- |
| Community/OpenSSL | Core + OpenSSL adapter | Complete Community functionality | Public release candidate allowed after Community evidence passes. |
| Enterprise/OpenSSL | Core + OpenSSL adapter + Enterprise layer | Complete Community functionality plus Enterprise features | Commercial profile; no AnoCrypto or KCMVP claim. |
| Enterprise/AnoCrypto-C | Core + AnoCrypto-C adapter + Enterprise layer | Only capabilities implemented by the external SDK and adapter | Development/integration only until required operation parity is complete. |

## Backend Contract

The operation-level adapter contract must cover the operations consumed by the
service and CLI, including:

- CSR inspection,
- certificate issuance,
- CRL generation,
- OCSP request inspection,
- OCSP response generation,
- responder certificate validation,
- backend identity and capability reporting,
- stable error mapping.

The contract must not expose OpenSSL or AnoCrypto-C SDK types.

## Capability And Failure Semantics

Every adapter reports a capability set. Unsupported AnoCrypto-C operations must
return a stable error such as `backend.capability_unavailable`.

A product profile declares required capabilities:

- missing optional capability: request fails explicitly,
- missing required capability: startup or release gate fails,
- dependency initialization/version mismatch: profile fails closed.

A skipped test is not proof of support. A parity item moves from pending only
when the real external SDK path executes and passes the required positive and
negative tests.

## No Automatic Fallback

The following behavior is prohibited:

- AnoCrypto-C operation failure followed by an OpenSSL retry,
- unsupported AnoCrypto-C capability transparently calling OpenSSL,
- AnoCrypto-C initialization failure starting an OpenSSL profile without an
  explicit configuration change.

OpenSSL compatibility is selected as `Enterprise/OpenSSL` before startup or at
build/package selection time. It is not an implicit fallback from
`Enterprise/AnoCrypto-C`.

## Migration Gates

Before Enterprise/AnoCrypto-C can be production-releasable:

1. Community/OpenSSL behavior remains pinned by golden and contract tests,
2. explicit product/build profiles select one adapter without automatic fallback,
3. the Enterprise adapter consumes a pinned external AnoCrypto-C SDK,
4. required CSR, issuance, CRL, and OCSP capability parity is implemented,
5. stable error and capability-unavailable semantics are verified,
6. tests prove no hidden OpenSSL fallback occurs,
7. dependency version, build identity, artifact hash, platform, and capability
   evidence are recorded,
8. key handling and failure modes receive security review,
9. KCMVP claims, if any, are limited to the exact validated AnoCrypto-C module
   shape and operating environment.

## Relationship To Key Providers

Backend adapter selection and key-provider selection are separate.

- The selected backend adapter implements PKI operations through its dependency.
- The key provider owns `key_ref`, key location, exportability, readiness,
  authorization, and provider audit metadata.
- HSM/KMS/PKCS#11 providers may perform signing without exporting private key
  bytes.

Selecting AnoCrypto-C must not weaken non-exportability or cause private key
material to enter the service database.

## Required Release Metadata

Each build and release candidate records:

- edition,
- product profile,
- selected adapter,
- backend dependency and exact version,
- backend capability set,
- key-provider class,
- `fallback_used` (normally `false`),
- production-readiness status,
- KCMVP status and evidence pointer when applicable.

## Implemented Control Contract

The shared `Backend` contract now reports `BackendInfo` with adapter ID,
dependency/version, readiness, ABI/build metadata, and operation capabilities.
Core dispatch verifies each operation capability before calling an adapter.

Builds select one immutable product profile:

```text
Community: ANOPKI_PRODUCT_PROFILE=community-openssl
Enterprise: ANOPKI_PRODUCT_PROFILE=enterprise-openssl
Enterprise: ANOPKI_PRODUCT_PROFILE=enterprise-anocrypto-c
```

The CLI command `anopki-core backend info` exposes the selected profile and
backend metadata for release evidence. `fallback_enabled` is always false.
Enterprise/AnoCrypto-C builds require the real external CMake package and do not
link OpenSSL. Missing SDK configuration fails at CMake configure time.
