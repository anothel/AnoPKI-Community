# ADR 0005: Rename Project To AnoPKI

## Status

Accepted

## Context

The project previously used the development name `modern-pki`. The new public project name is `AnoPKI`.

The rename needs to cover user-facing documentation, build targets, Go command paths, C++ namespaces, environment variables, release artifacts, and webhook headers.

## Decision

Use **AnoPKI** as the public name and `anopki` as the technical identifier.

Key identifiers:

- C++ namespace: `anopki`
- Core CLI binary: `anopki-core`
- Go service command: `anopki-service`
- Environment variable prefix: `ANOPKI_`
- Webhook header prefix: `X-AnoPKI-`
- Go module path: `github.com/anothel/anopki/service`

## Consequences

- Existing local scripts and deployments that used `MODERN_PKI_*` variables must migrate to `ANOPKI_*` variables.
- Existing webhook receivers that verified `X-Modern-PKI-*` headers must migrate to `X-AnoPKI-*` headers.
- Release automation must publish `anopki-*` artifacts.
- Historical docs may mention `modern-pki` only as the previous name.
