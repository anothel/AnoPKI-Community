# Contributing

## Project Scope

`AnoPKI` is an operational PKI lifecycle service. Contributions should support certificate lifecycle operation: identity, enrollment, issuance policy, renewal, revocation, status publication, audit, notification, ACME automation, and operator safety.

Avoid unrelated product surface or speculative abstractions. Keep changes small, reviewed, documented, and verifiable.

## Prerequisites

- Go 1.25.11+
- CMake 3.20+
- C++20 compiler
- OpenSSL development libraries

On Windows, set `OPENSSL_ROOT_DIR` if CMake cannot find OpenSSL.

## Local Verification

Run Go service tests and build:

```powershell
cd service
go test ./...
go build ./cmd/anopki-service
```

Run C++ core build and tests:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

For targeted ACME smoke harness checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1
```

Do not claim remote CI has run unless you have checked the remote CI result.

## Roadmap Rules

- Use [docs/ROADMAP.md](docs/ROADMAP.md) as the source of truth for priorities.
- Move completed work out of "Next shape" and into completed or current status.
- Keep deferred work explicit with a reason.
- Leave `LICENSE` as a project owner decision unless the owner gives specific direction.

## Documentation Expectations

- Update README links when adding operator or contributor docs.
- Update service docs when behavior, endpoints, config, or environment variables change.
- Update runbooks when manual verification steps change.
- Document security-sensitive defaults and production requirements in [SECURITY.md](SECURITY.md).

## Agent Git Ownership

Agents must not run `git add`, `git commit`, or `git push` unless the user explicitly asks for that action in the current task. Read-only Git inspection is fine.

Do not revert unrelated edits. The working tree can include user-owned or other-worker changes.

## Commit Messages

Use concise, imperative commit messages that name the changed area and behavior:

```text
docs: add security policy
service: reject weak production bootstrap keys
acme: return issuer chain in certificate response
```

Prefer one logical change per commit. Include tests or verification notes in the commit body when useful.
