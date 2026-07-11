# Release Process

`AnoPKI` is pre-1.0. This process creates a reviewed release candidate; it
does not publish packages by itself.

## Preconditions

- Roadmap completed items have been removed from [ROADMAP](../ROADMAP.md).
- Release scope is aligned with
  [Release readiness action plan](../reference/release-readiness-action-plan.md).
- `README.md`, `SECURITY.md`, service docs, and runbooks match behavior.
- No real secrets, private keys, DB dumps, or production certificates are in the
  working tree.
- Owner has decided whether the release is internal-only or public.
- The tag name matches the repository `VERSION` file.

## Build And Test

Run service checks:

```powershell
cd service
$env:GOCACHE = "$PWD\..\.tmp\gocache"
go test ./...
go build ./cmd/anopki-service
```

Run core checks:

```powershell
$env:OPENSSL_ROOT_DIR = "C:\vcpkg\installed\x64-windows"
cmake -S . -B build -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

On Windows, `OPENSSL_ROOT_DIR` must point to a root containing
`bin\libcrypto*.dll`. CMake copies detected runtime DLLs beside `anopki-core`.
For direct test execution, either keep those copied DLLs beside test binaries or
prepend that `bin` directory to PATH for the current shell only. Do not modify
global PATH. `scripts\verify-local.ps1` detects common vcpkg locations, applies
a process-local PATH, restores it afterward, and fails early with setup guidance
instead of allowing CTest exit `0xc0000135`.

Run optional smoke checks when tools are available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -StartService -Run
```

Certbot smoke requires Linux/WSL or elevated Windows with certbot installed.

## Release Candidate Checklist

1. Confirm `git status --short` contains only intended files.
2. Run `git diff --check`.
3. Run the root README quickstart smoke checklist.
4. Confirm the Community release checklist:
   - docs validation passed,
   - service contract validation passed,
   - core CLI contract validation passed,
   - secret baseline scan passed,
   - Go service tests and build passed,
   - CMake configure/build and CTest passed,
   - compatibility matrix evidence is current,
   - known gaps are recorded.
5. Review endpoint, config, migration, and runbook changes.
6. Record exact verification commands and results in `CHANGELOG.md` or release
   notes.
7. Record known gaps from [ROADMAP](../ROADMAP.md), especially compatibility
   matrix updates and deferred EAB/DNS-01 conditions.
8. Attach the GitHub Actions run URL for `.github/workflows/ci.yml`. If this
   repository is published on GitHub, add a README badge/link using the
   canonical remote slug:

   ```markdown
   [![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
   ```

9. Attach compatibility evidence from
   [ACME client compatibility](../acme-client-compatibility.md) when ACME
   behavior changed.
10. Attach RFC 8555 evidence from
   [ACME conformance](../acme-rfc8555-conformance.md) when ACME behavior
   changed.
11. Attach route/OpenAPI, operation ID, path/query parameter, config/docs, API error
   mapping, docs validation, and secret baseline scan evidence from CI.
12. Attach the `.github/workflows/release.yml` run URL and uploaded
   `anopki-release` artifact containing smoke-checked archives,
   `SHA256SUMS`, CycloneDX SBOM, cosign signatures, and cosign certificates.
13. Copy and complete the compatibility evidence template from
   [Release evidence](../reference/release-evidence.md).
14. Keep candidate-specific command results, known gaps, and tag blockers in a
    versioned evidence draft such as
    [v0.1.0-alpha.0 candidate evidence](../reference/release-candidate-v0.1.0-alpha.0.md).

## Version Metadata

Builds should set:

- `serviceVersion`
- `serviceCommit`
- `serviceBuildTime`

The release workflow reads `VERSION`, checks that the tag without leading `v`
matches it, and injects the value into `serviceVersion`.

Verify the running service reports the expected values:

```powershell
curl.exe http://localhost:8080/version
```

## Approval

Before tagging or distributing:

- security-sensitive changes reviewed,
- deployment and rollback plan reviewed,
- backup and restore path confirmed,
- owner accepts remaining roadmap gaps,
- MPL-2.0 license status confirmed.

## Post-Release

1. Monitor `/readyz`, audit failures, outbox dead letters, expiration scan
   results, CRL publication, and OCSP health.
2. Record any release-specific operational notes in the next release candidate.
3. Move completed roadmap items out of the future roadmap.
