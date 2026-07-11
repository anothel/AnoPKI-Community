# Release Candidate Evidence: v0.1.0-alpha.0

Status: local evidence complete; external release evidence pending. Do not tag
or publish from this document.

Evidence date: 2026-07-11. Branch: `main`. Verified commit:
`2be155780d4b024c76b0a901ec130e83fc221f2f`. The tracked worktree was clean
before this evidence update.

## Release Position

- Version source: `VERSION` = `0.1.0-alpha.0`; intended tag is
  `v0.1.0-alpha.0`.
- Maturity: pre-1.0 alpha, not production-stable.
- Lifecycle and operator APIs: experimental/not-production-stable; public API
  compatibility freeze is not complete.
- Active crypto backend: OpenSSL-backed C++ core, OpenSSL 3.6.3 locally.
- AnoCrypto: intended migration direction only; not active, implemented, or
  production-ready in Community.

## Local Environment

| Tool | Observed value |
| --- | --- |
| OS | Microsoft Windows 11 Pro 10.0.26100, 64-bit |
| Python | 3.14.6 |
| Go | 1.26.4 windows/amd64 |
| CMake | 4.4.0-rc1 |
| C++ | MSVC 19.51.36246.0, Visual Studio 18 2026 generator |
| OpenSSL | vcpkg `openssl:x64-windows` 3.6.3 |

## Commands And Evidence

Run from repository root unless a working directory is shown.

| Command | Result | Expected evidence |
| --- | --- | --- |
| `python scripts/validate-community-boundary.py` | Pass | `community boundary ok` |
| `python scripts/test_validate_community_boundary.py` | Pass | `community boundary validator tests ok` |
| `python scripts/validate-docs.py` | Pass | `docs ok` |
| `python scripts/test_validate_docs.py` | Pass | `docs validator tests ok` |
| `python scripts/validate-service-contracts.py` | Pass | `service contracts ok` |
| `python scripts/test_validate_service_contracts.py` | Pass | `service contract validator tests ok` |
| `python scripts/validate-core-cli-contracts.py` | Pass | `core CLI contracts ok` |
| `python scripts/test_validate_core_cli_contracts.py` | Pass | `core CLI contract validator tests ok` |
| `python scripts/security-baseline-scan.py` | Pass | `secret baseline scan ok` |
| `python scripts/test_security_baseline_scan.py` | Pass | `security baseline scan tests ok` |
| `python scripts/test_validate_version_metadata.py` | Pass | `version metadata tests ok` |
| `python scripts/validate-version-metadata.py` | Pass | `version metadata ok` |
| `python scripts/validate-release-evidence.py` | Pass | `release evidence ok` |
| `python scripts/test_validate_release_evidence.py` | Pass | `release evidence validator tests ok` |
| `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1` | Pass | `run-certbot-smoke tests passed`; harness test only, not live client evidence. |
| `python scripts/test_verify_local.py` | Pass | Runtime detection success and missing-DLL failure behavior validated. |
| `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-local.ps1 -CheckOpenSSLRuntime -OpenSSLRootDir C:\vcpkg\installed\x64-windows` | Pass | Process-local runtime found at `C:\vcpkg\installed\x64-windows\bin`. |
| `$env:GOCACHE = "$PWD\..\.tmp\alpha-evidence\gocache"; go test ./...` from `service` | Pass | All tested packages `ok`; `domain` and `observability` report no test files. |
| `$env:GOCACHE = "$PWD\..\.tmp\alpha-evidence\gocache"; go vet ./...` from `service` | Pass | Exit 0, no findings. |
| `$env:GOCACHE = "$PWD\..\.tmp\alpha-evidence\gocache"; go build -o ..\.tmp\alpha-evidence\anopki-service.exe ./cmd/anopki-service` from `service` | Pass | Service executable created. |
| `cmake -S . -B .tmp\alpha-cmake -DOPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows` | Pass | OpenSSL Crypto 3.6.3 found; configure and generate complete. |
| `cmake --build .tmp\alpha-cmake --config Debug` | Pass | Core CLI and seven test executables built; `libcrypto-3-x64.dll` copied beside them. |
| `ctest --test-dir .tmp\alpha-cmake -C Debug --output-on-failure` | Pass | 7/7 tests passed. |
| `git diff --check` | Pass with line-ending warnings | No whitespace errors; Git reports expected LF-to-CRLF conversion warnings. |
| `git status --short` before evidence changes | Pass | Clean tracked worktree at verified commit. |

## Required Before Tagging

- Commit reviewed candidate changes, then record clean `git status` and final
  commit SHA.
- Run candidate commit through `.github/workflows/ci.yml` and record run URL and
  all job results.
- Complete compatibility evidence for Ubuntu/Windows, PostgreSQL, lego, and
  certbot where applicable.
- Run or obtain CI evidence for race detector, `go vet`, `staticcheck`, `gosec`,
  `govulncheck`, and parser fuzz/sanitizer smoke. Local `go vet` passed in this
  evidence run.
- Produce release workflow artifacts in a non-publishing verification run, or
  retain this as a blocker: source archive, service/core archives,
  `SHA256SUMS`, CycloneDX SBOM, and cosign evidence.
- Review known gaps and obtain owner acceptance before creating any tag.

## Known Gaps

- Public lifecycle/operator API compatibility freeze is incomplete.
- Public ACME remains experimental/smoke-only; EAB and DNS-01 are not present.
- PostgreSQL integration and live lego/certbot compatibility were not rerun for
  this local draft.
- `go test -race ./...` was not run locally because the supported Windows path
  requires a C toolchain/CGO or WSL; candidate CI/WSL evidence remains required.
- Parser fuzz/sanitizer smoke was not run because it requires a separate
  Clang/libFuzzer/AddressSanitizer build; use the CI fuzz job.
- `staticcheck`, `gosec`, and `govulncheck` were not rerun locally because they
  require separately acquired tools; candidate CI remains the evidence source.
- Release archives, `SHA256SUMS`, SBOM, cosign evidence, tagging, and publishing
  were intentionally not produced because this task forbids release publication.
- No HSM/KMS/PKCS#11 production provider or non-exportable signing path exists.
- Audit tamper-evidence storage and SIEM exporter integration remain incomplete.
- Backend parity currently uses semantic comparisons; no deterministic exact-DER
  case is active.
- AnoCrypto remains intended future work only.

Release readiness decision: local alpha evidence milestone is complete. The
candidate is not ready to tag or publish until external/CI and artifact evidence
above is closed or explicitly accepted as a release blocker exception.
