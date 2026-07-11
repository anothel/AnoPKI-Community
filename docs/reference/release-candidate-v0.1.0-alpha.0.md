# Release Candidate Evidence: v0.1.0-alpha.0

Status: draft only. Do not tag or publish from this document.

Evidence date: 2026-07-11. Branch: `main`. Baseline commit before candidate
changes: `7e68333f88d00c1d37b1e381184574f33dc4e498`.

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
| OS | Windows amd64 |
| Python | 3.14.6 |
| Go | 1.26.4 windows/amd64 |
| CMake | 4.4.0-rc1 |
| C++ | MSVC 19.51.36246.0, Visual Studio 18 2026 generator |
| OpenSSL | vcpkg `openssl:x64-windows` 3.6.3 |

## Commands And Evidence

Run from repository root unless a working directory is shown.

| Command | Result | Expected evidence |
| --- | --- | --- |
| `python scripts/validate-docs.py` | Pass | `docs ok` |
| `python scripts/validate-service-contracts.py` | Pass | `service contracts ok` |
| `python scripts/validate-core-cli-contracts.py` | Pass | `core CLI contracts ok` |
| `python scripts/security-baseline-scan.py` | Pass | `secret baseline scan ok` |
| `python scripts/test_validate_version_metadata.py` | Pass | `version metadata tests ok` |
| `python scripts/validate-version-metadata.py` | Pass | `version metadata ok` |
| `python scripts/validate-release-evidence.py` | Pass | `release evidence ok` |
| `$env:GOCACHE = "$PWD\..\.tmp\gocache"; go test ./...` from `service` | Pass | All tested packages `ok`; `domain` and `observability` report no test files. |
| `cmake -S . -B build -DOPENSSL_ROOT_DIR=C:\vcpkg\installed\x64-windows` | Pass | OpenSSL Crypto 3.6.3 found; configure and generate complete. |
| `cmake --build build --config Debug` | Pass | Core CLI and seven test executables built. |
| `ctest --test-dir build -C Debug --output-on-failure` | Pass | 7/7 tests passed. |
| `build\Debug\anopki_core_openssl_golden_test.exe build tests\fixtures\backend-parity` | Pass | Five OpenSSL operations report `semantic_equal`. |
| `git diff --check` | Pass with line-ending warnings | No whitespace errors; Git reports expected LF-to-CRLF conversion warnings. |
| `git status --short` | Open | Candidate changes are not committed; cleanliness evidence must be captured after review. |

## Required Before Tagging

- Commit reviewed candidate changes, then record clean `git status` and final
  commit SHA.
- Run candidate commit through `.github/workflows/ci.yml` and record run URL and
  all job results.
- Complete compatibility evidence for Ubuntu/Windows, PostgreSQL, lego, and
  certbot where applicable.
- Run or obtain CI evidence for race detector, `go vet`, `staticcheck`, `gosec`,
  `govulncheck`, and parser fuzz/sanitizer smoke.
- Produce release workflow artifacts in a non-publishing verification run, or
  retain this as a blocker: source archive, service/core archives,
  `SHA256SUMS`, CycloneDX SBOM, and cosign evidence.
- Review known gaps and obtain owner acceptance before creating any tag.

## Known Gaps

- Public lifecycle/operator API compatibility freeze is incomplete.
- Public ACME remains experimental/smoke-only; EAB and DNS-01 are not present.
- PostgreSQL integration and live lego/certbot compatibility were not rerun for
  this local draft.
- No HSM/KMS/PKCS#11 production provider or non-exportable signing path exists.
- Audit tamper-evidence storage and SIEM exporter integration remain incomplete.
- Backend parity currently uses semantic comparisons; no deterministic exact-DER
  case is active.
- AnoCrypto remains intended future work only.

Release readiness decision: not ready to tag or publish until required evidence
above is closed or explicitly accepted as a release blocker exception.
