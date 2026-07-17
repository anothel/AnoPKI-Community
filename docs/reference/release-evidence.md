# Release Evidence

This file records release artifact, supply-chain, and compatibility decisions.
Release candidates attach evidence here by command output or CI run URL.

Current draft: [v0.1.0-alpha.0 candidate evidence](release-candidate-v0.1.0-alpha.0.md).

## Tool Decisions

| Area | Selected tool | Evidence hook |
| --- | --- | --- |
| Go test, vet, and build | Go 1.25.11 minimum plus current CI Go | CI `go-baseline` matrix. |
| Go staticcheck | `staticcheck` | CI `go-analysis` job via `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`. |
| Go security scan | `gosec` | CI `go-analysis` job via `go run github.com/securego/gosec/v2/cmd/gosec@latest ./...`. |
| Go race detector | `go test -race ./...` | CI `go-analysis` job with `CGO_ENABLED=1`. |
| Go dependency vulnerability scan | `govulncheck` | CI `go-analysis` job via `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`. |
| PostgreSQL | PostgreSQL 16 service integration | CI `postgres-integration` job records client/server versions. |
| C++ parser fuzz/sanitizer smoke | Clang/libFuzzer with AddressSanitizer | CI `cpp-fuzz-smoke` job builds CSR, OCSP, and CRL parser targets and runs each for at most 20 seconds. |
| Community boundary | `scripts/validate-community-boundary.py` | CI `community-boundary` job. |
| Secret baseline | `scripts/security-baseline-scan.py` | CI `secret-baseline` job and README smoke checklist. |
| SBOM | `syft` CycloneDX JSON | Release workflow writes `dist/anopki.sbom.cdx.json`. |
| Artifact signing | `cosign` keyless signing | Tag-only publish job signs checksums, SBOM, and archives; manual dry-runs record signing as skipped. |

## Release Artifacts

Pre-1.0 releases distribute archives, not installers or container images:

- source archive from the signed tag,
- `anopki-service` binary archive,
- `anopki-core` CLI binary archive,
- `SHA256SUMS`,
- CycloneDX SBOM JSON,
- cosign signatures and transparency-log references for archives, checksums,
  and SBOM.

The manually dispatched release workflow runs with read-only repository
permissions. It builds Linux amd64 service/core archives with the repository
version in their filenames, writes `SHA256SUMS`, validates archive contents,
generates a CycloneDX SBOM with `syft`, records signing as skipped, and uploads
the `dist/` directory only to the workflow run.

Publishing is a separate job limited to a matching `v*` tag push. It requires
a signed annotated tag and the `release` GitHub environment before receiving
`contents: write` and OIDC permissions, signing evidence with `cosign`, and
creating or updating the matching GitHub Release.

Container images, OS packages, and Helm charts stay out until a deployment
target is selected.

## Compatibility Matrix

Each release candidate records this matrix in release notes:

| Area | Required evidence |
| --- | --- |
| OS | GitHub Actions Ubuntu result plus any Windows local verification used for release. |
| Go | `go version` from CI and release host; CI pins at least Go 1.25.11 for standard-library vulnerability fixes. |
| OpenSSL | CMake configure output or package version used by C++ build. |
| SQLite | Go test result for memory/SQLite stores. |
| PostgreSQL | PostgreSQL integration job result and DSN major version. |
| lego | ACME smoke result when ACME behavior changed. |
| certbot | Linux or elevated Windows smoke result when environment exists; WSL certbot evidence is recorded in the ACME client compatibility matrix. |

## Release Candidate Compatibility Evidence Template

Copy this table into release notes for each release candidate and replace
`pending` with the command output, CI URL, artifact URL, or explicit skip reason.

| Area | Command or source | Result | Evidence pointer |
| --- | --- | --- | --- |
| OS | GitHub Actions Ubuntu job plus any Windows local verification | pending | pending |
| Go | `go version` from CI and release host | pending | pending |
| OpenSSL | CMake configure output or package version | pending | pending |
| SQLite | Local or CI Go test result covering SQLite store | pending | pending |
| PostgreSQL | PostgreSQL integration job and DSN major version | pending | pending |
| lego | ACME smoke command/output when ACME behavior changed | pending | pending |
| certbot | WSL/Linux/elevated Windows smoke command/output when ACME behavior changed | pending | pending |


## Local ZIP Baseline Evidence - 2026-07-06

This evidence was gathered from the uploaded `AnoPKI.zip` source tree in a Linux sandbox. The ZIP did not include `.git`, so `git status --short` and `git diff --check` could not prove repository baseline cleanliness. Re-run those commands in the real repository before tagging.

Environment observed locally:

| Tool | Observed value | Release impact |
| --- | --- | --- |
| Python | 3.13.5 | Docs and script validators ran locally. |
| Go | 1.23.2 | Too old for this repository; `go.mod` requires Go 1.25.0 or newer and CI is pinned to Go 1.25.11. |
| CMake | 3.31.6 | Core configure/build ran locally. |
| C++ compiler | G++ 14.2.0 | Debug core build and CTest ran locally. |
| Fuzz compiler | Clang++ 17.0.0 from the local Swift toolchain | Fuzz build ran; default sanitizer execution needs CI confirmation. |
| OpenSSL | 3.5.5 | Active local crypto backend evidence for this baseline. |

Local command results:

| Command | Result | Notes |
| --- | --- | --- |
| `python scripts/validate-docs.py` | Pass | `docs ok`. |
| `python scripts/test_validate_docs.py` | Pass | `docs validator tests ok`. |
| `python scripts/validate-service-contracts.py` | Pass | `service contracts ok`. |
| `python scripts/validate-core-cli-contracts.py` | Pass | `core CLI contracts ok`. |
| `python scripts/validate-release-evidence.py` | Pass | `release evidence ok`. |
| `python scripts/security-baseline-scan.py` | Pass | `secret baseline scan ok`. |
| `python scripts/test_validate_service_contracts.py` | Pass | `service contract validator tests ok`. |
| `python scripts/test_validate_core_cli_contracts.py` | Pass | `core CLI contract validator tests ok`. |
| `python scripts/test_validate_release_evidence.py` | Pass | `release evidence validator tests ok`. |
| `python scripts/test_security_baseline_scan.py` | Pass | `security baseline scan tests ok`. |
| `python scripts/test_validate_version_metadata.py` | Pass | `version metadata tests ok`. |
| `python scripts/validate-version-metadata.py` | Pass | `version metadata ok`. |
| `python scripts/test_validate_release_artifacts.py` | Pass | `release artifact tests ok`. |
| `python scripts/test_webhook_receiver_verification.py` | Pass | `webhook receiver verification tests passed: 10`. |
| `python scripts/test_verify_local.py` | Blocked locally | PowerShell executable was not available in the sandbox. |
| `go test ./...` | Blocked locally | Host Go was 1.23.2; toolchain download for Go 1.25.0 failed because network access was unavailable. |
| `go build ./cmd/anopki-service` | Blocked locally | Same Go toolchain blocker as `go test ./...`. |
| `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug` | Pass | Found OpenSSL Crypto 3.5.5. |
| `cmake --build build --config Debug` | Pass | Built `anopki_core`, `anopki-core`, and core tests. |
| `ctest --test-dir build -C Debug --output-on-failure` | Pass | 5/5 tests passed. |
| `cmake -S . -B build-fuzz -DANOPKI_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++` | Pass | Found OpenSSL Crypto 3.5.5. |
| `cmake --build build-fuzz --target anopki_core_csr_fuzz anopki_core_ocsp_fuzz anopki_core_crl_fuzz` | Pass | Local linker printed `.eh_frame` warnings but returned success. |
| `./build-fuzz/anopki_core_csr_fuzz -runs=1` | Blocked in default local sanitizer run | The local Swift Clang AddressSanitizer runtime crashed before useful project evidence was produced. Re-run in CI. |
| `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build-fuzz/anopki_core_csr_fuzz -runs=1` | Pass locally | 2 runs completed. |
| `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build-fuzz/anopki_core_ocsp_fuzz -runs=1` | Pass locally | 2 runs completed. |
| `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 ./build-fuzz/anopki_core_crl_fuzz -runs=1` | Pass locally | 2 runs completed. |

This local ZIP baseline is not enough to tag a release candidate. Release-closing evidence still needs a real Git working tree, Go 1.25.11 service test/build/lint/security jobs, GitHub Actions CI URL, ACME smoke evidence where applicable, and release workflow artifacts containing archives, `SHA256SUMS`, CycloneDX SBOM, cosign signatures, and cosign certificates.

## Local Repository Baseline Evidence - 2026-07-07

This evidence was gathered from the real Windows working tree after the ZIP
baseline. It is local verification evidence only; release-closing evidence still
needs CI run URLs and release workflow artifacts.

Environment observed locally:

| Tool | Observed value | Release impact |
| --- | --- | --- |
| Python | 3.14.6 | Docs and script validators ran locally. |
| Go | 1.26.4 windows/amd64 | Service tests, vet, build, and `govulncheck` ran locally with patched standard library. |
| WSL Go | 1.26.0 linux/amd64 | Race detector ran through WSL; `govulncheck` on this toolchain reports standard-library findings fixed by Go 1.26.4. |
| WSL GCC | Ubuntu 15.2.0 | Cgo race detector support was available through WSL. |
| CMake | 4.4.0-rc1 | Core configure/build ran locally. |

Local command results:

| Command | Result | Notes |
| --- | --- | --- |
| `git status --short --branch` | Pass | Clean `main...origin/main` at the start of this baseline. |
| `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-local.ps1` | Pass | `local verification ok`; includes docs, contract, security baseline, ACME harness tests, C++ configure/build/CTest, Go test/vet/build. |
| `wsl -- bash -lc "cd /mnt/d/project/AnoPKI/service && mkdir -p ../.gocache/wsl ../.gomodcache/wsl && GOCACHE=/mnt/d/project/AnoPKI/.gocache/wsl GOMODCACHE=/mnt/d/project/AnoPKI/.gomodcache/wsl CGO_ENABLED=1 go test -race ./..."` | Pass | Race detector completed under WSL. |
| `wsl -- bash -lc "cd /mnt/d/project/AnoPKI/service && mkdir -p ../.gocache/wsl ../.gomodcache/wsl && GOCACHE=/mnt/d/project/AnoPKI/.gocache/wsl GOMODCACHE=/mnt/d/project/AnoPKI/.gomodcache/wsl go run honnef.co/go/tools/cmd/staticcheck@latest ./..."` | Pass | `staticcheck` completed with exit code 0. |
| `wsl -- bash -lc "cd /mnt/d/project/AnoPKI/service && mkdir -p ../.gocache/wsl ../.gomodcache/wsl && GOCACHE=/mnt/d/project/AnoPKI/.gocache/wsl GOMODCACHE=/mnt/d/project/AnoPKI/.gomodcache/wsl go run github.com/securego/gosec/v2/cmd/gosec@latest ./..."` | Pass | `gosec` reported 0 issues across 26 files. |
| `wsl -- bash -lc "cd /mnt/d/project/AnoPKI/service && mkdir -p ../.gocache/wsl ../.gomodcache/wsl && GOCACHE=/mnt/d/project/AnoPKI/.gocache/wsl GOMODCACHE=/mnt/d/project/AnoPKI/.gomodcache/wsl go run golang.org/x/vuln/cmd/govulncheck@latest ./..."` | Blocked by WSL Go version | WSL Go 1.26.0 reported reachable standard-library findings fixed by Go 1.26.4. |
| `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` | Pass | Windows Go 1.26.4 returned `No vulnerabilities found.` |

## CI Baseline Evidence - 2026-07-07

GitHub Actions run
<https://github.com/anothel/AnoPKI/actions/runs/28866431369> passed for commit
`8274f6b91779385e888eff7633c78ff79a464ddc`
(`docs: record local repository baseline evidence`).

Reported job results:

| Job | Result | Runtime |
| --- | --- | ---: |
| `docs` | Pass | 14s |
| `go-service` | Pass | 1m 22s |
| `cpp-core` | Pass | 41s |
| `cpp-fuzz-smoke` | Pass | 35s |
| Total workflow runtime | Pass | 2m 52s |

This closes the CI URL gap for the local repository baseline. Release-closing
evidence still needs release workflow artifacts containing archives,
`SHA256SUMS`, CycloneDX SBOM, cosign signatures, and cosign certificates.

## Required Evidence Per Release Candidate

- `python scripts/validate-docs.py`
- `python scripts/test_validate_docs.py`
- `python scripts/validate-community-boundary.py`
- `python scripts/test_validate_community_boundary.py`
- `python scripts/test_webhook_receiver_verification.py`
- `python scripts/test_verify_local.py`
- `python scripts/test_validate_version_metadata.py`
- `python scripts/validate-version-metadata.py`
- `python scripts/test_validate_release_artifacts.py`
- `python scripts/test_validate_service_contracts.py`
- `python scripts/validate-service-contracts.py`
- `python scripts/test_validate_core_cli_contracts.py`
- `python scripts/validate-core-cli-contracts.py`
- `python scripts/test_validate_release_evidence.py`
- `python scripts/validate-release-evidence.py`
- `python scripts/test_security_baseline_scan.py`
- `python scripts/security-baseline-scan.py`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`
- `go run github.com/securego/gosec/v2/cmd/gosec@latest ./...`
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
- `go build -o .tmp\verify-local\anopki-service.exe ./cmd/anopki-service`
- `cmake -S . -B build`
- `cmake --build build --config Debug`
- `ctest --test-dir build -C Debug --output-on-failure`
- `cmake -S . -B build-fuzz -DANOPKI_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++`
- `cmake --build build-fuzz --target anopki_core_csr_fuzz anopki_core_ocsp_fuzz anopki_core_crl_fuzz`
- `./build-fuzz/anopki_core_csr_fuzz -runs=1`
- `./build-fuzz/anopki_core_ocsp_fuzz -runs=1`
- `./build-fuzz/anopki_core_crl_fuzz -runs=1`
- release workflow artifact containing SBOM output from `syft`
- release workflow artifact containing signature output from `cosign`
- compatibility matrix row evidence

On Windows hosts without a native C toolchain, run the race-detector check
through WSL and keep Go caches inside ignored workspace paths:

```powershell
wsl -- bash -lc "cd /mnt/d/project/AnoPKI/service && mkdir -p ../.gocache/wsl ../.gomodcache/wsl && GOCACHE=/mnt/d/project/AnoPKI/.gocache/wsl GOMODCACHE=/mnt/d/project/AnoPKI/.gomodcache/wsl CGO_ENABLED=1 go test -race ./..."
```

Run `govulncheck` with a patched Go toolchain. WSL Go `1.26.0` reports
standard-library findings fixed in Go `1.26.4`; Windows Go `1.26.4` returns
`No vulnerabilities found.` for the current tree.

## Product Profile Evidence

Every release candidate records the assembled target, not only a dependency
name.

| Profile | Required evidence | Release rule |
| --- | --- | --- |
| Community/OpenSSL | Community commit, OpenSSL version, full contract/golden tests, artifact evidence | Public release candidate allowed when the standard checklist passes. |
| Enterprise/OpenSSL | Community baseline commit, Enterprise overlay version, OpenSSL version, Community plus Enterprise tests | Commercial release candidate allowed; AnoCrypto/KCMVP claims prohibited. |
| Enterprise/AnoCrypto-C | Community baseline, Enterprise overlay, exact AnoCrypto-C SDK version/build/fingerprint, capability matrix, no-fallback tests, parity evidence | Production release blocked until all required Community operations are supported. |

Required profile metadata:

- edition,
- product profile,
- selected adapter,
- backend dependency and exact version,
- supported capability set,
- key-provider class,
- `fallback_used`,
- production-readiness status,
- KCMVP status and evidence pointer when applicable.

`fallback_used` should normally be `false`. An AnoCrypto-C operation must not
silently execute through OpenSSL. OpenSSL compatibility is a separately built
or configured Enterprise/OpenSSL profile.

## Current Community Backend Evidence

Current expected Community entry:

| Field | Current value | Evidence |
| --- | --- | --- |
| Product profile | Community/OpenSSL | Build configuration and version metadata. |
| Selected adapter | OpenSSL adapter/current OpenSSL-backed implementation | CMake configure output, OpenSSL version, CTest, core CLI contracts. |
| AnoCrypto-C used | No | Community boundary validation. |
| Fallback used | No | Configuration and negative boundary tests. |

Community documents may describe the backend-neutral core refactor and external
Enterprise AnoCrypto-C direction, but must not mark AnoCrypto-C as active in a
Community release.

## Enterprise/AnoCrypto-C Evidence Gate

Do not mark Enterprise/AnoCrypto-C production-ready until:

- the real external `AnoCryptoC::AnoCryptoC` SDK is consumed,
- the exact SDK artifact and build identity are pinned,
- required CSR, issuance, CRL, and OCSP operations pass positive and negative
  parity tests,
- unsupported-capability tests prove OpenSSL is not called,
- all required product capabilities are declared available,
- KCMVP wording, if used, points to exact valid evidence.

## Backend Control Evidence

Each candidate records the output of:

```text
anopki-core backend info
```

The JSON must match the assembled artifact and includes `product_profile`,
`edition`, `selected_backend`, `fallback_enabled`, dependency/version, readiness,
capabilities, ABI version, and build fingerprint. Community/OpenSSL and
Enterprise/OpenSSL require the complete operation capability set.
Enterprise/AnoCrypto-C remains pending and reports no operation-level capabilities and
remains a development/integration profile.


## Key Provider Evidence

Each signing-capable release candidate records the provider result from the
actual C++ signing path, not only the Go readiness preflight.

Required fields:

| Field | Required value/evidence for this slice |
| --- | --- |
| operation | `certificate_issue`, `crl_generate_sign`, or `ocsp_response_sign` |
| product profile | `community-openssl` |
| selected backend | `openssl` |
| provider ID/class | `file` / `file` |
| reference class | `file` or bare-path compatibility; raw path omitted |
| readiness | actual C++ acquire result |
| exportability | `true` |
| requested signature algorithm | tested request value |
| key algorithm compatibility | pass or stable `provider.algorithm_mismatch` |
| signer certificate binding | pass or stable `provider.key_binding_mismatch` |
| signing result | `X509_sign`/`X509_CRL_sign`/`OCSP_basic_sign` success or stable `provider.sign_failed` |
| fallback used | `false` |
| production policy | exportable file provider rejected |
| golden result | existing certificate, CRL, and OCSP golden fixtures unchanged |
| boundary result | `issue.cpp`, `crl.cpp`, and `ocsp.cpp` contain no direct signing-key file open/PEM private-key read |

Evidence must include:

- full Community CTest result from the reviewed repository commit,
- certificate, CRL, and OCSP OpenSSL golden fixture results,
- `file:` and bare-path success tests,
- all required negative provider tests,
- source-boundary validator and validator self-tests,
- single-provider resolver and test-only software-token contract test,
- evidence-mismatch and provider-failure no-fallback tests,
- exact OpenSSL/compiler/platform metadata,
- reviewed Community commit SHA.

`keyref.Provider.CheckReady=ready` is preflight evidence only and cannot replace
actual provider acquire/binding/signing evidence.

Current scope statement:

```text
certificate issuance: FileKeyProvider implemented, exportable, local/dev only
CRL signing: FileKeyProvider implemented, exportable, local/dev only
OCSP response signing: FileKeyProvider implemented, exportable, local/dev only
test-only software-token resolver contract: implemented; not a runtime provider
real non-exportable provider: not implemented
fallback_used: false
production_ready: false for file-provider signing
```
