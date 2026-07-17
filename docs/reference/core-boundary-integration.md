# Core Boundary Integration

Go unit tests use fake `anopki-core` commands for argument and JSON mapping
coverage. The integration contract tests run the real C++ CLI binary through
the Go runner and check success paths for CSR inspection, certificate issuance,
and CRL generation, plus structured command errors on parser failures.

Build the C++ CLI first, then run:

```powershell
$env:ANOPKI_CORE_BIN = (Resolve-Path ..\build\Debug\anopki-core.exe).Path
go test ./internal/corecli -run CoreCLIIntegration -v
```

From Linux or a single-config build, point `ANOPKI_CORE_BIN` at the built
`anopki-core` executable.


## Key Provider Boundary

ADR 0007 keeps the current one-operation CLI contract for the implemented certificate, CRL, and OCSP file-provider slices. Go performs policy/readiness preflight, while the selected C++ adapter/provider performs the actual key open, binding check, and signing. A future remote KMS prepare/sign/finalize protocol would be a versioned contract change with separate operation-state evidence.
