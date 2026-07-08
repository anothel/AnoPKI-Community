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
