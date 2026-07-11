# Crypto Backend Parity

Community owns the backend-neutral fixture at
`tests/fixtures/backend-parity/manifest.txt`. Enterprise should take this file
unchanged through its normal Community upstream sync.

## Fixture Format

The version 1 format is UTF-8 `key=value`. Blank lines and lines beginning with
`#` are ignored. Required operation keys are:

- `operation.csr_parse.comparison`
- `operation.certificate_issue.comparison`
- `operation.crl_generate_sign.comparison`
- `operation.ocsp_decode.comparison`
- `operation.ocsp_response_sign.comparison`

Comparison is `semantic` or `exact_der`. Semantic cases compare decoded stable
fields stored in the manifest. Exact DER cases compare complete DER bytes and
use `operation.<name>.expected_der_file` to reference a checked binary fixture.
No exact DER case is active because the current harness generates fresh keys.

Results use four values:

| Result | Meaning |
| --- | --- |
| `semantic_equal` | Stable decoded fields match. |
| `exact_der_equal` | Complete DER bytes match. |
| `unsupported_pending` | Backend cannot run the operation; output includes a reason. |
| `failure` | Fixture, execution, or comparison failed. |

## Run

Community OpenSSL parity runs in CTest as `anopki.core_openssl_golden`:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR"
cmake --build build --config Debug
ctest --test-dir build -C Debug -R anopki.core_openssl_golden --output-on-failure
```

Direct harness command on Windows:

```powershell
build\Debug\anopki_core_openssl_golden_test.exe build tests\fixtures\backend-parity
```

Enterprise runs the same OpenSSL test and registers its incomplete AnoCrypto
skeleton as a skipped CTest. The skip output must list every operation as
`unsupported_pending` with an explicit reason. A future AnoCrypto backend should
replace that pending invocation with a real run against the unchanged manifest.

## Release Evidence

Record backend name/version, fixture format version, command, each operation
result, and overall CTest status. Skips are gaps, not passes. Do not record a
future AnoCrypto backend as active or production-ready until all required
operations run and release gates close.
