# PKI-16 M1 acceptance harness

This test-only runner exercises the Community OpenSSL service over HTTP using
SQLite and real operator, write and read API keys. It covers the PKI-16 portions
of C-PKI-01 through C-PKI-03 and C-NEG-01 in the
[acceptance plan](https://anothel.atlassian.net/wiki/spaces/AnoPKI/pages/2228228).
Follow-up coverage for signed CRL and OCSP, PostgreSQL, restart and fault
injection, and ACME nonce behavior is tracked separately under
[GitHub #38](https://github.com/anothel/AnoPKI-Community/issues/38) and
[Jira PKI-16](https://anothel.atlassian.net/browse/PKI-16).

## Build and preflight

Use a clean checkout on Linux x86_64 with Python 3.11+, Go 1.25.11+, a C++20
toolchain, CMake, and OpenSSL 3. Build both executables from the checked-out
commit. The runner checks Core backend readiness and records binary digests.
During live execution it checks the service's reported commit against HEAD.

```bash
build_dir=$(mktemp -d)
commit_sha=$(git rev-parse HEAD)
cmake -S . -B "$build_dir/core" -DCMAKE_BUILD_TYPE=Release -DANOPKI_PRODUCT_PROFILE=community-openssl
cmake --build "$build_dir/core" --target anopki-core
(cd service && go build -ldflags "-X main.serviceCommit=$commit_sha" -o "$build_dir/anopki-service" ./cmd/anopki-service)
export ANOPKI_CORE_BIN="$build_dir/core/anopki-core"
export ANOPKI_SERVICE_BIN="$build_dir/anopki-service"

python3 -B scripts/m1-acceptance/test_preflight.py
python3 -B scripts/test_verify_authorization_boundary.py
python3 scripts/m1-acceptance/run.py
```

The command writes JSON to stdout. Preflight probes binaries without opening
a listener, generating keys, or opening SQLite. Missing binaries produce
`NOT_RUN`, and preflight-only execution always leaves live acceptance
`NOT_RUN`. The JSON includes the checked-out SHA, dirty status, tool versions,
and binary and fixture SHA-256 values. Keep the exact build commands and
binary paths with the runner's evidence.

## Authorized live acceptance

Use this command only after the repository owner has approved the isolated
runner and the scope for disposable SQLite and temporary keys.

```bash
python3 scripts/m1-acceptance/run.py --live --authorized-runner > m1-result.json
```

Write the report outside the checkout for repeat runs. The runner starts its
own service on an ephemeral IPv4 loopback port and confirms the listener
belongs to that child before sending credentials. It creates its own CA and
leaf keys and SQLite file inside a private temporary directory. API tokens
are held in memory for the run.
There are no options to supply a service endpoint, database DSN, CA, or
credentials. The outbox delivery worker and expiration scan are disabled for
the isolated lifecycle run.

The JSON records per-case status, commands and HTTP results, disposable
certificate IDs and serials, and SHA-256 hashes of CSR and certificate DER.
Raw PEMs, keys, tokens, SQLite contents, request and response bodies, and
service logs are omitted. The runner terminates its service process group and
removes scratch data on normal exit and handled failures. After a forced kill
or host loss, check for a surviving child and its `/tmp/anopki-m1-*`
directory before disposing of the lab. Remove the separate build directory
and keep only the reviewed JSON evidence.

The flow uses the same CSR SAN values and lifecycle routes as the
[manual demo](../../docs/runbooks/manual-demo.md). The scope assertions follow
the existing Go route fixtures. Approval and revocation are write-capable
routes. Key management, audit, and the signer metric endpoint require
operator scope. After lab approval, reuse these existing regression checks
alongside the live harness.

```bash
(cd service && go test -count=1 -v -run '^(TestCoreCLIIntegrationSuccessPaths|TestCoreCLIIntegrationCommandErrors)$' ./internal/corecli)
(cd service && go test -count=1 -v -run '^Test(APIKeyScope.*|APIKeyAuthRejectsExpiredKey|RenewCertificate|ReissueCertificate|RevokeCertificate)$' ./internal/httpapi)
python3 scripts/verify-authorization-boundary.py --out-dir "$build_dir/auth-evidence"
cmake --build "$build_dir/core" --target anopki_core_issue_profile_test
ctest --test-dir "$build_dir/core" -R '^anopki[.]core_issue_profile$' --output-on-failure
```

Record a missing-`ANOPKI_CORE_BIN` skip from the Go integration tests as
`NOT_RUN`. Issuance replay evidence is limited to the same service process
after successful finalization. The live report leaves broader acceptance
and independent reviewer disposition to the owner.
