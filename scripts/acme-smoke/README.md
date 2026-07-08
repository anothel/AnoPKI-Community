# ACME smoke harness

This directory is for live ACME-client compatibility checks against a local
`anopki-service`.

The harness is intentionally small: it checks the ACME directory endpoint,
prints the exact client command, and can run it when `-Run` is supplied.
Preflight mode does not require an ACME client to be installed. Live run mode
requires the selected client and exits `2` when it is missing.

See the root [contributing guide](../../CONTRIBUTING.md) before changing the
harness, and the root [security policy](../../SECURITY.md) before using
smoke-only environment variables around real infrastructure.

## Current local status

The current Windows workspace shell does not have these clients on `PATH`:

- `certbot`
- `lego`
- `step`

Certbot remains the default client. Certbot 5.6.0 on this Windows non-admin
shell exits before ACME traffic with:

```text
certbot must be run on a shell with administrative rights
```

Use `-Client lego` as the local non-admin fallback when you need live ACME
traffic from this shell. In this workspace, lego `v4.35.2+dev-release` at
`.tmp\lego-bin\lego.exe` has completed a live HTTP-01 run through certificate
response with the harness-started service.

WSL certbot 5.6.0 with PowerShell 7.6.3 has also completed the live HTTP-01
run:

```bash
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/acme-smoke/run-certbot-smoke.ps1 -CertbotPath /snap/bin/certbot -WorkDir .tmp/acme-smoke-certbot-wsl -StartService -DirectoryTimeoutSec 60 -Run
```

## Service modes

You can run against a separately started service, or let the harness start a
temporary local service with `-StartService`.

### Separate service

Start the service separately when you want to control the service process:

```powershell
cd service
$env:ANOPKI_ADDR = "127.0.0.1:8080"
$env:ANOPKI_DB_DRIVER = "sqlite"
$env:ANOPKI_DB_DSN = "..\.tmp\acme-smoke\anopki.db"
$env:ANOPKI_CORE_BIN = "..\build\Debug\anopki-core.exe"
$env:ANOPKI_ACME_HTTP01_BASE_URL = "http://127.0.0.1:5002"
go run .\cmd\anopki-service
```

Then verify the ACME directory in preflight mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1
```

Run certbot when preflight is clean and certbot is installed:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Run
```

### Harness-started service

Use `-StartService` when you want the harness to start `anopki-service`
with temporary SQLite state:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -StartService
```

For a live certbot run with the harness-started service:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -StartService -Run
```

`-StartService` starts the service with:

- `ANOPKI_DB_DRIVER=sqlite`
- a temporary SQLite database under `.tmp\acme-smoke`
- `ANOPKI_ACME_HTTP01_BASE_URL=http://127.0.0.1:{Http01Port}`
- `ANOPKI_ACME_BOOTSTRAP_DEFAULTS=true`
- `ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF=.tmp\acme-smoke\acme-smoke-issuer.key`
- workspace-local Go build cache under `.gocache` and the current Go module cache
- a temporary service binary under `.tmp\acme-smoke`

Logs and temporary state are written under `.tmp\acme-smoke`.

## Client selection

`-Client` selects the ACME client runner:

- `certbot`: default runner.
- `lego`: fallback runner for Windows non-admin shells where certbot exits
  before ACME traffic.

`-LegoPath` defaults to `lego`. If lego is installed with `go install`, copy or
place the binary at:

```text
.tmp\lego-bin\lego.exe
```

Live lego smoke with harness-started service:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -StartService -Run -DirectoryTimeoutSec 60
```

The lego runner uses the same local HTTP-01 webroot server and service override
as certbot. For local HTTPS ACME directory compatibility, the harness starts a
temporary HTTPS loopback proxy and passes `--tls-skip-verify` to lego.

## Preflight and live run

The default mode is preflight. It does not invoke the selected client and works
without certbot or lego installed. Use it to verify the local service and
inspect the client command that would be run.

`-Run` performs the live ACME client smoke. In this mode, the selected client
must be available on `PATH` or passed with `-CertbotPath` / `-LegoPath`; if it
is missing, the harness exits `2`.

The default challenge mode is `webroot`. The harness starts a local Python
static-file server on `127.0.0.1:{Http01Port}` and passes webroot options to
the selected client. This avoids binding an ACME client standalone to a local
port.

Standalone mode is still available:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -ChallengeMode standalone -Run
```

On Windows, certbot 5.6.0 exits before ACME traffic unless the shell has
administrative rights, even in webroot mode. In a non-admin shell this harness
can verify service startup and print the certbot command, but the live certbot
run stops at certbot's own administrative-rights check. Use the lego fallback
for a non-admin live HTTP-01 smoke, or run certbot from Linux/WSL.

## HTTP-01 local limitation

By default, `AnoPKI` validates HTTP-01 by fetching:

```text
http://{identifier}/.well-known/acme-challenge/{token}
```

That means a local certbot smoke would normally need the requested domain to
resolve to the machine running certbot, and certbot standalone would need to
answer on port 80.

For smoke tests, set:

```powershell
$env:ANOPKI_ACME_HTTP01_BASE_URL = "http://127.0.0.1:5002"
```

Then the service fetches the challenge token from that base URL while certbot
answers on `-Http01Port 5002`.

The default smoke domain is:

```text
edge-01.example.test
```

For local-only testing without the override, map it to loopback in the system
hosts file, or change `-Domain` to a name that resolves locally. On Windows,
binding port 80 may require an elevated shell.

DNS-01 is out of scope for this harness.
