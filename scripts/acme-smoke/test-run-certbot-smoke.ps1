# SPDX-License-Identifier: MPL-2.0
param(
    [string]$Runner = (Join-Path $PSScriptRoot "run-certbot-smoke.ps1")
)

$ErrorActionPreference = "Stop"

function Assert-Equal {
    param(
        [string]$Name,
        [object]$Actual,
        [object]$Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Name = $Actual, want $Expected"
    }
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Start-DirectoryStub {
    param([int]$Port)

    $stubDir = ".tmp\acme-smoke-test"
    New-Item -ItemType Directory -Force -Path $stubDir | Out-Null
    $stubPath = Join-Path $stubDir "directory-stub-$Port.js"
    $script = @"
const http = require("http");
const port = $Port;
const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/acme/directory") {
    res.writeHead(200, {"content-type": "application/json"});
    res.end(JSON.stringify({
      newNonce: "http://127.0.0.1:$Port/acme/new-nonce",
      newAccount: "http://127.0.0.1:$Port/acme/new-account",
      newOrder: "http://127.0.0.1:$Port/acme/new-order"
    }));
    return;
  }
  res.writeHead(404);
  res.end();
});
server.listen(port, "127.0.0.1");
"@
    Set-Content -LiteralPath $stubPath -Value $script -Encoding ASCII
    return Start-Process -FilePath "node" -ArgumentList @($stubPath) -WindowStyle Hidden -PassThru
}

function New-FakeServiceProject {
    $projectDir = ".tmp\acme-smoke-test\fake-service"
    $mainDir = Join-Path $projectDir "cmd\anopki-service"
    New-Item -ItemType Directory -Force -Path $mainDir | Out-Null
    Set-Content -LiteralPath (Join-Path $projectDir "go.mod") -Encoding ASCII -Value @"
module fake-anopki-service

go 1.22
"@
    Set-Content -LiteralPath (Join-Path $mainDir "main.go") -Encoding ASCII -Value @"
package main

import (
	"encoding/json"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("ANOPKI_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	http.HandleFunc("/acme/directory", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce": "http://" + addr + "/acme/new-nonce",
			"newAccount": "http://" + addr + "/acme/new-account",
			"newOrder": "http://" + addr + "/acme/new-order",
		})
	})
	_ = http.ListenAndServe(addr, nil)
}
"@
    return $projectDir
}

function Wait-DirectoryStub {
    param(
        [string]$ServiceUrl,
        [int]$TimeoutSec = 5
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSec)
    do {
        try {
            Invoke-RestMethod -Uri "$ServiceUrl/acme/directory" -TimeoutSec 1 | Out-Null
            return
        } catch {
            Start-Sleep -Milliseconds 100
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "directory stub did not start: $ServiceUrl"
}

function Stop-DirectoryStub {
    param($Process)

    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Invoke-Runner {
    param([string[]]$RunnerArgs)

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $Runner @RunnerArgs 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = ($output -join [Environment]::NewLine)
        }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($Runner, [ref]$null, [ref]$parseErrors) | Out-Null
Assert-Equal "parse error count" $parseErrors.Count 0

$proxySource = Get-Content -Raw (Join-Path $PSScriptRoot "acme-https-proxy.go")
if ($proxySource -notmatch "X-Forwarded-Proto") {
    throw "ACME HTTPS proxy must forward X-Forwarded-Proto"
}

$runnerSource = Get-Content -Raw $Runner
if ($runnerSource -notmatch "function Invoke-NativeCommand") {
    throw "runner must capture native stderr without promoting progress output to terminating errors"
}
if ($runnerSource -notmatch 'Resolve-OptionalCommand "python3"') {
    throw "runner must fall back to python3 for WSL/Linux webroot mode"
}

$port = Get-FreePort
$job = Start-DirectoryStub -Port $port
try {
    $serviceUrl = "http://127.0.0.1:$port"
    Wait-DirectoryStub -ServiceUrl $serviceUrl
    $missingCertbot = "definitely-missing-certbot-for-AnoPKI-smoke"

    $preflight = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-CertbotPath", $missingCertbot,
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    if ($preflight.ExitCode -ne 0) {
        throw "preflight exit code without certbot = $($preflight.ExitCode), want 0`n$($preflight.Output)"
    }
    if ($preflight.Output -notmatch "certbot unavailable") {
        throw "preflight output missing certbot unavailable marker"
    }
    if ($preflight.Output -notmatch "--webroot" -or $preflight.Output -notmatch "--webroot-path") {
        throw "preflight output missing default webroot certbot args"
    }

    $standalonePreflight = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-CertbotPath", $missingCertbot,
        "-ChallengeMode", "standalone",
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    Assert-Equal "standalone preflight exit code without certbot" $standalonePreflight.ExitCode 0
    if ($standalonePreflight.Output -notmatch "--standalone" -or $standalonePreflight.Output -notmatch "--http-01-port") {
        throw "standalone preflight output missing standalone certbot args"
    }

    $missingLego = "definitely-missing-lego-for-AnoPKI-smoke"
    $legoPreflight = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-Client", "lego",
        "-LegoPath", $missingLego,
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    Assert-Equal "lego preflight exit code without lego" $legoPreflight.ExitCode 0
    if ($legoPreflight.Output -notmatch "lego unavailable") {
        throw "lego preflight output missing lego unavailable marker"
    }
    if ($legoPreflight.Output -notmatch "--http.webroot" -or $legoPreflight.Output -notmatch "--domains") {
        throw "lego preflight output missing lego webroot args"
    }
    if ($legoPreflight.Output -notmatch "--tls-skip-verify" -or $legoPreflight.Output -notmatch "https://127.0.0.1:8443/acme/directory") {
        throw "lego preflight output missing local HTTPS proxy args"
    }

    $legoRunMissing = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-Client", "lego",
        "-LegoPath", $missingLego,
        "-WorkDir", ".tmp\acme-smoke-test",
        "-Run"
    )
    Assert-Equal "lego run exit code without lego" $legoRunMissing.ExitCode 2

    $runMissing = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-CertbotPath", $missingCertbot,
        "-WorkDir", ".tmp\acme-smoke-test",
        "-Run"
    )
    Assert-Equal "run exit code without certbot" $runMissing.ExitCode 2

    $unavailable = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", "http://127.0.0.1:1",
        "-CertbotPath", $missingCertbot,
        "-DirectoryTimeoutSec", "1",
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    Assert-Equal "unavailable service exit code" $unavailable.ExitCode 3

    $fakeServiceProject = New-FakeServiceProject
    $fakeServiceUrl = "http://127.0.0.1:$(Get-FreePort)"
    $startServiceUnavailable = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $fakeServiceUrl,
        "-CertbotPath", $missingCertbot,
        "-DirectoryTimeoutSec", "1",
        "-WorkDir", ".tmp\acme-smoke-test",
        "-ServiceProjectPath", $fakeServiceProject,
        "-ServiceBin", ".tmp\acme-smoke-test\anopki-service.exe",
        "-ServiceLogDir", ".tmp\acme-smoke-test\service-logs",
        "-StartService"
    )
    if ($startServiceUnavailable.ExitCode -ne 0) {
        throw "start service preflight exit code = $($startServiceUnavailable.ExitCode), want 0`n$($startServiceUnavailable.Output)"
    }
    if ($startServiceUnavailable.Output -match "Key in dictionary") {
        throw "start service failed before directory wait: $($startServiceUnavailable.Output)"
    }
    $serviceCommand = Get-Content -Raw ".tmp\acme-smoke-test\service-logs\anopki-service.start.ps1"
    if ($serviceCommand -notmatch "GOCACHE" -or $serviceCommand -notmatch "GOMODCACHE") {
        throw "service startup command does not set workspace Go caches"
    }
    if ($serviceCommand -notmatch "ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF") {
        throw "service startup command does not set ACME bootstrap issuer key ref"
    }
} finally {
    Stop-DirectoryStub $job
}

Write-Host "run-certbot-smoke tests passed"
