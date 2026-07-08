# SPDX-License-Identifier: MPL-2.0
param(
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")

function Get-PowerShellCommand {
    $currentProcess = Get-Process -Id $PID
    if ($currentProcess.Path) {
        return $currentProcess.Path
    }
    foreach ($candidate in @("pwsh", "powershell")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    throw "PowerShell executable not found"
}

$PowerShellCommand = Get-PowerShellCommand
$VerifyTmp = Join-Path $RepoRoot ".tmp\verify-local"

$steps = @(
    @{
        Name = "docs validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-docs.py"
        Command = @("python", "scripts\validate-docs.py")
    },
    @{
        Name = "docs validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_docs.py"
        Command = @("python", "scripts\test_validate_docs.py")
    },
    @{
        Name = "webhook receiver verification tests"
        Dir = $RepoRoot
        Display = "python scripts\test_webhook_receiver_verification.py"
        Command = @("python", "scripts\test_webhook_receiver_verification.py")
    },
    @{
        Name = "local verification wrapper tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_local.py"
        Command = @("python", "scripts\test_verify_local.py")
    },
    @{
        Name = "version metadata tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_version_metadata.py"
        Command = @("python", "scripts\test_validate_version_metadata.py")
    },
    @{
        Name = "version metadata validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-version-metadata.py"
        Command = @("python", "scripts\validate-version-metadata.py")
    },
    @{
        Name = "release artifact validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_release_artifacts.py"
        Command = @("python", "scripts\test_validate_release_artifacts.py")
    },
    @{
        Name = "service contract validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_service_contracts.py"
        Command = @("python", "scripts\test_validate_service_contracts.py")
    },
    @{
        Name = "service contract validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-service-contracts.py"
        Command = @("python", "scripts\validate-service-contracts.py")
    },
    @{
        Name = "core CLI contract validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_core_cli_contracts.py"
        Command = @("python", "scripts\test_validate_core_cli_contracts.py")
    },
    @{
        Name = "core CLI contract validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-core-cli-contracts.py"
        Command = @("python", "scripts\validate-core-cli-contracts.py")
    },
    @{
        Name = "release evidence validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_release_evidence.py"
        Command = @("python", "scripts\test_validate_release_evidence.py")
    },
    @{
        Name = "release evidence validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-release-evidence.py"
        Command = @("python", "scripts\validate-release-evidence.py")
    },
    @{
        Name = "security baseline scanner tests"
        Dir = $RepoRoot
        Display = "python scripts\test_security_baseline_scan.py"
        Command = @("python", "scripts\test_security_baseline_scan.py")
    },
    @{
        Name = "security baseline scan"
        Dir = $RepoRoot
        Display = "python scripts\security-baseline-scan.py"
        Command = @("python", "scripts\security-baseline-scan.py")
    },
    @{
        Name = "ACME smoke harness tests"
        Dir = $RepoRoot
        Display = "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1"
        Command = @($PowerShellCommand, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ".\scripts\acme-smoke\test-run-certbot-smoke.ps1")
    },
    @{
        Name = "C++ configure"
        Dir = $RepoRoot
        Display = "cmake -S . -B build"
        Command = @("cmake", "-S", ".", "-B", "build")
    },
    @{
        Name = "C++ build"
        Dir = $RepoRoot
        Display = "cmake --build build --config Debug"
        Command = @("cmake", "--build", "build", "--config", "Debug")
    },
    @{
        Name = "C++ tests"
        Dir = $RepoRoot
        Display = "ctest --test-dir build -C Debug --output-on-failure"
        Command = @("ctest", "--test-dir", "build", "-C", "Debug", "--output-on-failure")
    },
    @{
        Name = "Go tests"
        Dir = Join-Path $RepoRoot "service"
        Display = "go test ./..."
        Command = @("go", "test", "./...")
    },
    @{
        Name = "Go vet"
        Dir = Join-Path $RepoRoot "service"
        Display = "go vet ./..."
        Command = @("go", "vet", "./...")
    },
    @{
        Name = "Go build"
        Dir = Join-Path $RepoRoot "service"
        Display = "go build -o .tmp\verify-local\anopki-service.exe ./cmd/anopki-service"
        Command = @("go", "build", "-o", (Join-Path $VerifyTmp "anopki-service.exe"), "./cmd/anopki-service")
    }
)

if ($List) {
    foreach ($step in $steps) {
        Write-Output $step.Display
    }
    exit 0
}

$goCache = Join-Path $RepoRoot ".gocache"
New-Item -ItemType Directory -Force -Path $goCache | Out-Null
New-Item -ItemType Directory -Force -Path $VerifyTmp | Out-Null
$previousGoCache = $env:GOCACHE
try {
    $env:GOCACHE = $goCache
    foreach ($step in $steps) {
        Write-Host "==> $($step.Name)"
        Push-Location -LiteralPath $step.Dir
        try {
            $command = $step.Command
            & $command[0] @($command | Select-Object -Skip 1)
            if ($LASTEXITCODE -ne 0) {
                exit $LASTEXITCODE
            }
        }
        finally {
            Pop-Location
        }
    }
}
finally {
    $env:GOCACHE = $previousGoCache
}

Write-Host "local verification ok"
