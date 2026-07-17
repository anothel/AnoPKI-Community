# SPDX-License-Identifier: MPL-2.0
param(
    [switch]$List,
    [switch]$CheckOpenSSLRuntime,
    [string]$OpenSSLRootDir = $env:OPENSSL_ROOT_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")

function Resolve-OpenSSLRuntime {
    param([string]$ExplicitRoot)

    $candidates = @()
    if ($ExplicitRoot) {
        $candidates += $ExplicitRoot
    }
    else {
        if ($env:VCPKG_ROOT) {
            $candidates += Join-Path $env:VCPKG_ROOT "installed\x64-windows"
        }
        $candidates += "C:\vcpkg\installed\x64-windows"
        $candidates += Join-Path $RepoRoot "vcpkg_installed\x64-windows"
    }

    foreach ($candidate in $candidates) {
        $bin = Join-Path $candidate "bin"
        if ((Test-Path -LiteralPath $bin -PathType Container) -and
            (Get-ChildItem -LiteralPath $bin -Filter "libcrypto*.dll" -File -ErrorAction SilentlyContinue)) {
            return @{
                Root = (Resolve-Path -LiteralPath $candidate).Path
                Bin = (Resolve-Path -LiteralPath $bin).Path
            }
        }
    }

    $searched = $candidates -join ", "
    throw "OpenSSL runtime DLLs not found. Set OPENSSL_ROOT_DIR to a vcpkg triplet root containing bin\libcrypto*.dll (example: C:\vcpkg\installed\x64-windows). Searched: $searched"
}

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
        Name = "release metadata generator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_generate_release_metadata.py"
        Command = @("python", "scripts\test_generate_release_metadata.py")
    },
    @{
        Name = "Go release verification runner tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_go_release.py"
        Command = @("python", "scripts\test_verify_go_release.py")
    },
    @{
        Name = "recovery drill tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_recovery_drill.py"
        Command = @("python", "scripts\test_verify_recovery_drill.py")
    },
    @{
        Name = "SQLite recovery drill"
        Dir = $RepoRoot
        Display = "python scripts\verify-recovery-drill.py --out-dir .tmp\recovery-evidence\verify-local"
        Command = @("python", "scripts\verify-recovery-drill.py", "--out-dir", ".tmp\recovery-evidence\verify-local")
    },
    @{
        Name = "status outage drill tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_status_outage_drill.py"
        Command = @("python", "scripts\test_verify_status_outage_drill.py")
    },
    @{
        Name = "CRL and OCSP outage drill"
        Dir = $RepoRoot
        Display = "python scripts\verify-status-outage-drill.py --out-dir .tmp\status-outage-evidence\verify-local"
        Command = @("python", "scripts\verify-status-outage-drill.py", "--out-dir", ".tmp\status-outage-evidence\verify-local")
    },
    @{
        Name = "audit/replay drill tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_audit_replay_drill.py"
        Command = @("python", "scripts\test_verify_audit_replay_drill.py")
    },
    @{
        Name = "audit repair and dead-letter replay drill"
        Dir = $RepoRoot
        Display = "python scripts\verify-audit-replay-drill.py --out-dir .tmp\audit-replay-evidence\verify-local"
        Command = @("python", "scripts\verify-audit-replay-drill.py", "--out-dir", ".tmp\audit-replay-evidence\verify-local")
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
        Name = "Go baseline release verification"
        Dir = $RepoRoot
        Display = "python scripts\verify-go-release.py --profile baseline --out-dir .tmp\go-evidence\verify-local"
        Command = @("python", "scripts\verify-go-release.py", "--profile", "baseline", "--out-dir", ".tmp\go-evidence\verify-local")
    }
)

if ($List) {
    foreach ($step in $steps) {
        Write-Output $step.Display
    }
    exit 0
}

$openSSLRuntime = $null
if ($env:OS -eq "Windows_NT") {
    $openSSLRuntime = Resolve-OpenSSLRuntime -ExplicitRoot $OpenSSLRootDir
    Write-Host "Using process-local OpenSSL runtime DLLs from $($openSSLRuntime.Bin)"
}

if ($CheckOpenSSLRuntime) {
    Write-Host "OpenSSL runtime check ok"
    exit 0
}

$goCache = Join-Path $RepoRoot ".gocache"
New-Item -ItemType Directory -Force -Path $goCache | Out-Null
New-Item -ItemType Directory -Force -Path $VerifyTmp | Out-Null
$previousGoCache = $env:GOCACHE
$previousOpenSSLRootDir = $env:OPENSSL_ROOT_DIR
$previousPath = $env:PATH
try {
    $env:GOCACHE = $goCache
    if ($null -ne $openSSLRuntime) {
        $env:OPENSSL_ROOT_DIR = $openSSLRuntime.Root
        $env:PATH = "$($openSSLRuntime.Bin);$env:PATH"
    }
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
    $env:OPENSSL_ROOT_DIR = $previousOpenSSLRootDir
    $env:PATH = $previousPath
}

Write-Host "local verification ok"
