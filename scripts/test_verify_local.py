#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the local verification wrapper."""

from __future__ import annotations

import subprocess
import shutil
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def find_powershell() -> str:
    for executable in ("pwsh", "powershell"):
        path = shutil.which(executable)
        if path:
            return path
    raise SystemExit("PowerShell executable not found; install pwsh or Windows PowerShell")


def main() -> None:
    script = ROOT / "scripts" / "verify-local.ps1"
    result = subprocess.run(
        [
            find_powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-List",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr or result.stdout)
    expected_commands = [
        'python scripts\\validate-docs.py',
        'python scripts\\test_validate_docs.py',
        'python scripts\\test_webhook_receiver_verification.py',
        'python scripts\\test_verify_local.py',
        'python scripts\\test_validate_version_metadata.py',
        'python scripts\\validate-version-metadata.py',
        'python scripts\\test_generate_release_metadata.py',
        'python scripts\\test_verify_go_release.py',
        'python scripts\\test_verify_recovery_drill.py',
        'python scripts\\verify-recovery-drill.py --out-dir .tmp\\recovery-evidence\\verify-local',
        'python scripts\\test_verify_status_outage_drill.py',
        'python scripts\\verify-status-outage-drill.py --out-dir .tmp\\status-outage-evidence\\verify-local',
        'python scripts\\test_verify_audit_replay_drill.py',
        'python scripts\\verify-audit-replay-drill.py --out-dir .tmp\\audit-replay-evidence\\verify-local',
        'python scripts\\test_verify_issuer_rollover_drill.py',
        'python scripts\\verify-issuer-rollover-drill.py --out-dir .tmp\\issuer-rollover-evidence\\verify-local',
        'python scripts\\test_verify_multi_node_reliability.py',
        'python scripts\\verify-multi-node-reliability.py --out-dir .tmp\\multi-node-evidence\\verify-local',
        'python scripts\\test_verify_postgres_recovery_drill.py',
        'python scripts\\test_validate_release_artifacts.py',
        'python scripts\\test_validate_service_contracts.py',
        'python scripts\\validate-service-contracts.py',
        'python scripts\\test_validate_core_cli_contracts.py',
        'python scripts\\validate-core-cli-contracts.py',
        'python scripts\\test_validate_release_evidence.py',
        'python scripts\\validate-release-evidence.py',
        'python scripts\\test_security_baseline_scan.py',
        'python scripts\\security-baseline-scan.py',
        'powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\acme-smoke\\test-run-certbot-smoke.ps1',
        'cmake -S . -B build',
        'cmake --build build --config Debug',
        'ctest --test-dir build -C Debug --output-on-failure',
        'python scripts\\verify-go-release.py --profile baseline --out-dir .tmp\\go-evidence\\verify-local',
    ]
    commands = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if commands != expected_commands:
        raise SystemExit(
            "verify-local command list drifted:\n"
            + "\n".join(commands)
            + "\nexpected:\n"
            + "\n".join(expected_commands)
        )
    script_text = script.read_text(encoding="utf-8")
    if "GOCACHE" not in script_text or ".gocache" not in script_text:
        raise SystemExit("verify-local must keep Go build cache inside the workspace")
    if 'Command = @("powershell",' in script_text:
        raise SystemExit("verify-local must not hard-code nested PowerShell executable")
    if "verify-go-release.py" not in script_text or ".tmp\\go-evidence" not in script_text:
        raise SystemExit("verify-local must run the supported-Go evidence wrapper under .tmp")
    if "verify-recovery-drill.py" not in script_text or ".tmp\\recovery-evidence" not in script_text:
        raise SystemExit("verify-local must run the SQLite recovery drill under .tmp")
    if "verify-status-outage-drill.py" not in script_text or ".tmp\\status-outage-evidence" not in script_text:
        raise SystemExit("verify-local must run the CRL/OCSP outage drill under .tmp")
    if "verify-audit-replay-drill.py" not in script_text or ".tmp\\audit-replay-evidence" not in script_text:
        raise SystemExit("verify-local must run the audit/replay drill under .tmp")
    if "verify-issuer-rollover-drill.py" not in script_text or ".tmp\\issuer-rollover-evidence" not in script_text:
        raise SystemExit("verify-local must run the issuer rollover drill under .tmp")
    if "verify-multi-node-reliability.py" not in script_text or ".tmp\\multi-node-evidence" not in script_text:
        raise SystemExit("verify-local must run the multi-node reliability drill under .tmp")
    if "Resolve-OpenSSLRuntime" not in script_text or "libcrypto*.dll" not in script_text:
        raise SystemExit("verify-local must validate Windows OpenSSL runtime DLLs")
    if "$env:PATH = $previousPath" not in script_text:
        raise SystemExit("verify-local must restore process-local PATH")
    if os.name == "nt":
        missing_runtime = subprocess.run(
            [
                find_powershell(),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-CheckOpenSSLRuntime",
                "-OpenSSLRootDir",
                str(ROOT / ".tmp" / "missing-openssl-runtime"),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if missing_runtime.returncode == 0 or "OpenSSL runtime DLLs not found" not in (missing_runtime.stdout + missing_runtime.stderr):
            raise SystemExit("verify-local must fail early when Windows OpenSSL runtime DLLs are missing")
    print("verify-local tests ok")


if __name__ == "__main__":
    main()
