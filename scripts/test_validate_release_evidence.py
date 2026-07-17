#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Tests for Community release evidence validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
SCRIPT = ROOT / "scripts" / "validate-release-evidence.py"


def require_release_workflow() -> None:
    if not RELEASE_WORKFLOW.is_file():
        raise SystemExit("missing release workflow: .github/workflows/release.yml")
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    required = [
        "on:", "workflow_dispatch:", "tags:", "contents: read", "contents: write",
        "id-token: write", 'go-version: "1.25.12"',
        "python scripts/verify-go-release.py", "--profile full",
        "anopki-go-verification.tar.gz", "anopki-recovery-verification.tar.gz",
        "anopki-status-outage-verification.tar.gz", "anopki-audit-replay-verification.tar.gz", "anopki-issuer-rollover-verification.tar.gz",
        "python scripts/verify-recovery-drill.py", "python scripts/verify-status-outage-drill.py", "python scripts/verify-audit-replay-drill.py", "python scripts/verify-issuer-rollover-drill.py",
        "cmake --build build-release --config Release", 'VERSION="$(cat VERSION)"',
        "go build -ldflags", "anopki-service-v${VERSION}-linux-amd64.tar.gz",
        "anopki-core-v${VERSION}-linux-amd64.tar.gz",
        "python scripts/validate-release-artifacts.py dist", "syft scan dir:dist",
        "cosign sign-blob", "actions/upload-artifact", "actions/download-artifact",
        "SIGNING-STATUS.txt", "Signing skipped: manual dry-run",
        "publish-tagged-release:",
        "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        "environment: release", "Require a signed annotated tag",
        "GH_TOKEN: ${{ github.token }}", "gh release create", "gh release upload",
    ]
    missing = [value for value in required if value not in text]
    if missing:
        raise SystemExit(".github/workflows/release.yml missing:\n" + "\n".join(missing))


def copy_release_evidence_inputs(dst: Path) -> None:
    files = [
        "docs/reference/release-evidence.md",
        "scripts/verify-local.ps1",
        "scripts/verify-go-release.py",
        "scripts/verify-recovery-drill.py",
        "scripts/verify-status-outage-drill.py",
        "scripts/verify-audit-replay-drill.py",
        "scripts/verify-issuer-rollover-drill.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ]
    for name in files:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )


def mutate(path: Path, old: str, new: str = "") -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"missing fixture text: {old}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_missing_compatibility_matrix_row_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "docs/reference/release-evidence.md", "| certbot |", "| certbot-drift |")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "release evidence compatibility matrix missing" in result.stderr


def test_compatibility_matrix_row_detail_drift_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "docs/reference/release-evidence.md", "The maintained floor is Go 1.25.11", "The maintained floor is Go 1.25")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "release evidence compatibility matrix row detail drift" in result.stderr


def test_certbot_wsl_evidence_link_drift_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "docs/reference/release-evidence.md", "WSL certbot evidence", "certbot evidence")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "release evidence compatibility matrix row detail drift" in result.stderr


def test_missing_ci_version_metadata_validation_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/ci.yml", "python scripts/validate-version-metadata.py")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "validate-version-metadata.py" in result.stderr


def test_missing_go_runner_staticcheck_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-go-release.py", 'STATICCHECK_VERSION = "2026.1"')
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "STATICCHECK_VERSION" in result.stderr


def test_missing_go_runner_gosec_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-go-release.py", 'GOSEC_VERSION = "v2.25.0"')
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "GOSEC_VERSION" in result.stderr


def test_missing_ci_go_evidence_upload_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/ci.yml", "anopki-go-analysis-1.26.5")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "anopki-go-analysis-1.26.5" in result.stderr


def test_missing_ci_fuzz_smoke_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/ci.yml", "ANOPKI_ENABLE_FUZZING=ON")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "ANOPKI_ENABLE_FUZZING=ON" in result.stderr


def test_missing_release_go_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "anopki-go-verification.tar.gz")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "anopki-go-verification.tar.gz" in result.stderr


def test_missing_release_signing_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "cosign sign-blob")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "cosign sign-blob" in result.stderr


def test_missing_release_dry_run_gate_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(
        tmp_path / ".github/workflows/release.yml",
        "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        "if: always()",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "github.event_name == 'push'" in result.stderr


def test_release_evidence_placeholder_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs/reference/release-evidence.md"
    evidence.write_text(evidence.read_text(encoding="utf-8") + "\nTODO\n", encoding="utf-8")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "contains placeholder text" in result.stderr


def test_missing_local_verification_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "docs/reference/release-evidence.md", "- `python scripts/validate-docs.py`")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "release evidence missing local verification commands" in result.stderr


def test_missing_compatibility_evidence_template_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(
        tmp_path / "docs/reference/release-evidence.md",
        "## Release Candidate Compatibility Evidence Template",
        "## Release Candidate Compatibility Drift",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "release evidence compatibility template missing" in result.stderr




def test_missing_recovery_runner_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-recovery-drill.py", "private-key-exclusion")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "private-key-exclusion" in result.stderr


def test_missing_release_recovery_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "anopki-recovery-verification.tar.gz")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "anopki-recovery-verification.tar.gz" in result.stderr


def test_missing_status_outage_runner_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-status-outage-drill.py", "sensitive-evidence-exclusion")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "sensitive-evidence-exclusion" in result.stderr


def test_missing_release_status_outage_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "anopki-status-outage-verification.tar.gz")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "anopki-status-outage-verification.tar.gz" in result.stderr



def test_audit_replay_minimum_go_version_format_drift_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(
        tmp_path / "scripts/verify-audit-replay-drill.py",
        "MINIMUM_GO_VERSION = (1, 25, 11)",
        "MINIMUM_GO_VERSION=(1,25,11)",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "MINIMUM_GO_VERSION = (1, 25, 11)" in result.stderr


def test_missing_audit_replay_runner_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-audit-replay-drill.py", "dead-letter-attempt-history-preserved")
    result = run_validator(tmp_path)
    assert result.returncode == 1


def test_missing_release_audit_replay_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "anopki-audit-replay-verification.tar.gz")
    result = run_validator(tmp_path)
    assert result.returncode == 1

def test_missing_issuer_rollover_runner_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / "scripts/verify-issuer-rollover-drill.py", "same-parent-chain-required")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "same-parent-chain-required" in result.stderr


def test_missing_release_issuer_rollover_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    mutate(tmp_path / ".github/workflows/release.yml", "anopki-issuer-rollover-verification.tar.gz")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "anopki-issuer-rollover-verification.tar.gz" in result.stderr


def main() -> None:
    result = run_validator(ROOT)
    if result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    if "release evidence ok" not in result.stdout:
        raise SystemExit(f"unexpected validator output: {result.stdout!r}")
    tests = [
        test_missing_compatibility_matrix_row_fails,
        test_compatibility_matrix_row_detail_drift_fails,
        test_certbot_wsl_evidence_link_drift_fails,
        test_missing_ci_version_metadata_validation_fails,
        test_missing_go_runner_staticcheck_fails,
        test_missing_go_runner_gosec_fails,
        test_missing_ci_go_evidence_upload_fails,
        test_missing_ci_fuzz_smoke_fails,
        test_missing_release_go_evidence_fails,
        test_missing_recovery_runner_fails,
        test_missing_release_recovery_evidence_fails,
        test_missing_status_outage_runner_fails,
        test_missing_release_status_outage_evidence_fails,
        test_audit_replay_minimum_go_version_format_drift_fails,
        test_missing_audit_replay_runner_fails,
        test_missing_release_audit_replay_evidence_fails,
        test_missing_issuer_rollover_runner_fails,
        test_missing_release_issuer_rollover_evidence_fails,
        test_missing_release_signing_evidence_fails,
        test_missing_release_dry_run_gate_fails,
        test_release_evidence_placeholder_fails,
        test_missing_local_verification_evidence_fails,
        test_missing_compatibility_evidence_template_fails,
    ]
    for test in tests:
        with tempfile.TemporaryDirectory() as dirname:
            test(Path(dirname))
    require_release_workflow()
    print("release evidence validator tests ok")


if __name__ == "__main__":
    main()
