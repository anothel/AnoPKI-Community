#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Tests for release evidence validation."""

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
        "on:",
        "workflow_dispatch:",
        "tags:",
        "contents: read",
        "contents: write",
        "id-token: write",
        'go-version: "1.25.11"',
        "cmake --build build-release --config Release",
        'VERSION="$(cat VERSION)"',
        "go build -ldflags",
        "anopki-service-v${VERSION}-linux-amd64.tar.gz",
        "anopki-core-v${VERSION}-linux-amd64.tar.gz",
        "python scripts/validate-release-artifacts.py dist",
        "syft scan dir:dist",
        "cosign sign-blob",
        "actions/upload-artifact",
        "actions/download-artifact",
        "SIGNING-STATUS.txt",
        "Signing skipped: manual dry-run",
        "publish-tagged-release:",
        "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
        "environment: release",
        "Require a signed annotated tag",
        "GH_TOKEN: ${{ github.token }}",
        "gh release create",
        "gh release upload",
    ]
    missing = [value for value in required if value not in text]
    if missing:
        raise SystemExit(".github/workflows/release.yml missing:\n" + "\n".join(missing))


def copy_release_evidence_inputs(dst: Path) -> None:
    files = [
        "docs/reference/release-evidence.md",
        "scripts/verify-local.ps1",
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
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_missing_compatibility_matrix_row_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace("| certbot |", "| certbot-drift |", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "release evidence compatibility matrix missing" in result.stderr


def test_compatibility_matrix_row_detail_drift_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace(
            "CI pins at least Go 1.25.11",
            "CI pins at least Go 1.25",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "release evidence compatibility matrix row detail drift" in result.stderr


def test_certbot_wsl_evidence_link_drift_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace("WSL certbot evidence", "certbot evidence", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "release evidence compatibility matrix row detail drift" in result.stderr


def test_missing_ci_version_metadata_validation_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    ci = tmp_path / ".github" / "workflows" / "ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace("python scripts/validate-version-metadata.py", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "validate-version-metadata.py" in result.stderr


def test_missing_ci_staticcheck_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    ci = tmp_path / ".github" / "workflows" / "ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace(
            "go run honnef.co/go/tools/cmd/staticcheck@latest ./...",
            "",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "staticcheck@latest" in result.stderr


def test_missing_ci_gosec_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    ci = tmp_path / ".github" / "workflows" / "ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace(
            "go run github.com/securego/gosec/v2/cmd/gosec@latest ./...",
            "",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "gosec@latest" in result.stderr


def test_missing_ci_fuzz_smoke_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    ci = tmp_path / ".github" / "workflows" / "ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace("ANOPKI_ENABLE_FUZZING=ON", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ANOPKI_ENABLE_FUZZING=ON" in result.stderr


def test_missing_release_signing_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    release = tmp_path / ".github" / "workflows" / "release.yml"
    release.write_text(
        release.read_text(encoding="utf-8").replace("cosign sign-blob", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "cosign sign-blob" in result.stderr


def test_missing_release_dry_run_gate_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    release = tmp_path / ".github" / "workflows" / "release.yml"
    release.write_text(
        release.read_text(encoding="utf-8").replace(
            "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
            "if: always()",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "github.event_name == 'push'" in result.stderr


def test_release_evidence_placeholder_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8") + "\nTODO\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "contains placeholder text" in result.stderr


def test_missing_local_verification_evidence_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace("- `python scripts/validate-docs.py`", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "release evidence missing local verification commands" in result.stderr


def test_missing_compatibility_evidence_template_fails(tmp_path: Path) -> None:
    copy_release_evidence_inputs(tmp_path)
    evidence = tmp_path / "docs" / "reference" / "release-evidence.md"
    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace(
            "## Release Candidate Compatibility Evidence Template",
            "## Release Candidate Compatibility Drift",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "release evidence compatibility template missing" in result.stderr


def main() -> None:
    result = run_validator(ROOT)
    if result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    if "release evidence ok" not in result.stdout:
        raise SystemExit(f"unexpected validator output: {result.stdout!r}")
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_compatibility_matrix_row_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_compatibility_matrix_row_detail_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_certbot_wsl_evidence_link_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_ci_version_metadata_validation_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_ci_staticcheck_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_ci_gosec_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_ci_fuzz_smoke_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_release_signing_evidence_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_release_dry_run_gate_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_release_evidence_placeholder_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_local_verification_evidence_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_compatibility_evidence_template_fails(Path(dirname))
    require_release_workflow()
    print("release evidence validator tests ok")


if __name__ == "__main__":
    main()
