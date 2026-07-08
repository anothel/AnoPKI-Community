#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for release version metadata validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-version-metadata.py"


def copy_version_inputs(dst: Path) -> None:
    for name in [
        "VERSION",
        "CMakeLists.txt",
        "src/version.cpp",
        ".github/workflows/release.yml",
    ]:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def run_validator(root: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_current_version_metadata_pass() -> None:
    result = run_validator()
    assert result.returncode == 0, result.stderr or result.stdout


def test_invalid_version_format_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copy_version_inputs(root)
        (root / "VERSION").write_text("1.2\n", encoding="utf-8")
        result = run_validator(root)

    assert result.returncode == 1
    assert "VERSION must be MAJOR.MINOR.PATCH" in result.stderr


def test_missing_version_file_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copy_version_inputs(root)
        (root / "VERSION").unlink()
        result = run_validator(root)

    assert result.returncode == 1
    assert "missing required file: VERSION" in result.stderr


def test_release_workflow_version_drift_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        copy_version_inputs(root)
        release = root / ".github" / "workflows" / "release.yml"
        release.write_text(
            release.read_text(encoding="utf-8").replace("-X main.serviceVersion=${VERSION}", "", 1),
            encoding="utf-8",
        )
        result = run_validator(root)

    assert result.returncode == 1
    assert "-X main.serviceVersion=${VERSION}" in result.stderr


def main() -> None:
    test_current_version_metadata_pass()
    test_invalid_version_format_fails()
    test_missing_version_file_fails()
    test_release_workflow_version_drift_fails()
    print("version metadata tests ok")


if __name__ == "__main__":
    main()
