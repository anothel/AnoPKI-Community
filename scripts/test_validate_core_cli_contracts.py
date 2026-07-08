#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for core CLI JSON contract validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-core-cli-contracts.py"


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def copy_contract_inputs(dst: Path) -> None:
    for name in [
        "service/internal/corecli/runner.go",
        "src/cli/main.cpp",
        "docs/reference/core-cli-contract.md",
    ]:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def test_current_core_cli_contracts_pass() -> None:
    result = run_validator(ROOT)
    assert result.returncode == 0, result.stderr + result.stdout


def test_missing_doc_field_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    doc = tmp_path / "docs" / "reference" / "core-cli-contract.md"
    doc.write_text(
        doc.read_text(encoding="utf-8").replace("- `issuer_key_ref`\n", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "core CLI contract doc drift" in result.stderr


def test_go_json_tag_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    runner = tmp_path / "service" / "internal" / "corecli" / "runner.go"
    runner.write_text(
        runner.read_text(encoding="utf-8").replace('json:"issuer_key_ref"', 'json:"issuer_key_reference"', 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "Go corecli JSON fields drift" in result.stderr


def test_cpp_parser_key_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    cli = tmp_path / "src" / "cli" / "main.cpp"
    cli.write_text(
        cli.read_text(encoding="utf-8").replace('"issuer_key_ref"', '"issuer_key_reference"', 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "C++ core CLI parser fields drift" in result.stderr


def test_cpp_emitter_key_drift_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    cli = tmp_path / "src" / "cli" / "main.cpp"
    cli.write_text(
        cli.read_text(encoding="utf-8").replace('\\"certificate_pem\\"', '\\"certificate_pem_drift\\"', 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "C++ core CLI emitter fields drift" in result.stderr


def test_unknown_doc_section_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    doc = tmp_path / "docs" / "reference" / "core-cli-contract.md"
    doc.write_text(
        doc.read_text(encoding="utf-8") + "\n### contract drift\n\n- `field`\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "core CLI contract doc has unknown sections" in result.stderr


def main() -> None:
    test_current_core_cli_contracts_pass()
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_doc_field_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_go_json_tag_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_cpp_parser_key_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_cpp_emitter_key_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_unknown_doc_section_fails(Path(dirname))
    print("core CLI contract validator tests ok")


if __name__ == "__main__":
    main()
