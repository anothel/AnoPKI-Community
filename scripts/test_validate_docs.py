#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for docs validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-docs.py"


def copy_docs_inputs(dst: Path) -> None:
    required = [
        "LICENSE",
        "README.md",
        ".env.example",
        "service/README.md",
        "scripts/acme-smoke/README.md",
        "scripts/verify-local.ps1",
        ".github/workflows/ci.yml",
    ]
    for path in required:
        target = dst / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / path, target)
    for path in (ROOT / "docs").rglob("*"):
        if path.is_file():
            target = dst / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    for path in ("CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"):
        shutil.copy2(ROOT / path, dst / path)


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def test_current_docs_pass() -> None:
    result = run_validator(ROOT)
    assert result.returncode == 0, result.stderr + result.stdout


def test_readme_missing_verify_local_command_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace("python scripts\\validate-service-contracts.py", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "README quickstart missing verify-local commands" in result.stderr


def test_missing_required_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "ROADMAP.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_acme_compatibility_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "acme-client-compatibility.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_audit_tamper_evidence_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "security" / "audit-tamper-evidence.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_siem_detections_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "security" / "siem-detections.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_access_model_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "security" / "access-model.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_production_hardening_checklist_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "runbooks" / "production-hardening-checklist.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_missing_key_provider_semantics_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "security" / "key-provider-semantics.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_stale_software_token_roadmap_item_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8") + "\n- Add a mock/software-token provider before selecting a real provider.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "completed software-token contract work" in result.stderr


def test_missing_software_token_contract_wording_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    semantics = tmp_path / "docs" / "security" / "key-provider-semantics.md"
    semantics.write_text(
        semantics.read_text(encoding="utf-8").replace("test-only software-token resolver contract", "resolver contract", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "KeyProvider signing direction docs missing required wording" in result.stderr


def test_missing_wsl_certbot_compatibility_row_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    compatibility = tmp_path / "docs" / "acme-client-compatibility.md"
    compatibility.write_text(
        compatibility.read_text(encoding="utf-8").replace("WSL Ubuntu, PowerShell 7.6.3", "Linux drift", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ACME compatibility matrix missing required evidence" in result.stderr


def test_missing_acme_account_key_evidence_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    compatibility = tmp_path / "docs" / "acme-client-compatibility.md"
    compatibility.write_text(
        compatibility.read_text(encoding="utf-8").replace("| RSA |", "| key drift |", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ACME compatibility matrix missing required evidence" in result.stderr


def test_missing_acme_challenge_result_evidence_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    compatibility = tmp_path / "docs" / "acme-client-compatibility.md"
    compatibility.write_text(
        compatibility.read_text(encoding="utf-8").replace("| HTTP-01 webroot | Pass |", "| dns-01 | Pass |", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ACME compatibility matrix missing required evidence" in result.stderr


def test_stale_public_tls_readme_next_work_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nCurrent execution focus: release operations unless public TLS issuance enables a linting hook.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "README still treats public TLS lint hook as future work" in result.stderr


def test_invalid_openapi_json_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "reference" / "openapi.json").write_text("{", encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "invalid OpenAPI JSON" in result.stderr


def test_missing_readme_link_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\n[Missing](docs/missing.md)\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "README links point to missing files" in result.stderr


def test_license_text_drift_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    license_file = tmp_path / "LICENSE"
    license_file.write_text(
        license_file.read_text(encoding="utf-8").replace("Mozilla Public License Version 2.0", "Custom License"),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "LICENSE is not MPL-2.0 text" in result.stderr


def test_ci_missing_docs_validator_tests_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    ci = tmp_path / ".github" / "workflows" / "ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace("python scripts/test_validate_docs.py", "", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "CI docs job missing docs validation commands" in result.stderr


def main() -> None:
    test_current_docs_pass()
    with tempfile.TemporaryDirectory() as dirname:
        test_readme_missing_verify_local_command_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_required_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_acme_compatibility_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_audit_tamper_evidence_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_siem_detections_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_access_model_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_production_hardening_checklist_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_key_provider_semantics_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_wsl_certbot_compatibility_row_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_acme_account_key_evidence_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_acme_challenge_result_evidence_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_stale_public_tls_readme_next_work_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_invalid_openapi_json_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_readme_link_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_license_text_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_ci_missing_docs_validator_tests_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_source_file_header_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_ignored_go_module_cache_headers_pass(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_anocrypto_strategy_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_anocrypto_direction_removed_from_roadmap_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_legacy_identifiers_outside_migration_context_fail(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_key_provider_signing_adr_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_key_provider_direction_drift_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_stale_software_token_roadmap_item_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_software_token_contract_wording_fails(Path(dirname))
    print("docs validator tests ok")


def test_missing_source_file_header_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    script = tmp_path / "scripts" / "missing_header.py"
    script.write_text("print('missing header')\n", encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "first-party source files missing SPDX header" in result.stderr


def test_ignored_go_module_cache_headers_pass(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    cached = tmp_path / ".gomodcache" / "wsl" / "example.test" / "dep.go"
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text("package dep\n", encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout


def test_missing_anocrypto_strategy_doc_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "reference" / "crypto-backend-strategy.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_anocrypto_direction_removed_from_roadmap_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8").replace("AnoCrypto-C", "BackendFuture"),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ROADMAP does not mention the external AnoCrypto-C adapter direction" in result.stderr


def test_legacy_identifiers_outside_migration_context_fail(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\n"
        + ("modern" + "-pki")
        + "\n"
        + ("MODERN" + "_PKI")
        + "\n"
        + ("X-Modern" + "-PKI")
        + "\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "legacy project identifiers found outside migration or historical docs" in result.stderr


def test_missing_key_provider_signing_adr_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs" / "adr" / "0007-key-provider-signing-boundary.md").unlink()

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "missing required docs" in result.stderr


def test_key_provider_direction_drift_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    adr = tmp_path / "docs" / "adr" / "0007-key-provider-signing-boundary.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("deliberately scoped hybrid", "automatic universal provider"),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "KeyProvider signing direction docs missing required wording" in result.stderr


if __name__ == "__main__":
    main()
