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
        "EDITION.md",
        ".env.example",
        "service/README.md",
        "scripts/acme-smoke/README.md",
        "tests/fixtures/backend-parity/README.md",
        "tests/fixtures/ocsp/README.md",
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


def test_non_community_readme_focus_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8")
        + "\nCurrent execution focus: external AnoCrypto-C capability parity.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "non-Community execution focus" in result.stderr


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



def test_missing_remaining_key_provider_scope_rule_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8").replace(
            "Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision.",
            "Future provider scope decision.",
            1,
        ),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "ROADMAP does not contain the remaining KeyProvider scope rule" in result.stderr


def test_completed_whole_repository_warning_cleanup_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8")
        + "\n- Remove known warnings that prevent a clean whole-repository warning-as-error build.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "completed whole-repository warning cleanup" in result.stderr


def test_completed_provider_result_correlation_roadmap_item_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8") + "\n- Complete provider-result audit correlation.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "completed provider-result audit correlation" in result.stderr


def test_completed_service_release_profile_metadata_roadmap_item_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8")
        + "\n- Expose selected product profile and backend metadata through the Go service/version and release manifests.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "completed service/release profile metadata work" in result.stderr


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
    assert "README.md:" in result.stderr
    assert "missing repository path: docs/missing.md" in result.stderr


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


def append_doc(root: Path, name: str, text: str) -> None:
    with (root / name).open("a", encoding="utf-8") as doc:
        doc.write("\n" + text + "\n")


def test_relative_links_and_fragments_pass(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    (tmp_path / "docs/anchor (example).md").write_text(
        "# Café & `foo_bar`\n\n"
        "Same heading\n------------\n\n"
        "## Same heading\n\n"
        '<a name="explicit-anchor"></a>\n\n'
        '# `<route>` and `__init__`\n',
        encoding="utf-8",
    )
    append_doc(
        tmp_path, "README.md",
        '[active](docs/acme-client-compatibility.md#verified-scenario-map)\n'
        '[current](#current-status)\n'
        '[encoded](docs/anchor%20%28example%29.md#caf%C3%A9--foo_bar)\n'
        '[angle](<docs/anchor (example).md#same-heading> "Optional title")\n'
        '[duplicate heading][second]\n'
        '[second]: /docs/anchor%20%28example%29.md#same-heading-1\n\n'
        '[custom](docs/anchor%20%28example%29.md#explicit-anchor)\n'
        '[code heading](docs/anchor%20%28example%29.md#route-and-__init__)\n'
        '[external](https://example.test/nonexistent#ignore)\n'
        '`[inline code](missing.md)`\n'
        '`<!--` followed by [a real link](#current-status)\n'
        '[empty]()\n\n[empty]: missing.md\n\n'
        '<!-- [comment](missing.md) -->\n'
        '~~~~markdown\n```\n[example](missing.md)\n~~~~',
    )
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr


def test_broken_links_report_source_and_destination(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "docs/architecture/issuance-flow.md",
        '[missing](../does-not-exist.md#anything)\n'
        '[fragment](../ROADMAP.md#typo)\n'
        '[same page](#fabricated-heading)\n'
        '[![clickable image](missing-image.png)](../ROADMAP.md)\n'
        '[fenced heading](#not-a-heading)\n\n'
        '```markdown\n# Not a heading\n```\n\n'
        '[missing reference][broken]\n\n[broken]: ../missing-reference.md\n\n'
        'A literal ` at the end of a paragraph.\n\n'
        '[visible](../missing-between-backticks.md) and another literal `.',
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    for detail in (
        "does-not-exist.md#anything", "ROADMAP.md#typo", "#fabricated-heading",
        "#not-a-heading", "missing-reference.md", "missing-image.png", "missing-between-backticks.md",
    ):
        assert any(
            line.startswith("docs/architecture/issuance-flow.md:") and detail in line
            for line in result.stderr.splitlines()
        ), result.stderr


def test_index_duplicate_uses_normalized_destination(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "docs/INDEX.md",
        "## More navigation\n\n"
        "Document | Purpose\n--- | ---\n"
        "[Another roadmap](ROADMAP.md) | Another entry for the same file.\n\n"
        "- [Duplicate][roadmap]\n"
        "- [New destination](acme-revocation.md#reason-semantics-and-approved-internal-transport)"
        " [Again](acme-revocation.md#reason-semantics-and-approved-internal-transport)\n"
        "- [Direct to evaluation](ROADMAP.md#remaining-evaluation-work)\n\n"
        "[roadmap]: ./reference/../ROADMAP.md",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "duplicate INDEX target" in result.stderr
    assert result.stderr.count("duplicate INDEX target docs/ROADMAP.md") == 2
    assert "duplicate INDEX target docs/acme-revocation.md#reason-semantics" in result.stderr


def test_index_intentional_repeat_passes(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "docs/INDEX.md",
        "- [Roadmap](./ROADMAP.md) <!-- index-repeat: alternate entry point for operators -->\n"
        "- [Evaluation](ROADMAP.md#remaining-evaluation-work)\n"
        "- [Deferred](ROADMAP.md#deferred--not-selected)\n\n"
        "| Document | Purpose |\n| --- | --- |\n"
        "| [Changelog](../CHANGELOG.md) | Completed work, linked from the [roadmap](ROADMAP.md). |",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr


def test_completed_roadmap_work_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "docs/ROADMAP.md",
        "## Completed Phase 5\n\n- [x] Publish release evidence.\n- **Done:** Update references."
        "\n- Phase 4 was completed.",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    for detail in ("Completed Phase 5", "[x] Publish release evidence", "Update references", "Phase 4 was completed"):
        assert detail in result.stderr, result.stderr


def test_dated_history_and_scoped_claims_pass(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "docs/ROADMAP.md",
        "On 2026-07-24 the alpha.0 engineering closeout was recorded.\n"
        "- [ ] Review remaining interoperability after the completed smoke runs.",
    )
    append_doc(
        tmp_path, "docs/reference/release-candidate-v0.1.0-alpha.0.md",
        "As of 2026-07-24, no GitHub Release has been published.\n"
        "- [x] Add a mock/software-token provider to the historical test plan.",
    )
    append_doc(
        tmp_path, "README.md",
        "On 2026-07-24, there was no published GitHub Release.\n"
        "Certbot and lego are supported only for the verified scenarios.\n\n"
        "### Historical closeout — 2026-07-24\n\n"
        "No GitHub Release has been published.",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 0, result.stderr


def test_contradictory_current_release_claims_fail(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(
        tmp_path, "README.md",
        "No GitHub Release has been published.\n"
        "`v0.1.0-alpha.1` is production-ready.\n"
        "`v0.1.0-alpha.1` has not been published.",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "current release claim" in result.stderr
    assert "No GitHub Release has been published" in result.stderr
    assert "production-ready" in result.stderr
    assert "has not been published" in result.stderr


def test_conflicting_release_publication_flags_fail(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    evidence = tmp_path / "docs/reference/release-evidence.md"
    text = evidence.read_text(encoding="utf-8")
    text = text.replace("`prerelease=true`", "`prerelease=false`", 1)
    text = text.replace("No alpha.0 GitHub Release", "An alpha.0 GitHub Release", 1)
    evidence.write_text(text, encoding="utf-8")
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "alpha.1 publication record" in result.stderr
    assert "alpha.0 tag attempt" in result.stderr


def test_contradictory_client_support_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    append_doc(tmp_path, "README.md", "All ACME clients are supported.\nCertbot and lego are fully supported.")
    append_doc(
        tmp_path, "docs/acme-client-compatibility.md",
        "| certbot 5.6.0 | Windows non-admin PowerShell | RSA | HTTP-01 webroot | Pass | CI is green. |",
    )
    result = run_validator(tmp_path)
    assert result.returncode == 1
    assert "All ACME clients are supported" in result.stderr
    assert "Certbot and lego are fully supported" in result.stderr
    assert "certbot 5.6.0 | Windows non-admin PowerShell" in result.stderr


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
        test_non_community_readme_focus_fails(Path(dirname))
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
        test_generated_build_tree_headers_are_ignored(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_source_file_header_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_ignored_go_module_cache_headers_pass(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_anocrypto_strategy_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_anocrypto_direction_removed_from_roadmap_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_separate_project_adapter_execution_in_roadmap_fails(Path(dirname))
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
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_remaining_key_provider_scope_rule_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_completed_whole_repository_warning_cleanup_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_completed_provider_result_correlation_roadmap_item_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_completed_service_release_profile_metadata_roadmap_item_fails(Path(dirname))
    for test in (
        test_relative_links_and_fragments_pass,
        test_broken_links_report_source_and_destination,
        test_index_duplicate_uses_normalized_destination,
        test_index_intentional_repeat_passes,
        test_completed_roadmap_work_fails,
        test_dated_history_and_scoped_claims_pass,
        test_contradictory_current_release_claims_fail,
        test_conflicting_release_publication_flags_fail,
        test_contradictory_client_support_fails,
    ):
        with tempfile.TemporaryDirectory() as dirname:
            test(Path(dirname))
    print("docs validator tests ok")


def test_generated_build_tree_headers_are_ignored(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    generated = tmp_path / "build-werror-full" / "generated" / "anopki" / "version_config.hpp"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text("#pragma once\n", encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout


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


def test_separate_project_adapter_execution_in_roadmap_fails(tmp_path: Path) -> None:
    copy_docs_inputs(tmp_path)
    roadmap = tmp_path / "docs" / "ROADMAP.md"
    roadmap.write_text(
        roadmap.read_text(encoding="utf-8")
        + "\n- Pin a real immutable AnoCrypto-C SDK artifact in Community CI.\n",
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "separate-project adapter execution work" in result.stderr


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
