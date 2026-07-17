#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Cheap docs-as-code checks for the PKI documentation baseline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_HEADER_EXTENSIONS = {".cpp", ".go", ".hpp", ".ps1", ".py"}
SOURCE_HEADER_SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".gocache",
    ".gomodcache",
    ".tmp",
    ".tmp-gocache",
    ".vscode",
    "build",
    "build-fuzz",
    "build-release",
}


LEGACY_IDENTIFIER_ALLOWED_PATHS = {
    "CHANGELOG.md",
    "docs/adr/0005-project-rename-to-anopki.md",
    "docs/reference/project-identity-and-license.md",
    "docs/runbooks/anopki-rename-migration.md",
}
LEGACY_IDENTIFIER_TOKENS = (
    "modern" + "-pki",
    "MODERN" + "_PKI",
    "X-Modern" + "-PKI",
)
LEGACY_SCAN_EXTENSIONS = {
    "",
    ".cpp",
    ".go",
    ".hpp",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".txt",
    ".yaml",
    ".yml",
}
LEGACY_SCAN_FILENAMES = {
    ".env.example",
    ".gitignore",
    "CMakeLists.txt",
}

REQUIRED = [
    "LICENSE",
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/ROADMAP.md",
    "docs/INDEX.md",
    "docs/acme-client-compatibility.md",
    "docs/acme-rfc8555-conformance.md",
    "docs/architecture/pki-context.md",
    "docs/architecture/ca-hierarchy.md",
    "docs/architecture/issuance-flow.md",
    "docs/architecture/renewal-flow.md",
    "docs/architecture/revocation-flow.md",
    "docs/policy/certificate-profiles.md",
    "docs/policy/algorithm-policy.md",
    "docs/policy/cp-cps-map.md",
    "docs/operations/issuance-runbook.md",
    "docs/operations/renewal-runbook.md",
    "docs/operations/revocation-runbook.md",
    "docs/operations/mass-revocation-plan.md",
    "docs/operations/key-ceremony.md",
    "docs/operations/backup-restore-runbook.md",
    "docs/runbooks/production-hardening-checklist.md",
    "docs/security/threat-model.md",
    "docs/security/access-model.md",
    "docs/security/audit-log-schema.md",
    "docs/security/audit-tamper-evidence.md",
    "docs/security/key-provider-semantics.md",
    "docs/security/siem-detections.md",
    "docs/adr/0001-ca-backend-selection.md",
    "docs/adr/0002-acme-adoption.md",
    "docs/adr/0003-hsm-kms-strategy.md",
    "docs/reference/improvement-analysis-alignment.md",
    "docs/reference/release-readiness-action-plan.md",
    "docs/reference/core-cli-contract.md",
    "docs/reference/core-boundary-integration.md",
    "docs/reference/api-surface-status.md",
    "docs/reference/fuzzing.md",
    "docs/reference/release-evidence.md",
    "docs/reference/openapi.json",
    "docs/reference/project-identity-and-license.md",
    "docs/reference/source-file-header-policy.md",
    "docs/reference/documentation-governance.md",
    "docs/reference/crypto-backend-strategy.md",
    "docs/runbooks/anopki-rename-migration.md",
    "docs/adr/0004-license-change-to-mpl-2.0.md",
    "docs/adr/0005-project-rename-to-anopki.md",
    "docs/adr/0006-crypto-backend-direction-anocrypto.md",
    "docs/adr/0007-key-provider-signing-boundary.md",
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def check_required_files(root: Path) -> None:
    missing = [path for path in REQUIRED if not (root / path).is_file()]
    if missing:
        fail("missing required docs:\n" + "\n".join(missing))


def check_openapi_json(root: Path) -> None:
    path = root / "docs/reference/openapi.json"
    try:
        with path.open(encoding="utf-8") as fh:
            json.load(fh)
    except json.JSONDecodeError as exc:
        fail(f"invalid OpenAPI JSON: {path}: {exc}")


def check_readme_links(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)#][^)]+)\)", readme)
    missing = []
    for link in links:
        if "://" in link or link.startswith("mailto:"):
            continue
        target = (root / link).resolve()
        if not target.exists():
            missing.append(link)
    if missing:
        fail("README links point to missing files:\n" + "\n".join(missing))


def check_license_state(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    if "No `LICENSE` file has been selected yet" in readme or "all rights are reserved" in readme:
        fail("README still says license is undecided")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    if "Mozilla Public License Version 2.0" not in license_text or "mozilla.org/MPL/2.0" not in license_text:
        fail("LICENSE is not MPL-2.0 text")


def is_generated_or_ignored_path(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    return any(
        part in SOURCE_HEADER_SKIP_DIRS or part.startswith("build-")
        for part in parts
    )


def first_party_source_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if is_generated_or_ignored_path(path, root):
            continue
        if path.name == "CMakeLists.txt" or path.suffix in SOURCE_HEADER_EXTENSIONS:
            files.append(path)
    return files


def check_source_file_headers(root: Path) -> None:
    missing = []
    for path in first_party_source_files(root):
        head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:5])
        if "SPDX-License-Identifier: MPL-2.0" not in head:
            missing.append(str(path.relative_to(root)))
    if missing:
        fail("first-party source files missing SPDX header:\n" + "\n".join(sorted(missing)))


def check_readme_verify_local_commands(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    script = (root / "scripts/verify-local.ps1").read_text(encoding="utf-8")
    commands = re.findall(r'Display\s*=\s*"([^"]+)"', script)
    missing = [command for command in commands if command not in readme]
    if missing:
        fail("README quickstart missing verify-local commands:\n" + "\n".join(missing))


def check_readme_current_execution_state(root: Path) -> None:
    readme = (root / "README.md").read_text(encoding="utf-8")
    if "unless public TLS issuance enables a linting hook" in readme:
        fail("README still treats public TLS lint hook as future work")
    stale_scope = [
        "external AnoCrypto-C capability parity",
        "selecting a real local provider only after deployment",
    ]
    stale = [text for text in stale_scope if text in readme]
    if stale:
        fail("README still contains non-Community execution focus:\n" + "\n".join(stale))


def check_anocrypto_direction(root: Path) -> None:
    strategy = (root / "docs/reference/crypto-backend-strategy.md").read_text(encoding="utf-8")
    adr = (root / "docs/adr/0006-crypto-backend-direction-anocrypto.md").read_text(encoding="utf-8")
    roadmap = (root / "docs/ROADMAP.md").read_text(encoding="utf-8")
    required = ["AnoCrypto-C", "OpenSSL", "backend-neutral"]
    missing = [text for text in required if text not in strategy + adr]
    if missing:
        fail("External adapter boundary docs missing required wording:\n" + "\n".join(missing))
    separate_project_rule = "Enterprise/OpenSSL and Enterprise/AnoCrypto-C profiles: Enterprise project."
    if separate_project_rule not in roadmap:
        fail("ROADMAP does not mention the external AnoCrypto-C adapter direction")
    stale_execution = [
        "Pin a real immutable AnoCrypto-C SDK artifact",
        "Expand the external AnoCrypto-C adapter",
        "Keep Enterprise/AnoCrypto-C production release blocked",
        "Add negative tests proving that unsupported AnoCrypto-C operations",
    ]
    stale = [text for text in stale_execution if text in roadmap]
    if stale:
        fail("ROADMAP still contains separate-project adapter execution work:\n" + "\n".join(stale))


def check_key_provider_direction(root: Path) -> None:
    adr = (root / "docs/adr/0007-key-provider-signing-boundary.md").read_text(encoding="utf-8")
    semantics = (root / "docs/security/key-provider-semantics.md").read_text(encoding="utf-8")
    roadmap = (root / "docs/ROADMAP.md").read_text(encoding="utf-8")
    adr_required = ["deliberately scoped hybrid", "FileKeyProvider", "Remote KMS", "test-only software-token"]
    semantics_required = [
        "deliberately scoped hybrid",
        "provider.invalid_reference",
        "test-only software-token resolver contract",
        "GET /version",
        "anopki-release-metadata.json",
    ]
    missing = [text for text in adr_required if text not in adr]
    missing += [text for text in semantics_required if text not in semantics]
    if missing:
        fail("KeyProvider signing direction docs missing required wording:\n" + "\n".join(missing))
    stale_roadmap = [
        "Implement ADR 0007 certificate-issuance `FileKeyProvider` vertical slice",
        "Implement one file-provider signing vertical slice",
        "adapter that still reads file keys directly",
    ]
    stale = [text for text in stale_roadmap if text in roadmap]
    if stale:
        fail("ROADMAP still lists the completed certificate FileKeyProvider slice:\n" + "\n".join(stale))
    completed_roadmap = ["Add a mock/software-token provider", "Add a PKCS#11 mock or software-token test path"]
    completed = [text for text in completed_roadmap if text in roadmap]
    if completed:
        fail("ROADMAP still lists completed software-token contract work:\n" + "\n".join(completed))
    if "provider-result audit correlation" in roadmap:
        fail("ROADMAP still lists completed provider-result audit correlation work")
    if "Expose selected product profile and backend metadata through the Go service/version and release manifests" in roadmap:
        fail("ROADMAP still lists completed service/release profile metadata work")
    remaining_scope = "Do not introduce a runtime software-token, PKCS#11, HSM or KMS provider in Community without a new scope decision."
    if remaining_scope not in roadmap:
        fail("ROADMAP does not contain the remaining KeyProvider scope rule")
    if "Remove known warnings that prevent a clean whole-repository warning-as-error build." in roadmap:
        fail("ROADMAP still lists completed whole-repository warning cleanup")

def should_scan_legacy_identifiers(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if is_generated_or_ignored_path(path, root):
        return False
    if str(rel).replace("\\", "/") in LEGACY_IDENTIFIER_ALLOWED_PATHS:
        return False
    return path.name in LEGACY_SCAN_FILENAMES or path.suffix in LEGACY_SCAN_EXTENSIONS


def check_legacy_identifier_scope(root: Path) -> None:
    hits: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or not should_scan_legacy_identifiers(path, root):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for token in LEGACY_IDENTIFIER_TOKENS:
            for line_number, line in enumerate(content.splitlines(), start=1):
                if token in line:
                    hits.append(f"{rel}:{line_number}: {token}")
    if hits:
        fail(
            "legacy project identifiers found outside migration or historical docs:\n"
            + "\n".join(sorted(hits))
        )

def check_ci_docs_validation_commands(root: Path) -> None:
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    required = [
        "python scripts/validate-docs.py",
        "python scripts/test_validate_docs.py",
        "python scripts/test_verify_local.py",
    ]
    missing = [command for command in required if command not in ci]
    if missing:
        fail("CI docs job missing docs validation commands:\n" + "\n".join(missing))


def check_acme_compatibility_matrix(root: Path) -> None:
    compatibility = (root / "docs/acme-client-compatibility.md").read_text(encoding="utf-8")
    required = [
        "| Client | OS / shell | Account key | Challenge | Smoke result | Evidence |",
        "lego v4.35.2+dev-release",
        "Windows non-admin PowerShell",
        "| P-256 |",
        "lego v4.35.2+dev-release | Windows non-admin PowerShell | P-256 | HTTP-01 webroot | Pass",
        "certbot 5.6.0",
        "WSL Ubuntu, PowerShell 7.6.3",
        "| RSA |",
        "certbot 5.6.0 | WSL Ubuntu, PowerShell 7.6.3 | RSA | HTTP-01 webroot | Pass",
        "| HTTP-01 webroot | Pass |",
        "Successfully received certificate.",
        "| not reached |",
        "certbot 5.6.0 | Windows non-admin PowerShell | not reached | HTTP-01 webroot / standalone | Blocked before ACME traffic",
        "| HTTP-01 webroot / standalone | Blocked before ACME traffic |",
        "Blocked before ACME traffic",
        "certbot must be run on a shell with administrative rights",
    ]
    missing = [text for text in required if text not in compatibility]
    if missing:
        fail("ACME compatibility matrix missing required evidence:\n" + "\n".join(missing))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=ROOT, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    check_required_files(root)
    check_openapi_json(root)
    check_readme_links(root)
    check_license_state(root)
    check_source_file_headers(root)
    check_anocrypto_direction(root)
    check_key_provider_direction(root)
    check_readme_verify_local_commands(root)
    check_readme_current_execution_state(root)
    check_legacy_identifier_scope(root)
    check_ci_docs_validation_commands(root)
    check_acme_compatibility_matrix(root)
    print("docs ok")


if __name__ == "__main__":
    main()
