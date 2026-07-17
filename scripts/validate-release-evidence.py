#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate Community release evidence decisions and CI hooks."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOC_TEXT = [
    "# Release Evidence",
    "## Tool Decisions",
    "## Release Artifacts",
    "## Compatibility Matrix",
    "## SQLite Recovery Evidence Runner",
    "## CRL And OCSP Outage Evidence Runner",
    "## Audit Repair And Dead-Letter Replay Evidence Runner",
    "## Supported-Go Evidence Runner",
    "## Required Evidence Per Release Candidate",
    "verify-go-release.py",
    "anopki-go-verification.tar.gz",
    "anopki-recovery-verification.tar.gz",
    "anopki-status-outage-verification.tar.gz",
    "anopki-audit-replay-verification.tar.gz",
    "syft",
    "cosign",
    "govulncheck",
    "go vet ./...",
    "go test -race ./...",
    "staticcheck",
    "gosec",
    "Clang/libFuzzer",
    "anopki-backend-info.json",
    "anopki-release-metadata.json",
]

REQUIRED_COMPATIBILITY_ROWS = [
    "OS", "Go", "OpenSSL", "SQLite", "PostgreSQL", "lego", "certbot",
]

REQUIRED_COMPATIBILITY_ROW_TEXT = {
    "OS": ["GitHub Actions Ubuntu", "Windows local verification"],
    "Go": ["go version", "Go 1.25.11"],
    "OpenSSL": ["CMake configure"],
    "SQLite": ["Go test", "SQLite"],
    "PostgreSQL": ["PostgreSQL integration", "DSN major version"],
    "lego": ["ACME smoke"],
    "certbot": ["Linux or elevated Windows", "WSL certbot evidence"],
}

REQUIRED_COMPATIBILITY_TEMPLATE_TEXT = [
    "## Release Candidate Compatibility Evidence Template",
    "| Area | Command or source | Result | Evidence pointer |",
    "| OS | GitHub Actions Ubuntu job plus any Windows local verification |",
    "| Go | `go version` from CI and release host |",
    "| OpenSSL | CMake configure output or package version |",
    "| SQLite | Local or CI Go test result covering SQLite store |",
    "| PostgreSQL | PostgreSQL integration job and DSN major version |",
    "| lego | ACME smoke command/output when ACME behavior changed |",
    "| certbot | WSL/Linux/elevated Windows smoke command/output when ACME behavior changed |",
]

REQUIRED_CI_TEXT = [
    "python scripts/test_validate_version_metadata.py",
    "python scripts/validate-version-metadata.py",
    "python scripts/test_generate_release_metadata.py",
    "python scripts/test_verify_go_release.py",
    "python scripts/test_verify_recovery_drill.py",
    "python scripts/verify-recovery-drill.py",
    "anopki-recovery-verification",
    "python scripts/test_verify_status_outage_drill.py",
    "python scripts/verify-status-outage-drill.py",
    "anopki-status-outage-verification",
    "python scripts/test_verify_audit_replay_drill.py",
    "python scripts/verify-audit-replay-drill.py",
    "anopki-audit-replay-verification",
    "python scripts/test_validate_release_artifacts.py",
    "python scripts/test_validate_release_evidence.py",
    "python scripts/validate-release-evidence.py",
    'go: ["1.25.12", "1.26.5"]',
    'go-version: "1.26.5"',
    'go-version: "1.25.12"',
    "python ../scripts/verify-go-release.py",
    "--profile baseline",
    "--profile analysis",
    "anopki-go-baseline-${{ matrix.go }}",
    '--commit "${GITHUB_SHA}"',
    "anopki-go-analysis-1.26.5",
    "ANOPKI_ENABLE_FUZZING=ON",
    "anopki_core_csr_fuzz",
    "anopki_core_ocsp_fuzz",
    "anopki_core_crl_fuzz",
    "-max_total_time=20",
    "timeout 30s",
    "postgres-integration:",
    'PGPASSWORD=anopki psql -h localhost -U anopki -d anopki_test -Atc "SHOW server_version;"',
    "pkg-config --modversion openssl",
    "acme-harness:",
    "test-run-certbot-smoke.ps1",
    "no live lego or certbot compatibility claim",
]

REQUIRED_GO_RUNNER_TEXT = [
    "MINIMUM_GO_VERSION = (1, 25, 11)",
    '"baseline"',
    '"analysis"',
    '"full"',
    'StepDefinition("go-test"',
    '(go_command, "test", "./...")',
    'StepDefinition("go-vet"',
    '(go_command, "vet", "./...")',
    'StepDefinition("go-race"',
    '(go_command, "test", "-race", "./...")',
    'STATICCHECK_VERSION = "2026.1"',
    'GOSEC_VERSION = "v2.25.0"',
    'GOVULNCHECK_VERSION = "v1.1.4"',
    "honnef.co/go/tools/cmd/staticcheck@",
    "github.com/securego/gosec/v2/cmd/gosec@",
    "golang.org/x/vuln/cmd/govulncheck@",
    "GOTOOLCHAIN",
    "go-verification.json",
    "go-verification.md",
    "resolve_commit",
    "GITHUB_SHA",
]

REQUIRED_RECOVERY_RUNNER_TEXT = [
    "MIGRATION = Path",
    "schema_migrations",
    "certificate_issuance_attempts",
    "crl_publications",
    "webhook_deliveries",
    "private-key-exclusion",
    "recovery-verification.json",
    "recovery-verification.md",
    "resolve_commit",
    "SENSITIVE_FIXTURES",
]

REQUIRED_STATUS_OUTAGE_RUNNER_TEXT = [
    "MINIMUM_GO_VERSION = (1, 25, 11)",
    "community_status_outage_drill",
    "TestPublishCRLOutageRecoversWithoutPhantomPublication",
    "TestRespondOCSPOutageRecoversWithoutSuccessAudit",
    "TestPublishCRLOutageReturnsBadGatewayAndRecovers",
    "TestRespondOCSPOutageReturnsBadGatewayAndRecovers",
    "status-outage-verification.json",
    "status-outage-verification.md",
    "status-outage-test.log",
    "resolve_commit",
    "sensitive-evidence-exclusion",
]

REQUIRED_AUDIT_REPLAY_RUNNER_TEXT = [
    "MINIMUM_GO_VERSION=(1,25,11)",
    "community_audit_replay_drill",
    "TestRepairMissingIssuanceAuditEventsPreservesCurrentEvidenceAndIsIdempotent",
    "TestReplayDeadLetterOutboxMessagesPreservesHistoryAndCompletesAfterRecovery",
    "audit-replay-verification.json",
    "audit-replay-verification.md",
    "audit-replay-test.log",
    "dead-letter-attempt-history-preserved",
    "sensitive-evidence-exclusion",
]

REQUIRED_RELEASE_TEXT = [
    "workflow_dispatch:",
    "tags:",
    "contents: read",
    "contents: write",
    "id-token: write",
    'go-version: "1.25.12"',
    "python scripts/verify-go-release.py",
    "--profile full",
    "anopki-go-verification.tar.gz",
    "python scripts/verify-recovery-drill.py",
    "anopki-recovery-verification.tar.gz",
    "python scripts/verify-status-outage-drill.py",
    "anopki-status-outage-verification.tar.gz",
    "python scripts/verify-audit-replay-drill.py",
    "anopki-audit-replay-verification.tar.gz",
    '--commit "${GITHUB_SHA}"',
    'VERSION="$(cat VERSION)"',
    "go build -ldflags",
    "cmake --build build-release --config Release",
    "anopki-service-v${VERSION}-linux-amd64.tar.gz",
    "anopki-core-v${VERSION}-linux-amd64.tar.gz",
    "./dist/anopki-core backend info > dist/anopki-backend-info.json",
    "python scripts/generate-release-metadata.py",
    "anopki-release-metadata.json",
    "sha256sum dist/*.tar.gz dist/anopki-backend-info.json dist/anopki-release-metadata.json",
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


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_text(path: Path, required: list[str]) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    text = path.read_text(encoding="utf-8")
    missing = [value for value in required if value not in text]
    if missing:
        fail(f"{path} missing:\n" + "\n".join(missing))
    forbidden = [value for value in ("TBD", "TODO") if value in text]
    if forbidden:
        fail(f"{path} contains placeholder text: {', '.join(forbidden)}")
    return text


def markdown_section(text: str, heading: str) -> str:
    start = text.find(heading)
    if start == -1:
        return ""
    rest = text[start + len(heading):]
    next_heading = rest.find("\n## ")
    if next_heading != -1:
        rest = rest[:next_heading]
    return rest


def check_compatibility_matrix(text: str) -> None:
    section = markdown_section(text, "## Compatibility Matrix")
    missing = [area for area in REQUIRED_COMPATIBILITY_ROWS if f"| {area} |" not in section]
    if missing:
        fail("release evidence compatibility matrix missing:\n" + "\n".join(missing))
    drift = []
    for area, snippets in REQUIRED_COMPATIBILITY_ROW_TEXT.items():
        match = re.search(rf"^\|\s*{re.escape(area)}\s*\|(?P<body>.*)\|$", section, flags=re.MULTILINE)
        if not match:
            continue
        row = match.group("body")
        missing_snippets = [snippet for snippet in snippets if snippet not in row]
        if missing_snippets:
            drift.append(f"{area}: " + ", ".join(missing_snippets))
    if drift:
        fail("release evidence compatibility matrix row detail drift:\n" + "\n".join(drift))


def check_compatibility_evidence_template(text: str) -> None:
    missing = [value for value in REQUIRED_COMPATIBILITY_TEMPLATE_TEXT if value not in text]
    if missing:
        fail("release evidence compatibility template missing:\n" + "\n".join(missing))


def check_local_verification_evidence(root: Path, text: str) -> None:
    script = require_text(root / "scripts/verify-local.ps1", [])
    commands = re.findall(r'Display\s*=\s*"([^"]+)"', script)
    evidence_section = markdown_section(text, "## Required Evidence Per Release Candidate")
    normalized_text = evidence_section.replace("\\", "/")
    missing = [command for command in commands if command.replace("\\", "/") not in normalized_text]
    if missing:
        fail("release evidence missing local verification commands:\n" + "\n".join(missing))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=ROOT, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    doc = require_text(root / "docs/reference/release-evidence.md", REQUIRED_DOC_TEXT)
    check_compatibility_matrix(doc)
    check_compatibility_evidence_template(doc)
    check_local_verification_evidence(root, doc)
    require_text(root / "scripts/verify-go-release.py", REQUIRED_GO_RUNNER_TEXT)
    require_text(root / "scripts/verify-recovery-drill.py", REQUIRED_RECOVERY_RUNNER_TEXT)
    require_text(root / "scripts/verify-status-outage-drill.py", REQUIRED_STATUS_OUTAGE_RUNNER_TEXT)
    require_text(root / "scripts/verify-audit-replay-drill.py", REQUIRED_AUDIT_REPLAY_RUNNER_TEXT)
    require_text(root / ".github/workflows/ci.yml", REQUIRED_CI_TEXT)
    require_text(root / ".github/workflows/release.yml", REQUIRED_RELEASE_TEXT)
    print("release evidence ok")


if __name__ == "__main__":
    main()
