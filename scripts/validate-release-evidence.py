#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate release evidence decisions and CI hooks."""

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
    "## Required Evidence Per Release Candidate",
    "syft",
    "cosign",
    "govulncheck",
    "go vet ./...",
    "go test -race ./...",
    "staticcheck",
    "gosec",
    "Clang/libFuzzer",
]

REQUIRED_COMPATIBILITY_ROWS = [
    "OS",
    "Go",
    "OpenSSL",
    "SQLite",
    "PostgreSQL",
    "lego",
    "certbot",
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
    "python scripts/test_validate_release_artifacts.py",
    "python scripts/test_validate_release_evidence.py",
    "python scripts/validate-release-evidence.py",
    'go-version: "1.25.11"',
    'go: ["1.25.11", "1.26.x"]',
    'go-version: "1.26.x"',
    "go test -race ./...",
    "go vet ./...",
    "staticcheck@latest",
    "gosec@latest",
    "govulncheck@latest",
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

REQUIRED_RELEASE_TEXT = [
    "workflow_dispatch:",
    "tags:",
    "contents: read",
    "contents: write",
    "id-token: write",
    'go-version: "1.25.11"',
    'VERSION="$(cat VERSION)"',
    "go build -ldflags",
    "cmake --build build-release --config Release",
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
    text = markdown_section(text, "## Compatibility Matrix")
    missing = [
        area
        for area in REQUIRED_COMPATIBILITY_ROWS
        if f"| {area} |" not in text
    ]
    if missing:
        fail("release evidence compatibility matrix missing:\n" + "\n".join(missing))
    drift = []
    for area, snippets in REQUIRED_COMPATIBILITY_ROW_TEXT.items():
        match = re.search(rf"^\|\s*{re.escape(area)}\s*\|(?P<body>.*)\|$", text, flags=re.MULTILINE)
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
    require_text(root / ".github/workflows/ci.yml", REQUIRED_CI_TEXT)
    require_text(root / ".github/workflows/release.yml", REQUIRED_RELEASE_TEXT)
    print("release evidence ok")


if __name__ == "__main__":
    main()
