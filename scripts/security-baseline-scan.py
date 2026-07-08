#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""High-confidence local secret baseline scan.

This is intentionally small. Full SAST/SCA/SBOM remains a tool-selection task.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git",
    ".gocache",
    ".gomodcache",
    ".tmp",
    ".vscode",
    "build",
    "build-ninja",
    "build-verify",
    "build-vs",
}

TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cmake",
    ".cpp",
    ".go",
    ".h",
    ".hpp",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".sql",
    ".txt",
    ".yml",
    ".yaml",
}

PATTERNS = [
    ("private-key-pem", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
]


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    kind: str


def is_scannable(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE", "CMakeLists.txt"}


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return findings
    for index, line in enumerate(lines, start=1):
        if "secret-scan: allow" in line:
            continue
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                findings.append(Finding(path=path, line=index, kind=kind))
    return findings


def scan_root(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and is_scannable(path.relative_to(root)):
            findings.extend(scan_file(path))
    return findings


def main() -> int:
    findings = scan_root(ROOT)
    if findings:
        for finding in findings:
            print(f"{finding.path.relative_to(ROOT)}:{finding.line}: {finding.kind}", file=sys.stderr)
        return 1
    print("secret baseline scan ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
