#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run the Community audit-chain integrity verification drill."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".tmp" / "audit-chain-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

EXPECTED_TESTS = (
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestApplyInitialMigrationBackfillsAuditHashChain",
    ),
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestAuditChainAppendAndVerifyAcrossStores",
    ),
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestAuditChainTamperingDetected",
    ),
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestAuditChainPruneCheckpointPreservesVerification",
    ),
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestAuditChainRejectsInvalidMetadata",
    ),
    (
        "github.com/anothel/anopki/service/internal/httpapi",
        "TestAuditIntegrityEndpoint",
    ),
)

EXPECTED_CHECKS = (
    "audit-migration-backfill",
    "audit-chain-monotonic-index",
    "audit-chain-canonical-sha256",
    "audit-chain-tamper-detection",
    "audit-retention-checkpoint",
    "audit-tail-state-verification",
    "audit-invalid-metadata-rejected",
    "audit-integrity-endpoint",
    "audit-hash-no-in-place-repair",
    "sensitive-evidence-exclusion",
)

FORBIDDEN_EVIDENCE_TEXT = (
    '"key_ref"',
    '"private_key"',
    '"password"',
    '"credential"',
    '"certificate_pem"',
    '"csr_pem"',
    "-----begin private key-----",
    "-----begin encrypted private key-----",
)


class DrillFailure(RuntimeError):
    """Raised when evidence cannot be created safely."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_go_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match:
        raise DrillFailure("unable to parse Go version")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def resolve_commit(root: Path, explicit: str) -> str:
    if explicit:
        value = explicit.lower()
        if not COMMIT_RE.fullmatch(value):
            raise DrillFailure("commit must be an exact lowercase 40-character SHA")
        return value
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    value = result.stdout.strip().lower()
    if result.returncode == 0 and COMMIT_RE.fullmatch(value):
        return value
    return "unavailable"


def redact(text: str, output_dir: Path) -> str:
    replacements = {
        str(ROOT): "<repo>",
        str(ROOT.resolve()): "<repo>",
        str(Path.home()): "<home>",
        str(output_dir): "<evidence-dir>",
        str(output_dir.resolve()): "<evidence-dir>",
    }
    for original, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(original, replacement)
    return text


def parse_test_events(output: str) -> dict[tuple[str, str], str]:
    observed: dict[tuple[str, str], str] = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        action = event.get("Action")
        package = event.get("Package")
        test = event.get("Test")
        if action in {"pass", "fail", "skip"} and isinstance(package, str) and isinstance(test, str):
            observed[(package, test)] = action
    return observed


def evidence_template(commit: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_audit_hash_chain_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "result": "failed",
        "go_version": "unavailable",
        "test_command": [],
        "tests": [],
        "checks": [],
        "redaction": {
            "private_key_markers_found": False,
            "raw_key_references_in_evidence": False,
            "sensitive_values_in_evidence": False,
        },
        "blocker": "",
    }


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence["completed_at"] = utc_now()
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    lowered = serialized.lower()
    for forbidden in FORBIDDEN_EVIDENCE_TEXT:
        if forbidden in lowered:
            raise DrillFailure("forbidden sensitive content in audit-chain integrity evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit-chain-verification.json").write_text(serialized, encoding="utf-8")
    lines = [
        "# AnoPKI Community Audit Hash-Chain Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Go: `{evidence['go_version']}`",
        "",
        "## Checks",
        "",
    ]
    lines.extend(f"- `{check['name']}`: `{check['status']}`" for check in evidence["checks"])
    if evidence["blocker"]:
        lines.extend(["", "## Blocker", "", f"`{evidence['blocker']}`"])
    (output_dir / "audit-chain-verification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_drill(root: Path, output_dir: Path, go_executable: str, commit: str) -> dict[str, Any]:
    evidence = evidence_template(resolve_commit(root, commit))
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "audit-chain-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "audit-chain-mod")
    Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)

    version_result = subprocess.run(
        [go_executable, "version"],
        cwd=root / "service",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    evidence["go_version"] = redact(version_result.stdout.strip(), output_dir) or "unavailable"
    if version_result.returncode != 0:
        evidence["blocker"] = "unable to execute selected Go toolchain"
        write_evidence(output_dir, evidence)
        return evidence
    try:
        version = parse_go_version(version_result.stdout)
    except DrillFailure as exc:
        evidence["blocker"] = str(exc)
        write_evidence(output_dir, evidence)
        return evidence
    if version < MINIMUM_GO_VERSION:
        evidence["blocker"] = f"unsupported Go version {version[0]}.{version[1]}.{version[2]}; minimum is 1.25.11"
        write_evidence(output_dir, evidence)
        return evidence

    test_regex = "^(" + "|".join(name for _, name in EXPECTED_TESTS) + ")$"
    command = [
        go_executable,
        "test",
        "-json",
        "-count=1",
        "-run",
        test_regex,
        "./internal/store",
        "./internal/httpapi",
    ]
    evidence["test_command"] = [redact(item, output_dir) for item in command]
    test_result = subprocess.run(
        command,
        cwd=root / "service",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit-chain-test.log").write_text(redact(test_result.stdout, output_dir), encoding="utf-8")
    observed = parse_test_events(test_result.stdout)
    evidence["tests"] = [
        {"package": package, "name": name, "status": observed.get((package, name), "missing")}
        for package, name in EXPECTED_TESTS
    ]
    passed = test_result.returncode == 0 and all(item["status"] == "pass" for item in evidence["tests"])
    evidence["checks"] = [
        {"name": name, "status": "passed" if passed else "failed"}
        for name in EXPECTED_CHECKS
    ]
    evidence["result"] = "passed" if passed else "failed"
    evidence["blocker"] = "" if passed else "one or more required audit-chain integrity tests failed or were missing"
    write_evidence(output_dir, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    test_regex = "^(" + "|".join(name for _, name in EXPECTED_TESTS) + ")$"
    command = [
        args.go,
        "test",
        "-json",
        "-count=1",
        "-run",
        test_regex,
        "./internal/store",
        "./internal/httpapi",
    ]
    if args.list:
        print(subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command))
        return 0
    evidence = run_drill(ROOT, args.out_dir.resolve(), args.go, args.commit)
    if evidence["result"] == "passed":
        print(f"audit-chain integrity drill passed: {len(EXPECTED_CHECKS)} checks")
        return 0
    print(evidence["blocker"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
