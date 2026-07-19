#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run the Community Audit hash-chain integrity verification drill."""

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
DEFAULT_OUTPUT = ROOT / ".tmp" / "audit-integrity-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
POSTGRES_DSN_ENV = "ANOPKI_POSTGRES_TEST_DSN"

BASELINE_TESTS = (
    ("github.com/anothel/anopki/service/internal/store", "TestAuditEventHashIsStable"),
    ("github.com/anothel/anopki/service/internal/store", "TestVerifyAuditEventsDetectsCheckpointAndEventTampering"),
    ("github.com/anothel/anopki/service/internal/store", "TestAuditIntegrityAppendCheckpointAndPruneParity"),
    ("github.com/anothel/anopki/service/internal/store", "TestMemoryAuditTamperFailsClosed"),
    ("github.com/anothel/anopki/service/internal/store", "TestMemoryAuditCheckpointTamperDetected"),
    ("github.com/anothel/anopki/service/internal/store", "TestMemoryAuditCheckpointTamperDetectedAfterFullPrune"),
    ("github.com/anothel/anopki/service/internal/store", "TestSQLiteAuditTamperAndCheckpointTamperFailClosed"),
    ("github.com/anothel/anopki/service/internal/store", "TestAuditHashChainMigrationBackfillsLegacySQLiteRowsBeforeUniqueIndex"),
    ("github.com/anothel/anopki/service/internal/httpapi", "TestGetAuditIntegrity"),
    ("github.com/anothel/anopki/service/internal/httpapi", "TestPruneAuditEventsByRetentionCutoff"),
)

POSTGRES_TEST = (
    "github.com/anothel/anopki/service/internal/store",
    "TestPostgresIntegrationRepositoryParity/audit_integrity_chain",
)

EXPECTED_CHECKS = (
    "canonical-hash-stability",
    "event-and-checkpoint-tamper-detection",
    "memory-sqlite-append-prune-parity",
    "memory-tamper-fail-closed",
    "checkpoint-tamper-detection",
    "full-prune-checkpoint-tamper-detection",
    "sqlite-tamper-fail-closed",
    "legacy-backfill-before-unique-index",
    "integrity-api-reporting",
    "retention-prune-checkpoint",
    "postgres-append-prune-parity",
    "sensitive-evidence-exclusion",
)

FORBIDDEN_EVIDENCE_TEXT = (
    '"key_ref"',
    '"private_key"',
    '"password"',
    '"credential"',
    '"session_token"',
    '"postgres_dsn"',
    "postgres://",
    "postgresql://",
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin ec private key-----",
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
    postgres_dsn = os.environ.get(POSTGRES_DSN_ENV, "").strip()
    if postgres_dsn:
        replacements[postgres_dsn] = "<postgres-dsn>"
    for original, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(original, replacement)
    return text


def evidence_sensitivity(texts: tuple[str, ...]) -> dict[str, bool]:
    lowered = "\n".join(texts).lower()
    private_key_markers = (
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin encrypted private key-----",
    )
    raw_key_markers = ('"key_ref"', "key_ref=")
    database_markers = ("postgres://", "postgresql://")
    sensitive_markers = (
        '"private_key"',
        '"password"',
        '"credential"',
        '"session_token"',
        '"postgres_dsn"',
    )
    return {
        "private_key_markers_found": any(marker in lowered for marker in private_key_markers),
        "raw_key_references_in_evidence": any(marker in lowered for marker in raw_key_markers),
        "database_credentials_in_evidence": any(marker in lowered for marker in database_markers),
        "sensitive_values_in_evidence": any(marker in lowered for marker in sensitive_markers),
    }


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


def baseline_command(go_executable: str) -> list[str]:
    test_regex = "^(" + "|".join(name for _, name in BASELINE_TESTS) + ")$"
    return [
        go_executable,
        "test",
        "-json",
        "-count=1",
        "-run",
        test_regex,
        "./internal/store",
        "./internal/httpapi",
    ]


def postgres_command(go_executable: str) -> list[str]:
    return [
        go_executable,
        "test",
        "-json",
        "-count=1",
        "-run",
        "^TestPostgresIntegrationRepositoryParity$/^audit_integrity_chain$",
        "./internal/store",
    ]


def evidence_template(commit: str, require_postgres: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_audit_integrity_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "result": "failed",
        "go_version": "unavailable",
        "postgres_required": require_postgres,
        "test_commands": {"baseline": [], "postgres": []},
        "tests": [],
        "checks": [],
        "redaction": {
            "private_key_markers_found": False,
            "raw_key_references_in_evidence": False,
            "database_credentials_in_evidence": False,
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
            raise DrillFailure("forbidden sensitive content in Audit integrity evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit-integrity-verification.json").write_text(serialized, encoding="utf-8")
    lines = [
        "# AnoPKI Community Audit Integrity Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Go: `{evidence['go_version']}`",
        f"- PostgreSQL required: `{str(evidence['postgres_required']).lower()}`",
        "",
        "## Checks",
        "",
    ]
    lines.extend(f"- `{check['name']}`: `{check['status']}`" for check in evidence["checks"])
    if evidence["blocker"]:
        lines.extend(["", "## Blocker", "", f"`{evidence['blocker']}`"])
    (output_dir / "audit-integrity-verification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_status(observed: dict[tuple[str, str], str], package: str, name: str) -> str:
    return observed.get((package, name), "missing")


def run_drill(
    root: Path,
    output_dir: Path,
    go_executable: str,
    commit: str,
    require_postgres: bool = False,
) -> dict[str, Any]:
    evidence = evidence_template(resolve_commit(root, commit), require_postgres)
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "audit-integrity-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "audit-integrity-mod")
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

    output_dir.mkdir(parents=True, exist_ok=True)
    baseline = baseline_command(go_executable)
    evidence["test_commands"]["baseline"] = [redact(item, output_dir) for item in baseline]
    baseline_result = subprocess.run(
        baseline,
        cwd=root / "service",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    baseline_log = redact(baseline_result.stdout, output_dir)
    (output_dir / "audit-integrity-baseline-test.log").write_text(baseline_log, encoding="utf-8")
    baseline_observed = parse_test_events(baseline_result.stdout)
    evidence["tests"] = [
        {
            "backend": "memory-sqlite-http",
            "package": package,
            "name": name,
            "status": test_status(baseline_observed, package, name),
        }
        for package, name in BASELINE_TESTS
    ]
    baseline_passed = baseline_result.returncode == 0 and all(
        item["status"] == "pass" for item in evidence["tests"]
    )

    postgres = postgres_command(go_executable)
    evidence["test_commands"]["postgres"] = [redact(item, output_dir) for item in postgres]
    postgres_status = "not_run"
    postgres_log = "PostgreSQL Audit integrity parity not requested for this local run.\n"
    if require_postgres:
        if not environment.get(POSTGRES_DSN_ENV, "").strip():
            postgres_status = "missing"
            postgres_log = f"{POSTGRES_DSN_ENV} is required but was not set.\n"
        else:
            postgres_result = subprocess.run(
                postgres,
                cwd=root / "service",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            postgres_log = postgres_result.stdout
            postgres_observed = parse_test_events(postgres_result.stdout)
            postgres_status = test_status(postgres_observed, *POSTGRES_TEST)
            if postgres_result.returncode != 0 and postgres_status == "pass":
                postgres_status = "fail"
    postgres_log = redact(postgres_log, output_dir)
    (output_dir / "audit-integrity-postgres-test.log").write_text(postgres_log, encoding="utf-8")
    evidence["redaction"] = evidence_sensitivity((baseline_log, postgres_log))
    sensitive_evidence_passed = not any(evidence["redaction"].values())
    evidence["tests"].append(
        {
            "backend": "postgresql",
            "package": POSTGRES_TEST[0],
            "name": POSTGRES_TEST[1],
            "status": postgres_status,
        }
    )

    expected_baseline = {name: test_status(baseline_observed, package, name) for package, name in BASELINE_TESTS}
    check_statuses = {
        "canonical-hash-stability": expected_baseline["TestAuditEventHashIsStable"],
        "event-and-checkpoint-tamper-detection": expected_baseline["TestVerifyAuditEventsDetectsCheckpointAndEventTampering"],
        "memory-sqlite-append-prune-parity": expected_baseline["TestAuditIntegrityAppendCheckpointAndPruneParity"],
        "memory-tamper-fail-closed": expected_baseline["TestMemoryAuditTamperFailsClosed"],
        "checkpoint-tamper-detection": expected_baseline["TestMemoryAuditCheckpointTamperDetected"],
        "full-prune-checkpoint-tamper-detection": expected_baseline["TestMemoryAuditCheckpointTamperDetectedAfterFullPrune"],
        "sqlite-tamper-fail-closed": expected_baseline["TestSQLiteAuditTamperAndCheckpointTamperFailClosed"],
        "legacy-backfill-before-unique-index": expected_baseline["TestAuditHashChainMigrationBackfillsLegacySQLiteRowsBeforeUniqueIndex"],
        "integrity-api-reporting": expected_baseline["TestGetAuditIntegrity"],
        "retention-prune-checkpoint": expected_baseline["TestPruneAuditEventsByRetentionCutoff"],
        "postgres-append-prune-parity": postgres_status,
        "sensitive-evidence-exclusion": "pass" if sensitive_evidence_passed else "fail",
    }
    evidence["checks"] = [
        {
            "name": name,
            "status": (
                "passed"
                if check_statuses[name] == "pass"
                else "not_run"
                if check_statuses[name] == "not_run"
                else "failed"
            ),
        }
        for name in EXPECTED_CHECKS
    ]

    postgres_passed = postgres_status == "pass" if require_postgres else postgres_status == "not_run"
    passed = baseline_passed and postgres_passed and sensitive_evidence_passed
    evidence["result"] = "passed" if passed else "failed"
    if not baseline_passed:
        evidence["blocker"] = "one or more required Memory/SQLite/API Audit integrity tests failed or were missing"
    elif require_postgres and postgres_status != "pass":
        evidence["blocker"] = "required PostgreSQL Audit integrity parity test failed or was missing"
    elif not sensitive_evidence_passed:
        evidence["blocker"] = "generated Audit integrity evidence contained prohibited sensitive content"
    else:
        evidence["blocker"] = ""
    write_evidence(output_dir, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--require-postgres", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        formatter = subprocess.list2cmdline if os.name == "nt" else shlex.join
        print(formatter(baseline_command(args.go)))
        print(formatter(postgres_command(args.go)))
        return 0
    evidence = run_drill(
        ROOT,
        args.out_dir.resolve(),
        args.go,
        args.commit,
        require_postgres=args.require_postgres,
    )
    if evidence["result"] == "passed":
        passed_checks = sum(check["status"] == "passed" for check in evidence["checks"])
        print(f"Audit integrity drill passed: {passed_checks} checks")
        return 0
    print(evidence["blocker"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
