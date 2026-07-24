#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run exact-commit PostgreSQL multi-node failover and traffic-shift evidence."""

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
DEFAULT_OUTPUT = ROOT / ".tmp" / "postgres-multi-node-failover-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE = "github.com/anothel/anopki/service/internal/lifecycle"
LOG_NAME = "postgres-multi-node-failover-test.log"
DSN_ENV = "ANOPKI_POSTGRES_FAILOVER_DSN"

TESTS = (
    "TestPostgresMultiNodeIssuanceFailoverIntegration",
    "TestPostgresMultiNodeCRLFailoverIntegration",
    "TestPostgresMultiNodeOutboxTrafficShiftIntegration",
)

EXPECTED_CHECKS = (
    "independent-postgres-node-connections",
    "issuance-active-lease-not-stolen",
    "issuance-expired-lease-takeover",
    "issuance-stale-writer-cas-rejected",
    "issuance-finalization-idempotent-without-resign",
    "crl-active-lease-not-stolen",
    "crl-expired-lease-takeover",
    "crl-stale-completion-cas-rejected",
    "crl-numbering-contiguous-after-failover",
    "outbox-active-lease-not-stolen",
    "outbox-expired-lease-traffic-shift",
    "outbox-stale-completion-cas-rejected",
    "outbox-exactly-once-handler-and-attempt",
    "sensitive-evidence-exclusion",
)

FORBIDDEN_TEXT = (
    "postgres://",
    "postgresql://",
    "password=",
    "pgpassword",
    "file:local-dev-only",
    '"key_ref"',
    '"private_key"',
    '"credential"',
    "-----begin private key-----",
    "-----begin encrypted private key-----",
)


class DrillFailure(RuntimeError):
    """Raised when PostgreSQL failover evidence cannot be created safely."""


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


def redact(text: str, output_dir: Path, dsn: str) -> str:
    replacements = {
        str(ROOT): "<repo>",
        str(ROOT.resolve()): "<repo>",
        str(Path.home()): "<home>",
        str(output_dir): "<evidence-dir>",
        str(output_dir.resolve()): "<evidence-dir>",
    }
    if dsn:
        replacements[dsn] = "<postgres-dsn>"
    for original, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(original, replacement)
    return text


def sensitivity(texts: tuple[str, ...], dsn: str) -> dict[str, bool]:
    lowered = "\n".join(texts).lower()
    return {
        "postgres_dsn_found": bool(dsn and dsn.lower() in lowered) or "postgres://" in lowered or "postgresql://" in lowered,
        "database_credentials_found": any(value in lowered for value in ("password=", "pgpassword")),
        "raw_key_references_found": "file:local-dev-only" in lowered or '"key_ref"' in lowered,
        "private_key_markers_found": any(value in lowered for value in ("-----begin private key-----", "-----begin encrypted private key-----")),
    }


def parse_test_events(output: str) -> dict[str, str]:
    observed: dict[str, str] = {}
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
        if action in {"pass", "fail", "skip"} and package == PACKAGE and isinstance(test, str):
            observed[test] = action
    return observed


def test_regex() -> str:
    return "^(" + "|".join(re.escape(name) for name in TESTS) + ")$"


def go_command(go_executable: str | list[str], *arguments: str) -> list[str]:
    prefix = [go_executable] if isinstance(go_executable, str) else go_executable
    return [*prefix, *arguments]


def command(go_executable: str | list[str]) -> list[str]:
    return go_command(go_executable, "test", "-json", "-count=1", "-run", test_regex(), "./internal/lifecycle")


def evidence_template(commit: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_postgres_multi_node_failover_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "postgres_required": True,
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "result": "failed",
        "go_version": "unavailable",
        "test_command": [],
        "tests": [],
        "checks": [],
        "redaction": {
            "postgres_dsn_found": False,
            "database_credentials_found": False,
            "raw_key_references_found": False,
            "private_key_markers_found": False,
        },
        "blocker": "",
    }


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence["completed_at"] = utc_now()
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    lowered = serialized.lower()
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in lowered:
            raise DrillFailure("forbidden sensitive content in PostgreSQL multi-node failover evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "postgres-multi-node-failover-verification.json").write_text(serialized, encoding="utf-8")
    lines = [
        "# AnoPKI Community PostgreSQL Multi-Node Failover Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Go: `{evidence['go_version']}`",
        "- PostgreSQL: `required`",
        "",
        "## Checks",
        "",
    ]
    lines.extend(f"- `{check['name']}`: `{check['status']}`" for check in evidence["checks"])
    if evidence["blocker"]:
        lines.extend(["", "## Blocker", "", f"`{evidence['blocker']}`"])
    markdown = "\n".join(lines) + "\n"
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in markdown.lower():
            raise DrillFailure("forbidden sensitive content in PostgreSQL multi-node failover Markdown")
    (output_dir / "postgres-multi-node-failover-verification.md").write_text(markdown, encoding="utf-8")


def run_drill(root: Path, output_dir: Path, go_executable: str | list[str], commit: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_template(resolve_commit(root, commit))
    dsn = os.environ.get(DSN_ENV, "").strip()
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "postgres-multi-node-failover-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "postgres-multi-node-failover-mod")
    Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)

    try:
        if not dsn:
            raise DrillFailure(f"{DSN_ENV} is required")
        if evidence["commit"] == "unavailable":
            raise DrillFailure("exact Community commit is required")

        version_result = subprocess.run(
            go_command(go_executable, "version"),
            cwd=root / "service",
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        evidence["go_version"] = redact(version_result.stdout.strip(), output_dir, dsn) or "unavailable"
        if version_result.returncode != 0:
            raise DrillFailure("Go executable failed")
        if parse_go_version(version_result.stdout) < MINIMUM_GO_VERSION:
            raise DrillFailure("Go 1.25.11 or newer is required")

        args = command(go_executable)
        evidence["test_command"] = [redact(item, output_dir, dsn) for item in args]
        result = subprocess.run(
            args,
            cwd=root / "service",
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=False,
        )
        raw_log = result.stdout
        redacted_log = redact(raw_log, output_dir, dsn)
        observed = parse_test_events(raw_log)
        evidence["tests"] = [
            {"package": PACKAGE, "name": name, "status": observed.get(name, "missing")}
            for name in TESTS
        ]
        evidence["redaction"] = sensitivity((redacted_log,), dsn)
        passed = (
            result.returncode == 0
            and all(test["status"] == "pass" for test in evidence["tests"])
            and not any(evidence["redaction"].values())
        )
        evidence["checks"] = [
            {"name": name, "status": "passed" if passed else "failed"}
            for name in EXPECTED_CHECKS
        ]
        evidence["result"] = "passed" if passed else "failed"
        evidence["blocker"] = "" if passed else "one or more PostgreSQL multi-node failover tests, checks, or redaction rules failed"
        stored_log = redacted_log
        if any(forbidden in redacted_log.lower() for forbidden in FORBIDDEN_TEXT):
            stored_log = "sensitive command output detected and omitted\n"
            evidence["result"] = "failed"
            evidence["blocker"] = "sensitive command output detected"
            for check in evidence["checks"]:
                check["status"] = "failed"
        (output_dir / LOG_NAME).write_text(stored_log, encoding="utf-8")
    except (OSError, subprocess.SubprocessError, DrillFailure) as exc:
        evidence["result"] = "failed"
        evidence["blocker"] = str(exc)
        evidence["checks"] = [{"name": name, "status": "failed"} for name in EXPECTED_CHECKS]
        if not (output_dir / LOG_NAME).exists():
            (output_dir / LOG_NAME).write_text("drill did not execute\n", encoding="utf-8")

    write_evidence(output_dir, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        cmd = command(args.go)
        print(subprocess.list2cmdline(cmd) if os.name == "nt" else shlex.join(cmd))
        return 0
    evidence = run_drill(ROOT, args.out_dir.resolve(), args.go, args.commit)
    if evidence["result"] == "passed":
        print(f"PostgreSQL multi-node failover drill passed: {len(EXPECTED_CHECKS)} checks")
        return 0
    print(f"PostgreSQL multi-node failover drill failed: {evidence['blocker']}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
