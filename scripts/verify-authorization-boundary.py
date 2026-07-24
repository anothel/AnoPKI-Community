#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run exact-commit Community generic authorization boundary evidence."""

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
DEFAULT_OUTPUT = ROOT / ".tmp" / "authorization-boundary-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE = "github.com/anothel/anopki/service/internal/httpapi"
BASELINE_LOG_NAME = "authorization-boundary-baseline.log"
RACE_LOG_NAME = "authorization-boundary-race.log"

TESTS = (
    "TestRequestAuthorizerRunsAfterAuthenticationAndScopeAndSkipsPublicRoutes",
    "TestRequestAuthorizerReceivesMinimalAuditContextWithoutSecrets",
    "TestRequestAuthorizerOutcomesFailClosed",
    "TestRequestAuthorizerReceivesCanceledContext",
    "TestRequestAuthorizerConcurrentDecisionsDoNotLeak",
    "TestRequestAuthorizationRouteFixture",
    "TestRequiredScopeCompatibilityFixture",
    "TestRequestAuthorizerDefaultTimeout",
    "TestRequestAuthorizerTimeoutIsCapped",
    "TestRequestAuthorizerTimeoutFailsClosed",
    "TestRequestAuthorizerRunsAfterLegacyScopeAndSkipsPublicRoutes",
    "TestRequestAuthorizerInputExcludesRequestSecrets",
    "TestDebugVarsRequiresOperatorScope",
    "TestRequiredScopeHardeningFixture",
    "TestAuthorizationAuditMetadataClassification",
    "TestRequestAuthorizerAllowDecisionCorrelatesLifecycleAudit",
    "TestRequestAuthorizerDenyDecisionCorrelatesFailureAudit",
    "TestRequestAuthorizerTimeoutAuditDoesNotExposeEvaluatorError",
    "TestRequestAuthorizerInvalidReferencesAreOmitted",
    "TestRequestsWithoutAuthorizerDoNotClaimAuthorizationEvidence",
)

EXPECTED_CHECKS = (
    "authentication-before-authorizer",
    "legacy-scope-before-authorizer",
    "public-route-authorizer-exclusion",
    "canonical-route-and-request-secret-exclusion",
    "fail-closed-outcome-matrix",
    "bounded-timeout-and-context-cancellation",
    "concurrent-decision-isolation",
    "route-classification-and-debug-operator-scope",
    "allow-decision-audit-correlation",
    "deny-decision-failure-audit-correlation",
    "timeout-error-redaction",
    "invalid-reference-omission",
    "absent-authorizer-no-evidence-claim",
    "focused-race-clean",
    "sensitive-evidence-exclusion",
)

FORBIDDEN_TEXT = (
    "raw-api-key-secret",
    "raw-token-secret",
    "cookie-secret",
    "body-secret",
    "query-secret",
    "path-secret",
    "authorization: bearer",
    "-----begin private key-----",
    "-----begin encrypted private key-----",
    '"password"',
    '"credential"',
    '"session_token"',
    '"request_body"',
    '"query_string"',
    '"raw_evaluator_error"',
)


class DrillFailure(RuntimeError):
    """Raised when authorization evidence cannot be created safely."""


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


def sensitivity(texts: tuple[str, ...]) -> dict[str, bool]:
    lowered = "\n".join(texts).lower()
    return {
        "credential_markers_found": any(value in lowered for value in ("authorization: bearer", '"password"', '"credential"', '"session_token"')),
        "request_payload_values_found": any(value in lowered for value in ("raw-api-key-secret", "raw-token-secret", "cookie-secret", "body-secret", "query-secret", "path-secret")),
        "raw_evaluator_errors_found": "raw_evaluator_error" in lowered or "evaluator-internal-secret" in lowered,
        "sensitive_values_in_evidence": any(value in lowered for value in ("-----begin private key-----", "-----begin encrypted private key-----")),
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


def command(go_executable: str | list[str], *, race: bool) -> list[str]:
    args = ["test"]
    if race:
        args.append("-race")
    args.extend(["-json", "-count=1", "-run", test_regex(), "./internal/httpapi"])
    return go_command(go_executable, *args)


def evidence_template(commit: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_authorization_boundary_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "result": "failed",
        "go_version": "unavailable",
        "test_commands": {"baseline": [], "race": []},
        "tests": [],
        "checks": [],
        "redaction": {
            "credential_markers_found": False,
            "request_payload_values_found": False,
            "raw_evaluator_errors_found": False,
            "sensitive_values_in_evidence": False,
        },
        "blocker": "",
    }


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence["completed_at"] = utc_now()
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    lowered = serialized.lower()
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in lowered:
            raise DrillFailure("forbidden sensitive content in authorization evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "authorization-boundary-verification.json").write_text(serialized, encoding="utf-8")
    lines = [
        "# AnoPKI Community Authorization Boundary Evidence",
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
    (output_dir / "authorization-boundary-verification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_phase(root: Path, output_dir: Path, environment: dict[str, str], go_executable: str | list[str], phase: str, race: bool) -> tuple[subprocess.CompletedProcess[str], str, dict[str, str]]:
    args = command(go_executable, race=race)
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
    log = redact(result.stdout, output_dir)
    log_name = RACE_LOG_NAME if race else BASELINE_LOG_NAME
    stored_log = log
    lowered_log = log.lower()
    if any(forbidden in lowered_log for forbidden in FORBIDDEN_TEXT):
        stored_log = "sensitive command output detected and omitted\n"
    (output_dir / log_name).write_text(stored_log, encoding="utf-8")
    return result, log, parse_test_events(result.stdout)


def run_drill(root: Path, output_dir: Path, go_executable: str | list[str], commit: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_template(resolve_commit(root, commit))
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "authorization-boundary-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "authorization-boundary-mod")
    Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)

    try:
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
        evidence["go_version"] = redact(version_result.stdout.strip(), output_dir)
        if version_result.returncode != 0:
            raise DrillFailure("Go executable failed")
        if parse_go_version(version_result.stdout) < MINIMUM_GO_VERSION:
            raise DrillFailure("Go 1.25.11 or newer is required")
        if evidence["commit"] == "unavailable":
            raise DrillFailure("exact Community commit is required")

        logs: list[str] = []
        phases: list[tuple[str, bool]] = [("baseline", False), ("race", True)]
        all_passed = True
        for phase, race in phases:
            args = command(go_executable, race=race)
            evidence["test_commands"][phase] = command("go", race=race)
            result, log, observed = run_phase(root, output_dir, environment, go_executable, phase, race)
            logs.append(log)
            for name in TESTS:
                status = observed.get(name, "missing")
                evidence["tests"].append({"phase": phase, "package": PACKAGE, "name": name, "status": status})
                if status != "pass":
                    all_passed = False
            if result.returncode != 0:
                all_passed = False

        redaction = sensitivity(tuple(logs))
        evidence["redaction"] = redaction
        sensitive = any(redaction.values())
        check_status = "passed" if all_passed else "failed"
        evidence["checks"] = [{"name": name, "status": check_status} for name in EXPECTED_CHECKS[:-2]]
        evidence["checks"].append({"name": "focused-race-clean", "status": "passed" if all(test["status"] == "pass" for test in evidence["tests"] if test["phase"] == "race") else "failed"})
        evidence["checks"].append({"name": "sensitive-evidence-exclusion", "status": "failed" if sensitive else "passed"})
        evidence["result"] = "passed" if all(check["status"] == "passed" for check in evidence["checks"]) else "failed"
        if evidence["result"] != "passed":
            evidence["blocker"] = "focused authorization boundary evidence did not pass"
    except (DrillFailure, OSError, subprocess.SubprocessError) as exc:
        evidence["blocker"] = str(exc)
        evidence["result"] = "failed"
        if not evidence["checks"]:
            evidence["checks"] = [{"name": name, "status": "failed"} for name in EXPECTED_CHECKS]
    write_evidence(output_dir, evidence)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--go", default="go")
    parser.add_argument("--commit", default="")
    args = parser.parse_args()
    evidence = run_drill(args.root.resolve(), args.out_dir.resolve(), args.go, args.commit)
    if evidence["result"] != "passed":
        print(f"authorization boundary drill failed: {evidence['blocker']}", file=sys.stderr)
        raise SystemExit(1)
    print(f"authorization boundary drill passed: {len(EXPECTED_CHECKS)} checks")


if __name__ == "__main__":
    main()
