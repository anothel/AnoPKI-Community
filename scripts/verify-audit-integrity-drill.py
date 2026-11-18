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


def go_arguments(go_executable: str | list[str], *arguments: str) -> list[str]:
    prefix = [go_executable] if isinstance(go_executable, str) else go_executable
    return [*prefix, *arguments]


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
        "sensitive_values_in_evidence": any(marker in lowered for marker in sensitive_markers) or bool(re.search(r"(?i)(password|credential|token|secret|authorization|dsn|private[_ -]?key)\s*[=:]", lowered)),
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


def baseline_command(go_executable: str | list[str]) -> list[str]:
    test_regex = "^(" + "|".join(name for _, name in BASELINE_TESTS) + ")$"
    return go_arguments(
        go_executable,
        "test",
        "-json",
        "-count=1",
        "-run",
        test_regex,
        "./internal/store",
        "./internal/httpapi",
    )


def postgres_command(go_executable: str | list[str]) -> list[str]:
    return go_arguments(
        go_executable,
        "test",
        "-json",
        "-count=1",
        "-run",
        "^TestPostgresIntegrationRepositoryParity$/^audit_integrity_chain$",
        "./internal/store",
    )


def evidence_template(commit: str, require_postgres: bool) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "stages": {},
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
    go_executable: str | list[str],
    commit: str,
    require_postgres: bool = False,
) -> dict[str, Any]:
    # Never persist arbitrary subprocess text, command prefixes or exceptions.
    evidence = evidence_template(resolve_commit(root, commit), require_postgres)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("audit-integrity-baseline-test.log", "audit-integrity-postgres-test.log"):
        (output_dir / name).unlink(missing_ok=True)
    evidence["blocker"] = "execution incomplete"
    write_evidence(output_dir, evidence)
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "audit-integrity-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "audit-integrity-mod")

    def execute(stage: str, command: list[str], expected: tuple = ()) -> tuple[str, dict]:
        record = {"status": "running", "exit_code": None, "packages": []}
        evidence["stages"][stage] = record
        write_evidence(output_dir, evidence)
        try:
            Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
            Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                command, cwd=root / "service", env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            record["status"] = "setup_error"
            write_evidence(output_dir, evidence)
            return "", {}
        record["exit_code"] = result.returncode
        # A deny check is defense in depth; publication uses a strict projection.
        flags = evidence_sensitivity((redact(result.stdout, output_dir),))
        flags["sensitive_values_in_evidence"] |= any(flags.values())
        for key, value in flags.items():
            evidence["redaction"][key] |= value
        observed = parse_test_events(result.stdout)
        packages = sorted({package for package, _ in expected})
        terminal = {}
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(event, dict) and event.get("Package") in packages and not event.get("Test"):
                if event.get("Action") in ("pass", "fail", "skip"):
                    terminal[event["Package"]] = event["Action"]
        record["packages"] = [{"package": package, "status": terminal.get(package, "incomplete")} for package in packages]
        statuses = [test_status(observed, *test) for test in expected]
        record["status"] = (
            "nonzero_exit" if result.returncode != 0 and "fail" not in statuses
            else "failed" if "fail" in statuses or "fail" in terminal.values()
            else "missing" if "missing" in statuses
            else "incomplete" if any(package not in terminal for package in packages)
            else "failed" if any(status != "pass" for status in statuses + list(terminal.values()))
            else "passed"
        )
        write_evidence(output_dir, evidence)
        return result.stdout, observed

    version_output, _ = execute("toolchain", go_arguments(go_executable, "version"))
    try:
        version = parse_go_version(version_output)
    except DrillFailure:
        evidence["blocker"] = "unable to parse or execute selected Go toolchain"
        write_evidence(output_dir, evidence)
        return evidence
    evidence["go_version"] = "go version go" + ".".join(map(str, version))
    if evidence["stages"]["toolchain"]["status"] != "passed" or version < MINIMUM_GO_VERSION:
        evidence["blocker"] = "unsupported or failed Go toolchain"
        write_evidence(output_dir, evidence)
        return evidence

    evidence["test_commands"] = {"baseline": baseline_command("go"), "postgres": postgres_command("go")}
    _, baseline_observed = execute("baseline", baseline_command(go_executable), BASELINE_TESTS)
    evidence["tests"] = [
        {"backend": "memory-sqlite-http", "package": package, "name": name,
         "status": test_status(baseline_observed, package, name)}
        for package, name in BASELINE_TESTS
    ]
    baseline_passed = evidence["stages"]["baseline"]["status"] == "passed"
    postgres_status = "not_run"
    if require_postgres:
        if not environment.get(POSTGRES_DSN_ENV, "").strip():
            postgres_status = "missing"
            evidence["stages"]["postgres"] = {"status": "missing_dsn", "exit_code": None, "packages": []}
        else:
            _, observed = execute("postgres", postgres_command(go_executable), (POSTGRES_TEST,))
            postgres_status = test_status(observed, *POSTGRES_TEST)
            if evidence["stages"]["postgres"]["status"] != "passed" and postgres_status == "pass":
                postgres_status = "fail"
    sensitive_evidence_passed = not any(evidence["redaction"].values())
    evidence["tests"].append(
        {"backend": "postgresql", "package": POSTGRES_TEST[0], "name": POSTGRES_TEST[1], "status": postgres_status}
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


def validate_evidence(output_dir: Path) -> None:
    """Fail closed: only the runner's bounded structured vocabulary may upload."""
    report = output_dir / "audit-integrity-verification.json"
    try:
        evidence = json.loads(report.read_text(encoding="utf-8"))
        allowed = set()
        template = evidence_template("unavailable", False)
        if not isinstance(evidence, dict) or set(evidence) != set(template):
            raise ValueError()
        for key, value in evidence.items():
            if type(value) is not type(template[key]):
                raise ValueError()
        statuses = {"pass", "fail", "skip", "missing", "not_run"}
        expected_tests = [
            {"backend": "memory-sqlite-http", "package": package, "name": name}
            for package, name in BASELINE_TESTS
        ] + [{"backend": "postgresql", "package": POSTGRES_TEST[0], "name": POSTGRES_TEST[1]}]
        if len(evidence["tests"]) not in (0, len(BASELINE_TESTS), len(expected_tests)):
            raise ValueError()
        for test, expected in zip(evidence["tests"], expected_tests):
            if not isinstance(test, dict) or set(test) != {*expected, "status"}:
                raise ValueError()
            if any(test[k] != v for k, v in expected.items()) or test["status"] not in statuses:
                raise ValueError()
        if evidence["checks"] and (
            len(evidence["checks"]) != len(EXPECTED_CHECKS) or any(
                set(check) != {"name", "status"} or check["name"] != name
                or check["status"] not in {"passed", "failed", "not_run"}
                for check, name in zip(evidence["checks"], EXPECTED_CHECKS)
            )
        ):
            raise ValueError()
        if set(evidence["redaction"]) != set(template["redaction"]) or any(
            type(v) is not bool for v in evidence["redaction"].values()
        ):
            raise ValueError()
        if evidence["test_commands"] not in (
            template["test_commands"], {"baseline": baseline_command("go"), "postgres": postgres_command("go")}
        ):
            raise ValueError()
        if set(evidence["stages"]) - {"toolchain", "baseline", "postgres"}:
            raise ValueError()
        for stage, record in evidence["stages"].items():
            if not isinstance(record, dict) or set(record) != {"status", "exit_code", "packages"}:
                raise ValueError()
            if record["status"] not in {"running", "passed", "failed", "missing", "incomplete", "setup_error", "nonzero_exit", "missing_dsn"}:
                raise ValueError()
            code = record["exit_code"]
            if code is not None and (type(code) is not int or not -255 <= code <= 255):
                raise ValueError()
            packages = sorted({p for p, _ in (BASELINE_TESTS if stage == "baseline" else (POSTGRES_TEST,) if stage == "postgres" else ())})
            if not isinstance(record["packages"], list) or len(record["packages"]) not in (0, len(packages)):
                raise ValueError()
            for item, package in zip(record["packages"], packages):
                if not isinstance(item, dict) or set(item) != {"package", "status"} or item["package"] != package or item["status"] not in {"pass", "fail", "skip", "incomplete"}:
                    raise ValueError()
        def strings(value: Any) -> set[str]:
            if isinstance(value, str):
                return {value}
            if isinstance(value, dict):
                return set(value) | set().union(*(strings(v) for v in value.values()), set())
            if isinstance(value, list):
                return set().union(*(strings(v) for v in value), set())
            return set()
        allowed |= strings(template)
        allowed |= set(EXPECTED_CHECKS)
        allowed |= {value for test in (*BASELINE_TESTS, POSTGRES_TEST) for value in test}
        allowed |= set(baseline_command("go") + postgres_command("go"))
        allowed |= {
            "toolchain", "baseline", "postgres", "status", "exit_code", "packages",
            "package", "backend", "name", "memory-sqlite-http", "postgresql",
            "pass", "fail", "skip", "missing", "not_run", "passed", "failed",
            "running", "setup_error", "nonzero_exit", "incomplete", "missing_dsn",
            "execution incomplete", "unable to parse or execute selected Go toolchain",
            "unsupported or failed Go toolchain",
            "one or more required Memory/SQLite/API Audit integrity tests failed or were missing",
            "required PostgreSQL Audit integrity parity test failed or was missing",
            "generated Audit integrity evidence contained prohibited sensitive content",
        }
        allowed |= {evidence["commit"], evidence["started_at"], evidence["completed_at"], evidence["go_version"]}
        if evidence["commit"] != "unavailable" and not COMMIT_RE.fullmatch(evidence["commit"]):
            raise ValueError()
        for key in ("started_at", "completed_at"):
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", evidence[key]):
                raise ValueError()
        if evidence["go_version"] != "unavailable" and not re.fullmatch(r"go version go\d+\.\d+\.\d+", evidence["go_version"]):
            raise ValueError()
        if strings(evidence) - allowed or evidence["schema_version"] != 2:
            raise ValueError()
        if any(evidence_sensitivity((report.read_text(),)).values()):
            raise ValueError()
        # Recreate Markdown from validated JSON; never trust existing Markdown.
        write_evidence(output_dir, evidence)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise DrillFailure("unsafe or invalid Audit integrity evidence") from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--require-postgres", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--validate-evidence", action="store_true")
    args = parser.parse_args()
    if args.validate_evidence:
        validate_evidence(args.out_dir.resolve())
        return 0
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
