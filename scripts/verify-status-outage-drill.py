#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run the Community CRL/OCSP outage-and-recovery verification drill."""

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
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".tmp" / "status-outage-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PRIVATE_KEY_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "-----BEGIN " + "RSA PRIVATE KEY-----",
    "-----BEGIN " + "EC PRIVATE KEY-----",
    "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
)
EXPECTED_TESTS = (
    ("github.com/anothel/anopki/service/internal/lifecycle", "TestPublishCRLOutageRecoversWithoutPhantomPublication"),
    ("github.com/anothel/anopki/service/internal/lifecycle", "TestRespondOCSPOutageRecoversWithoutSuccessAudit"),
    ("github.com/anothel/anopki/service/internal/httpapi", "TestPublishCRLOutageReturnsBadGatewayAndRecovers"),
    ("github.com/anothel/anopki/service/internal/httpapi", "TestRespondOCSPOutageReturnsBadGatewayAndRecovers"),
)
EXPECTED_CHECKS = (
    "crl-failure-maps-bad-gateway",
    "crl-no-phantom-publication",
    "crl-recovery-preserves-numbering",
    "ocsp-failure-maps-bad-gateway",
    "ocsp-no-success-audit-on-failure",
    "ocsp-recovery-writes-one-success-audit",
    "provider-evidence-required-after-recovery",
    "sensitive-evidence-exclusion",
)


class DrillFailure(RuntimeError):
    """Fail-closed status outage drill error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_go_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match:
        raise DrillFailure(f"unable to parse Go version from: {text.strip()!r}")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def command_text(command: Iterable[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(command))
    return shlex.join(command)


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
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and COMMIT_RE.fullmatch(value) else "unavailable"


def redact(text: str, output_dir: Path) -> str:
    replacements = {
        str(ROOT): "<repo>",
        str(ROOT.resolve()): "<repo>",
        str(Path.home()): "<home>",
        str(output_dir): "<evidence-dir>",
        str(output_dir.resolve()): "<evidence-dir>",
    }
    for source, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if source:
            text = text.replace(source, replacement)
    return text


def run_command(command: list[str], *, cwd: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def parse_test_events(output: str) -> dict[tuple[str, str], str]:
    observed: dict[tuple[str, str], str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        package = event.get("Package")
        test = event.get("Test")
        action = event.get("Action")
        if isinstance(package, str) and isinstance(test, str) and action in {"pass", "fail", "skip"}:
            observed[(package, test)] = str(action)
    return observed


def evidence_template(commit: str, started_at: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_status_outage_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "started_at": started_at,
        "completed_at": started_at,
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


def write_markdown(path: Path, evidence: dict[str, Any]) -> None:
    lines = [
        "# AnoPKI Community Status Outage Drill Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Go: `{evidence['go_version']}`",
        f"- Minimum Go: `{evidence['minimum_go_version']}`",
        f"- Started: `{evidence['started_at']}`",
        f"- Completed: `{evidence['completed_at']}`",
        "",
        "## Tests",
        "",
        "| Package | Test | Result |",
        "| --- | --- | --- |",
    ]
    for test in evidence["tests"]:
        lines.append(f"| `{test['package']}` | `{test['name']}` | `{test['status']}` |")
    lines.extend(["", "## Checks", ""])
    for check in evidence["checks"]:
        lines.append(f"- `{check['name']}`: `{check['status']}`")
    if evidence["blocker"]:
        lines.extend(["", "## Blocker", "", f"`{evidence['blocker']}`"])
    lines.extend(
        [
            "",
            "## Evidence Rules",
            "",
            "- CRL and OCSP failures must not create success artifacts or success audits.",
            "- Recovery must use the same selected provider contract and completed signing evidence.",
            "- Raw key references, key material, credentials and fixture secrets are excluded.",
            "- Local evidence does not authorize publication.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence["completed_at"] = utc_now()
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    lower = serialized.lower()
    if any(marker.lower() in lower for marker in PRIVATE_KEY_MARKERS):
        raise DrillFailure("private-key material found in outage evidence")
    if any(forbidden in lower for forbidden in ('"key_ref"', '"private_key"', '"password"', '"credential"', '"session_token"')):
        raise DrillFailure("forbidden sensitive field found in outage evidence")
    (output_dir / "status-outage-verification.json").write_text(serialized, encoding="utf-8")
    write_markdown(output_dir / "status-outage-verification.md", evidence)


def run_drill(root: Path, output_dir: Path, go_command: str, commit: str) -> dict[str, Any]:
    started = utc_now()
    evidence = evidence_template(resolve_commit(root, commit), started)
    output_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "status-outage-build")
    environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "status-outage-mod")
    Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
    Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)

    service_dir = root / "service"
    version_result = run_command([go_command, "version"], cwd=service_dir, environment=environment)
    version_output = redact(version_result.stdout.strip(), output_dir)
    evidence["go_version"] = version_output or "unavailable"
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
        evidence["blocker"] = (
            f"unsupported Go version {version[0]}.{version[1]}.{version[2]}; minimum is 1.25.11"
        )
        write_evidence(output_dir, evidence)
        return evidence

    regex = "^(" + "|".join(test for _, test in EXPECTED_TESTS) + ")$"
    command = [go_command, "test", "-json", "-count=1", "-run", regex, "./internal/lifecycle", "./internal/httpapi"]
    evidence["test_command"] = [redact(item, output_dir) for item in command]
    result = run_command(command, cwd=service_dir, environment=environment)
    redacted_log = redact(result.stdout, output_dir)
    (output_dir / "status-outage-test.log").write_text(redacted_log, encoding="utf-8")
    observed = parse_test_events(result.stdout)
    evidence["tests"] = [
        {"package": package, "name": name, "status": observed.get((package, name), "missing")}
        for package, name in EXPECTED_TESTS
    ]
    all_passed = result.returncode == 0 and all(test["status"] == "pass" for test in evidence["tests"])
    evidence["checks"] = [
        {"name": name, "status": "passed" if all_passed else "failed"}
        for name in EXPECTED_CHECKS
    ]
    if all_passed:
        evidence["result"] = "passed"
    else:
        evidence["blocker"] = "one or more required CRL/OCSP outage tests failed or were missing"
    write_evidence(output_dir, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", dest="go_command")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    regex = "^(" + "|".join(test for _, test in EXPECTED_TESTS) + ")$"
    command = [args.go_command, "test", "-json", "-count=1", "-run", regex, "./internal/lifecycle", "./internal/httpapi"]
    if args.list:
        print(command_text(command))
        return 0
    evidence = run_drill(ROOT, args.out_dir.resolve(), args.go_command, args.commit)
    if evidence["result"] == "passed":
        print(f"status outage drill passed: {len(EXPECTED_CHECKS)} checks")
        return 0
    print(str(evidence["blocker"]), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
