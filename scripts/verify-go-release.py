#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run Community Go release checks and write redacted local evidence."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "service"
DEFAULT_OUTPUT = ROOT / ".tmp" / "go-release-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
STATICCHECK_VERSION = "2026.1"
GOSEC_VERSION = "v2.25.0"
GOVULNCHECK_VERSION = "v1.1.4"
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SAFE_GO_ENV_FIELDS = ("GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED")
SENSITIVE_ENV_NAME_RE = re.compile(
    r"(?:TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|PRIVATE_KEY|API_KEY)", re.IGNORECASE
)
URL_USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")


@dataclass(frozen=True)
class StepDefinition:
    name: str
    command: tuple[str, ...]
    environment: dict[str, str] | None = None


@dataclass
class StepResult:
    name: str
    command: list[str]
    status: str
    exit_code: int
    duration_seconds: float
    log_file: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_go_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match:
        raise ValueError(f"unable to parse Go version from: {text.strip()!r}")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def version_text(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def command_text(command: Iterable[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(command))
    return shlex.join(command)


def redactor(
    output_dir: Path,
    environment: dict[str, str],
    extra_values: Iterable[str] = (),
) -> Callable[[str], str]:
    replacements = {
        str(ROOT): "<repo>",
        str(ROOT.resolve()): "<repo>",
        str(Path.home()): "<home>",
        str(output_dir): "<evidence-dir>",
        str(output_dir.resolve()): "<evidence-dir>",
    }
    for value in extra_values:
        if value and (os.sep in value or (os.altsep and os.altsep in value)):
            replacements[value] = "<tool>"
            try:
                replacements[str(Path(value).resolve())] = "<tool>"
            except OSError:
                pass
    for name, value in environment.items():
        if SENSITIVE_ENV_NAME_RE.search(name) and len(value) >= 4:
            replacements[value] = "<redacted-env>"

    def redact(text: str) -> str:
        for value, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
            if value:
                text = text.replace(value, replacement)
        return URL_USERINFO_RE.sub(r"\1<redacted-userinfo>@", text)

    return redact


def step_definitions(go_command: str, profile: str, binary_path: Path) -> list[StepDefinition]:
    baseline = [
        StepDefinition("go-test", (go_command, "test", "./...")),
        StepDefinition("go-vet", (go_command, "vet", "./...")),
        StepDefinition(
            "go-build",
            (go_command, "build", "-trimpath", "-o", str(binary_path), "./cmd/anopki-service"),
        ),
    ]
    analysis = [
        StepDefinition("go-race", (go_command, "test", "-race", "./..."), {"CGO_ENABLED": "1"}),
        StepDefinition(
            "staticcheck",
            (go_command, "run", f"honnef.co/go/tools/cmd/staticcheck@{STATICCHECK_VERSION}", "./..."),
        ),
        StepDefinition(
            "gosec",
            (go_command, "run", f"github.com/securego/gosec/v2/cmd/gosec@{GOSEC_VERSION}", "./..."),
        ),
        StepDefinition(
            "govulncheck",
            (go_command, "run", f"golang.org/x/vuln/cmd/govulncheck@{GOVULNCHECK_VERSION}", "./..."),
        ),
    ]
    if profile == "baseline":
        return baseline
    if profile == "analysis":
        return analysis
    return baseline + analysis


def resolve_commit(environment: dict[str, str], explicit: str = "") -> str:
    if explicit:
        return explicit.lower() if COMMIT_RE.fullmatch(explicit) else "invalid"
    for name in ("ANOPKI_COMMIT", "GITHUB_SHA"):
        value = environment.get(name, "").strip()
        if value:
            return value.lower() if COMMIT_RE.fullmatch(value) else "invalid"
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return "unavailable"
    value = result.stdout.strip()
    return value.lower() if result.returncode == 0 and COMMIT_RE.fullmatch(value) else "unavailable"


def run_command(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, payload: dict[str, object]) -> None:
    steps = payload.get("steps", [])
    tool_versions = payload.get("tool_versions", {})
    lines = [
        "# AnoPKI Community Go Verification Evidence",
        "",
        f"- Result: `{payload['result']}`",
        f"- Profile: `{payload['profile']}`",
        f"- Commit: `{payload['commit']}`",
        f"- Go: `{payload.get('go_version', 'unknown')}`",
        f"- Minimum Go: `{payload['minimum_go_version']}`",
        f"- Platform: `{payload['platform']}`",
        f"- Started: `{payload['started_at']}`",
        f"- Completed: `{payload['completed_at']}`",
        "",
        "## Tool Pins",
        "",
    ]
    if isinstance(tool_versions, dict):
        for name in sorted(tool_versions):
            lines.append(f"- {name}: `{tool_versions[name]}`")
    lines.extend(
        [
            "",
            "## Steps",
            "",
            "| Step | Result | Exit | Seconds | Log |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        lines.append(
            "| {name} | {status} | {exit_code} | {duration_seconds:.3f} | `{log_file}` |".format(
                **step
            )
        )
    blocker = payload.get("blocker")
    if blocker:
        lines.extend(["", "## Blocker", "", f"`{blocker}`"])
    lines.extend(
        [
            "",
            "## Evidence Rules",
            "",
            "- This file records local execution only; it does not authorize a release.",
            "- Absolute repository, home, evidence and explicit tool paths are redacted.",
            "- A failed or unavailable command remains failed; it is not converted to a waiver.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_evidence(output_dir: Path, payload: dict[str, object]) -> None:
    payload["completed_at"] = utc_now()
    write_json(output_dir / "go-verification.json", payload)
    write_markdown(output_dir / "go-verification.md", payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("baseline", "analysis", "full"), default="full")
    parser.add_argument("--go", default="go", dest="go_command")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--minimum-go", default=version_text(MINIMUM_GO_VERSION))
    parser.add_argument("--commit", default="", help="exact 40-character Community commit for evidence binding")
    parser.add_argument("--list", action="store_true", help="print the selected commands without running them")
    args = parser.parse_args()

    try:
        minimum = parse_go_version("go" + args.minimum_go)
    except ValueError as exc:
        parser.error(str(exc))

    output_dir = args.out_dir.resolve()
    binary_suffix = ".exe" if os.name == "nt" else ""
    binary_path = output_dir / f"anopki-service{binary_suffix}"
    definitions = step_definitions(args.go_command, args.profile, binary_path)

    if args.list:
        for step in definitions:
            print(command_text(step.command))
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    cache_root = ROOT / ".tmp" / "go-cache"
    build_cache = cache_root / "build"
    module_cache = cache_root / "mod"
    build_cache.mkdir(parents=True, exist_ok=True)
    module_cache.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    environment = os.environ.copy()
    environment.update(
        {
            "GOCACHE": str(build_cache),
            "GOMODCACHE": str(module_cache),
            "GOTOOLCHAIN": "local",
        }
    )
    redact = redactor(output_dir, environment, (args.go_command,))

    payload: dict[str, object] = {
        "schema_version": 1,
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "profile": args.profile,
        "commit": resolve_commit(environment, args.commit),
        "minimum_go_version": version_text(minimum),
        "platform": f"{platform.system().lower()}/{platform.machine().lower()}",
        "started_at": started_at,
        "completed_at": started_at,
        "result": "failed",
        "go_version": "unknown",
        "go_environment": {},
        "tool_versions": {
            "staticcheck": STATICCHECK_VERSION,
            "gosec": GOSEC_VERSION,
            "govulncheck": GOVULNCHECK_VERSION,
        },
        "steps": [],
    }

    if payload["commit"] == "invalid":
        payload["blocker"] = "invalid Community commit; expected 40 hexadecimal characters"
        write_evidence(output_dir, payload)
        print(f"go verification failed: {payload['blocker']}", file=sys.stderr)
        return 1

    try:
        version_result = run_command((args.go_command, "version"), cwd=SERVICE, environment=environment)
    except FileNotFoundError:
        payload["blocker"] = "go executable not found"
        write_evidence(output_dir, payload)
        print("go verification failed: go executable not found", file=sys.stderr)
        return 1

    version_output = redact(version_result.stdout.strip())
    payload["go_version"] = version_output
    if version_result.returncode != 0:
        payload["blocker"] = f"go version failed with exit {version_result.returncode}: {version_output}"
        write_evidence(output_dir, payload)
        print(f"go verification failed: {payload['blocker']}", file=sys.stderr)
        return 1

    try:
        actual_version = parse_go_version(version_output)
    except ValueError as exc:
        payload["blocker"] = str(exc)
        write_evidence(output_dir, payload)
        print(f"go verification failed: {exc}", file=sys.stderr)
        return 1

    if actual_version < minimum:
        payload["blocker"] = (
            f"unsupported Go version {version_text(actual_version)}; minimum is {version_text(minimum)}"
        )
        write_evidence(output_dir, payload)
        print(f"go verification failed: {payload['blocker']}", file=sys.stderr)
        return 1

    env_result = run_command(
        (args.go_command, "env", "-json", *SAFE_GO_ENV_FIELDS),
        cwd=SERVICE,
        environment=environment,
    )
    if env_result.returncode != 0:
        payload["blocker"] = f"go env failed with exit {env_result.returncode}"
        write_evidence(output_dir, payload)
        print(f"go verification failed: {payload['blocker']}", file=sys.stderr)
        return 1
    try:
        go_environment = json.loads(env_result.stdout)
    except json.JSONDecodeError as exc:
        payload["blocker"] = f"go env returned invalid JSON: {exc}"
        write_evidence(output_dir, payload)
        print(f"go verification failed: {payload['blocker']}", file=sys.stderr)
        return 1
    payload["go_environment"] = {
        key: redact(str(value)) for key, value in go_environment.items() if key in SAFE_GO_ENV_FIELDS
    }

    results: list[StepResult] = []
    try:
        for index, step in enumerate(definitions, start=1):
            step_environment = environment.copy()
            if step.environment:
                step_environment.update(step.environment)
            started = time.monotonic()
            result = run_command(step.command, cwd=SERVICE, environment=step_environment)
            duration = time.monotonic() - started
            log_name = f"{index:02d}-{step.name}.log"
            log_path = logs_dir / log_name
            log_path.write_text(redact(result.stdout), encoding="utf-8")
            step_result = StepResult(
                name=step.name,
                command=[redact(part) for part in step.command],
                status="passed" if result.returncode == 0 else "failed",
                exit_code=result.returncode,
                duration_seconds=round(duration, 3),
                log_file=f"logs/{log_name}",
            )
            results.append(step_result)
            payload["steps"] = [asdict(item) for item in results]
            if result.returncode != 0:
                payload["blocker"] = f"{step.name} failed with exit {result.returncode}"
                break
    finally:
        try:
            binary_path.unlink(missing_ok=True)
        except OSError:
            pass

    payload["result"] = "passed" if len(results) == len(definitions) and all(
        item.status == "passed" for item in results
    ) else "failed"
    write_evidence(output_dir, payload)

    if payload["result"] == "passed":
        print(f"Go {args.profile} verification passed; evidence: {output_dir / 'go-verification.json'}")
        return 0
    print(f"Go {args.profile} verification failed: {payload.get('blocker', 'unknown failure')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
