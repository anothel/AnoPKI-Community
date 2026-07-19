#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Self-checks for the Community Go release evidence runner."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-go-release.py"

FAKE_GO = r'''#!/usr/bin/env python3
import importlib.util
import json
import os
import pathlib
import sys

args = sys.argv[1:]
version = os.environ.get("FAKE_GO_VERSION", "go1.25.12")
if args == ["version"]:
    print(f"go version {version} linux/amd64")
    raise SystemExit(0)
if len(args) >= 2 and args[0] == "env" and args[1] == "-json":
    print(json.dumps({
        "GOVERSION": version,
        "GOOS": "linux",
        "GOARCH": "amd64",
        "CGO_ENABLED": os.environ.get("CGO_ENABLED", "1"),
        "GOPROXY": "https://user:password@proxy.invalid",
        "GOSUMDB": "sum.golang.org",
    }))
    raise SystemExit(0)
name = " ".join(args)
fail = os.environ.get("FAKE_GO_FAIL", "")
print(f"fake go: {name}")
if os.environ.get("ANOPKI_TEST_SECRET"):
    print(os.environ["ANOPKI_TEST_SECRET"])
if args and args[0] == "build" and "-o" in args:
    output = pathlib.Path(args[args.index("-o") + 1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("fake binary", encoding="utf-8")
if fail and fail in name:
    print("requested failure")
    raise SystemExit(9)
raise SystemExit(0)
'''


def make_fake_go(root: Path) -> Path:
    script = root / "fake-go.py"
    script.write_text(FAKE_GO, encoding="utf-8")
    if os.name == "nt":
        launcher = root / "fake-go.cmd"
        launcher.write_text(
            f'@"{sys.executable}" "%~dp0fake-go.py" %*\n', encoding="utf-8"
        )
        return launcher
    script.chmod(0o755)
    return script


def run(profile: str, *, version: str = "go1.25.12", fail: str = ""):
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    fake_go = make_fake_go(root)
    output = root / "evidence"
    env = os.environ.copy()
    env["FAKE_GO_VERSION"] = version
    env["ANOPKI_COMMIT"] = "0123456789abcdef0123456789abcdef01234567"
    env["ANOPKI_TEST_SECRET"] = "super-secret-value"
    if fail:
        env["FAKE_GO_FAIL"] = fail
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--profile",
            profile,
            "--go",
            str(fake_go),
            "--out-dir",
            str(output),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads((output / "go-verification.json").read_text(encoding="utf-8"))
    return temp, result, payload, output, fake_go


def test_full_profile_passes() -> None:
    temp, result, payload, output, fake_go = run("full")
    try:
        assert result.returncode == 0, result.stderr or result.stdout
        assert payload["result"] == "passed"
        assert payload["product_profile"] == "community-openssl"
        assert payload["commit"] == "0123456789abcdef0123456789abcdef01234567"
        assert payload["minimum_go_version"] == "1.25.11"
        assert payload["tool_versions"] == {
            "staticcheck": "2026.1",
            "gosec": "v2.25.0",
            "govulncheck": "v1.1.4",
        }
        assert [step["name"] for step in payload["steps"]] == [
            "go-test",
            "go-vet",
            "go-build",
            "go-race",
            "staticcheck",
            "gosec",
            "govulncheck",
        ]
        assert not (output / "anopki-service").exists()
        serialized = json.dumps(payload)
        assert str(ROOT) not in serialized
        assert str(fake_go) not in serialized
        assert "super-secret-value" not in serialized
        assert set(payload["go_environment"]) == {"GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"}
        logs = "".join(path.read_text(encoding="utf-8") for path in (output / "logs").glob("*.log"))
        assert "super-secret-value" not in logs
        assert "<redacted-env>" in logs
        assert str(fake_go) not in logs
        assert "password@proxy.invalid" not in serialized
    finally:
        temp.cleanup()


def test_minimum_go_passes() -> None:
    temp, result, payload, _, _ = run("baseline", version="go1.25.11")
    try:
        assert result.returncode == 0, result.stderr or result.stdout
        assert payload["result"] == "passed"
    finally:
        temp.cleanup()


def test_old_go_fails_closed() -> None:
    temp, result, payload, _, _ = run("baseline", version="go1.25.10")
    try:
        assert result.returncode == 1
        assert payload["result"] == "failed"
        assert payload["steps"] == []
        assert "unsupported Go version" in payload["blocker"]
        assert payload["commit"] == "0123456789abcdef0123456789abcdef01234567"
    finally:
        temp.cleanup()


def test_step_failure_is_recorded_and_stops() -> None:
    temp, result, payload, output, _ = run("full", fail="vet ./...")
    try:
        assert result.returncode == 1
        assert payload["result"] == "failed"
        assert [step["name"] for step in payload["steps"]] == ["go-test", "go-vet"]
        assert payload["steps"][-1]["exit_code"] == 9
        assert (output / "logs" / "02-go-vet.log").is_file()
        assert "go-vet failed" in payload["blocker"]
        assert not (output / "anopki-service").exists()
    finally:
        temp.cleanup()


def test_invalid_commit_fails_closed() -> None:
    temp = tempfile.TemporaryDirectory()
    try:
        root = Path(temp.name)
        fake_go = make_fake_go(root)
        output = root / "evidence"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--profile",
                "baseline",
                "--go",
                str(fake_go),
                "--out-dir",
                str(output),
                "--commit",
                "main",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        payload = json.loads((output / "go-verification.json").read_text(encoding="utf-8"))
        assert result.returncode == 1
        assert payload["steps"] == []
        assert "invalid Community commit" in payload["blocker"]
    finally:
        temp.cleanup()


def test_list_is_deterministic_and_side_effect_free() -> None:
    spec = importlib.util.spec_from_file_location("verify_go_release", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory() as dirname:
        output = Path(dirname) / "not-created"
        definitions = module.step_definitions("go", "analysis", output / "anopki-service")
        assert not output.exists()
    lines = [module.command_text(step.command) for step in definitions]
    assert len(lines) == 4
    assert lines[0] == "go test -race ./..."
    assert "staticcheck@2026.1" in lines[1]
    assert "gosec@v2.25.0" in lines[2]
    assert "govulncheck@v1.1.4" in lines[3]


def main() -> None:
    test_full_profile_passes()
    test_minimum_go_passes()
    test_old_go_fails_closed()
    test_step_failure_is_recorded_and_stops()
    test_invalid_commit_fails_closed()
    test_list_is_deterministic_and_side_effect_free()
    print("Go release verification runner tests ok")


if __name__ == "__main__":
    main()
