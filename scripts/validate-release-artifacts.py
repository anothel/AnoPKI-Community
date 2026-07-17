#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Smoke-check release archives and profile metadata before upload/signing."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
BACKEND_INFO_NAME = "anopki-backend-info.json"
RELEASE_METADATA_NAME = "anopki-release-metadata.json"
GO_EVIDENCE_NAME = "anopki-go-verification.tar.gz"


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_archive(dist: Path, name: str, member: str) -> Path:
    path = dist / name
    if not path.is_file():
        fail(f"missing release archive: {path}")
    try:
        with tarfile.open(path, "r:gz") as archive:
            names = set(archive.getnames())
    except tarfile.TarError as exc:
        fail(f"invalid tar archive {path}: {exc}")
    if member not in names:
        fail(f"{path.name} missing member: {member}")
    unexpected = sorted(names - {member})
    if unexpected:
        fail(f"{path.name} unexpected archive members:\n" + "\n".join(unexpected))
    return path



def parse_go_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match:
        fail(f"unable to parse Go version from evidence: {text!r}")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def require_go_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / GO_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing Go verification evidence archive: {path}")
    if path.stat().st_size > 50 * 1024 * 1024:
        fail(f"Go verification evidence archive is unexpectedly large: {path.name}")

    expected_steps = [
        "go-test",
        "go-vet",
        "go-build",
        "go-race",
        "staticcheck",
        "gosec",
        "govulncheck",
    ]
    expected_files = {
        "go-verification.json",
        "go-verification.md",
        *(f"logs/{index:02d}-{name}.log" for index, name in enumerate(expected_steps, start=1)),
    }

    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            allowed_directories = {"logs"}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if member.isdir():
                    if normalized.rstrip("/") not in allowed_directories:
                        fail(f"{path.name} contains unexpected directory: {member.name}")
                    continue
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member

            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing Go evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected Go evidence members:\n" + "\n".join(extra))

            evidence_member = files["go-verification.json"]
            if evidence_member.size > 1024 * 1024:
                fail("Go verification JSON is unexpectedly large")
            extracted = archive.extractfile(evidence_member)
            if extracted is None:
                fail(f"{path.name} cannot read go-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid Go verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid Go verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("Go verification evidence must be a JSON object")
    expected_fields = {
        "schema_version",
        "product",
        "edition",
        "product_profile",
        "profile",
        "commit",
        "minimum_go_version",
        "platform",
        "started_at",
        "completed_at",
        "result",
        "go_version",
        "go_environment",
        "tool_versions",
        "steps",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("Go verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("Go verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["product"] != "AnoPKI":
        fail("Go verification evidence identity is invalid")
    if evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("Go verification evidence profile is invalid")
    if evidence["profile"] != "full" or evidence["result"] != "passed":
        fail("Go verification full profile did not pass")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("Go verification commit is invalid")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("Go verification minimum version is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("Go verification toolchain identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("Go verification used an unsupported toolchain")

    go_environment = evidence["go_environment"]
    if not isinstance(go_environment, dict) or set(go_environment) != {"GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"}:
        fail("Go verification environment fields are invalid")
    if not all(isinstance(value, str) and value for value in go_environment.values()):
        fail("Go verification environment values are invalid")

    expected_tools = {
        "staticcheck": "2026.1",
        "gosec": "v2.25.0",
        "govulncheck": "v1.1.4",
    }
    if evidence["tool_versions"] != expected_tools:
        fail("Go verification tool pins are invalid")

    serialized_evidence = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in ("key_ref", "private_key", "password", "credential", "session_token", "api_key"):
        if forbidden in serialized_evidence:
            fail(f"Go verification evidence contains forbidden sensitive field: {forbidden}")

    steps = evidence["steps"]
    if not isinstance(steps, list) or len(steps) != len(expected_steps):
        fail("Go verification full step set is invalid")
    observed_names: list[str] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            fail("Go verification step must be an object")
        if set(step) != {"name", "command", "status", "exit_code", "duration_seconds", "log_file"}:
            fail("Go verification step fields are invalid")
        observed_names.append(str(step["name"]))
        if step["status"] != "passed" or step["exit_code"] != 0:
            fail("Go verification contains a failed step")
        if not isinstance(step["command"], list) or not all(isinstance(item, str) for item in step["command"]):
            fail("Go verification step command is invalid")
        if not isinstance(step["duration_seconds"], (int, float)) or isinstance(step["duration_seconds"], bool) or step["duration_seconds"] < 0:
            fail("Go verification step duration is invalid")
        expected_log = f"logs/{index:02d}-{expected_steps[index - 1]}.log"
        if step["log_file"] != expected_log:
            fail("Go verification step log binding is invalid")
    if observed_names != expected_steps:
        fail("Go verification full step order is invalid")

    commands = [" ".join(step["command"]) for step in steps]
    required_command_text = (
        "test ./...",
        "vet ./...",
        "build -trimpath",
        "test -race ./...",
        "staticcheck@2026.1",
        "gosec@v2.25.0",
        "govulncheck@v1.1.4",
    )
    for command, required in zip(commands, required_command_text):
        if required not in command:
            fail(f"Go verification command drift: missing {required}")
    return path, evidence

def read_checksums(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing checksum file: {path}")
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if not digest or not name:
            fail(f"invalid checksum line: {line}")
        if name in checksums:
            fail(f"duplicate checksum entry: {name}")
        checksums[name] = digest
    return checksums


def read_json_object(path: Path, label: str) -> dict[str, object]:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def require_exact_fields(value: dict[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        fail(f"{label} missing fields:\n" + "\n".join(missing))
    if extra:
        fail(f"{label} has unknown fields:\n" + "\n".join(extra))


def validate_backend_info(info: dict[str, object]) -> None:
    require_exact_fields(
        info,
        {
            "product_profile",
            "edition",
            "selected_backend",
            "fallback_enabled",
            "backend_id",
            "backend_dependency",
            "backend_version",
            "backend_readiness",
            "backend_capabilities",
            "backend_abi_version",
            "backend_build_fingerprint",
        },
        "backend info",
    )
    if info["product_profile"] != "community-openssl" or info["edition"] != "community":
        fail("backend info does not describe Community/OpenSSL")
    if info["selected_backend"] != "openssl" or info["backend_id"] != "openssl":
        fail("backend info does not select the OpenSSL adapter")
    if info["fallback_enabled"] is not False:
        fail("backend info enables fallback")
    if info["backend_readiness"] != "ready":
        fail("backend info is not ready")
    if not isinstance(info["backend_abi_version"], int) or isinstance(info["backend_abi_version"], bool) or info["backend_abi_version"] <= 0:
        fail("backend info ABI version is invalid")
    capabilities = info["backend_capabilities"]
    if not isinstance(capabilities, list) or not capabilities or not all(isinstance(item, str) and item for item in capabilities):
        fail("backend info capabilities are invalid")
    if len(capabilities) != len(set(capabilities)):
        fail("backend info capabilities contain duplicates")


def validate_release_metadata(metadata: dict[str, object], backend: dict[str, object]) -> None:
    require_exact_fields(
        metadata,
        {
            "schema_version",
            "product",
            "version",
            "commit",
            "build_time",
            "edition",
            "product_profile",
            "selected_backend",
            "fallback_enabled",
            "fallback_used",
            "backend",
            "key_provider_policy",
            "production_ready",
            "kcmvp_status",
        },
        "release metadata",
    )
    if metadata["schema_version"] != 1 or metadata["product"] != "AnoPKI" or metadata["version"] != VERSION:
        fail("release metadata identity/version mismatch")
    if metadata["edition"] != backend["edition"] or metadata["product_profile"] != backend["product_profile"]:
        fail("release metadata profile mismatch")
    if metadata["selected_backend"] != backend["selected_backend"]:
        fail("release metadata selected backend mismatch")
    if metadata["fallback_enabled"] is not False or metadata["fallback_used"] is not False:
        fail("release metadata fallback state is invalid")
    if metadata["production_ready"] is not False or metadata["kcmvp_status"] != "not_applicable":
        fail("release metadata maturity claim is invalid")

    backend_metadata = metadata["backend"]
    if not isinstance(backend_metadata, dict):
        fail("release metadata backend must be an object")
    require_exact_fields(
        backend_metadata,
        {"id", "dependency", "version", "readiness", "capabilities", "abi_version", "build_fingerprint"},
        "release metadata backend",
    )
    expected_backend = {
        "id": backend["backend_id"],
        "dependency": backend["backend_dependency"],
        "version": backend["backend_version"],
        "readiness": backend["backend_readiness"],
        "capabilities": backend["backend_capabilities"],
        "abi_version": backend["backend_abi_version"],
        "build_fingerprint": backend["backend_build_fingerprint"],
    }
    if backend_metadata != expected_backend:
        fail("release metadata backend evidence does not match core backend info")

    policy = metadata["key_provider_policy"]
    if not isinstance(policy, dict):
        fail("release metadata key provider policy must be an object")
    expected_policy = {
        "supported_classes": ["file"],
        "file_provider_exportability": "exportable",
        "file_provider_allowed_in_production": False,
        "core_signing_evidence_required": True,
        "automatic_provider_fallback": False,
    }
    if policy != expected_policy:
        fail("release metadata key provider policy mismatch")

    serialized = json.dumps(metadata, sort_keys=True).lower()
    for forbidden in ("key_ref", "private_key", "issuer_key", "credential", "session_token", "pin_value"):
        if forbidden in serialized:
            fail(f"release metadata contains forbidden sensitive field: {forbidden}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: validate-release-artifacts.py <dist-dir>")
    dist = Path(sys.argv[1])
    service = require_archive(
        dist,
        f"anopki-service-v{VERSION}-linux-amd64.tar.gz",
        "anopki-service",
    )
    core = require_archive(
        dist,
        f"anopki-core-v{VERSION}-linux-amd64.tar.gz",
        "anopki-core",
    )
    backend_path = dist / BACKEND_INFO_NAME
    metadata_path = dist / RELEASE_METADATA_NAME
    go_evidence, go_evidence_value = require_go_evidence_archive(dist)
    backend = read_json_object(backend_path, "backend info")
    validate_backend_info(backend)
    metadata = read_json_object(metadata_path, "release metadata")
    validate_release_metadata(metadata, backend)
    if go_evidence_value["commit"] != metadata["commit"]:
        fail("Go verification commit does not match release metadata")

    checksums = read_checksums(dist / "SHA256SUMS")
    artifacts = (service, core, go_evidence, backend_path, metadata_path)
    expected_names = {artifact.name for artifact in artifacts}
    extra_names = sorted(set(checksums) - expected_names)
    missing_names = sorted(expected_names - set(checksums))
    if extra_names:
        fail("unexpected checksum entries:\n" + "\n".join(extra_names))
    if missing_names:
        fail("missing checksum entries:\n" + "\n".join(missing_names))
    for artifact in artifacts:
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if checksums.get(artifact.name) != digest:
            fail(f"checksum mismatch: {artifact.name}")
    print("release artifacts ok")


if __name__ == "__main__":
    main()
