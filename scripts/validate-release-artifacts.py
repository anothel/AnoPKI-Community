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
RECOVERY_EVIDENCE_NAME = "anopki-recovery-verification.tar.gz"
STATUS_OUTAGE_EVIDENCE_NAME = "anopki-status-outage-verification.tar.gz"
AUDIT_REPLAY_EVIDENCE_NAME = "anopki-audit-replay-verification.tar.gz"
AUDIT_INTEGRITY_EVIDENCE_NAME = "anopki-audit-integrity-verification.tar.gz"
ISSUER_ROLLOVER_EVIDENCE_NAME = "anopki-issuer-rollover-verification.tar.gz"
POSTGRES_RECOVERY_EVIDENCE_NAME = "anopki-postgres-recovery-verification.tar.gz"
MULTI_NODE_EVIDENCE_NAME = "anopki-multi-node-verification.tar.gz"


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



def require_recovery_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / RECOVERY_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing recovery verification evidence archive: {path}")
    if path.stat().st_size > 5 * 1024 * 1024:
        fail(f"recovery verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {"recovery-verification.json", "recovery-verification.md"}
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing recovery evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected recovery evidence members:\n" + "\n".join(extra))
            member = files["recovery-verification.json"]
            if member.size > 1024 * 1024:
                fail("recovery verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read recovery-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid recovery verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid recovery verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("recovery verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "product", "edition", "product_profile", "commit",
        "database_driver", "migration_version", "migration_checksum", "started_at",
        "completed_at", "result", "backup_sha256", "restored_state_sha256",
        "state_counts", "artifact_hashes", "checks", "redaction",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("recovery verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("recovery verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["product"] != "AnoPKI":
        fail("recovery verification evidence identity is invalid")
    if evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("recovery verification evidence profile is invalid")
    if evidence["database_driver"] != "sqlite" or evidence["migration_version"] != 2:
        fail("recovery verification database or migration is invalid")
    if evidence["result"] != "passed":
        fail("recovery verification drill did not pass")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("recovery verification commit is invalid")
    for field in ("migration_checksum", "backup_sha256", "restored_state_sha256"):
        if not isinstance(evidence[field], str) or not re.fullmatch(r"[0-9a-f]{64}", evidence[field]):
            fail(f"recovery verification {field} is invalid")

    expected_counts = {
        "schema_migrations": 2,
        "issuers": 1,
        "ocsp_responders": 1,
        "certificates": 1,
        "certificate_issuance_attempts": 1,
        "revocations": 1,
        "crl_publications": 1,
        "crl_generation_claims": 0,
        "audit_events": 2,
        "audit_chain_state": 1,
        "outbox_messages": 1,
        "job_attempts": 1,
        "notification_endpoints": 1,
        "webhook_deliveries": 1,
        "api_keys": 1,
    }
    counts = evidence["state_counts"]
    if counts != expected_counts:
        fail("recovery verification state counts are invalid")

    hashes = evidence["artifact_hashes"]
    if not isinstance(hashes, dict) or set(hashes) != {"certificate_pem", "crl_pem", "signing_evidence"}:
        fail("recovery verification artifact hashes are invalid")
    if not all(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in hashes.values()):
        fail("recovery verification artifact hash values are invalid")

    expected_checks = [
        "sqlite-integrity", "foreign-key-integrity", "schema-migration",
        "restore-state-match", "state-counts", "key-reference-preservation",
        "crl-artifact", "issuance-attempt", "outbox-and-webhook-state",
        "audit-state", "audit-chain-state", "private-key-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("recovery verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("recovery verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("recovery verification contains a failed check")
    if names != expected_checks:
        fail("recovery verification check order is invalid")

    redaction = evidence["redaction"]
    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_fixture_values_in_evidence": False,
    }
    if redaction != expected_redaction:
        fail("recovery verification redaction evidence is invalid")
    def collect_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            keys = {str(key).lower() for key in value}
            for child in value.values():
                keys.update(collect_keys(child))
            return keys
        if isinstance(value, list):
            keys: set[str] = set()
            for child in value:
                keys.update(collect_keys(child))
            return keys
        return set()

    evidence_keys = collect_keys(evidence)
    for forbidden in ("key_ref", "private_key", "password", "credential", "session_token", "webhook_secret"):
        if forbidden in evidence_keys:
            fail(f"recovery verification evidence contains forbidden sensitive field: {forbidden}")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("recovery verification evidence contains private-key material")
    return path, evidence

def require_status_outage_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / STATUS_OUTAGE_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing status outage verification evidence archive: {path}")
    if path.stat().st_size > 5 * 1024 * 1024:
        fail(f"status outage verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "status-outage-verification.json",
        "status-outage-verification.md",
        "status-outage-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing status outage evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected status outage evidence members:\n" + "\n".join(extra))
            member = files["status-outage-verification.json"]
            if member.size > 1024 * 1024:
                fail("status outage verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read status-outage-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid status outage verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid status outage verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("status outage verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "started_at", "completed_at", "result",
        "go_version", "test_command", "tests", "checks", "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("status outage verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("status outage verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_status_outage_drill":
        fail("status outage verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("status outage verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("status outage verification drill did not pass")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("status outage verification minimum Go version is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("status outage verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("status outage verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("status outage verification used an unsupported Go toolchain")

    expected_tests = [
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestPublishCRLOutageRecoversWithoutPhantomPublication"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestRespondOCSPOutageRecoversWithoutSuccessAudit"),
        ("github.com/anothel/anopki/service/internal/httpapi", "TestPublishCRLOutageReturnsBadGatewayAndRecovers"),
        ("github.com/anothel/anopki/service/internal/httpapi", "TestRespondOCSPOutageReturnsBadGatewayAndRecovers"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("status outage verification test set is invalid")
    observed_tests: list[tuple[str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"package", "name", "status"}:
            fail("status outage verification test fields are invalid")
        observed_tests.append((str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("status outage verification contains a failed test")
    if observed_tests != expected_tests:
        fail("status outage verification test order is invalid")

    expected_checks = [
        "crl-failure-maps-bad-gateway",
        "crl-no-phantom-publication",
        "crl-recovery-preserves-numbering",
        "ocsp-failure-maps-bad-gateway",
        "ocsp-no-success-audit-on-failure",
        "ocsp-recovery-writes-one-success-audit",
        "provider-evidence-required-after-recovery",
        "sensitive-evidence-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("status outage verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("status outage verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("status outage verification contains a failed check")
    if names != expected_checks:
        fail("status outage verification check order is invalid")

    command = evidence["test_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        fail("status outage verification test command is invalid")
    command_text = " ".join(command)
    for required in ("test -json", "./internal/lifecycle", "./internal/httpapi", "TestPublishCRLOutage", "TestRespondOCSPOutage"):
        if required not in command_text:
            fail(f"status outage verification command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_values_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("status outage verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in ('"key_ref"', '"private_key"', '"password"', '"credential"', '"session_token"'):
        if forbidden in serialized:
            fail(f"status outage verification evidence contains forbidden sensitive field: {forbidden}")
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("status outage verification evidence contains private-key material")
    return path, evidence


def require_audit_replay_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / AUDIT_REPLAY_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing audit/replay verification evidence archive: {path}")
    if path.stat().st_size > 5 * 1024 * 1024:
        fail(f"audit/replay verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "audit-replay-verification.json",
        "audit-replay-verification.md",
        "audit-replay-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing audit/replay evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected audit/replay evidence members:\n" + "\n".join(extra))
            member = files["audit-replay-verification.json"]
            if member.size > 1024 * 1024:
                fail("audit/replay verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read audit-replay-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid audit/replay verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid audit/replay verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("audit/replay verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "started_at", "completed_at", "result",
        "go_version", "test_command", "tests", "checks", "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("audit/replay verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("audit/replay verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_audit_replay_drill":
        fail("audit/replay verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("audit/replay verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("audit/replay verification drill did not pass")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("audit/replay verification minimum Go version is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("audit/replay verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("audit/replay verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("audit/replay verification used an unsupported Go toolchain")

    expected_tests = [
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestRepairMissingIssuanceAuditEventsPreservesCurrentEvidenceAndIsIdempotent"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestReplayDeadLetterOutboxMessagesPreservesHistoryAndCompletesAfterRecovery"),
        ("github.com/anothel/anopki/service/internal/httpapi", "TestRepairMissingIssuanceAuditEvents"),
        ("github.com/anothel/anopki/service/internal/httpapi", "TestReplayDeadLetterOutboxMessagesRecoversAfterOperatorReplay"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("audit/replay verification test set is invalid")
    observed_tests: list[tuple[str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"package", "name", "status"}:
            fail("audit/replay verification test fields are invalid")
        observed_tests.append((str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("audit/replay verification contains a failed test")
    if observed_tests != expected_tests:
        fail("audit/replay verification test order is invalid")

    expected_checks = [
        "audit-repair-current-signing-evidence",
        "audit-repair-current-policy-evidence",
        "audit-repair-idempotent",
        "audit-repair-sensitive-input-redaction",
        "dead-letter-scope-guarded",
        "dead-letter-attempt-history-preserved",
        "dead-letter-webhook-history-preserved",
        "dead-letter-recovery-completes",
        "dead-letter-replay-audited",
        "sensitive-evidence-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("audit/replay verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("audit/replay verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("audit/replay verification contains a failed check")
    if names != expected_checks:
        fail("audit/replay verification check order is invalid")

    command = evidence["test_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        fail("audit/replay verification test command is invalid")
    command_text = " ".join(command)
    for required in (
        "test -json", "./internal/lifecycle", "./internal/httpapi",
        "TestRepairMissingIssuanceAuditEvents", "TestReplayDeadLetterOutboxMessages",
    ):
        if required not in command_text:
            fail(f"audit/replay verification command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_values_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("audit/replay verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in (
        '"key_ref"', '"private_key"', '"password"', '"credential"',
        '"session_token"', '"payload_json"', '"endpoint_secret"',
    ):
        if forbidden in serialized:
            fail(f"audit/replay verification evidence contains forbidden sensitive field: {forbidden}")
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("audit/replay verification evidence contains private-key material")
    return path, evidence

def require_audit_integrity_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / AUDIT_INTEGRITY_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing Audit integrity verification evidence archive: {path}")
    if path.stat().st_size > 10 * 1024 * 1024:
        fail(f"Audit integrity verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "audit-integrity-verification.json",
        "audit-integrity-verification.md",
        "audit-integrity-baseline-test.log",
        "audit-integrity-postgres-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing Audit integrity evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected Audit integrity evidence members:\n" + "\n".join(extra))
            contents: dict[str, str] = {}
            forbidden_archive_text = (
                '"key_ref"', '"private_key"', '"password"', '"credential"',
                '"session_token"', '"postgres_dsn"', "postgres://",
                "-----begin private key-----", "-----begin encrypted private key-----",
            )
            for name, archive_member in files.items():
                maximum_size = 1024 * 1024 if name.endswith(".json") else 5 * 1024 * 1024
                if archive_member.size > maximum_size:
                    fail(f"Audit integrity verification member is unexpectedly large: {name}")
                extracted = archive.extractfile(archive_member)
                if extracted is None:
                    fail(f"{path.name} cannot read {name}")
                try:
                    contents[name] = extracted.read().decode("utf-8")
                except UnicodeDecodeError as exc:
                    fail(f"Audit integrity verification member is not UTF-8: {name}: {exc}")
                lowered_member = contents[name].lower()
                for forbidden in forbidden_archive_text:
                    if forbidden in lowered_member:
                        fail(f"Audit integrity verification archive contains forbidden sensitive content: {name}: {forbidden}")
            try:
                evidence = json.loads(contents["audit-integrity-verification.json"])
            except json.JSONDecodeError as exc:
                fail(f"invalid Audit integrity verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid Audit integrity verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("Audit integrity verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "started_at", "completed_at", "result",
        "go_version", "postgres_required", "test_commands", "tests", "checks",
        "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("Audit integrity verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("Audit integrity verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_audit_integrity_drill":
        fail("Audit integrity verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("Audit integrity verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("Audit integrity verification drill did not pass")
    if evidence["postgres_required"] is not True:
        fail("Audit integrity verification release evidence must require PostgreSQL")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("Audit integrity verification minimum Go version is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("Audit integrity verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("Audit integrity verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("Audit integrity verification used an unsupported Go toolchain")

    expected_tests = [
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestAuditEventHashIsStable"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestVerifyAuditEventsDetectsCheckpointAndEventTampering"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestAuditIntegrityAppendCheckpointAndPruneParity"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestMemoryAuditTamperFailsClosed"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestMemoryAuditCheckpointTamperDetected"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestMemoryAuditCheckpointTamperDetectedAfterFullPrune"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestSQLiteAuditTamperAndCheckpointTamperFailClosed"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/store", "TestAuditHashChainMigrationBackfillsLegacySQLiteRowsBeforeUniqueIndex"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/httpapi", "TestGetAuditIntegrity"),
        ("memory-sqlite-http", "github.com/anothel/anopki/service/internal/httpapi", "TestPruneAuditEventsByRetentionCutoff"),
        ("postgresql", "github.com/anothel/anopki/service/internal/store", "TestPostgresIntegrationRepositoryParity/audit_integrity_chain"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("Audit integrity verification test set is invalid")
    observed_tests: list[tuple[str, str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"backend", "package", "name", "status"}:
            fail("Audit integrity verification test fields are invalid")
        observed_tests.append((str(test["backend"]), str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("Audit integrity verification contains a failed or skipped test")
    if observed_tests != expected_tests:
        fail("Audit integrity verification test order is invalid")

    expected_checks = [
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
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("Audit integrity verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("Audit integrity verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("Audit integrity verification contains a failed or skipped check")
    if names != expected_checks:
        fail("Audit integrity verification check order is invalid")

    commands = evidence["test_commands"]
    if not isinstance(commands, dict) or set(commands) != {"baseline", "postgres"}:
        fail("Audit integrity verification command set is invalid")
    for name in ("baseline", "postgres"):
        command = commands[name]
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            fail(f"Audit integrity verification {name} command is invalid")
    baseline_text = " ".join(commands["baseline"])
    for required in (
        "test -json", "./internal/store", "./internal/httpapi",
        "TestAuditIntegrityAppendCheckpointAndPruneParity",
        "TestSQLiteAuditTamperAndCheckpointTamperFailClosed",
        "TestAuditHashChainMigrationBackfillsLegacySQLiteRowsBeforeUniqueIndex",
        "TestGetAuditIntegrity", "TestPruneAuditEventsByRetentionCutoff",
    ):
        if required not in baseline_text:
            fail(f"Audit integrity verification baseline command drift: missing {required}")
    postgres_text = " ".join(commands["postgres"])
    for required in (
        "test -json", "./internal/store", "TestPostgresIntegrationRepositoryParity",
        "audit_integrity_chain",
    ):
        if required not in postgres_text:
            fail(f"Audit integrity verification PostgreSQL command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "database_credentials_in_evidence": False,
        "sensitive_values_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("Audit integrity verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in (
        '"key_ref"', '"private_key"', '"password"', '"credential"',
        '"session_token"', '"postgres_dsn"', "postgres://", "-----begin private key-----",
        "-----begin encrypted private key-----",
    ):
        if forbidden in serialized:
            fail(f"Audit integrity verification evidence contains forbidden sensitive content: {forbidden}")
    return path, evidence


def require_issuer_rollover_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / ISSUER_ROLLOVER_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing issuer rollover verification evidence archive: {path}")
    if path.stat().st_size > 5 * 1024 * 1024:
        fail(f"issuer rollover verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "issuer-rollover-verification.json",
        "issuer-rollover-verification.md",
        "issuer-rollover-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing issuer rollover evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected issuer rollover evidence members:\n" + "\n".join(extra))
            member = files["issuer-rollover-verification.json"]
            if member.size > 1024 * 1024:
                fail("issuer rollover verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read issuer-rollover-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid issuer rollover verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid issuer rollover verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("issuer rollover verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "started_at", "completed_at", "result",
        "go_version", "test_command", "tests", "checks", "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("issuer rollover verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("issuer rollover verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_issuer_rollover_drill":
        fail("issuer rollover verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("issuer rollover verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("issuer rollover verification drill did not pass")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("issuer rollover verification minimum Go version is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("issuer rollover verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("issuer rollover verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("issuer rollover verification used an unsupported Go toolchain")

    expected_tests = [
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestCertificateProfileIssuerRolloverAndRollbackPreservesOverlap"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestCertificateProfileIssuerRolloverRejectsDifferentParentAndStaleRetry"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestCertificateProfileIssuerRolloverRollsBackWhenAuditFails"),
        ("github.com/anothel/anopki/service/internal/store", "TestCertificateProfileIssuerConditionalUpdate"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("issuer rollover verification test set is invalid")
    observed_tests: list[tuple[str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"package", "name", "status"}:
            fail("issuer rollover verification test fields are invalid")
        observed_tests.append((str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("issuer rollover verification contains a failed test")
    if observed_tests != expected_tests:
        fail("issuer rollover verification test order is invalid")

    expected_checks = [
        "same-parent-chain-required",
        "profile-switch-atomic",
        "stale-retry-rejected",
        "old-issuer-overlap-maintained",
        "new-issuance-uses-new-issuer",
        "rollback-restores-old-issuer",
        "old-issuer-crl-remains-available",
        "audit-and-outbox-exactly-once",
        "transaction-rolls-back-on-evidence-failure",
        "sensitive-evidence-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("issuer rollover verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("issuer rollover verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("issuer rollover verification contains a failed check")
    if names != expected_checks:
        fail("issuer rollover verification check order is invalid")

    command = evidence["test_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        fail("issuer rollover verification test command is invalid")
    command_text = " ".join(command)
    for required in (
        "test -json", "./internal/lifecycle", "./internal/store",
        "TestCertificateProfileIssuerRolloverAndRollbackPreservesOverlap",
        "TestCertificateProfileIssuerRolloverRejectsDifferentParentAndStaleRetry",
        "TestCertificateProfileIssuerRolloverRollsBackWhenAuditFails",
        "TestCertificateProfileIssuerConditionalUpdate",
    ):
        if required not in command_text:
            fail(f"issuer rollover verification command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_values_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("issuer rollover verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in (
        '"key_ref"', '"private_key"', '"password"', '"credential"',
        '"session_token"', '"payload_json"', '"endpoint_secret"',
    ):
        if forbidden in serialized:
            fail(f"issuer rollover verification evidence contains forbidden sensitive field: {forbidden}")
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("issuer rollover verification evidence contains private-key material")
    return path, evidence


def require_multi_node_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / MULTI_NODE_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing multi-node verification evidence archive: {path}")
    if path.stat().st_size > 5 * 1024 * 1024:
        fail(f"multi-node verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "multi-node-verification.json",
        "multi-node-verification.md",
        "multi-node-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing multi-node evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected multi-node evidence members:\n" + "\n".join(extra))
            member = files["multi-node-verification.json"]
            if member.size > 1024 * 1024:
                fail("multi-node verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read multi-node-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid multi-node verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid multi-node verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("multi-node verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "started_at", "completed_at", "result",
        "go_version", "test_command", "tests", "checks", "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("multi-node verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("multi-node verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_multi_node_reliability_drill":
        fail("multi-node verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("multi-node verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("multi-node verification drill did not pass")
    if evidence["minimum_go_version"] != "1.25.11":
        fail("multi-node verification minimum Go version is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("multi-node verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("multi-node verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("multi-node verification used an unsupported Go toolchain")

    expected_tests = [
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestIssueCertificateActiveClaimPreventsSecondServiceSigning"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestPublishCRLActiveClaimPreventsSecondServiceSigning"),
        ("github.com/anothel/anopki/service/internal/lifecycle", "TestOutboxDispatcherActiveLeasePreventsSecondNodeHandling"),
        ("github.com/anothel/anopki/service/internal/store", "TestMemoryStoreCRLGenerationClaims"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("multi-node verification test set is invalid")
    observed_tests: list[tuple[str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"package", "name", "status"}:
            fail("multi-node verification test fields are invalid")
        observed_tests.append((str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("multi-node verification contains a failed test")
    if observed_tests != expected_tests:
        fail("multi-node verification test order is invalid")

    expected_checks = [
        "certificate-signing-single-writer",
        "certificate-finalization-idempotent",
        "crl-generation-single-writer",
        "crl-sequence-contiguous",
        "crl-claim-released-after-completion",
        "outbox-active-lease-not-stolen",
        "outbox-handler-exactly-once",
        "stale-claim-cas-rejected",
        "automatic-fallback-disabled",
        "sensitive-evidence-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("multi-node verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("multi-node verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("multi-node verification contains a failed check")
    if names != expected_checks:
        fail("multi-node verification check order is invalid")

    command = evidence["test_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        fail("multi-node verification test command is invalid")
    command_text = " ".join(command)
    for required in (
        "test -json", "./internal/lifecycle", "./internal/store",
        "TestIssueCertificateActiveClaimPreventsSecondServiceSigning",
        "TestPublishCRLActiveClaimPreventsSecondServiceSigning",
        "TestOutboxDispatcherActiveLeasePreventsSecondNodeHandling",
        "TestMemoryStoreCRLGenerationClaims",
    ):
        if required not in command_text:
            fail(f"multi-node verification command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_values_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("multi-node verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in (
        '"key_ref"', '"private_key"', '"password"', '"credential"',
        '"session_token"', '"payload_json"', '"endpoint_secret"',
    ):
        if forbidden in serialized:
            fail(f"multi-node verification evidence contains forbidden sensitive field: {forbidden}")
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("multi-node verification evidence contains private-key material")
    return path, evidence


def require_postgres_recovery_evidence_archive(dist: Path) -> tuple[Path, dict[str, object]]:
    path = dist / POSTGRES_RECOVERY_EVIDENCE_NAME
    if not path.is_file():
        fail(f"missing PostgreSQL recovery verification evidence archive: {path}")
    if path.stat().st_size > 10 * 1024 * 1024:
        fail(f"PostgreSQL recovery verification evidence archive is unexpectedly large: {path.name}")
    expected_files = {
        "postgres-recovery-verification.json",
        "postgres-recovery-verification.md",
        "postgres-recovery-test.log",
    }
    try:
        with tarfile.open(path, "r:gz") as archive:
            files: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                normalized = member.name.removeprefix("./")
                posix = PurePosixPath(normalized)
                if not normalized or posix.is_absolute() or ".." in posix.parts:
                    fail(f"{path.name} contains unsafe archive member: {member.name}")
                if not member.isfile():
                    fail(f"{path.name} contains non-regular member: {member.name}")
                if normalized in files:
                    fail(f"{path.name} contains duplicate member: {normalized}")
                files[normalized] = member
            missing = sorted(expected_files - set(files))
            extra = sorted(set(files) - expected_files)
            if missing:
                fail(f"{path.name} missing PostgreSQL recovery evidence members:\n" + "\n".join(missing))
            if extra:
                fail(f"{path.name} has unexpected PostgreSQL recovery evidence members:\n" + "\n".join(extra))
            member = files["postgres-recovery-verification.json"]
            if member.size > 1024 * 1024:
                fail("PostgreSQL recovery verification JSON is unexpectedly large")
            extracted = archive.extractfile(member)
            if extracted is None:
                fail(f"{path.name} cannot read postgres-recovery-verification.json")
            try:
                evidence = json.loads(extracted.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"invalid PostgreSQL recovery verification evidence: {exc}")
    except tarfile.TarError as exc:
        fail(f"invalid PostgreSQL recovery verification evidence archive {path}: {exc}")

    if not isinstance(evidence, dict):
        fail("PostgreSQL recovery verification evidence must be a JSON object")
    expected_fields = {
        "schema_version", "evidence_type", "product", "edition", "product_profile",
        "commit", "minimum_go_version", "required_postgres_major", "started_at",
        "completed_at", "result", "go_version", "postgres_client_versions",
        "postgres_server_version", "test_command", "tests", "checks", "state_counts",
        "migration_checksum", "backup_sha256", "state_digest_before", "state_digest_after",
        "key_reference_hashes", "artifact_hashes", "audit_chain", "redaction", "blocker",
    }
    missing_fields = sorted(expected_fields - set(evidence))
    extra_fields = sorted(set(evidence) - expected_fields)
    if missing_fields:
        fail("PostgreSQL recovery verification evidence missing fields:\n" + "\n".join(missing_fields))
    if extra_fields:
        fail("PostgreSQL recovery verification evidence has unknown fields:\n" + "\n".join(extra_fields))
    if evidence["schema_version"] != 1 or evidence["evidence_type"] != "community_postgres_recovery_drill":
        fail("PostgreSQL recovery verification evidence identity is invalid")
    if evidence["product"] != "AnoPKI" or evidence["edition"] != "community" or evidence["product_profile"] != "community-openssl":
        fail("PostgreSQL recovery verification evidence profile is invalid")
    if evidence["result"] != "passed" or evidence["blocker"] != "":
        fail("PostgreSQL recovery verification drill did not pass")
    if evidence["minimum_go_version"] != "1.25.11" or evidence["required_postgres_major"] != 16:
        fail("PostgreSQL recovery verification version policy is invalid")
    if not isinstance(evidence["commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", evidence["commit"]):
        fail("PostgreSQL recovery verification commit is invalid")
    if not isinstance(evidence["go_version"], str) or "go version go" not in evidence["go_version"]:
        fail("PostgreSQL recovery verification Go identity is invalid")
    if parse_go_version(evidence["go_version"]) < (1, 25, 11):
        fail("PostgreSQL recovery verification used an unsupported Go toolchain")
    if not isinstance(evidence["postgres_server_version"], str):
        fail("PostgreSQL recovery verification server version is invalid")
    server_match = re.search(r"(\d+)(?:\.\d+)?", evidence["postgres_server_version"])
    if server_match is None or int(server_match.group(1)) != 16:
        fail("PostgreSQL recovery verification did not use PostgreSQL 16")
    clients = evidence["postgres_client_versions"]
    if not isinstance(clients, dict) or set(clients) != {"psql", "pg_dump", "pg_restore"}:
        fail("PostgreSQL recovery client version set is invalid")
    for name, value in clients.items():
        if not isinstance(value, str):
            fail(f"PostgreSQL recovery {name} version is invalid")
        client_match = re.search(r"(\d+)(?:\.\d+)?", value)
        if client_match is None or int(client_match.group(1)) != 16:
            fail(f"PostgreSQL recovery {name} did not use PostgreSQL 16")

    expected_tests = [
        ("github.com/anothel/anopki/service/internal/store", "TestPostgresRecoveryDrillMigrationRollbackIntegration"),
        ("github.com/anothel/anopki/service/internal/store", "TestPostgresRecoveryDrillDirtyMigrationRejectedIntegration"),
    ]
    tests = evidence["tests"]
    if not isinstance(tests, list) or len(tests) != len(expected_tests):
        fail("PostgreSQL recovery verification test set is invalid")
    observed_tests: list[tuple[str, str]] = []
    for test in tests:
        if not isinstance(test, dict) or set(test) != {"package", "name", "status"}:
            fail("PostgreSQL recovery verification test fields are invalid")
        observed_tests.append((str(test["package"]), str(test["name"])))
        if test["status"] != "pass":
            fail("PostgreSQL recovery verification contains a failed test")
    if observed_tests != expected_tests:
        fail("PostgreSQL recovery verification test order is invalid")

    expected_checks = [
        "postgres-client-tools-available",
        "postgres-16-server-verified",
        "current-migration-clean",
        "failed-migration-transaction-rolled-back",
        "dirty-migration-rejected",
        "custom-format-backup-created",
        "source-damage-detected",
        "restore-state-digest-matched",
        "key-reference-hashes-preserved",
        "signing-and-crl-artifacts-preserved",
        "audit-outbox-webhook-state-preserved",
        "sensitive-evidence-exclusion",
    ]
    checks = evidence["checks"]
    if not isinstance(checks, list) or len(checks) != len(expected_checks):
        fail("PostgreSQL recovery verification check set is invalid")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status"}:
            fail("PostgreSQL recovery verification check fields are invalid")
        names.append(str(check["name"]))
        if check["status"] != "passed":
            fail("PostgreSQL recovery verification contains a failed check")
    if names != expected_checks:
        fail("PostgreSQL recovery verification check order is invalid")

    expected_counts = {
        "schema_migrations": 2,
        "identities": 1,
        "issuers": 1,
        "ocsp_responders": 1,
        "notification_endpoints": 1,
        "certificate_profiles": 1,
        "enrollments": 1,
        "certificates": 1,
        "certificate_issuance_attempts": 1,
        "revocations": 1,
        "crl_publications": 1,
        "audit_events": 2,
        "audit_chain_state": 1,
        "outbox_messages": 1,
        "job_attempts": 1,
        "webhook_deliveries": 1,
        "api_keys": 1,
    }
    if evidence["state_counts"] != expected_counts:
        fail("PostgreSQL recovery verification state counts are invalid")
    for field in ("migration_checksum", "backup_sha256", "state_digest_before", "state_digest_after"):
        if not isinstance(evidence[field], str) or not re.fullmatch(r"[0-9a-f]{64}", evidence[field]):
            fail(f"PostgreSQL recovery verification {field} is invalid")
    if evidence["state_digest_before"] != evidence["state_digest_after"]:
        fail("PostgreSQL recovery restored state digest does not match")
    key_hashes = evidence["key_reference_hashes"]
    if not isinstance(key_hashes, dict) or set(key_hashes) != {"issuer", "responder"}:
        fail("PostgreSQL recovery key reference hashes are invalid")
    artifact_hashes = evidence["artifact_hashes"]
    expected_artifacts = {
        "certificate_pem", "signing_evidence_json", "crl_pem", "audit_metadata_json",
        "outbox_payload_json", "notification_secret_digest", "api_token_hash",
    }
    if not isinstance(artifact_hashes, dict) or set(artifact_hashes) != expected_artifacts:
        fail("PostgreSQL recovery artifact hashes are invalid")
    for value in [*key_hashes.values(), *artifact_hashes.values()]:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            fail("PostgreSQL recovery hash value is invalid")

    audit_chain = evidence["audit_chain"]
    if not isinstance(audit_chain, dict) or set(audit_chain) != {
        "hash_algorithm", "latest_sequence", "latest_event_hash",
        "checkpoint_sequence", "checkpoint_event_hash",
    }:
        fail("PostgreSQL recovery audit chain state is invalid")
    if (
        audit_chain["hash_algorithm"] != "sha256-v1"
        or audit_chain["latest_sequence"] != 2
        or not isinstance(audit_chain["latest_event_hash"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", audit_chain["latest_event_hash"])
        or audit_chain["checkpoint_sequence"] != 0
        or audit_chain["checkpoint_event_hash"] != ""
    ):
        fail("PostgreSQL recovery audit chain values are invalid")

    command = evidence["test_command"]
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        fail("PostgreSQL recovery verification test command is invalid")
    command_text = " ".join(command)
    for required in (
        "test -json", "./internal/store",
        "TestPostgresRecoveryDrillMigrationRollbackIntegration",
        "TestPostgresRecoveryDrillDirtyMigrationRejectedIntegration",
    ):
        if required not in command_text:
            fail(f"PostgreSQL recovery verification command drift: missing {required}")

    expected_redaction = {
        "private_key_markers_found": False,
        "raw_key_references_in_evidence": False,
        "sensitive_values_in_evidence": False,
        "database_dsn_in_evidence": False,
    }
    if evidence["redaction"] != expected_redaction:
        fail("PostgreSQL recovery verification redaction evidence is invalid")
    serialized = json.dumps(evidence, sort_keys=True).lower()
    for forbidden in (
        '"key_ref"', '"private_key"', '"password"', '"credential"',
        '"session_token"', '"payload_json"', '"endpoint_secret"',
        "postgres://", "postgresql://", "pgpassword",
    ):
        if forbidden in serialized:
            fail(f"PostgreSQL recovery verification evidence contains forbidden sensitive field: {forbidden}")
    if "-----begin private key-----" in serialized or "-----begin encrypted private key-----" in serialized:
        fail("PostgreSQL recovery verification evidence contains private-key material")
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
    recovery_evidence, recovery_evidence_value = require_recovery_evidence_archive(dist)
    status_outage_evidence, status_outage_evidence_value = require_status_outage_evidence_archive(dist)
    audit_replay_evidence, audit_replay_evidence_value = require_audit_replay_evidence_archive(dist)
    audit_integrity_evidence, audit_integrity_evidence_value = require_audit_integrity_evidence_archive(dist)
    issuer_rollover_evidence, issuer_rollover_evidence_value = require_issuer_rollover_evidence_archive(dist)
    postgres_recovery_evidence, postgres_recovery_evidence_value = require_postgres_recovery_evidence_archive(dist)
    multi_node_evidence, multi_node_evidence_value = require_multi_node_evidence_archive(dist)
    backend = read_json_object(backend_path, "backend info")
    validate_backend_info(backend)
    metadata = read_json_object(metadata_path, "release metadata")
    validate_release_metadata(metadata, backend)
    if go_evidence_value["commit"] != metadata["commit"]:
        fail("Go verification commit does not match release metadata")
    if recovery_evidence_value["commit"] != metadata["commit"]:
        fail("recovery verification commit does not match release metadata")
    if status_outage_evidence_value["commit"] != metadata["commit"]:
        fail("status outage verification commit does not match release metadata")
    if audit_replay_evidence_value["commit"] != metadata["commit"]:
        fail("audit/replay verification commit does not match release metadata")
    if audit_integrity_evidence_value["commit"] != metadata["commit"]:
        fail("Audit integrity verification commit does not match release metadata")
    if issuer_rollover_evidence_value["commit"] != metadata["commit"]:
        fail("issuer rollover verification commit does not match release metadata")
    if postgres_recovery_evidence_value["commit"] != metadata["commit"]:
        fail("PostgreSQL recovery verification commit does not match release metadata")
    if multi_node_evidence_value["commit"] != metadata["commit"]:
        fail("multi-node verification commit does not match release metadata")

    checksums = read_checksums(dist / "SHA256SUMS")
    artifacts = (service, core, go_evidence, recovery_evidence, status_outage_evidence, audit_replay_evidence, audit_integrity_evidence, issuer_rollover_evidence, postgres_recovery_evidence, multi_node_evidence, backend_path, metadata_path)
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
