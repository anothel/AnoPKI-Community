#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run fail-closed PostgreSQL backup/restore and migration rollback evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".tmp" / "postgres-recovery-evidence"
MINIMUM_GO_VERSION = (1, 25, 11)
REQUIRED_POSTGRES_MAJOR = 16
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_TESTS = (
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestPostgresRecoveryDrillMigrationRollbackIntegration",
    ),
    (
        "github.com/anothel/anopki/service/internal/store",
        "TestPostgresRecoveryDrillDirtyMigrationRejectedIntegration",
    ),
)
EXPECTED_CHECKS = (
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
)
SELECTED_TABLES = (
    "schema_migrations",
    "identities",
    "issuers",
    "ocsp_responders",
    "notification_endpoints",
    "certificate_profiles",
    "enrollments",
    "certificates",
    "certificate_issuance_attempts",
    "revocations",
    "crl_publications",
    "crl_generation_claims",
    "audit_events",
    "audit_chain_state",
    "outbox_messages",
    "job_attempts",
    "webhook_deliveries",
    "api_keys",
)
SENSITIVE_FIXTURES = (
    "file:/var/lib/anopki/postgres-recovery-issuer.key",
    "pkcs11:postgres-recovery-responder",
    "postgres-recovery-webhook-secret",
    "postgres-recovery-api-token-hash",
)
PRIVATE_KEY_MARKERS = (
    "-----begin private key-----",
    "-----begin rsa private key-----",
    "-----begin ec private key-----",
    "-----begin encrypted private key-----",
)


class DrillFailure(RuntimeError):
    """A fail-closed PostgreSQL recovery drill failure."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def audit_event_hash(
    previous_hash: str,
    *,
    sequence: int,
    event_id: str,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    metadata_json: str,
    created_at: str,
) -> str:
    payload = {
        "hash_algorithm": "sha256-v1",
        "sequence": sequence,
        "id": event_id,
        "actor": actor,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "metadata": json.loads(metadata_json),
        "created_at": created_at,
    }
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_bytes(previous_hash.encode("utf-8") + encoded)


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


def parse_go_version(text: str) -> tuple[int, int, int]:
    match = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not match:
        raise DrillFailure("unable to parse Go version")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def parse_postgres_major(text: str) -> int:
    match = re.search(r"(\d+)(?:\.\d+)?", text)
    if not match:
        raise DrillFailure("unable to parse PostgreSQL version")
    return int(match.group(1))


def sanitize_database_name(value: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
        raise DrillFailure("generated PostgreSQL database name is invalid")
    return value


def parse_postgres_dsn(value: str) -> dict[str, Any]:
    value = value.strip()
    if not value:
        raise DrillFailure("PostgreSQL recovery DSN is required")
    parsed = urlsplit(value)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise DrillFailure("PostgreSQL recovery DSN must use postgres:// or postgresql://")
    if not parsed.hostname or not parsed.username:
        raise DrillFailure("PostgreSQL recovery DSN must include user and host")
    database = parsed.path.lstrip("/")
    if not database or "/" in database:
        raise DrillFailure("PostgreSQL recovery DSN must include one database name")
    return {
        "scheme": parsed.scheme,
        "username": parsed.username,
        "password": parsed.password or "",
        "hostname": parsed.hostname,
        "port": parsed.port,
        "database": database,
        "query": parsed.query,
    }


def build_postgres_uri(config: dict[str, Any], database: str, *, include_password: bool) -> str:
    database = sanitize_database_name(database)
    username = quote(str(config["username"]), safe="")
    password = quote(str(config["password"]), safe="")
    userinfo = username
    if include_password and password:
        userinfo += f":{password}"
    host = str(config["hostname"])
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{config['port']}" if config.get("port") else ""
    netloc = f"{userinfo}@{host}{port}"
    return urlunsplit((str(config["scheme"]), netloc, f"/{database}", str(config.get("query", "")), ""))


def redact(text: str, secrets_to_hide: tuple[str, ...], paths_to_hide: tuple[Path, ...]) -> str:
    replacements: dict[str, str] = {}
    for value in secrets_to_hide:
        if value:
            replacements[value] = "<redacted>"
    replacements[str(ROOT)] = "<repo>"
    replacements[str(ROOT.resolve())] = "<repo>"
    replacements[str(Path.home())] = "<home>"
    for path in paths_to_hide:
        replacements[str(path)] = "<work>"
        try:
            replacements[str(path.resolve())] = "<work>"
        except OSError:
            pass
    for original, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(original, replacement)
    return text


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DrillFailure(f"unable to execute {command[0]}: {exc}") from exc


def require_tools(names: tuple[str, ...]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for name in names:
        path = shutil.which(name)
        if not path:
            raise DrillFailure(f"required PostgreSQL recovery tool is unavailable: {name}")
        resolved[name] = path
    return resolved


def psql_command(uri: str, sql: str, tools: dict[str, str]) -> list[str]:
    return [
        tools["psql"],
        "--no-psqlrc",
        "--dbname",
        uri,
        "--set",
        "ON_ERROR_STOP=1",
        "--tuples-only",
        "--no-align",
        "--quiet",
        "--command",
        sql,
    ]


def run_psql(
    uri: str,
    sql: str,
    *,
    tools: dict[str, str],
    env: dict[str, str],
    cwd: Path,
    timeout: int = 180,
) -> str:
    result = run_command(psql_command(uri, sql, tools), cwd=cwd, env=env, timeout=timeout)
    if result.returncode != 0:
        raise DrillFailure("PostgreSQL command failed")
    return result.stdout.strip()


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


def seed_sql() -> str:
    certificate_pem = "-----BEGIN CERTIFICATE-----\\nUE9TVEdSRVMtUkVDT1ZFUlktQ0VSVA==\\n-----END CERTIFICATE-----\\n"
    responder_pem = "-----BEGIN CERTIFICATE-----\\nUE9TVEdSRVMtT0NTUC1SRVNQT05ERVI=\\n-----END CERTIFICATE-----\\n"
    crl_pem = "-----BEGIN X509 CRL-----\\nUE9TVEdSRVMtUkVDT1ZFUlktQ1JM\\n-----END X509 CRL-----\\n"
    signing_evidence = json.dumps(
        {
            "evidence_source": "core_signing",
            "operation": "certificate_issue",
            "provider_id": "file",
            "provider_class": "file",
            "provider_readiness": "ready",
            "provider_exportability": "exportable",
            "reference_class": "file",
            "key_algorithm": "rsa",
            "requested_signature_algorithm": "rsa-sha256",
            "issuer_binding_verified": True,
            "fallback_used": False,
            "result_code": "ok",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).replace("'", "''")
    audit_metadata_raw = json.dumps(
        {
            "result": "ok",
            "evidence_source": "core_signing",
            "policy_decision": "allow",
            "policy_decision_reason": "issuance_policy_passed",
            "policy_validation_evidence_refs": ["sha256:" + "a" * 64],
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    audit_metadata = audit_metadata_raw.replace("'", "''")
    audit_metadata_2_raw = '{"result":"ok"}'
    audit_hash_1 = audit_event_hash(
        "", sequence=1, event_id="audit-pg-recovery-1", actor="operator",
        action="certificate.issued", resource_type="certificate",
        resource_id="certificate-pg-recovery-1", metadata_json=audit_metadata_raw,
        created_at="2026-07-18T00:00:02Z",
    )
    audit_hash_2 = audit_event_hash(
        audit_hash_1, sequence=2, event_id="audit-pg-recovery-2", actor="operator",
        action="crl.published", resource_type="crl",
        resource_id="crl-pg-recovery-1", metadata_json=audit_metadata_2_raw,
        created_at="2026-07-18T00:10:00Z",
    )
    outbox_payload = json.dumps(
        {"certificate_id": "certificate-pg-recovery-1", "event": "certificate.issued"},
        separators=(",", ":"),
        sort_keys=True,
    ).replace("'", "''")
    return f"""
BEGIN;
INSERT INTO identities (
    id, type, name, external_id, owner, team, service, environment, deployment_target,
    last_seen_at, metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
) VALUES (
    'identity-pg-recovery-1', 'service', 'postgres-recovery-fixture', '', 'platform', 'pki',
    'anopki', 'test', 'postgres-recovery', NULL, '{{}}', '["restore.example"]', '[]',
    'active', '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO issuers (
    id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url,
    crl_distribution_points, trust_anchor, created_at, updated_at
) VALUES (
    'issuer-pg-recovery-1', 'PostgreSQL Recovery CA', 'root_ca', 'active', '',
    E'{certificate_pem}', '{SENSITIVE_FIXTURES[0]}', 'https://pki.example/issuer',
    '["https://pki.example/crl"]', TRUE, '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO ocsp_responders (
    id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
) VALUES (
    'responder-pg-recovery-1', 'issuer-pg-recovery-1', 'PostgreSQL Recovery OCSP', 'active',
    E'{responder_pem}', '{SENSITIVE_FIXTURES[1]}', '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO notification_endpoints (
    id, name, type, status, url, secret, event_types, created_at, updated_at
) VALUES (
    'endpoint-pg-recovery-1', 'PostgreSQL Recovery Receiver', 'webhook', 'active',
    'https://receiver.invalid/anopki', '{SENSITIVE_FIXTURES[2]}', '["certificate.issued"]',
    '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO certificate_profiles (
    id, name, description, issuer_id, validity_period_seconds, subject_template,
    allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
    allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
    subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
) VALUES (
    'profile-pg-recovery-1', 'postgres-recovery-profile', '', 'issuer-pg-recovery-1', 86400, '',
    '["*.example"]', '[]', '["rsa"]', 2048, '["rsa-sha256"]', '{{}}', '{{}}', '{{}}',
    TRUE, TRUE, FALSE, '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO enrollments (
    id, identity_id, issuer_id, certificate_profile_id, source_certificate_id, csr_pem, status,
    requested_subject, requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses,
    requested_not_after, approved_by, approved_at, created_at, updated_at
) VALUES (
    'enrollment-pg-recovery-1', 'identity-pg-recovery-1', 'issuer-pg-recovery-1',
    'profile-pg-recovery-1', '', '-----BEGIN CERTIFICATE REQUEST-----\\nUE9TVEdSRVMtQ1NS\\n-----END CERTIFICATE REQUEST-----\\n',
    'issued', 'CN=restore.example', '["restore.example"]', '[]', '["restore.example"]', '[]',
    '2026-07-19T00:00:00Z', 'operator', '2026-07-18T00:00:00Z',
    '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO certificates (
    id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
    dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
    renewal_notified_at, created_at, updated_at
) VALUES (
    'certificate-pg-recovery-1', 'identity-pg-recovery-1', 'issuer-pg-recovery-1',
    'enrollment-pg-recovery-1', 'profile-pg-recovery-1', '1001', 'CN=restore.example',
    '["restore.example"]', '[]', '2026-07-18T00:00:00Z', '2026-07-19T00:00:00Z',
    'revoked', E'{certificate_pem}', NULL, '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
INSERT INTO certificate_issuance_attempts (
    enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number,
    subject, not_before, not_after, signing_started_at, signed_at, finalized_at, last_error,
    signing_evidence_json, created_at, updated_at
) VALUES (
    'enrollment-pg-recovery-1', 'completed', NULL, 'certificate-pg-recovery-1', E'{certificate_pem}',
    '1001', 'CN=restore.example', '2026-07-18T00:00:00Z', '2026-07-19T00:00:00Z',
    '2026-07-18T00:00:00Z', '2026-07-18T00:00:01Z', '2026-07-18T00:00:02Z', '',
    '{signing_evidence}', '2026-07-18T00:00:00Z', '2026-07-18T00:00:02Z'
);
INSERT INTO revocations (
    id, certificate_id, reason, revoked_by, revoked_at, created_at
) VALUES (
    'revocation-pg-recovery-1', 'certificate-pg-recovery-1', 'keyCompromise', 'operator',
    '2026-07-18T00:10:00Z', '2026-07-18T00:10:00Z'
);
INSERT INTO crl_publications (
    id, issuer_id, distribution_point, crl_number, this_update, next_update, status,
    crl_pem, created_at, updated_at
) VALUES (
    'crl-pg-recovery-1', 'issuer-pg-recovery-1', 'https://pki.example/crl', 1,
    '2026-07-18T00:10:00Z', '2026-07-19T00:10:00Z', 'published', E'{crl_pem}',
    '2026-07-18T00:10:00Z', '2026-07-18T00:10:00Z'
);
INSERT INTO audit_events (
    id, sequence, actor, action, resource_type, resource_id, metadata_json,
    hash_algorithm, previous_event_hash, event_hash, created_at
) VALUES
    ('audit-pg-recovery-1', 1, 'operator', 'certificate.issued', 'certificate',
     'certificate-pg-recovery-1', '{audit_metadata}', 'sha256-v1', '',
     '{audit_hash_1}', '2026-07-18T00:00:02Z'),
    ('audit-pg-recovery-2', 2, 'operator', 'crl.published', 'crl',
     'crl-pg-recovery-1', '{{"result":"ok"}}', 'sha256-v1', '{audit_hash_1}',
     '{audit_hash_2}', '2026-07-18T00:10:00Z');
UPDATE audit_chain_state
SET hash_algorithm = 'sha256-v1',
    latest_sequence = 2,
    latest_event_hash = '{audit_hash_2}',
    checkpoint_sequence = 0,
    checkpoint_event_hash = '',
    updated_at = '2026-07-18T00:10:00Z'
WHERE singleton_id = 1;
INSERT INTO outbox_messages (
    id, type, payload_json, status, available_at, processing_deadline_at,
    attempt_count, max_attempts, last_error, created_at, updated_at
) VALUES (
    'outbox-pg-recovery-1', 'certificate.issued', '{outbox_payload}', 'dead_letter',
    '2026-07-18T00:00:02Z', NULL, 3, 3, 'receiver unavailable',
    '2026-07-18T00:00:02Z', '2026-07-18T00:03:00Z'
);
INSERT INTO job_attempts (
    id, outbox_message_id, status, error, started_at, finished_at, created_at
) VALUES (
    'job-pg-recovery-1', 'outbox-pg-recovery-1', 'failed', 'receiver unavailable',
    '2026-07-18T00:02:00Z', '2026-07-18T00:02:01Z', '2026-07-18T00:02:00Z'
);
INSERT INTO webhook_deliveries (
    outbox_message_id, endpoint_id, status, attempt_count, last_error,
    last_attempted_at, created_at, updated_at
) VALUES (
    'outbox-pg-recovery-1', 'endpoint-pg-recovery-1', 'failed', 3, 'receiver unavailable',
    '2026-07-18T00:03:00Z', '2026-07-18T00:00:02Z', '2026-07-18T00:03:00Z'
);
INSERT INTO api_keys (
    id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
) VALUES (
    'api-key-pg-recovery-1', 'postgres recovery key', '{SENSITIVE_FIXTURES[3]}', 'active',
    'operator', '["operator"]', NULL, NULL, '2026-07-18T00:00:00Z', '2026-07-18T00:00:00Z'
);
COMMIT;
"""


def snapshot_sql() -> str:
    count_pairs = ",".join(
        f"'{table}', (SELECT COUNT(*) FROM {table})" for table in SELECTED_TABLES
    )
    return f"""
SELECT json_build_object(
    'migration', (SELECT json_build_object('version', version, 'checksum', checksum, 'dirty', dirty) FROM schema_migrations WHERE version = 2),
    'counts', json_build_object({count_pairs}),
    'issuer_key_ref', (SELECT key_ref FROM issuers WHERE id = 'issuer-pg-recovery-1'),
    'responder_key_ref', (SELECT key_ref FROM ocsp_responders WHERE id = 'responder-pg-recovery-1'),
    'certificate_pem', (SELECT certificate_pem FROM certificates WHERE id = 'certificate-pg-recovery-1'),
    'signing_evidence_json', (SELECT signing_evidence_json FROM certificate_issuance_attempts WHERE enrollment_id = 'enrollment-pg-recovery-1'),
    'crl_pem', (SELECT crl_pem FROM crl_publications WHERE id = 'crl-pg-recovery-1'),
    'audit_metadata_json', (SELECT metadata_json FROM audit_events WHERE id = 'audit-pg-recovery-1'),
    'audit_chain', (SELECT json_build_object(
        'hash_algorithm', hash_algorithm,
        'latest_sequence', latest_sequence,
        'latest_event_hash', latest_event_hash,
        'checkpoint_sequence', checkpoint_sequence,
        'checkpoint_event_hash', checkpoint_event_hash
    ) FROM audit_chain_state WHERE singleton_id = 1),
    'outbox_payload_json', (SELECT payload_json FROM outbox_messages WHERE id = 'outbox-pg-recovery-1'),
    'endpoint_secret', (SELECT secret FROM notification_endpoints WHERE id = 'endpoint-pg-recovery-1'),
    'api_token_hash', (SELECT token_hash FROM api_keys WHERE id = 'api-key-pg-recovery-1'),
    'statuses', json_build_object(
        'certificate', (SELECT status FROM certificates WHERE id = 'certificate-pg-recovery-1'),
        'attempt', (SELECT status FROM certificate_issuance_attempts WHERE enrollment_id = 'enrollment-pg-recovery-1'),
        'crl', (SELECT status FROM crl_publications WHERE id = 'crl-pg-recovery-1'),
        'outbox', (SELECT status FROM outbox_messages WHERE id = 'outbox-pg-recovery-1'),
        'webhook', (SELECT status FROM webhook_deliveries WHERE outbox_message_id = 'outbox-pg-recovery-1' AND endpoint_id = 'endpoint-pg-recovery-1')
    )
)::text;
"""


def safe_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    migration = raw.get("migration")
    counts = raw.get("counts")
    statuses = raw.get("statuses")
    audit_chain = raw.get("audit_chain")
    if not isinstance(migration, dict) or not isinstance(counts, dict) or not isinstance(statuses, dict) or not isinstance(audit_chain, dict):
        raise DrillFailure("PostgreSQL recovery snapshot shape is invalid")
    safe = {
        "migration": migration,
        "counts": counts,
        "statuses": statuses,
        "audit_chain": audit_chain,
        "key_reference_hashes": {
            "issuer": sha256_text(str(raw.get("issuer_key_ref", ""))),
            "responder": sha256_text(str(raw.get("responder_key_ref", ""))),
        },
        "artifact_hashes": {
            "certificate_pem": sha256_text(str(raw.get("certificate_pem", ""))),
            "signing_evidence_json": sha256_text(str(raw.get("signing_evidence_json", ""))),
            "crl_pem": sha256_text(str(raw.get("crl_pem", ""))),
            "audit_metadata_json": sha256_text(str(raw.get("audit_metadata_json", ""))),
            "outbox_payload_json": sha256_text(str(raw.get("outbox_payload_json", ""))),
            "notification_secret_digest": sha256_text(str(raw.get("endpoint_secret", ""))),
            "api_token_hash": sha256_text(str(raw.get("api_token_hash", ""))),
        },
    }
    return safe


def load_snapshot(uri: str, *, tools: dict[str, str], env: dict[str, str], cwd: Path) -> dict[str, Any]:
    output = run_psql(uri, snapshot_sql(), tools=tools, env=env, cwd=cwd)
    try:
        raw = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DrillFailure("unable to decode PostgreSQL recovery snapshot") from exc
    if not isinstance(raw, dict):
        raise DrillFailure("PostgreSQL recovery snapshot must be an object")
    return safe_snapshot(raw)


def evidence_template(commit: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_type": "community_postgres_recovery_drill",
        "product": "AnoPKI",
        "edition": "community",
        "product_profile": "community-openssl",
        "commit": commit,
        "minimum_go_version": "1.25.11",
        "required_postgres_major": REQUIRED_POSTGRES_MAJOR,
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "result": "failed",
        "go_version": "unavailable",
        "postgres_client_versions": {},
        "postgres_server_version": "unavailable",
        "test_command": [],
        "tests": [],
        "checks": [],
        "state_counts": {},
        "migration_checksum": "",
        "backup_sha256": "",
        "state_digest_before": "",
        "state_digest_after": "",
        "key_reference_hashes": {},
        "artifact_hashes": {},
        "audit_chain": {},
        "redaction": {
            "private_key_markers_found": False,
            "raw_key_references_in_evidence": False,
            "sensitive_values_in_evidence": False,
            "database_dsn_in_evidence": False,
        },
        "blocker": "",
    }


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    evidence["completed_at"] = utc_now()
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    lowered = serialized.lower()
    for forbidden in (*SENSITIVE_FIXTURES, *PRIVATE_KEY_MARKERS, "postgres://", "postgresql://", "pgpassword"):
        if forbidden.lower() in lowered:
            raise DrillFailure("forbidden sensitive content in PostgreSQL recovery evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "postgres-recovery-verification.json").write_text(serialized, encoding="utf-8")
    lines = [
        "# AnoPKI Community PostgreSQL Recovery Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Go: `{evidence['go_version']}`",
        f"- PostgreSQL server: `{evidence['postgres_server_version']}`",
        "",
        "## Checks",
        "",
    ]
    lines.extend(f"- `{check['name']}`: `{check['status']}`" for check in evidence["checks"])
    if evidence["blocker"]:
        lines.extend(["", "## Blocker", "", f"`{evidence['blocker']}`"])
    (output_dir / "postgres-recovery-verification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_drill(
    root: Path,
    output_dir: Path,
    go_executable: str,
    dsn: str,
    commit: str,
) -> dict[str, Any]:
    evidence = evidence_template(resolve_commit(root, commit))
    output_dir = output_dir.resolve()
    work_dir: Path | None = None
    created_databases: list[str] = []
    private_values: list[str] = [dsn]
    log_lines: list[str] = []
    try:
        config = parse_postgres_dsn(dsn)
        tools = require_tools(("psql", "pg_dump", "pg_restore"))
        environment = os.environ.copy()
        if config["password"]:
            environment["PGPASSWORD"] = str(config["password"])
            private_values.append(str(config["password"]))
        environment["GOTOOLCHAIN"] = "local"
        environment["GOCACHE"] = str(root / ".tmp" / "go-cache" / "postgres-recovery-build")
        environment["GOMODCACHE"] = str(root / ".tmp" / "go-cache" / "postgres-recovery-mod")
        Path(environment["GOCACHE"]).mkdir(parents=True, exist_ok=True)
        Path(environment["GOMODCACHE"]).mkdir(parents=True, exist_ok=True)

        version_result = run_command([go_executable, "version"], cwd=root / "service", env=environment)
        evidence["go_version"] = version_result.stdout.strip() or "unavailable"
        if version_result.returncode != 0:
            raise DrillFailure("unable to execute selected Go toolchain")
        version = parse_go_version(version_result.stdout)
        if version < MINIMUM_GO_VERSION:
            raise DrillFailure(
                f"unsupported Go version {version[0]}.{version[1]}.{version[2]}; minimum is 1.25.11"
            )

        for name in ("psql", "pg_dump", "pg_restore"):
            result = run_command([tools[name], "--version"], cwd=root, env=environment)
            if result.returncode != 0:
                raise DrillFailure(f"unable to read {name} version")
            client_version = result.stdout.strip()
            if parse_postgres_major(client_version) != REQUIRED_POSTGRES_MAJOR:
                raise DrillFailure(
                    f"{name} major must be {REQUIRED_POSTGRES_MAJOR}"
                )
            evidence["postgres_client_versions"][name] = client_version

        suffix = f"{os.getpid()}_{secrets.token_hex(4)}"
        source_db = sanitize_database_name(f"anopki_recovery_src_{suffix}")
        restore_db = sanitize_database_name(f"anopki_recovery_dst_{suffix}")
        created_databases.extend((source_db, restore_db))
        admin_uri = build_postgres_uri(config, "postgres", include_password=False)
        source_uri = build_postgres_uri(config, source_db, include_password=False)
        restore_uri = build_postgres_uri(config, restore_db, include_password=False)
        source_go_dsn = build_postgres_uri(config, source_db, include_password=True)
        private_values.extend((source_uri, restore_uri, source_go_dsn, source_db, restore_db))

        for database in created_databases:
            run_psql(
                admin_uri,
                f'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = \'{database}\' AND pid <> pg_backend_pid();',
                tools=tools,
                env=environment,
                cwd=root,
            )
            run_psql(admin_uri, f'DROP DATABASE IF EXISTS "{database}";', tools=tools, env=environment, cwd=root)
            run_psql(admin_uri, f'CREATE DATABASE "{database}";', tools=tools, env=environment, cwd=root)

        server_version = run_psql(source_uri, "SHOW server_version;", tools=tools, env=environment, cwd=root)
        evidence["postgres_server_version"] = server_version
        if parse_postgres_major(server_version) != REQUIRED_POSTGRES_MAJOR:
            raise DrillFailure(f"PostgreSQL server major must be {REQUIRED_POSTGRES_MAJOR}")

        test_regex = "^(" + "|".join(name for _, name in EXPECTED_TESTS) + ")$"
        test_command = [
            go_executable,
            "test",
            "-json",
            "-count=1",
            "-run",
            test_regex,
            "./internal/store",
        ]
        evidence["test_command"] = list(test_command)
        test_env = environment.copy()
        test_env["ANOPKI_POSTGRES_RECOVERY_DSN"] = source_go_dsn
        test_result = run_command(test_command, cwd=root / "service", env=test_env, timeout=300)
        observed = parse_test_events(test_result.stdout)
        evidence["tests"] = [
            {"package": package, "name": name, "status": observed.get((package, name), "missing")}
            for package, name in EXPECTED_TESTS
        ]
        if test_result.returncode != 0 or any(item["status"] != "pass" for item in evidence["tests"]):
            raise DrillFailure("one or more PostgreSQL migration rollback tests failed or were missing")
        log_lines.append(test_result.stdout)

        run_psql(source_uri, seed_sql(), tools=tools, env=environment, cwd=root, timeout=240)
        before = load_snapshot(source_uri, tools=tools, env=environment, cwd=root)
        expected_checksum = sha256_bytes((root / "service/internal/store/migrations/0002_audit_hash_chain.sql").read_bytes())
        migration = before["migration"]
        if migration.get("dirty") is not False or migration.get("checksum") != expected_checksum:
            raise DrillFailure("current PostgreSQL migration is dirty or has a checksum mismatch")

        work_dir = Path(tempfile.mkdtemp(prefix="anopki-postgres-recovery-"))
        dump_path = work_dir / "postgres-recovery.dump"
        dump_result = run_command(
            [
                tools["pg_dump"],
                "--dbname",
                source_uri,
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--file",
                str(dump_path),
            ],
            cwd=root,
            env=environment,
            timeout=300,
        )
        if dump_result.returncode != 0 or not dump_path.is_file() or dump_path.stat().st_size == 0:
            raise DrillFailure("PostgreSQL custom-format backup failed")
        evidence["backup_sha256"] = sha256_bytes(dump_path.read_bytes())

        run_psql(
            source_uri,
            """
BEGIN;
UPDATE schema_migrations SET dirty = TRUE WHERE version = 2;
UPDATE issuers SET key_ref = 'file:/damaged-postgres-recovery.key' WHERE id = 'issuer-pg-recovery-1';
UPDATE certificate_issuance_attempts SET signing_evidence_json = '' WHERE enrollment_id = 'enrollment-pg-recovery-1';
DELETE FROM webhook_deliveries WHERE outbox_message_id = 'outbox-pg-recovery-1';
DELETE FROM job_attempts WHERE outbox_message_id = 'outbox-pg-recovery-1';
DELETE FROM crl_publications WHERE id = 'crl-pg-recovery-1';
COMMIT;
""",
            tools=tools,
            env=environment,
            cwd=root,
        )
        damaged = load_snapshot(source_uri, tools=tools, env=environment, cwd=root)
        before_digest = sha256_text(json.dumps(before, separators=(",", ":"), sort_keys=True))
        damaged_digest = sha256_text(json.dumps(damaged, separators=(",", ":"), sort_keys=True))
        if damaged_digest == before_digest:
            raise DrillFailure("PostgreSQL source damage was not detected")

        restore_result = run_command(
            [
                tools["pg_restore"],
                "--dbname",
                restore_uri,
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
                str(dump_path),
            ],
            cwd=root,
            env=environment,
            timeout=300,
        )
        if restore_result.returncode != 0:
            raise DrillFailure("PostgreSQL restore failed")
        after = load_snapshot(restore_uri, tools=tools, env=environment, cwd=root)
        after_digest = sha256_text(json.dumps(after, separators=(",", ":"), sort_keys=True))
        if after_digest != before_digest:
            raise DrillFailure("restored PostgreSQL state does not match the backup source")

        evidence["state_counts"] = before["counts"]
        evidence["migration_checksum"] = expected_checksum
        evidence["state_digest_before"] = before_digest
        evidence["state_digest_after"] = after_digest
        evidence["key_reference_hashes"] = before["key_reference_hashes"]
        evidence["artifact_hashes"] = before["artifact_hashes"]
        evidence["audit_chain"] = before["audit_chain"]
        evidence["checks"] = [{"name": name, "status": "passed"} for name in EXPECTED_CHECKS]
        evidence["result"] = "passed"
        evidence["blocker"] = ""
    except DrillFailure as exc:
        evidence["blocker"] = str(exc)
        evidence["checks"] = [
            {"name": name, "status": "failed" if not evidence["checks"] else "not_run"}
            for name in EXPECTED_CHECKS
        ] if not evidence["checks"] else evidence["checks"]
    finally:
        if work_dir is not None:
            shutil.rmtree(work_dir, ignore_errors=True)
        try:
            config = parse_postgres_dsn(dsn)
            tools = require_tools(("psql", "pg_dump", "pg_restore"))
            cleanup_env = os.environ.copy()
            if config["password"]:
                cleanup_env["PGPASSWORD"] = str(config["password"])
            admin_uri = build_postgres_uri(config, "postgres", include_password=False)
            for database in reversed(created_databases):
                try:
                    run_psql(
                        admin_uri,
                        f'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = \'{database}\' AND pid <> pg_backend_pid();',
                        tools=tools,
                        env=cleanup_env,
                        cwd=root,
                    )
                    run_psql(admin_uri, f'DROP DATABASE IF EXISTS "{database}";', tools=tools, env=cleanup_env, cwd=root)
                except DrillFailure:
                    pass
        except DrillFailure:
            pass

    safe_log = redact("\n".join(log_lines), tuple(private_values), (output_dir, work_dir or output_dir))
    lowered_log = safe_log.lower()
    if any(
        forbidden.lower() in lowered_log
        for forbidden in (*SENSITIVE_FIXTURES, *PRIVATE_KEY_MARKERS, "postgres://", "postgresql://", "pgpassword")
    ):
        evidence["result"] = "failed"
        evidence["blocker"] = "forbidden sensitive content in PostgreSQL recovery test log"
        safe_log = ""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "postgres-recovery-test.log").write_text(safe_log, encoding="utf-8")
    evidence["go_version"] = redact(str(evidence["go_version"]), tuple(private_values), (output_dir,))
    evidence["postgres_server_version"] = redact(str(evidence["postgres_server_version"]), tuple(private_values), (output_dir,))
    evidence["blocker"] = redact(str(evidence["blocker"]), tuple(private_values), (output_dir,))
    write_evidence(output_dir, evidence)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--dsn", default=os.environ.get("ANOPKI_POSTGRES_RECOVERY_DSN", ""))
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--commit", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    test_regex = "^(" + "|".join(name for _, name in EXPECTED_TESTS) + ")$"
    command = [args.go, "test", "-json", "-count=1", "-run", test_regex, "./internal/store"]
    if args.list:
        print(subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command))
        return 0
    evidence = run_drill(ROOT, args.out_dir.resolve(), args.go, args.dsn, args.commit)
    if evidence["result"] == "passed":
        print(f"PostgreSQL recovery drill passed: {len(EXPECTED_CHECKS)} checks")
        return 0
    print(evidence["blocker"], file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
