#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run a deterministic SQLite backup/restore evidence drill for AnoPKI Community."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = Path("service/internal/store/migrations/0001_init_sqlite.sql")
AUDIT_MIGRATION = Path("service/internal/store/migrations/0002_audit_hash_chain_sqlite.sql")
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN " + b"PRIVATE KEY-----",
    b"-----BEGIN " + b"RSA PRIVATE KEY-----",
    b"-----BEGIN " + b"EC PRIVATE KEY-----",
    b"-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----",
)
SENSITIVE_FIXTURES = (
    "file:/var/lib/anopki/test-issuer.key",
    "pkcs11:test-responder",
    "test-webhook-secret-not-production",
    "test-api-token-hash",
)
SELECTED_TABLES = (
    "schema_migrations",
    "issuers",
    "ocsp_responders",
    "certificates",
    "certificate_issuance_attempts",
    "revocations",
    "crl_publications",
    "crl_generation_claims",
    "audit_events",
    "audit_chain_state",
    "outbox_messages",
    "job_attempts",
    "notification_endpoints",
    "webhook_deliveries",
    "api_keys",
)
EXPECTED_COUNTS = {
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


class DrillFailure(RuntimeError):
    """A fail-closed recovery drill failure."""


@dataclass(frozen=True)
class DrillContext:
    root: Path
    work_dir: Path
    migration_checksum: str
    audit_migration_checksum: str
    commit: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
    metadata = json.loads(metadata_json)
    payload = {
        "hash_algorithm": "sha256-v1",
        "sequence": sequence,
        "id": event_id,
        "actor": actor,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "metadata": metadata,
        "created_at": created_at,
    }
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_bytes(previous_hash.encode("utf-8") + encoded)


def resolve_commit(root: Path, explicit: str | None) -> str:
    if explicit:
        if not re.fullmatch(r"[0-9a-f]{40}", explicit):
            raise DrillFailure("commit must be an exact lowercase 40-character SHA")
        return explicit
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    value = result.stdout.strip().lower()
    if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", value):
        return value
    return "unavailable"


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(ctx: DrillContext, path: Path) -> None:
    migration_path = ctx.root / MIGRATION
    sql = migration_path.read_text(encoding="utf-8")
    audit_sql = (ctx.root / AUDIT_MIGRATION).read_text(encoding="utf-8")
    with connect(path) as db:
        db.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                dirty INTEGER NOT NULL
            )
            """
        )
        db.executescript(sql)
        columns = {
            row[1]
            for row in db.execute("PRAGMA table_info(certificate_issuance_attempts)")
        }
        if "signing_evidence_json" not in columns:
            db.execute(
                "ALTER TABLE certificate_issuance_attempts "
                "ADD COLUMN signing_evidence_json TEXT NOT NULL DEFAULT ''"
            )
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
                endpoint_id TEXT NOT NULL REFERENCES notification_endpoints(id),
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                last_attempted_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (outbox_message_id, endpoint_id)
            );
            CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
                ON webhook_deliveries(endpoint_id, updated_at);
            CREATE TABLE IF NOT EXISTS crl_generation_claims (
                issuer_id TEXT NOT NULL REFERENCES issuers(id),
                distribution_point TEXT NOT NULL,
                crl_number INTEGER NOT NULL,
                lease_expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (issuer_id, distribution_point)
            );
            CREATE INDEX IF NOT EXISTS idx_crl_generation_claims_lease
                ON crl_generation_claims(lease_expires_at, issuer_id, distribution_point);
            """
        )
        db.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at, dirty) VALUES (?, ?, ?, 0)",
            (1, ctx.migration_checksum, "2026-07-17T00:00:00Z"),
        )
        db.executescript(audit_sql)
        db.execute(
            "INSERT INTO schema_migrations(version, checksum, applied_at, dirty) VALUES (?, ?, ?, 0)",
            (2, ctx.audit_migration_checksum, "2026-07-17T00:00:01Z"),
        )
        seed_database(db)


def seed_database(db: sqlite3.Connection) -> None:
    certificate_pem = "-----BEGIN CERTIFICATE-----\nVEVTVC1DRVJUSUZJQ0FURQ==\n-----END CERTIFICATE-----\n"
    responder_pem = "-----BEGIN CERTIFICATE-----\nVEVTVC1PQ1NQLVJFU1BPTkRFUg==\n-----END CERTIFICATE-----\n"
    crl_pem = "-----BEGIN X509 CRL-----\nVEVTVC1DUkwtQVJUSUZBQ1Q=\n-----END X509 CRL-----\n"
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
    )
    now = "2026-07-17T00:00:00Z"
    db.execute(
        "INSERT INTO identities VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "identity-restore-1", "service", "restore-fixture", "", "platform", "pki", "anopki",
            "test", "recovery-drill", None, "{}", '["restore.example"]', "[]", "active", now, now,
        ),
    )
    db.execute(
        "INSERT INTO issuers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "issuer-restore-1", "Recovery Test CA", "root_ca", "active", "", certificate_pem,
            SENSITIVE_FIXTURES[0], "https://pki.example/issuer", '["https://pki.example/crl"]', 1, now, now,
        ),
    )
    db.execute(
        "INSERT INTO ocsp_responders VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "responder-restore-1", "issuer-restore-1", "Recovery OCSP", "active", responder_pem,
            SENSITIVE_FIXTURES[1], now, now,
        ),
    )
    db.execute(
        "INSERT INTO notification_endpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "endpoint-restore-1", "Recovery Receiver", "webhook", "active",
            "https://receiver.invalid/anopki", SENSITIVE_FIXTURES[2], '["certificate.issued"]', now, now,
        ),
    )
    db.execute(
        "INSERT INTO certificate_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "profile-restore-1", "Recovery Profile", "test-only", "issuer-restore-1", 86400,
            "CN={{identity.name}}", '["restore.example"]', "[]", '["rsa"]', 2048,
            '["rsa-sha256"]', "{}", "{}", "{}", 1, 1, 0, now, now,
        ),
    )
    db.execute(
        "INSERT INTO enrollments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "enrollment-restore-1", "identity-restore-1", "issuer-restore-1", "profile-restore-1", "",
            "-----BEGIN CERTIFICATE REQUEST-----\nVEVTVA==\n-----END CERTIFICATE REQUEST-----\n", "issued",
            "CN=restore.example", '["restore.example"]', "[]", '["restore.example"]', "[]",
            "2026-07-18T00:00:00Z", "operator", now, now, now,
        ),
    )
    db.execute(
        "INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "certificate-restore-1", "identity-restore-1", "issuer-restore-1", "enrollment-restore-1",
            "profile-restore-1", "1001", "CN=restore.example", '["restore.example"]', "[]",
            now, "2026-07-18T00:00:00Z", "revoked", certificate_pem, None, now, now,
        ),
    )
    db.execute(
        """
        INSERT INTO certificate_issuance_attempts (
            enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number,
            subject, not_before, not_after, signing_started_at, signed_at, finalized_at, last_error,
            created_at, updated_at, signing_evidence_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "enrollment-restore-1", "signed", None, "certificate-restore-1", certificate_pem, "1001",
            "CN=restore.example", now, "2026-07-18T00:00:00Z", now, now, None, "", now, now,
            signing_evidence,
        ),
    )
    db.execute(
        "INSERT INTO revocations VALUES (?, ?, ?, ?, ?, ?)",
        ("revocation-restore-1", "certificate-restore-1", "key_compromise", "operator", now, now),
    )
    db.execute(
        "INSERT INTO crl_publications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "crl-restore-1", "issuer-restore-1", "https://pki.example/crl", 42, now,
            "2026-07-18T00:00:00Z", "published", crl_pem, now, now,
        ),
    )
    audit_metadata_1 = '{"result":"ok","signing_proven":true}'
    audit_metadata_2 = '{"reason":"key_compromise"}'
    audit_created_1 = now
    audit_created_2 = "2026-07-17T00:01:00Z"
    audit_hash_1 = audit_event_hash(
        "", sequence=1, event_id="audit-restore-1", actor="operator",
        action="certificate.issued", resource_type="certificate",
        resource_id="certificate-restore-1", metadata_json=audit_metadata_1,
        created_at=audit_created_1,
    )
    audit_hash_2 = audit_event_hash(
        audit_hash_1, sequence=2, event_id="audit-restore-2", actor="operator",
        action="certificate.revoked", resource_type="certificate",
        resource_id="certificate-restore-1", metadata_json=audit_metadata_2,
        created_at=audit_created_2,
    )
    db.execute(
        """
        INSERT INTO audit_events (
            id, actor, action, resource_type, resource_id, metadata_json, created_at,
            sequence, hash_algorithm, previous_event_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "audit-restore-1", "operator", "certificate.issued", "certificate",
            "certificate-restore-1", audit_metadata_1, audit_created_1,
            1, "sha256-v1", "", audit_hash_1,
        ),
    )
    db.execute(
        """
        INSERT INTO audit_events (
            id, actor, action, resource_type, resource_id, metadata_json, created_at,
            sequence, hash_algorithm, previous_event_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "audit-restore-2", "operator", "certificate.revoked", "certificate",
            "certificate-restore-1", audit_metadata_2, audit_created_2,
            2, "sha256-v1", audit_hash_1, audit_hash_2,
        ),
    )
    db.execute(
        """
        INSERT INTO audit_chain_state (
            singleton_id, hash_algorithm, latest_sequence, latest_event_hash,
            checkpoint_sequence, checkpoint_event_hash, updated_at
        ) VALUES (1, ?, ?, ?, 0, '', ?)
        """,
        ("sha256-v1", 2, audit_hash_2, audit_created_2),
    )
    db.execute(
        "INSERT INTO outbox_messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "outbox-restore-1", "certificate.revoked", '{"certificate_id":"certificate-restore-1"}',
            "dead_letter", now, None, 3, 3, "receiver unavailable", now, now,
        ),
    )
    db.execute(
        "INSERT INTO job_attempts VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "job-restore-1", "outbox-restore-1", "failed", "receiver unavailable", now,
            "2026-07-17T00:00:05Z", now,
        ),
    )
    db.execute(
        "INSERT INTO webhook_deliveries VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "outbox-restore-1", "endpoint-restore-1", "failed", 3, "receiver unavailable",
            "2026-07-17T00:00:05Z", now, now,
        ),
    )
    db.execute(
        "INSERT INTO api_keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "api-key-restore-1", "Recovery Operator", SENSITIVE_FIXTURES[3], "active", "operator",
            '["operator"]', None, None, now, now,
        ),
    )


def table_rows(db: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    columns = [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
    rows = [dict(zip(columns, row, strict=True)) for row in db.execute(f"SELECT * FROM {table}")]
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")))


def state_manifest(db: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    return {table: table_rows(db, table) for table in SELECTED_TABLES}


def state_digest(db: sqlite3.Connection) -> str:
    payload = json.dumps(state_manifest(db), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_text(payload)


def counts(db: sqlite3.Connection) -> dict[str, int]:
    return {table: int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in SELECTED_TABLES}


def create_backup(source: Path, target: Path) -> None:
    with connect(source) as source_db, connect(target) as target_db:
        source_db.backup(target_db)


def mutate_live_database(path: Path) -> None:
    with connect(path) as db:
        db.execute("DELETE FROM crl_publications")
        db.execute("UPDATE outbox_messages SET status = 'completed', last_error = ''")
        db.execute("UPDATE certificate_issuance_attempts SET signing_evidence_json = ''")
        db.execute("UPDATE schema_migrations SET dirty = 1")


def verify_restored_database(ctx: DrillContext, path: Path, expected_digest: str) -> tuple[list[dict[str, str]], dict[str, int], dict[str, str]]:
    checks: list[dict[str, str]] = []
    database_bytes = path.read_bytes()
    if any(marker in database_bytes for marker in PRIVATE_KEY_MARKERS):
        raise DrillFailure("restored database contains private-key material")
    with connect(path) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise DrillFailure(f"SQLite integrity check failed: {integrity}")
        checks.append({"name": "sqlite-integrity", "status": "passed"})
        foreign_key_rows = list(db.execute("PRAGMA foreign_key_check"))
        if foreign_key_rows:
            raise DrillFailure("SQLite foreign-key check failed")
        checks.append({"name": "foreign-key-integrity", "status": "passed"})

        migrations = list(
            db.execute(
                "SELECT version, checksum, dirty FROM schema_migrations ORDER BY version"
            )
        )
        expected_migrations = [
            (1, ctx.migration_checksum, 0),
            (2, ctx.audit_migration_checksum, 0),
        ]
        if migrations != expected_migrations:
            raise DrillFailure("schema migration state is missing, dirty, or checksum-mismatched")
        checks.append({"name": "schema-migration", "status": "passed"})

        restored_digest = state_digest(db)
        if restored_digest != expected_digest:
            raise DrillFailure("restored database state digest does not match the backup source")
        checks.append({"name": "restore-state-match", "status": "passed"})

        observed_counts = counts(db)
        if observed_counts != EXPECTED_COUNTS:
            raise DrillFailure("restored table counts do not match the recovery fixture")
        checks.append({"name": "state-counts", "status": "passed"})

        issuer_key_ref = db.execute("SELECT key_ref FROM issuers WHERE status = 'active'").fetchone()
        responder_key_ref = db.execute("SELECT key_ref FROM ocsp_responders WHERE status = 'active'").fetchone()
        if issuer_key_ref != (SENSITIVE_FIXTURES[0],) or responder_key_ref != (SENSITIVE_FIXTURES[1],):
            raise DrillFailure("active issuer or OCSP responder key reference was not preserved")
        checks.append({"name": "key-reference-preservation", "status": "passed"})

        crl = db.execute(
            "SELECT crl_number, status, crl_pem FROM crl_publications WHERE issuer_id = ? ORDER BY crl_number DESC LIMIT 1",
            ("issuer-restore-1",),
        ).fetchone()
        if crl is None or crl[0] != 42 or crl[1] != "published" or "BEGIN X509 CRL" not in crl[2]:
            raise DrillFailure("latest CRL publication was not restored")
        checks.append({"name": "crl-artifact", "status": "passed"})

        attempt = db.execute(
            "SELECT status, signing_evidence_json FROM certificate_issuance_attempts WHERE enrollment_id = ?",
            ("enrollment-restore-1",),
        ).fetchone()
        if attempt is None or attempt[0] != "signed":
            raise DrillFailure("signed issuance attempt was not restored")
        try:
            evidence = json.loads(attempt[1])
        except json.JSONDecodeError as exc:
            raise DrillFailure("restored signing evidence is not valid JSON") from exc
        if evidence.get("result_code") != "ok" or evidence.get("fallback_used") is not False:
            raise DrillFailure("restored signing evidence is not a proven no-fallback result")
        checks.append({"name": "issuance-attempt", "status": "passed"})

        outbox = db.execute(
            "SELECT status, attempt_count, max_attempts FROM outbox_messages WHERE id = ?",
            ("outbox-restore-1",),
        ).fetchone()
        delivery = db.execute(
            "SELECT status, attempt_count FROM webhook_deliveries WHERE outbox_message_id = ?",
            ("outbox-restore-1",),
        ).fetchone()
        if outbox != ("dead_letter", 3, 3) or delivery != ("failed", 3):
            raise DrillFailure("outbox or webhook delivery failure state was not restored")
        checks.append({"name": "outbox-and-webhook-state", "status": "passed"})

        audit_rows = list(
            db.execute(
                """
                SELECT id, sequence, hash_algorithm, previous_event_hash, event_hash,
                       actor, action, resource_type, resource_id, metadata_json, created_at
                FROM audit_events ORDER BY sequence
                """
            )
        )
        if len(audit_rows) != 2:
            raise DrillFailure("audit event state was not restored")
        checks.append({"name": "audit-state", "status": "passed"})
        previous_hash = ""
        for row in audit_rows:
            expected_hash = audit_event_hash(
                previous_hash,
                sequence=int(row[1]),
                event_id=str(row[0]),
                actor=str(row[5]),
                action=str(row[6]),
                resource_type=str(row[7]),
                resource_id=str(row[8]),
                metadata_json=str(row[9]),
                created_at=str(row[10]),
            )
            if row[2] != "sha256-v1" or row[3] != previous_hash or row[4] != expected_hash:
                raise DrillFailure("audit hash chain was not restored intact")
            previous_hash = str(row[4])
        chain_state = db.execute(
            """
            SELECT hash_algorithm, latest_sequence, latest_event_hash,
                   checkpoint_sequence, checkpoint_event_hash
            FROM audit_chain_state WHERE singleton_id = 1
            """
        ).fetchone()
        if chain_state != ("sha256-v1", 2, previous_hash, 0, ""):
            raise DrillFailure("audit chain checkpoint state was not restored")
        checks.append({"name": "audit-chain-state", "status": "passed"})

        artifact_hashes = {
            "certificate_pem": "sha256:" + sha256_text(
                db.execute("SELECT certificate_pem FROM certificates WHERE id = ?", ("certificate-restore-1",)).fetchone()[0]
            ),
            "crl_pem": "sha256:" + sha256_text(crl[2]),
            "signing_evidence": "sha256:" + sha256_text(attempt[1]),
        }

    database_bytes = path.read_bytes()
    if any(marker in database_bytes for marker in PRIVATE_KEY_MARKERS):
        raise DrillFailure("restored database contains private-key material")
    checks.append({"name": "private-key-exclusion", "status": "passed"})
    return checks, observed_counts, artifact_hashes


def render_markdown(evidence: dict[str, Any]) -> str:
    lines = [
        "# AnoPKI Community Recovery Drill Evidence",
        "",
        f"- Result: `{evidence['result']}`",
        f"- Commit: `{evidence['commit']}`",
        f"- Database: `{evidence['database_driver']}`",
        f"- Migration: `{evidence['migration_version']}`",
        f"- Backup SHA-256: `{evidence['backup_sha256']}`",
        f"- Restored state SHA-256: `{evidence['restored_state_sha256']}`",
        "",
        "## Checks",
        "",
    ]
    for check in evidence["checks"]:
        lines.append(f"- `{check['name']}`: {check['status']}")
    lines.extend(
        [
            "",
            "## Redaction",
            "",
            "The evidence omits raw key references, webhook secrets, API-key hashes, database files, and private-key material.",
            "",
        ]
    )
    return "\n".join(lines)


def run_drill(root: Path, out_dir: Path, commit: str) -> dict[str, Any]:
    started_at = utc_now()
    migration_bytes = (root / MIGRATION).read_bytes()
    migration_checksum = sha256_bytes(migration_bytes)
    audit_migration_bytes = (root / AUDIT_MIGRATION).read_bytes()
    audit_migration_checksum = sha256_bytes(audit_migration_bytes)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="anopki-recovery-") as tmp:
        work_dir = Path(tmp)
        ctx = DrillContext(
            root=root,
            work_dir=work_dir,
            migration_checksum=migration_checksum,
            audit_migration_checksum=audit_migration_checksum,
            commit=commit,
        )
        live = work_dir / "live.db"
        backup = work_dir / "backup.db"
        restored = work_dir / "restored.db"
        initialize_database(ctx, live)
        with connect(live) as db:
            expected_digest = state_digest(db)
        create_backup(live, backup)
        backup_sha256 = sha256_bytes(backup.read_bytes())
        mutate_live_database(live)
        create_backup(backup, restored)
        checks, observed_counts, artifact_hashes = verify_restored_database(ctx, restored, expected_digest)

        evidence: dict[str, Any] = {
            "schema_version": 1,
            "product": "AnoPKI",
            "edition": "community",
            "product_profile": "community-openssl",
            "commit": commit,
            "database_driver": "sqlite",
            "migration_version": 2,
            "migration_checksum": audit_migration_checksum,
            "started_at": started_at,
            "completed_at": utc_now(),
            "result": "passed",
            "backup_sha256": backup_sha256,
            "restored_state_sha256": expected_digest,
            "state_counts": observed_counts,
            "artifact_hashes": artifact_hashes,
            "checks": checks,
            "redaction": {
                "private_key_markers_found": False,
                "raw_key_references_in_evidence": False,
                "sensitive_fixture_values_in_evidence": False,
            },
        }

    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    markdown = render_markdown(evidence)
    lowered = (serialized + markdown).lower()
    for sensitive in SENSITIVE_FIXTURES:
        if sensitive.lower() in lowered:
            raise DrillFailure("recovery evidence exposed a sensitive fixture value")
    forbidden_markers = tuple(marker.decode("ascii").lower() for marker in PRIVATE_KEY_MARKERS)
    for forbidden in forbidden_markers:
        if forbidden in lowered:
            raise DrillFailure("recovery evidence exposed private-key material")
    (out_dir / "recovery-verification.json").write_text(serialized, encoding="utf-8")
    (out_dir / "recovery-verification.md").write_text(markdown, encoding="utf-8")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out-dir", type=Path, default=Path(".tmp/recovery-evidence"))
    parser.add_argument("--commit")
    args = parser.parse_args()
    root = args.root.resolve()
    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    try:
        evidence = run_drill(root, out_dir.resolve(), resolve_commit(root, args.commit))
    except (DrillFailure, OSError, sqlite3.Error) as exc:
        print(f"recovery drill failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"recovery drill passed: {len(evidence['checks'])} checks")


if __name__ == "__main__":
    main()
