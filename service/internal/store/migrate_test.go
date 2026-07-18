// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func TestApplyInitialMigrationRecordsSchemaMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	sqlBytes, err := migrationFiles.ReadFile("migrations/0001_init_sqlite.sql")
	if err != nil {
		t.Fatalf("read sqlite migration: %v", err)
	}

	var checksum string
	var dirty int
	var appliedAt string
	err = db.QueryRowContext(ctx, `
SELECT checksum, dirty, applied_at
FROM schema_migrations
WHERE version = 1`).Scan(&checksum, &dirty, &appliedAt)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if checksum != migrationChecksum(sqlBytes) {
		t.Fatalf("checksum = %q, want %q", checksum, migrationChecksum(sqlBytes))
	}
	if dirty != 0 {
		t.Fatalf("dirty = %d, want 0", dirty)
	}
	if appliedAt == "" {
		t.Fatalf("applied_at is empty")
	}
	if err := CheckInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("CheckInitialMigration returned error: %v", err)
	}

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration rerun returned error: %v", err)
	}
	var rerunAppliedAt string
	err = db.QueryRowContext(ctx, `
SELECT applied_at
FROM schema_migrations
WHERE version = 1`).Scan(&rerunAppliedAt)
	if err != nil {
		t.Fatalf("query schema_migrations after rerun: %v", err)
	}
	if rerunAppliedAt != appliedAt {
		t.Fatalf("rerun applied_at = %q, want %q", rerunAppliedAt, appliedAt)
	}
}

func TestApplyInitialMigrationPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ANOPKI_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("set ANOPKI_POSTGRES_TEST_DSN to run PostgreSQL migration integration test")
	}

	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := ApplyInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	sqlBytes, err := migrationFiles.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read postgres migration: %v", err)
	}

	var checksum string
	var dirty bool
	err = db.QueryRowContext(ctx, `
SELECT checksum, dirty
FROM schema_migrations
WHERE version = 1`).Scan(&checksum, &dirty)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if checksum != migrationChecksum(sqlBytes) {
		t.Fatalf("checksum = %q, want %q", checksum, migrationChecksum(sqlBytes))
	}
	if dirty {
		t.Fatalf("dirty = true, want false")
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("CheckInitialMigration returned error: %v", err)
	}
	if err := ApplyInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("ApplyInitialMigration rerun returned error: %v", err)
	}
}

func TestApplyInitialMigrationSerializesConcurrentSQLiteStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "anopki.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(8)

	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- ApplyInitialMigration(ctx, db, "sqlite")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ApplyInitialMigration concurrent error: %v", err)
		}
	}

	var count int
	err = db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM schema_migrations
WHERE version = 1 AND dirty = 0`).Scan(&count)
	if err != nil {
		t.Fatalf("query schema_migrations count: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_migrations clean version count = %d, want 1", count)
	}
}

func TestApplyInitialMigrationRejectsChecksumMismatch(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET checksum = 'bad' WHERE version = 1"); err != nil {
		t.Fatalf("corrupt schema_migrations checksum: %v", err)
	}

	err = ApplyInitialMigration(ctx, db, "sqlite")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("ApplyInitialMigration error = %v, want checksum mismatch", err)
	}
}

func TestApplyInitialMigrationRejectsDirtyMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET dirty = 1 WHERE version = 1"); err != nil {
		t.Fatalf("dirty schema_migrations row: %v", err)
	}

	err = ApplyInitialMigration(ctx, db, "sqlite")
	if err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("ApplyInitialMigration error = %v, want dirty migration", err)
	}
}

func TestCheckInitialMigrationRejectsDirtyMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET dirty = 1 WHERE version = 1"); err != nil {
		t.Fatalf("dirty schema_migrations row: %v", err)
	}

	err = CheckInitialMigration(ctx, db, "sqlite")
	if err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("CheckInitialMigration error = %v, want dirty migration", err)
	}
}

func TestApplyInitialMigrationUpgradesLegacySQLiteColumns(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	_, err = db.ExecContext(ctx, `
CREATE TABLE certificate_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
	validity_period_seconds INTEGER NOT NULL,
	subject_template TEXT NOT NULL,
	allowed_dns_patterns TEXT NOT NULL,
	allowed_ip_ranges TEXT NOT NULL,
	key_usage TEXT NOT NULL,
	extended_key_usage TEXT NOT NULL,
	basic_constraints TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE enrollments (
	id TEXT PRIMARY KEY,
	identity_id TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
	csr_pem TEXT NOT NULL,
	status TEXT NOT NULL,
	requested_subject TEXT NOT NULL,
	requested_dns_names TEXT NOT NULL,
	requested_ip_addresses TEXT NOT NULL,
	csr_dns_names TEXT NOT NULL,
	csr_ip_addresses TEXT NOT NULL,
	requested_not_after TEXT NOT NULL,
	approved_by TEXT NOT NULL,
	approved_at TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE certificates (
	id TEXT PRIMARY KEY,
	identity_id TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
	enrollment_id TEXT NOT NULL,
	serial_number TEXT NOT NULL,
	subject TEXT NOT NULL,
	dns_names TEXT NOT NULL,
	ip_addresses TEXT NOT NULL,
	not_before TEXT NOT NULL,
	not_after TEXT NOT NULL,
	status TEXT NOT NULL,
	certificate_pem TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE acme_accounts (
	id TEXT PRIMARY KEY,
	contacts TEXT NOT NULL,
	status TEXT NOT NULL,
	terms_of_service_agreed INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	for _, tt := range []struct {
		table string
		name  string
	}{
		{table: "identities", name: "owner"},
		{table: "identities", name: "team"},
		{table: "identities", name: "service"},
		{table: "identities", name: "environment"},
		{table: "identities", name: "deployment_target"},
		{table: "identities", name: "last_seen_at"},
		{table: "identities", name: "metadata_json"},
		{table: "identities", name: "allowed_dns_names"},
		{table: "identities", name: "allowed_ip_addresses"},
		{table: "certificate_profiles", name: "subject_key_identifier"},
		{table: "certificate_profiles", name: "authority_key_identifier"},
		{table: "certificate_profiles", name: "public_tls"},
		{table: "certificate_profiles", name: "allowed_key_algorithms"},
		{table: "certificate_profiles", name: "min_key_size_bits"},
		{table: "certificate_profiles", name: "allowed_signature_algorithms"},
		{table: "enrollments", name: "certificate_profile_id"},
		{table: "enrollments", name: "source_certificate_id"},
		{table: "certificates", name: "certificate_profile_id"},
		{table: "certificates", name: "renewal_notified_at"},
		{table: "outbox_messages", name: "attempt_count"},
		{table: "outbox_messages", name: "max_attempts"},
		{table: "outbox_messages", name: "last_error"},
		{table: "outbox_messages", name: "processing_deadline_at"},
		{table: "notification_endpoints", name: "secret"},
		{table: "certificate_issuance_attempts", name: "signing_evidence_json"},
		{table: "acme_accounts", name: "key_thumbprint"},
		{table: "acme_accounts", name: "key_jwk_json"},
		{table: "acme_authorizations", name: "validation_reuse_expires_at"},
	} {
		if !testSQLiteColumnExists(t, db, tt.table, tt.name) {
			t.Fatalf("column %s.%s does not exist after migration", tt.table, tt.name)
		}
	}
	for _, table := range []string{"ocsp_responders", "outbox_messages", "job_attempts", "notification_endpoints", "certificate_issuance_attempts", "acme_accounts", "acme_orders", "acme_authorizations", "acme_challenges"} {
		if !testSQLiteTableExists(t, db, table) {
			t.Fatalf("table %s does not exist after migration", table)
		}
	}
	for _, index := range []string{
		"idx_certificates_enrollment",
		"idx_certificates_issuer_serial",
		"idx_certificates_list_query",
		"idx_certificates_renewal_query",
		"idx_certificates_expiration_scan",
		"idx_identities_inventory_fields",
		"idx_identities_list_query",
		"idx_enrollments_list_query",
		"idx_certificate_issuance_attempts_status_lease",
		"idx_crl_publications_issuer_distribution_number",
		"idx_acme_accounts_key_thumbprint",
		"idx_outbox_messages_list_query",
	} {
		if !testSQLiteIndexExists(t, db, index) {
			t.Fatalf("index %s does not exist after migration", index)
		}
	}
}

func TestUnmarshalBasicConstraintsPolicyNormalizesLegacyLeafPathLen(t *testing.T) {
	var policy domain.BasicConstraintsPolicy
	if err := unmarshalBasicConstraintsPolicy(`{"critical":true,"ca":false,"max_path_len":0}`, &policy); err != nil {
		t.Fatalf("unmarshalBasicConstraintsPolicy returned error: %v", err)
	}
	if policy.MaxPathLen != nil {
		t.Fatalf("leaf legacy MaxPathLen = %#v, want nil", policy.MaxPathLen)
	}

	var caPolicy domain.BasicConstraintsPolicy
	if err := unmarshalBasicConstraintsPolicy(`{"critical":true,"ca":true,"max_path_len":0}`, &caPolicy); err != nil {
		t.Fatalf("unmarshalBasicConstraintsPolicy CA returned error: %v", err)
	}
	if caPolicy.MaxPathLen == nil || *caPolicy.MaxPathLen != 0 {
		t.Fatalf("CA MaxPathLen = %#v, want pointer to 0", caPolicy.MaxPathLen)
	}
}

func testSQLiteColumnExists(t *testing.T, db *sql.DB, table string, name string) bool {
	t.Helper()

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var columnName string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan PRAGMA table_info(%s): %v", table, err)
		}
		if columnName == name {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate PRAGMA table_info(%s): %v", table, err)
	}
	return false
}

func testSQLiteTableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	return name == table
}

func testSQLiteIndexExists(t *testing.T, db *sql.DB, index string) bool {
	t.Helper()

	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?", index).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("query sqlite_master for %s: %v", index, err)
	}
	return name == index
}

func TestApplyInitialMigrationBackfillsAuditHashChain(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := createSchemaMigrationsTable(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	v1, err := migrationFiles.ReadFile("migrations/0001_init_sqlite.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(v1)); err != nil {
		t.Fatal(err)
	}
	if err := insertSchemaMigration(ctx, db, "sqlite", 1, migrationChecksum(v1), false); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for _, event := range []domain.AuditEvent{
		testAuditEvent("legacy-audit-1", "alice", "identity.created", "identity", "identity-1", base),
		testAuditEvent("legacy-audit-2", "bob", "certificate.issued", "certificate", "certificate-1", base.Add(time.Minute)),
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO audit_events (id, actor, action, resource_type, resource_id, metadata_json, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, event.ID, event.Actor, event.Action, event.ResourceType, event.ResourceID, event.MetadataJSON, formatSQLTime(event.CreatedAt)); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	verification, err := NewSQLStore(db).VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Verified || verification.TotalEventCount != 2 || verification.TailChainIndex != 2 {
		t.Fatalf("verification = %#v", verification)
	}
	var version2 int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 2 AND dirty = 0`).Scan(&version2); err != nil {
		t.Fatal(err)
	}
	if version2 != 1 {
		t.Fatalf("version 2 count = %d", version2)
	}
}
