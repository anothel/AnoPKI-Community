// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

//go:embed migrations/0001_init.sql migrations/0001_init_sqlite.sql
var migrationFiles embed.FS

const initialMigrationVersion = 1
const sqliteMigrationBusyTimeoutMS = 5000
const postgresMigrationAdvisoryLockID int64 = 5847545710944921361

func ApplyInitialMigration(ctx context.Context, db *sql.DB, driver string) error {
	path, err := initialMigrationPath(driver)
	if err != nil {
		return err
	}

	sqlBytes, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read initial migration: %w", err)
	}

	tx, err := beginMigrationTx(ctx, db, driver)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := createSchemaMigrationsTable(ctx, tx, driver); err != nil {
		return err
	}
	checksum := migrationChecksum(sqlBytes)
	applied, err := checkSchemaMigration(ctx, tx, initialMigrationVersion, checksum)
	if err != nil {
		return err
	}
	if !applied {
		if err := insertSchemaMigration(ctx, tx, driver, initialMigrationVersion, checksum, true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("execute initial migration: %w", err)
		}
	}
	if err := applyCompatibilityMigrations(ctx, tx, driver); err != nil {
		return err
	}
	if !applied {
		if err := markSchemaMigrationClean(ctx, tx, driver, initialMigrationVersion, checksum); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func CheckInitialMigration(ctx context.Context, db *sql.DB, driver string) error {
	path, err := initialMigrationPath(driver)
	if err != nil {
		return err
	}
	sqlBytes, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read initial migration: %w", err)
	}
	applied, err := checkSchemaMigration(ctx, db, initialMigrationVersion, migrationChecksum(sqlBytes))
	if err != nil {
		return err
	}
	if !applied {
		return fmt.Errorf("schema migration version %d is not applied", initialMigrationVersion)
	}
	return nil
}

type migrationTx struct {
	sqlExecutor
	commit   func() error
	rollback func() error
	done     bool
}

func beginMigrationTx(ctx context.Context, db *sql.DB, driver string) (*migrationTx, error) {
	switch driver {
	case "sqlite":
		return beginSQLiteMigrationTx(ctx, db)
	case "pgx":
		return beginPostgresMigrationTx(ctx, db)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
}

func beginSQLiteMigrationTx(ctx context.Context, db *sql.DB) (*migrationTx, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open sqlite migration connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", sqliteMigrationBusyTimeoutMS)); err != nil {
		return nil, fmt.Errorf("set sqlite migration busy timeout: %w", errors.Join(err, conn.Close()))
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("begin sqlite migration transaction: %w", errors.Join(err, conn.Close()))
	}
	return &migrationTx{
		sqlExecutor: conn,
		commit: func() error {
			if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
				return errors.Join(err, conn.Close())
			}
			return conn.Close()
		},
		rollback: func() error {
			_, err := conn.ExecContext(ctx, "ROLLBACK")
			closeErr := conn.Close()
			if err != nil {
				return err
			}
			return closeErr
		},
	}, nil
}

func beginPostgresMigrationTx(ctx context.Context, db *sql.DB) (*migrationTx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin postgres migration transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", postgresMigrationAdvisoryLockID); err != nil {
		return nil, fmt.Errorf("lock postgres migration transaction: %w", errors.Join(err, tx.Rollback()))
	}
	return &migrationTx{
		sqlExecutor: tx,
		commit:      tx.Commit,
		rollback:    tx.Rollback,
	}, nil
}

func (tx *migrationTx) Commit() error {
	if tx.done {
		return nil
	}
	tx.done = true
	return tx.commit()
}

func (tx *migrationTx) Rollback() {
	if tx.done {
		return
	}
	tx.done = true
	_ = tx.rollback()
}

func initialMigrationPath(driver string) (string, error) {
	switch driver {
	case "sqlite":
		return "migrations/0001_init_sqlite.sql", nil
	case "pgx":
		return "migrations/0001_init.sql", nil
	default:
		return "", fmt.Errorf("unsupported database driver %q", driver)
	}
}

func migrationChecksum(sqlBytes []byte) string {
	sum := sha256.Sum256(sqlBytes)
	return hex.EncodeToString(sum[:])
}

func createSchemaMigrationsTable(ctx context.Context, exec sqlExecutor, driver string) error {
	appliedAtType := "TEXT"
	dirtyType := "INTEGER"
	if driver == "pgx" {
		appliedAtType = "TIMESTAMPTZ"
		dirtyType = "BOOLEAN"
	}

	_, err := exec.ExecContext(ctx, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	checksum TEXT NOT NULL,
	applied_at %s NOT NULL,
	dirty %s NOT NULL
)`, appliedAtType, dirtyType))
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func checkSchemaMigration(ctx context.Context, exec sqlExecutor, version int, checksum string) (bool, error) {
	var storedChecksum string
	var dirty int
	err := exec.QueryRowContext(ctx, `
SELECT checksum, CASE WHEN dirty THEN 1 ELSE 0 END
FROM schema_migrations
WHERE version = $1`, version).Scan(&storedChecksum, &dirty)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read schema_migrations version %d: %w", version, err)
	}
	if dirty != 0 {
		return false, fmt.Errorf("schema migration version %d is dirty", version)
	}
	if storedChecksum != checksum {
		return false, fmt.Errorf("schema migration version %d checksum mismatch", version)
	}
	return true, nil
}

func insertSchemaMigration(ctx context.Context, exec sqlExecutor, driver string, version int, checksum string, dirty bool) error {
	_, err := exec.ExecContext(ctx, `
INSERT INTO schema_migrations (version, checksum, applied_at, dirty)
VALUES ($1, $2, $3, $4)`,
		version,
		checksum,
		formatSQLTime(time.Now()),
		migrationDirtyValue(driver, dirty),
	)
	if err != nil {
		return fmt.Errorf("insert schema_migrations version %d: %w", version, err)
	}
	return nil
}

func markSchemaMigrationClean(ctx context.Context, exec sqlExecutor, driver string, version int, checksum string) error {
	_, err := exec.ExecContext(ctx, `
UPDATE schema_migrations
SET checksum = $1, applied_at = $2, dirty = $3
WHERE version = $4`,
		checksum,
		formatSQLTime(time.Now()),
		migrationDirtyValue(driver, false),
		version,
	)
	if err != nil {
		return fmt.Errorf("mark schema_migrations version %d clean: %w", version, err)
	}
	return nil
}

func migrationDirtyValue(driver string, dirty bool) any {
	if driver == "sqlite" {
		if dirty {
			return 1
		}
		return 0
	}
	return dirty
}

func applyCompatibilityMigrations(ctx context.Context, db sqlExecutor, driver string) error {
	switch driver {
	case "sqlite":
		return applySQLiteCompatibilityMigrations(ctx, db)
	case "pgx":
		return applyPostgresCompatibilityMigrations(ctx, db)
	default:
		return fmt.Errorf("unsupported database driver %q", driver)
	}
}

func applySQLiteCompatibilityMigrations(ctx context.Context, db sqlExecutor) error {
	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{table: "identities", name: "owner", definition: "owner TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "team", definition: "team TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "service", definition: "service TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "environment", definition: "environment TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "deployment_target", definition: "deployment_target TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "last_seen_at", definition: "last_seen_at TEXT"},
		{table: "identities", name: "metadata_json", definition: "metadata_json TEXT NOT NULL DEFAULT ''"},
		{table: "identities", name: "allowed_dns_names", definition: "allowed_dns_names TEXT NOT NULL DEFAULT '[]'"},
		{table: "identities", name: "allowed_ip_addresses", definition: "allowed_ip_addresses TEXT NOT NULL DEFAULT '[]'"},
		{table: "issuers", name: "parent_issuer_id", definition: "parent_issuer_id TEXT NOT NULL DEFAULT ''"},
		{table: "issuers", name: "aia_url", definition: "aia_url TEXT NOT NULL DEFAULT ''"},
		{table: "issuers", name: "crl_distribution_points", definition: "crl_distribution_points TEXT NOT NULL DEFAULT '[]'"},
		{table: "issuers", name: "trust_anchor", definition: "trust_anchor INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "subject_key_identifier", definition: "subject_key_identifier INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "authority_key_identifier", definition: "authority_key_identifier INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "public_tls", definition: "public_tls INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "allowed_key_algorithms", definition: "allowed_key_algorithms TEXT NOT NULL DEFAULT '[]'"},
		{table: "certificate_profiles", name: "min_key_size_bits", definition: "min_key_size_bits INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "allowed_signature_algorithms", definition: "allowed_signature_algorithms TEXT NOT NULL DEFAULT '[]'"},
		{table: "enrollments", name: "certificate_profile_id", definition: "certificate_profile_id TEXT NOT NULL DEFAULT ''"},
		{table: "enrollments", name: "source_certificate_id", definition: "source_certificate_id TEXT NOT NULL DEFAULT ''"},
		{table: "certificates", name: "certificate_profile_id", definition: "certificate_profile_id TEXT NOT NULL DEFAULT ''"},
		{table: "certificates", name: "renewal_notified_at", definition: "renewal_notified_at TEXT"},
		{table: "certificate_issuance_attempts", name: "signing_evidence_json", definition: "signing_evidence_json TEXT NOT NULL DEFAULT ''"},
	}

	for _, column := range columns {
		exists, err := sqliteColumnExists(ctx, db, column.table, column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", column.table, column.definition)); err != nil {
			return fmt.Errorf("add sqlite column %s.%s: %w", column.table, column.name, err)
		}
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS outbox_messages (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL,
			available_at TEXT NOT NULL,
			processing_deadline_at TEXT,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_due
			ON outbox_messages(status, available_at, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_processing_deadline
			ON outbox_messages(status, processing_deadline_at, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS job_attempts (
			id TEXT PRIMARY KEY,
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			status TEXT NOT NULL,
			error TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_attempts_outbox_message
			ON job_attempts(outbox_message_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS notification_endpoints (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL DEFAULT '',
			event_types TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_endpoints_status
			ON notification_endpoints(status, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			endpoint_id TEXT NOT NULL REFERENCES notification_endpoints(id),
			status TEXT NOT NULL,
			attempt_count INTEGER NOT NULL,
			last_error TEXT NOT NULL,
			last_attempted_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (outbox_message_id, endpoint_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
			ON webhook_deliveries(endpoint_id, updated_at)`,
		`CREATE INDEX IF NOT EXISTS idx_identities_inventory_fields
			ON identities(owner, team, service, environment, deployment_target, id)`,
		`CREATE INDEX IF NOT EXISTS idx_identities_list_query
			ON identities(owner, team, service, environment, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_enrollments_list_query
			ON enrollments(identity_id, issuer_id, certificate_profile_id, status, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_expiration_scan
			ON certificates(status, not_after, renewal_notified_at, id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_enrollment
			ON certificates(enrollment_id)
			WHERE enrollment_id <> ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_issuer_serial
			ON certificates(issuer_id, serial_number)
			WHERE issuer_id <> '' AND serial_number <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_list_query
			ON certificates(issuer_id, certificate_profile_id, status, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_renewal_query
			ON certificates(status, renewal_notified_at, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_list_query
			ON outbox_messages(status, type, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS certificate_issuance_attempts (
			enrollment_id TEXT PRIMARY KEY REFERENCES enrollments(id),
			status TEXT NOT NULL,
			lease_expires_at TEXT,
			certificate_id TEXT NOT NULL,
			certificate_pem TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			subject TEXT NOT NULL,
			not_before TEXT,
			not_after TEXT,
			signing_started_at TEXT,
			signed_at TEXT,
			finalized_at TEXT,
			last_error TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_certificate_issuance_attempts_status_lease
			ON certificate_issuance_attempts(status, lease_expires_at, updated_at, enrollment_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_publications_issuer_distribution_number
			ON crl_publications(issuer_id, distribution_point, crl_number)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			actor TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT '["operator"]',
			expires_at TEXT,
			last_used_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_token_hash
			ON api_keys(token_hash)`,
		`CREATE TABLE IF NOT EXISTS acme_accounts (
			id TEXT PRIMARY KEY,
			contacts TEXT NOT NULL,
			status TEXT NOT NULL,
			terms_of_service_agreed INTEGER NOT NULL,
			key_thumbprint TEXT NOT NULL DEFAULT '',
			key_jwk_json TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS acme_nonces (
			nonce TEXT PRIMARY KEY,
			issued_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_nonces_expires
			ON acme_nonces(expires_at)`,
		`CREATE TABLE IF NOT EXISTS acme_orders (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id),
			identity_id TEXT NOT NULL REFERENCES identities(id),
			issuer_id TEXT NOT NULL REFERENCES issuers(id),
			certificate_profile_id TEXT NOT NULL,
			status TEXT NOT NULL,
			csr_pem TEXT NOT NULL,
			requested_subject TEXT NOT NULL,
			requested_dns_names TEXT NOT NULL,
			requested_ip_addresses TEXT NOT NULL,
			requested_not_after TEXT NOT NULL,
			enrollment_id TEXT NOT NULL,
			certificate_id TEXT NOT NULL,
			expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account
			ON acme_orders(account_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id),
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL,
			expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_order
			ON acme_authorizations(order_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_challenges (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL REFERENCES acme_authorizations(id),
			type TEXT NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL,
			validated_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authorization
			ON acme_challenges(authorization_id, created_at, id)`,
		`UPDATE issuers
			SET trust_anchor = 1
			WHERE kind = 'root_ca' AND trust_anchor = 0`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("execute sqlite compatibility migration: %w", err)
		}
	}
	outboxColumns := []struct {
		name       string
		definition string
	}{
		{name: "attempt_count", definition: "attempt_count INTEGER NOT NULL DEFAULT 0"},
		{name: "max_attempts", definition: "max_attempts INTEGER NOT NULL DEFAULT 0"},
		{name: "last_error", definition: "last_error TEXT NOT NULL DEFAULT ''"},
		{name: "processing_deadline_at", definition: "processing_deadline_at TEXT"},
	}
	for _, column := range outboxColumns {
		exists, err := sqliteColumnExists(ctx, db, "outbox_messages", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE outbox_messages ADD COLUMN %s", column.definition)); err != nil {
			return fmt.Errorf("add sqlite column outbox_messages.%s: %w", column.name, err)
		}
	}
	if exists, err := sqliteColumnExists(ctx, db, "notification_endpoints", "secret"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, "ALTER TABLE notification_endpoints ADD COLUMN secret TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("add sqlite column notification_endpoints.secret: %w", err)
		}
	}
	if exists, err := sqliteColumnExists(ctx, db, "api_keys", "scopes"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE api_keys ADD COLUMN scopes TEXT NOT NULL DEFAULT '["operator"]'`); err != nil {
			return fmt.Errorf("add sqlite column api_keys.scopes: %w", err)
		}
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "expires_at", definition: "expires_at TEXT"},
		{name: "last_used_at", definition: "last_used_at TEXT"},
	} {
		exists, err := sqliteColumnExists(ctx, db, "api_keys", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE api_keys ADD COLUMN %s", column.definition)); err != nil {
			return fmt.Errorf("add sqlite column api_keys.%s: %w", column.name, err)
		}
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "key_thumbprint", definition: "key_thumbprint TEXT NOT NULL DEFAULT ''"},
		{name: "key_jwk_json", definition: "key_jwk_json TEXT NOT NULL DEFAULT ''"},
	} {
		exists, err := sqliteColumnExists(ctx, db, "acme_accounts", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE acme_accounts ADD COLUMN %s", column.definition)); err != nil {
			return fmt.Errorf("add sqlite column acme_accounts.%s: %w", column.name, err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_acme_accounts_key_thumbprint
		ON acme_accounts(key_thumbprint)
		WHERE key_thumbprint <> ''`); err != nil {
		return fmt.Errorf("create sqlite acme account thumbprint index: %w", err)
	}
	for _, tableColumn := range []struct {
		table      string
		name       string
		definition string
	}{
		{table: "acme_orders", name: "expires_at", definition: "expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'"},
		{table: "acme_authorizations", name: "expires_at", definition: "expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'"},
		{table: "acme_authorizations", name: "validation_reuse_expires_at", definition: "validation_reuse_expires_at TEXT"},
	} {
		exists, err := sqliteColumnExists(ctx, db, tableColumn.table, tableColumn.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", tableColumn.table, tableColumn.definition)); err != nil {
			return fmt.Errorf("add sqlite column %s.%s: %w", tableColumn.table, tableColumn.name, err)
		}
	}
	return nil
}

func sqliteColumnExists(ctx context.Context, db sqlExecutor, table string, name string) (bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, fmt.Errorf("inspect sqlite table %s: %w", table, err)
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
			return false, fmt.Errorf("scan sqlite table %s: %w", table, err)
		}
		if columnName == name {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("inspect sqlite table %s: %w", table, err)
	}
	return false, nil
}

func applyPostgresCompatibilityMigrations(ctx context.Context, db sqlExecutor) error {
	statements := []string{
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS service TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS deployment_target TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS metadata_json TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS allowed_dns_names TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE identities ADD COLUMN IF NOT EXISTS allowed_ip_addresses TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS subject_key_identifier BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS allowed_key_algorithms TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS min_key_size_bits INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS allowed_signature_algorithms TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS parent_issuer_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS aia_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS crl_distribution_points TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS trust_anchor BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS authority_key_identifier BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS public_tls BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS source_certificate_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS renewal_notified_at TIMESTAMPTZ",
		"ALTER TABLE certificate_issuance_attempts ADD COLUMN IF NOT EXISTS signing_evidence_json TEXT NOT NULL DEFAULT ''",
		`CREATE TABLE IF NOT EXISTS outbox_messages (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL,
			available_at TIMESTAMPTZ NOT NULL,
			processing_deadline_at TIMESTAMPTZ,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS processing_deadline_at TIMESTAMPTZ",
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_due
			ON outbox_messages(status, available_at, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_processing_deadline
			ON outbox_messages(status, processing_deadline_at, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS job_attempts (
			id TEXT PRIMARY KEY,
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			status TEXT NOT NULL,
			error TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			finished_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_attempts_outbox_message
			ON job_attempts(outbox_message_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS notification_endpoints (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL DEFAULT '',
			event_types TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE notification_endpoints ADD COLUMN IF NOT EXISTS secret TEXT NOT NULL DEFAULT ''",
		`CREATE INDEX IF NOT EXISTS idx_notification_endpoints_status
			ON notification_endpoints(status, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS webhook_deliveries (
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			endpoint_id TEXT NOT NULL REFERENCES notification_endpoints(id),
			status TEXT NOT NULL,
			attempt_count INTEGER NOT NULL,
			last_error TEXT NOT NULL,
			last_attempted_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (outbox_message_id, endpoint_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
			ON webhook_deliveries(endpoint_id, updated_at)`,
		`CREATE INDEX IF NOT EXISTS idx_identities_inventory_fields
			ON identities(owner, team, service, environment, deployment_target, id)`,
		`CREATE INDEX IF NOT EXISTS idx_identities_list_query
			ON identities(owner, team, service, environment, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_enrollments_list_query
			ON enrollments(identity_id, issuer_id, certificate_profile_id, status, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_expiration_scan
			ON certificates(status, not_after, renewal_notified_at, id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_enrollment
			ON certificates(enrollment_id)
			WHERE enrollment_id <> ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_issuer_serial
			ON certificates(issuer_id, serial_number)
			WHERE issuer_id <> '' AND serial_number <> ''`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_list_query
			ON certificates(issuer_id, certificate_profile_id, status, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_renewal_query
			ON certificates(status, renewal_notified_at, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_list_query
			ON outbox_messages(status, type, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS certificate_issuance_attempts (
			enrollment_id TEXT PRIMARY KEY REFERENCES enrollments(id),
			status TEXT NOT NULL,
			lease_expires_at TIMESTAMPTZ,
			certificate_id TEXT NOT NULL,
			certificate_pem TEXT NOT NULL,
			serial_number TEXT NOT NULL,
			subject TEXT NOT NULL,
			not_before TIMESTAMPTZ,
			not_after TIMESTAMPTZ,
			signing_started_at TIMESTAMPTZ,
			signed_at TIMESTAMPTZ,
			finalized_at TIMESTAMPTZ,
			last_error TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_certificate_issuance_attempts_status_lease
			ON certificate_issuance_attempts(status, lease_expires_at, updated_at, enrollment_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_crl_publications_issuer_distribution_number
			ON crl_publications(issuer_id, distribution_point, crl_number)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			actor TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT '["operator"]',
			expires_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT '["operator"]'`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_token_hash
			ON api_keys(token_hash)`,
		`CREATE TABLE IF NOT EXISTS acme_accounts (
			id TEXT PRIMARY KEY,
			contacts TEXT NOT NULL,
			status TEXT NOT NULL,
			terms_of_service_agreed BOOLEAN NOT NULL,
			key_thumbprint TEXT NOT NULL DEFAULT '',
			key_jwk_json TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE acme_accounts ADD COLUMN IF NOT EXISTS key_thumbprint TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE acme_accounts ADD COLUMN IF NOT EXISTS key_jwk_json TEXT NOT NULL DEFAULT ''",
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_acme_accounts_key_thumbprint
			ON acme_accounts(key_thumbprint)
			WHERE key_thumbprint <> ''`,
		`CREATE TABLE IF NOT EXISTS acme_nonces (
			nonce TEXT PRIMARY KEY,
			issued_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_nonces_expires
			ON acme_nonces(expires_at)`,
		`CREATE TABLE IF NOT EXISTS acme_orders (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id),
			identity_id TEXT NOT NULL REFERENCES identities(id),
			issuer_id TEXT NOT NULL REFERENCES issuers(id),
			certificate_profile_id TEXT NOT NULL,
			status TEXT NOT NULL,
			csr_pem TEXT NOT NULL,
			requested_subject TEXT NOT NULL,
			requested_dns_names TEXT NOT NULL,
			requested_ip_addresses TEXT NOT NULL,
			requested_not_after TIMESTAMPTZ NOT NULL,
			enrollment_id TEXT NOT NULL,
			certificate_id TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE acme_orders ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account
			ON acme_orders(account_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id),
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE acme_authorizations ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'",
		"ALTER TABLE acme_authorizations ADD COLUMN IF NOT EXISTS validation_reuse_expires_at TIMESTAMPTZ",
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_order
			ON acme_authorizations(order_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_challenges (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL REFERENCES acme_authorizations(id),
			type TEXT NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL,
			validated_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authorization
			ON acme_challenges(authorization_id, created_at, id)`,
		`UPDATE issuers
			SET trust_anchor = TRUE
			WHERE kind = 'root_ca' AND trust_anchor = FALSE`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("execute postgres compatibility migration: %w", err)
		}
	}
	return nil
}
