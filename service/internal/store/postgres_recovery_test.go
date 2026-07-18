// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func openPostgresRecoveryTestDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ANOPKI_POSTGRES_RECOVERY_DSN"))
	if dsn == "" {
		t.Skip("set ANOPKI_POSTGRES_RECOVERY_DSN to run PostgreSQL recovery drill tests")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres recovery database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	return db, ctx
}

func resetPostgresRecoverySchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatalf("drop postgres recovery schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatalf("create postgres recovery schema: %v", err)
	}
	if err := ApplyInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("CheckInitialMigration returned error: %v", err)
	}
}

func TestPostgresRecoveryDrillMigrationRollbackIntegration(t *testing.T) {
	db, ctx := openPostgresRecoveryTestDB(t)
	resetPostgresRecoverySchema(t, ctx, db)

	tx, err := beginPostgresMigrationTx(ctx, db)
	if err != nil {
		t.Fatalf("beginPostgresMigrationTx returned error: %v", err)
	}
	if err := insertSchemaMigration(ctx, tx, "pgx", 3, "rollback-probe", true); err != nil {
		t.Fatalf("insertSchemaMigration returned error: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE postgres_recovery_rollback_probe (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create rollback probe table: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO postgres_recovery_missing_table(id) VALUES (1)`); err == nil {
		t.Fatal("intentional migration failure unexpectedly succeeded")
	}
	tx.Rollback()

	var probeName sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.postgres_recovery_rollback_probe')`).Scan(&probeName); err != nil {
		t.Fatalf("query rollback probe table: %v", err)
	}
	if probeName.Valid {
		t.Fatalf("rollback probe table survived failed transaction: %q", probeName.String)
	}
	var versionCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 3`).Scan(&versionCount); err != nil {
		t.Fatalf("query rollback migration row: %v", err)
	}
	if versionCount != 0 {
		t.Fatalf("failed migration row count = %d, want 0", versionCount)
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("initial migration invalid after rollback: %v", err)
	}
}

func TestPostgresRecoveryDrillDirtyMigrationRejectedIntegration(t *testing.T) {
	db, ctx := openPostgresRecoveryTestDB(t)
	resetPostgresRecoverySchema(t, ctx, db)

	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET dirty = TRUE WHERE version = 1`); err != nil {
		t.Fatalf("mark migration dirty: %v", err)
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("CheckInitialMigration error = %v, want dirty migration rejection", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET dirty = FALSE WHERE version = 1`); err != nil {
		t.Fatalf("repair migration dirty flag: %v", err)
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("CheckInitialMigration after repair returned error: %v", err)
	}
}
