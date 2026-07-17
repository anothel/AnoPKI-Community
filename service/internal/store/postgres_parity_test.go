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

func TestPostgresIntegrationRepositoryParity(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, Repository)
	}{
		{name: "lifecycle_identity_policy", run: testIdentityPolicyFieldsRoundTrip},
		{name: "lifecycle_duplicate_certificate_keys", run: testRejectsDuplicateCertificateFinalizationKeys},
		{name: "lifecycle_issuance_attempts", run: testIssuanceAttempts},
		{name: "outbox_jobs", run: testOutboxAndJobAttempts},
		{name: "outbox_retry_metadata", run: testOutboxRetryMetadata},
		{name: "outbox_lease_recovery", run: testOutboxLeaseRecovery},
		{name: "webhook_delivery_tracking", run: testWebhookDeliveryTracking},
		{name: "audit_query_retention", run: testAuditEventQueryAndRetention},
		{name: "certificate_profile_issuer_transition", run: testCertificateProfileIssuerConditionalUpdate},
		{name: "nested_transactions", run: testNestedWithinTxUsesSameTransaction},
		{name: "acme_state", run: testACMEState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, newPostgresTestRepository(t))
		})
	}
}

func newPostgresTestRepository(t *testing.T) Repository {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ANOPKI_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("set ANOPKI_POSTGRES_TEST_DSN to run PostgreSQL repository parity integration tests")
	}

	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)

	resetPostgresTestSchema(t, ctx, db)
	if err := ApplyInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if err := CheckInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("CheckInitialMigration returned error: %v", err)
	}
	return NewSQLStore(db)
}

func resetPostgresTestSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatalf("drop postgres test schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatalf("create postgres test schema: %v", err)
	}
}
