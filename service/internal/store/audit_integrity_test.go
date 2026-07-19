// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	_ "modernc.org/sqlite"
)

func TestAuditIntegrityAppendCheckpointAndPruneParity(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testAuditIntegrityAppendCheckpointAndPrune(t, tt.repo)
		})
	}
}

func testAuditIntegrityAppendCheckpointAndPrune(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < 3; index++ {
		event := testAuditEvent(
			fmt.Sprintf("audit-%d", index+1),
			"operator",
			"audit.test",
			"audit",
			"resource",
			base.Add(time.Duration(index)*time.Minute),
		)
		if err := repo.CreateAuditEvent(ctx, event); err != nil {
			t.Fatalf("CreateAuditEvent(%d) returned error: %v", index, err)
		}
	}

	report, err := repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
	if !report.Valid || report.HashAlgorithm != AuditHashAlgorithmSHA256V1 || report.EventCount != 3 || report.FirstSequence != 1 || report.LastSequence != 3 || report.CheckpointSequence != 0 {
		t.Fatalf("initial integrity report = %#v", report)
	}

	deleted, err := repo.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("DeleteAuditEventsBefore returned error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	report, err = repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain after prune returned error: %v", err)
	}
	if !report.Valid || report.EventCount != 1 || report.FirstSequence != 3 || report.LastSequence != 3 || report.CheckpointSequence != 2 || report.CheckpointEventHash == "" {
		t.Fatalf("post-prune integrity report = %#v", report)
	}

	if err := repo.CreateAuditEvent(ctx, testAuditEvent("audit-4", "operator", "audit.test", "audit", "resource", base.Add(3*time.Minute))); err != nil {
		t.Fatalf("CreateAuditEvent after prune returned error: %v", err)
	}
	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if len(events) != 2 || events[0].Sequence != 3 || events[1].Sequence != 4 || events[1].PreviousEventHash != events[0].EventHash {
		t.Fatalf("events after append = %#v", events)
	}
}

func TestMemoryAuditTamperFailsClosed(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < 2; index++ {
		if err := repo.CreateAuditEvent(ctx, testAuditEvent(fmt.Sprintf("audit-memory-%d", index+1), "operator", "audit.test", "audit", "resource", base.Add(time.Duration(index)*time.Minute))); err != nil {
			t.Fatalf("CreateAuditEvent returned error: %v", err)
		}
	}
	repo.mu.Lock()
	repo.auditEvents[0].Action = "audit.tampered"
	repo.mu.Unlock()

	report, err := repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
	if report.Valid || report.FailureReason != "event_hash_mismatch" {
		t.Fatalf("tampered report = %#v", report)
	}
	if err := repo.CreateAuditEvent(ctx, testAuditEvent("audit-memory-3", "operator", "audit.test", "audit", "resource", base.Add(2*time.Minute))); !errors.Is(err, domain.ErrAuditIntegrity) {
		t.Fatalf("append error = %v, want ErrAuditIntegrity", err)
	}
	if _, err := repo.DeleteAuditEventsBefore(ctx, base.Add(time.Hour)); !errors.Is(err, domain.ErrAuditIntegrity) {
		t.Fatalf("prune error = %v, want ErrAuditIntegrity", err)
	}
}

func TestMemoryAuditCheckpointTamperDetected(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < 3; index++ {
		if err := repo.CreateAuditEvent(ctx, testAuditEvent(fmt.Sprintf("audit-checkpoint-%d", index+1), "operator", "audit.test", "audit", "resource", base.Add(time.Duration(index)*time.Minute))); err != nil {
			t.Fatalf("CreateAuditEvent returned error: %v", err)
		}
	}
	if _, err := repo.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute)); err != nil {
		t.Fatalf("DeleteAuditEventsBefore returned error: %v", err)
	}
	repo.mu.Lock()
	repo.auditState.CheckpointEventHash = tamperedAuditHash(repo.auditState.CheckpointEventHash)
	repo.mu.Unlock()
	report, err := repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
	if report.Valid || report.FailureReason != "previous_hash_mismatch" {
		t.Fatalf("checkpoint tamper report = %#v", report)
	}
}

func TestMemoryAuditCheckpointTamperDetectedAfterFullPrune(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < 2; index++ {
		if err := repo.CreateAuditEvent(ctx, testAuditEvent(fmt.Sprintf("audit-full-prune-%d", index+1), "operator", "audit.test", "audit", "resource", base.Add(time.Duration(index)*time.Minute))); err != nil {
			t.Fatalf("CreateAuditEvent returned error: %v", err)
		}
	}
	if _, err := repo.DeleteAuditEventsBefore(ctx, base.Add(time.Hour)); err != nil {
		t.Fatalf("DeleteAuditEventsBefore returned error: %v", err)
	}
	repo.mu.Lock()
	repo.auditState.CheckpointEventHash = tamperedAuditHash(repo.auditState.CheckpointEventHash)
	repo.mu.Unlock()
	report, err := repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("VerifyAuditChain returned error: %v", err)
	}
	if report.Valid || report.FailureReason != "state_latest_mismatch" {
		t.Fatalf("full-prune checkpoint tamper report = %#v", report)
	}
}

func TestSQLiteAuditTamperAndCheckpointTamperFailClosed(t *testing.T) {
	ctx := context.Background()
	db, repo := newTestSQLiteDBRepository(t)
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for index := 0; index < 3; index++ {
		if err := repo.CreateAuditEvent(ctx, testAuditEvent(fmt.Sprintf("audit-sqlite-%d", index+1), "operator", "audit.test", "audit", "resource", base.Add(time.Duration(index)*time.Minute))); err != nil {
			t.Fatalf("CreateAuditEvent returned error: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_events SET action = 'audit.tampered' WHERE sequence = 1`); err != nil {
		t.Fatalf("tamper audit event: %v", err)
	}
	report, err := repo.VerifyAuditChain(ctx)
	if err != nil || report.Valid || report.FailureReason != "event_hash_mismatch" {
		t.Fatalf("tampered VerifyAuditChain = %#v, %v", report, err)
	}
	if err := repo.CreateAuditEvent(ctx, testAuditEvent("audit-sqlite-4", "operator", "audit.test", "audit", "resource", base.Add(3*time.Minute))); !errors.Is(err, domain.ErrAuditIntegrity) {
		t.Fatalf("append error = %v, want ErrAuditIntegrity", err)
	}
	if _, err := repo.DeleteAuditEventsBefore(ctx, base.Add(time.Hour)); !errors.Is(err, domain.ErrAuditIntegrity) {
		t.Fatalf("prune error = %v, want ErrAuditIntegrity", err)
	}

	db2, repo2 := newTestSQLiteDBRepository(t)
	for index := 0; index < 3; index++ {
		if err := repo2.CreateAuditEvent(ctx, testAuditEvent(fmt.Sprintf("audit-sqlite-checkpoint-%d", index+1), "operator", "audit.test", "audit", "resource", base.Add(time.Duration(index)*time.Minute))); err != nil {
			t.Fatalf("CreateAuditEvent returned error: %v", err)
		}
	}
	if _, err := repo2.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute)); err != nil {
		t.Fatalf("DeleteAuditEventsBefore returned error: %v", err)
	}
	if _, err := db2.ExecContext(ctx, `UPDATE audit_chain_state SET checkpoint_event_hash = ? WHERE singleton_id = 1`, tamperedAuditHash(mustSQLiteCheckpointHash(t, db2))); err != nil {
		t.Fatalf("tamper checkpoint: %v", err)
	}
	report, err = repo2.VerifyAuditChain(ctx)
	if err != nil || report.Valid || report.FailureReason != "previous_hash_mismatch" {
		t.Fatalf("checkpoint tamper VerifyAuditChain = %#v, %v", report, err)
	}
}

func newTestSQLiteDBRepository(t *testing.T) (*sql.DB, *SQLStore) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := ApplyInitialMigration(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	return db, NewSQLStore(db)
}

func mustSQLiteCheckpointHash(t *testing.T, db *sql.DB) string {
	t.Helper()
	var value string
	if err := db.QueryRow(`SELECT checkpoint_event_hash FROM audit_chain_state WHERE singleton_id = 1`).Scan(&value); err != nil {
		t.Fatalf("read checkpoint hash: %v", err)
	}
	return value
}

func tamperedAuditHash(value string) string {
	if value == "" {
		return "0"
	}
	replacement := byte('0')
	if value[0] == replacement {
		replacement = '1'
	}
	return string(replacement) + value[1:]
}
