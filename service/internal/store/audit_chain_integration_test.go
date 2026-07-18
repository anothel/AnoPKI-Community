// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestAuditChainAppendAndVerifyAcrossStores(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
			for i, event := range []domain.AuditEvent{
				testAuditEvent("audit-1", "alice", "identity.created", "identity", "identity-1", base),
				testAuditEvent("audit-2", "bob", "certificate.issued", "certificate", "certificate-1", base.Add(time.Minute)),
			} {
				if err := tt.repo.CreateAuditEvent(ctx, event); err != nil {
					t.Fatalf("CreateAuditEvent %d: %v", i, err)
				}
			}
			verification, err := tt.repo.VerifyAuditChain(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !verification.Verified || verification.RetainedEventCount != 2 || verification.TotalEventCount != 2 || verification.TailChainIndex != 2 {
				t.Fatalf("verification = %#v", verification)
			}
		})
	}
}

func TestAuditChainTamperingDetected(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for _, event := range []domain.AuditEvent{
		testAuditEvent("audit-1", "alice", "identity.created", "identity", "identity-1", base),
		testAuditEvent("audit-2", "alice", "certificate.issued", "certificate", "certificate-1", base.Add(time.Minute)),
	} {
		if err := repo.CreateAuditEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	repo.mu.Lock()
	repo.auditEvents[0].MetadataJSON = `{"tampered":true}`
	repo.mu.Unlock()
	verification, err := repo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Verified || verification.BrokenChainIndex != 1 || verification.Reason != "event_hash_mismatch" {
		t.Fatalf("verification = %#v", verification)
	}
	if _, err := repo.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute)); err != domain.ErrAuditChainConflict {
		t.Fatalf("DeleteAuditEventsBefore tampered chain error = %v, want %v", err, domain.ErrAuditChainConflict)
	}

	checkpointRepo := NewMemoryStore()
	for i := 0; i < 2; i++ {
		event := testAuditEvent("checkpoint-audit-"+string(rune('1'+i)), "operator", "event.created", "event", "resource", base.Add(time.Duration(i)*time.Minute))
		if err := checkpointRepo.CreateAuditEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := checkpointRepo.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	checkpointRepo.mu.Lock()
	checkpointRepo.auditCheckpoints[0].ThroughEventHash = "tampered"
	checkpointRepo.mu.Unlock()
	checkpointVerification, err := checkpointRepo.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if checkpointVerification.Verified || checkpointVerification.Reason != "checkpoint_hash_mismatch" {
		t.Fatalf("checkpoint verification = %#v", checkpointVerification)
	}
}

func TestAuditChainPruneCheckpointPreservesVerification(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
			for i := 0; i < 3; i++ {
				event := testAuditEvent("audit-"+string(rune('1'+i)), "operator", "event.created", "event", "resource", base.Add(time.Duration(i)*time.Minute))
				if err := tt.repo.CreateAuditEvent(ctx, event); err != nil {
					t.Fatal(err)
				}
			}
			deleted, err := tt.repo.DeleteAuditEventsBefore(ctx, base.Add(90*time.Second))
			if err != nil || deleted != 2 {
				t.Fatalf("DeleteAuditEventsBefore = %d, %v", deleted, err)
			}
			verification, err := tt.repo.VerifyAuditChain(ctx)
			if err != nil || !verification.Verified {
				t.Fatalf("VerifyAuditChain = %#v, %v", verification, err)
			}
			if verification.Checkpoint.ThroughChainIndex != 2 || verification.RetainedEventCount != 1 || verification.TotalEventCount != 3 {
				t.Fatalf("verification after prune = %#v", verification)
			}
			if err := tt.repo.CreateAuditEvent(ctx, testAuditEvent("audit-4", "operator", "event.created", "event", "resource", base.Add(4*time.Minute))); err != nil {
				t.Fatal(err)
			}
			verification, _ = tt.repo.VerifyAuditChain(ctx)
			if !verification.Verified || verification.TailChainIndex != 4 {
				t.Fatalf("verification after append = %#v", verification)
			}
		})
	}
}

func TestAuditChainRejectsInvalidMetadata(t *testing.T) {
	ctx := context.Background()
	for _, repo := range []Repository{NewMemoryStore(), newTestSQLiteRepository(t)} {
		err := repo.CreateAuditEvent(ctx, domain.AuditEvent{ID: "bad", Actor: "a", Action: "x", ResourceType: "r", ResourceID: "1", MetadataJSON: "not-json", CreatedAt: time.Now()})
		if err == nil {
			t.Fatal("invalid audit metadata unexpectedly accepted")
		}
	}
}
