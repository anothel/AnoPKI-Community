// SPDX-License-Identifier: MPL-2.0
package store

import (
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestAuditEventHashIsStable(t *testing.T) {
	event := domain.AuditEvent{
		Sequence:      7,
		HashAlgorithm: AuditHashAlgorithmSHA256V1,
		ID:            "audit-1",
		Actor:         "admin",
		Action:        "identity.created",
		ResourceType:  "identity",
		ResourceID:    "identity-1",
		MetadataJSON:  `{"b":2,"a":1}`,
		CreatedAt:     time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	reordered := event
	reordered.MetadataJSON = `{"a":1,"b":2}`

	first, err := auditEventHash("prev", event)
	if err != nil {
		t.Fatalf("auditEventHash returned error: %v", err)
	}
	second, err := auditEventHash("prev", event)
	if err != nil {
		t.Fatalf("auditEventHash returned error: %v", err)
	}
	reorderedHash, err := auditEventHash("prev", reordered)
	if err != nil {
		t.Fatalf("auditEventHash returned error: %v", err)
	}
	if first == "" || first != second || first != reorderedHash {
		t.Fatalf("hashes = %q %q %q", first, second, reorderedHash)
	}
	linked, err := auditEventHash("other-prev", event)
	if err != nil {
		t.Fatalf("auditEventHash returned error: %v", err)
	}
	if linked == first {
		t.Fatalf("linked hash = %q, want different from %q", linked, first)
	}
	changedSequence := event
	changedSequence.Sequence++
	sequenceHash, err := auditEventHash("prev", changedSequence)
	if err != nil {
		t.Fatalf("auditEventHash returned error: %v", err)
	}
	if sequenceHash == first {
		t.Fatal("sequence is not committed by the audit hash")
	}
}

func TestVerifyAuditEventsDetectsCheckpointAndEventTampering(t *testing.T) {
	base := domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "admin",
		Action:       "identity.created",
		ResourceType: "identity",
		ResourceID:   "identity-1",
		MetadataJSON: `{}`,
		CreatedAt:    time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	first, err := withAuditEventHash(1, "", base)
	if err != nil {
		t.Fatalf("withAuditEventHash returned error: %v", err)
	}
	secondInput := base
	secondInput.ID = "audit-2"
	secondInput.CreatedAt = base.CreatedAt.Add(time.Minute)
	second, err := withAuditEventHash(2, first.EventHash, secondInput)
	if err != nil {
		t.Fatalf("withAuditEventHash returned error: %v", err)
	}
	if report := verifyAuditEvents([]domain.AuditEvent{first, second}, domain.AuditChainCheckpoint{}); !report.Valid {
		t.Fatalf("valid chain report = %#v", report)
	}

	tampered := second
	tampered.Action = "certificate.revoked"
	if report := verifyAuditEvents([]domain.AuditEvent{first, tampered}, domain.AuditChainCheckpoint{}); report.Valid || report.FailureReason != "event_hash_mismatch" {
		t.Fatalf("tampered event report = %#v", report)
	}

	checkpoint := domain.AuditChainCheckpoint{
		Sequence:      1,
		HashAlgorithm: AuditHashAlgorithmSHA256V1,
		EventHash:     first.EventHash,
	}
	if report := verifyAuditEvents([]domain.AuditEvent{second}, checkpoint); !report.Valid {
		t.Fatalf("pruned chain report = %#v", report)
	}
	checkpoint.EventHash = "0" + checkpoint.EventHash[1:]
	if report := verifyAuditEvents([]domain.AuditEvent{second}, checkpoint); report.Valid || report.FailureReason != "previous_hash_mismatch" {
		t.Fatalf("tampered checkpoint report = %#v", report)
	}
}
