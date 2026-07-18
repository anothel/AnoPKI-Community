// SPDX-License-Identifier: MPL-2.0
package store

import (
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestAuditEventHashIsStable(t *testing.T) {
	event := domain.AuditEvent{
		ID: "audit-1", Actor: "admin", Action: "identity.created",
		ResourceType: "identity", ResourceID: "identity-1",
		MetadataJSON: `{"b":2,"a":1}`, ChainIndex: 7,
		CreatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	reordered := event
	reordered.MetadataJSON = `{"a":1,"b":2}`
	first, err := computeAuditEventHash("prev", event)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := computeAuditEventHash("prev", event)
	reorderedHash, _ := computeAuditEventHash("prev", reordered)
	if first == "" || first != second || first != reorderedHash {
		t.Fatalf("hashes = %q %q %q", first, second, reorderedHash)
	}
	linked, _ := computeAuditEventHash("other-prev", event)
	if linked == first {
		t.Fatalf("linked hash = %q, want different", linked)
	}
}

func TestAuditEventHashRejectsInvalidMetadata(t *testing.T) {
	_, err := computeAuditEventHash("", domain.AuditEvent{ID: "audit-1", MetadataJSON: "not-json", ChainIndex: 1, CreatedAt: time.Now()})
	if err == nil {
		t.Fatal("invalid metadata unexpectedly hashed")
	}
}
