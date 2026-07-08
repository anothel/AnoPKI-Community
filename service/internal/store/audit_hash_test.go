// SPDX-License-Identifier: MPL-2.0
package store

import (
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestAuditEventHashIsStable(t *testing.T) {
	event := domain.AuditEvent{
		ID:           "audit-1",
		Actor:        "admin",
		Action:       "identity.created",
		ResourceType: "identity",
		ResourceID:   "identity-1",
		MetadataJSON: `{"b":2,"a":1}`,
		CreatedAt:    time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	reordered := event
	reordered.MetadataJSON = `{"a":1,"b":2}`

	first := auditEventHash("prev", event)
	second := auditEventHash("prev", event)
	reorderedHash := auditEventHash("prev", reordered)
	if first == "" || first != second || first != reorderedHash {
		t.Fatalf("hashes = %q %q %q", first, second, reorderedHash)
	}
	if linked := auditEventHash("other-prev", event); linked == first {
		t.Fatalf("linked hash = %q, want different from %q", linked, first)
	}
}
