// SPDX-License-Identifier: MPL-2.0
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type auditHashPayload struct {
	ID           string          `json:"id"`
	Actor        string          `json:"actor"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    string          `json:"created_at"`
}

func auditEventHash(previousHash string, event domain.AuditEvent) string {
	var metadata map[string]any
	_ = json.Unmarshal([]byte(event.MetadataJSON), &metadata)
	canonicalMetadata, _ := json.Marshal(metadata)
	payload, _ := json.Marshal(auditHashPayload{
		ID:           event.ID,
		Actor:        event.Actor,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Metadata:     canonicalMetadata,
		CreatedAt:    event.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	sum := sha256.Sum256(append([]byte(previousHash), payload...))
	return hex.EncodeToString(sum[:])
}

func withAuditEventHash(previousHash string, event domain.AuditEvent) domain.AuditEvent {
	event.PreviousEventHash = previousHash
	event.EventHash = auditEventHash(previousHash, event)
	return event
}
