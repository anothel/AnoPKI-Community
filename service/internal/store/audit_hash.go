// SPDX-License-Identifier: MPL-2.0
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

const auditHashAlgorithm = "sha256-v1"
const auditHashDomain = "AnoPKI-Audit-Event-sha256-v1"
const auditCheckpointDomain = "AnoPKI-Audit-Checkpoint-sha256-v1"

type auditHashPayload struct {
	Algorithm         string          `json:"algorithm"`
	ChainIndex        int64           `json:"chain_index"`
	PreviousEventHash string          `json:"previous_event_hash"`
	ID                string          `json:"id"`
	Actor             string          `json:"actor"`
	Action            string          `json:"action"`
	ResourceType      string          `json:"resource_type"`
	ResourceID        string          `json:"resource_id"`
	Metadata          json.RawMessage `json:"metadata"`
	CreatedAt         string          `json:"created_at"`
}

func canonicalAuditMetadata(raw string) (json.RawMessage, error) {
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Errorf("invalid audit metadata: %w", err)
	}
	canonical, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("canonicalize audit metadata: %w", err)
	}
	return canonical, nil
}

func computeAuditEventHash(previousHash string, event domain.AuditEvent) (string, error) {
	metadata, err := canonicalAuditMetadata(event.MetadataJSON)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(auditHashPayload{
		Algorithm:         auditHashAlgorithm,
		ChainIndex:        event.ChainIndex,
		PreviousEventHash: previousHash,
		ID:                event.ID,
		Actor:             event.Actor,
		Action:            event.Action,
		ResourceType:      event.ResourceType,
		ResourceID:        event.ResourceID,
		Metadata:          metadata,
		CreatedAt:         event.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", fmt.Errorf("marshal audit hash payload: %w", err)
	}
	digest := sha256.Sum256(append([]byte(auditHashDomain+"\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}

func withAuditEventHash(previousHash string, chainIndex int64, event domain.AuditEvent) (domain.AuditEvent, error) {
	event.ChainIndex = chainIndex
	event.HashAlgorithm = auditHashAlgorithm
	event.PreviousEventHash = previousHash
	eventHash, err := computeAuditEventHash(previousHash, event)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	event.EventHash = eventHash
	return event, nil
}

func auditCheckpointID(throughIndex int64, throughID string, throughHash string, cutoff time.Time) string {
	payload := fmt.Sprintf("%s\x00%d\x00%s\x00%s\x00%s", auditCheckpointDomain, throughIndex, throughID, throughHash, cutoff.UTC().Format(time.RFC3339Nano))
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

func verifyAuditChain(events []domain.AuditEvent, checkpoint domain.AuditChainCheckpoint, tailIndex int64, tailID string, tailHash string, totalCount int64) domain.AuditChainVerification {
	result := domain.AuditChainVerification{
		Verified:           true,
		HashAlgorithm:      auditHashAlgorithm,
		RetainedEventCount: len(events),
		TotalEventCount:    totalCount,
		TailChainIndex:     tailIndex,
		TailEventID:        tailID,
		TailEventHash:      tailHash,
		Checkpoint:         checkpoint,
	}
	if totalCount != tailIndex {
		result.Verified = false
		result.BrokenChainIndex = tailIndex
		result.Reason = "total_count_mismatch"
		return result
	}
	if checkpoint.ThroughChainIndex > 0 {
		expectedCheckpointID := auditCheckpointID(
			checkpoint.ThroughChainIndex,
			checkpoint.ThroughEventID,
			checkpoint.ThroughEventHash,
			checkpoint.RetentionCutoff,
		)
		if checkpoint.ID != expectedCheckpointID {
			result.Verified = false
			result.BrokenChainIndex = checkpoint.ThroughChainIndex
			result.Reason = "checkpoint_hash_mismatch"
			return result
		}
	} else if checkpoint.ID != "" || checkpoint.ThroughEventID != "" || checkpoint.ThroughEventHash != "" {
		result.Verified = false
		result.Reason = "invalid_empty_checkpoint"
		return result
	}
	previousHash := checkpoint.ThroughEventHash
	previousIndex := checkpoint.ThroughChainIndex
	for _, event := range events {
		if event.HashAlgorithm != auditHashAlgorithm {
			result.Verified = false
			result.BrokenChainIndex = event.ChainIndex
			result.Reason = "unsupported_hash_algorithm"
			return result
		}
		if event.ChainIndex != previousIndex+1 {
			result.Verified = false
			result.BrokenChainIndex = event.ChainIndex
			result.Reason = "non_contiguous_chain_index"
			return result
		}
		if event.PreviousEventHash != previousHash {
			result.Verified = false
			result.BrokenChainIndex = event.ChainIndex
			result.Reason = "previous_hash_mismatch"
			return result
		}
		expected, err := computeAuditEventHash(previousHash, event)
		if err != nil || expected != event.EventHash {
			result.Verified = false
			result.BrokenChainIndex = event.ChainIndex
			result.Reason = "event_hash_mismatch"
			return result
		}
		previousHash = event.EventHash
		previousIndex = event.ChainIndex
	}
	expectedID := checkpoint.ThroughEventID
	if len(events) > 0 {
		expectedID = events[len(events)-1].ID
	}
	if previousIndex != tailIndex || previousHash != tailHash || expectedID != tailID {
		result.Verified = false
		result.BrokenChainIndex = tailIndex
		result.Reason = "tail_state_mismatch"
	}
	return result
}
