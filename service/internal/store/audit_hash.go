// SPDX-License-Identifier: MPL-2.0
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

const AuditHashAlgorithmSHA256V1 = "sha256-v1"

type auditHashPayload struct {
	HashAlgorithm string          `json:"hash_algorithm"`
	Sequence      int64           `json:"sequence"`
	ID            string          `json:"id"`
	Actor         string          `json:"actor"`
	Action        string          `json:"action"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	Metadata      json.RawMessage `json:"metadata"`
	CreatedAt     string          `json:"created_at"`
}

type auditChainState struct {
	HashAlgorithm       string
	LatestSequence      int64
	LatestEventHash     string
	CheckpointSequence  int64
	CheckpointEventHash string
	UpdatedAt           time.Time
}

func emptyAuditChainState() auditChainState {
	return auditChainState{HashAlgorithm: AuditHashAlgorithmSHA256V1}
}

func auditEventHash(previousHash string, event domain.AuditEvent) (string, error) {
	canonicalMetadata, err := canonicalAuditMetadata(event.MetadataJSON)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(auditHashPayload{
		HashAlgorithm: event.HashAlgorithm,
		Sequence:      event.Sequence,
		ID:            event.ID,
		Actor:         event.Actor,
		Action:        event.Action,
		ResourceType:  event.ResourceType,
		ResourceID:    event.ResourceID,
		Metadata:      canonicalMetadata,
		CreatedAt:     event.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", fmt.Errorf("marshal audit hash payload: %w", err)
	}
	input := make([]byte, 0, len(previousHash)+len(payload))
	input = append(input, previousHash...)
	input = append(input, payload...)
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalAuditMetadata(value string) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.UseNumber()
	var metadata any
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode audit metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode audit metadata: trailing value")
		}
		return nil, fmt.Errorf("decode audit metadata: %w", err)
	}
	canonical, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal audit metadata: %w", err)
	}
	return canonical, nil
}

func withAuditEventHash(sequence int64, previousHash string, event domain.AuditEvent) (domain.AuditEvent, error) {
	if sequence <= 0 {
		return domain.AuditEvent{}, fmt.Errorf("audit sequence must be positive")
	}
	event.Sequence = sequence
	event.HashAlgorithm = AuditHashAlgorithmSHA256V1
	event.PreviousEventHash = previousHash
	hash, err := auditEventHash(previousHash, event)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	event.EventHash = hash
	return event, nil
}

func verifyAuditEvents(events []domain.AuditEvent, checkpoint domain.AuditChainCheckpoint) domain.AuditIntegrity {
	report := domain.AuditIntegrity{
		Valid:               false,
		HashAlgorithm:       AuditHashAlgorithmSHA256V1,
		EventCount:          len(events),
		CheckpointSequence:  checkpoint.Sequence,
		CheckpointEventHash: checkpoint.EventHash,
	}
	if checkpoint.Sequence < 0 {
		report.FailureReason = "checkpoint_sequence_invalid"
		return report
	}
	if checkpoint.Sequence == 0 {
		if checkpoint.EventHash != "" {
			report.FailureReason = "checkpoint_hash_unexpected"
			return report
		}
		if checkpoint.HashAlgorithm != "" && checkpoint.HashAlgorithm != AuditHashAlgorithmSHA256V1 {
			report.FailureReason = "checkpoint_algorithm_mismatch"
			return report
		}
	} else {
		if checkpoint.HashAlgorithm != AuditHashAlgorithmSHA256V1 {
			report.FailureReason = "checkpoint_algorithm_mismatch"
			return report
		}
		if !isAuditHash(checkpoint.EventHash) {
			report.FailureReason = "checkpoint_hash_invalid"
			return report
		}
	}

	expectedSequence := checkpoint.Sequence + 1
	previousHash := checkpoint.EventHash
	for index, event := range events {
		if event.Sequence != expectedSequence {
			report.FailureReason = "sequence_gap"
			return report
		}
		if event.HashAlgorithm != AuditHashAlgorithmSHA256V1 {
			report.FailureReason = "hash_algorithm_mismatch"
			return report
		}
		if event.PreviousEventHash != previousHash {
			report.FailureReason = "previous_hash_mismatch"
			return report
		}
		expectedHash, err := auditEventHash(previousHash, event)
		if err != nil {
			report.FailureReason = "metadata_invalid"
			return report
		}
		if event.EventHash != expectedHash || !isAuditHash(event.EventHash) {
			report.FailureReason = "event_hash_mismatch"
			return report
		}
		if index == 0 {
			report.FirstSequence = event.Sequence
		}
		report.LastSequence = event.Sequence
		report.LastEventHash = event.EventHash
		previousHash = event.EventHash
		expectedSequence++
	}
	if len(events) == 0 {
		report.LastSequence = checkpoint.Sequence
		report.LastEventHash = checkpoint.EventHash
	}
	report.Valid = true
	return report
}

func verifyAuditState(events []domain.AuditEvent, state auditChainState) domain.AuditIntegrity {
	checkpoint := domain.AuditChainCheckpoint{
		Sequence:      state.CheckpointSequence,
		HashAlgorithm: state.HashAlgorithm,
		EventHash:     state.CheckpointEventHash,
	}
	report := verifyAuditEvents(events, checkpoint)
	if !report.Valid {
		return report
	}
	if state.HashAlgorithm != AuditHashAlgorithmSHA256V1 {
		report.Valid = false
		report.FailureReason = "state_algorithm_mismatch"
		return report
	}
	if state.LatestSequence != report.LastSequence || state.LatestEventHash != report.LastEventHash {
		report.Valid = false
		report.FailureReason = "state_latest_mismatch"
		return report
	}
	return report
}

func auditIntegrityError(report domain.AuditIntegrity) error {
	if report.Valid {
		return nil
	}
	return fmt.Errorf("%w: %s", domain.ErrAuditIntegrity, report.FailureReason)
}

func isAuditHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}
