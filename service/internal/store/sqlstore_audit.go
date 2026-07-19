// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func (s *SQLStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return s.WithinTx(ctx, func(repo Repository) error {
		return repo.CreateAuditEvent(ctx, event)
	})
}

func (s *SQLStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEvents(ctx)
}

func (s *SQLStore) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEventsQuery(ctx, query)
}

func (s *SQLStore) VerifyAuditChain(ctx context.Context) (domain.AuditIntegrity, error) {
	var report domain.AuditIntegrity
	err := s.WithinTx(ctx, func(repo Repository) error {
		var err error
		report, err = repo.VerifyAuditChain(ctx)
		return err
	})
	return report, err
}

func (s *SQLStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	deleted := 0
	err := s.WithinTx(ctx, func(repo Repository) error {
		var err error
		deleted, err = repo.DeleteAuditEventsBefore(ctx, before)
		return err
	})
	return deleted, err
}

func (r sqlRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	state, events, report, err := r.lockAndVerifyAuditChain(ctx)
	if err != nil {
		return err
	}
	prepared, err := withAuditEventHash(report.LastSequence+1, report.LastEventHash, event)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO audit_events (
	id, sequence, actor, action, resource_type, resource_id, metadata_json,
	hash_algorithm, previous_event_hash, event_hash, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)`,
		prepared.ID,
		prepared.Sequence,
		prepared.Actor,
		prepared.Action,
		prepared.ResourceType,
		prepared.ResourceID,
		prepared.MetadataJSON,
		prepared.HashAlgorithm,
		prepared.PreviousEventHash,
		prepared.EventHash,
		formatSQLTime(prepared.CreatedAt),
	)
	if err != nil {
		return err
	}
	state.LatestSequence = prepared.Sequence
	state.LatestEventHash = prepared.EventHash
	state.UpdatedAt = time.Now()
	if err := r.updateAuditChainState(ctx, state); err != nil {
		return err
	}
	events = append(events, prepared)
	if after := verifyAuditState(events, state); !after.Valid {
		return auditIntegrityError(after)
	}
	return nil
}

func (r sqlRepository) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, sequence, actor, action, resource_type, resource_id, metadata_json,
	hash_algorithm, previous_event_hash, event_hash, created_at
FROM audit_events
ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (r sqlRepository) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, sequence, actor, action, resource_type, resource_id, metadata_json,
	hash_algorithm, previous_event_hash, event_hash, created_at
FROM audit_events`)
	where := make([]string, 0)
	args := make([]any, 0)
	addStringFilter := func(column string, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addStringFilter("actor", query.Actor)
	addStringFilter("action", query.Action)
	addStringFilter("resource_type", query.ResourceType)
	addStringFilter("resource_id", query.ResourceID)
	if !query.CreatedFrom.IsZero() {
		args = append(args, formatSQLTime(query.CreatedFrom))
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.CreatedTo.IsZero() {
		args = append(args, formatSQLTime(query.CreatedTo))
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if len(where) > 0 {
		sqlQuery.WriteString("\nWHERE ")
		sqlQuery.WriteString(strings.Join(where, " AND "))
	}
	if query.Sort == "desc" {
		sqlQuery.WriteString("\nORDER BY created_at DESC, id DESC")
	} else {
		sqlQuery.WriteString("\nORDER BY created_at ASC, id ASC")
	}
	if query.Limit > 0 {
		args = append(args, query.Limit)
		sqlQuery.WriteString(fmt.Sprintf("\nLIMIT $%d", len(args)))
		if query.Offset > 0 {
			args = append(args, query.Offset)
			sqlQuery.WriteString(fmt.Sprintf(" OFFSET $%d", len(args)))
		}
	}

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (r sqlRepository) VerifyAuditChain(ctx context.Context) (domain.AuditIntegrity, error) {
	if _, err := r.exec.ExecContext(ctx, `
UPDATE audit_chain_state
SET updated_at = updated_at
WHERE singleton_id = 1`); err != nil {
		return domain.AuditIntegrity{}, fmt.Errorf("lock audit chain state: %w", err)
	}
	state, err := r.readAuditChainState(ctx)
	if err != nil {
		return domain.AuditIntegrity{}, err
	}
	events, err := r.listAuditEventsBySequence(ctx)
	if err != nil {
		return domain.AuditIntegrity{}, err
	}
	return verifyAuditState(events, state), nil
}

func (r sqlRepository) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	state, events, _, err := r.lockAndVerifyAuditChain(ctx)
	if err != nil {
		return 0, err
	}
	deleteCount := auditRetentionPrefixLength(events, before)
	if deleteCount < 0 {
		return 0, fmt.Errorf("%w: retention_cutoff_non_prefix", domain.ErrAuditIntegrity)
	}
	if deleteCount == 0 {
		return 0, nil
	}
	lastDeleted := events[deleteCount-1]
	result, err := r.exec.ExecContext(ctx, `
DELETE FROM audit_events
WHERE sequence <= $1`, lastDeleted.Sequence)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows != int64(deleteCount) {
		return 0, fmt.Errorf("%w: prune_row_count_mismatch", domain.ErrAuditIntegrity)
	}
	state.CheckpointSequence = lastDeleted.Sequence
	state.CheckpointEventHash = lastDeleted.EventHash
	state.UpdatedAt = time.Now()
	if err := r.updateAuditChainState(ctx, state); err != nil {
		return 0, err
	}
	remaining := events[deleteCount:]
	if after := verifyAuditState(remaining, state); !after.Valid {
		return 0, auditIntegrityError(after)
	}
	return deleteCount, nil
}

func (r sqlRepository) lockAndVerifyAuditChain(ctx context.Context) (auditChainState, []domain.AuditEvent, domain.AuditIntegrity, error) {
	if _, err := r.exec.ExecContext(ctx, `
UPDATE audit_chain_state
SET updated_at = updated_at
WHERE singleton_id = 1`); err != nil {
		return auditChainState{}, nil, domain.AuditIntegrity{}, fmt.Errorf("lock audit chain state: %w", err)
	}
	state, err := r.readAuditChainState(ctx)
	if err != nil {
		return auditChainState{}, nil, domain.AuditIntegrity{}, err
	}
	events, err := r.listAuditEventsBySequence(ctx)
	if err != nil {
		return auditChainState{}, nil, domain.AuditIntegrity{}, err
	}
	report := verifyAuditState(events, state)
	if err := auditIntegrityError(report); err != nil {
		return state, events, report, err
	}
	return state, events, report, nil
}

func (r sqlRepository) readAuditChainState(ctx context.Context) (auditChainState, error) {
	var state auditChainState
	var updatedAt any
	err := r.exec.QueryRowContext(ctx, `
SELECT hash_algorithm, latest_sequence, latest_event_hash,
	checkpoint_sequence, checkpoint_event_hash, updated_at
FROM audit_chain_state
WHERE singleton_id = 1`).Scan(
		&state.HashAlgorithm,
		&state.LatestSequence,
		&state.LatestEventHash,
		&state.CheckpointSequence,
		&state.CheckpointEventHash,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auditChainState{}, fmt.Errorf("%w: state_missing", domain.ErrAuditIntegrity)
	}
	if err != nil {
		return auditChainState{}, err
	}
	state.UpdatedAt, err = parseSQLTime(updatedAt)
	if err != nil {
		return auditChainState{}, err
	}
	return state, nil
}

func (r sqlRepository) listAuditEventsBySequence(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, sequence, actor, action, resource_type, resource_id, metadata_json,
	hash_algorithm, previous_event_hash, event_hash, created_at
FROM audit_events
ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (r sqlRepository) updateAuditChainState(ctx context.Context, state auditChainState) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE audit_chain_state
SET hash_algorithm = $1,
	latest_sequence = $2,
	latest_event_hash = $3,
	checkpoint_sequence = $4,
	checkpoint_event_hash = $5,
	updated_at = $6
WHERE singleton_id = 1`,
		state.HashAlgorithm,
		state.LatestSequence,
		state.LatestEventHash,
		state.CheckpointSequence,
		state.CheckpointEventHash,
		formatSQLTime(state.UpdatedAt),
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("%w: state_missing", domain.ErrAuditIntegrity)
	}
	return nil
}
