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

type auditChainState struct {
	TailChainIndex  int64
	TailEventID     string
	TailEventHash   string
	TotalEventCount int64
}

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

func (s *SQLStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	deleted := 0
	err := s.WithinTx(ctx, func(repo Repository) error {
		var err error
		deleted, err = repo.DeleteAuditEventsBefore(ctx, before)
		return err
	})
	return deleted, err
}

func (s *SQLStore) VerifyAuditChain(ctx context.Context) (domain.AuditChainVerification, error) {
	return s.repository().VerifyAuditChain(ctx)
}

func readAuditChainState(ctx context.Context, exec sqlExecutor) (auditChainState, error) {
	var state auditChainState
	err := exec.QueryRowContext(ctx, `
SELECT tail_chain_index, tail_event_id, tail_event_hash, total_event_count
FROM audit_chain_state
WHERE id = 1`).Scan(&state.TailChainIndex, &state.TailEventID, &state.TailEventHash, &state.TotalEventCount)
	if err != nil {
		return auditChainState{}, fmt.Errorf("read audit chain state: %w", err)
	}
	return state, nil
}

func validateAuditTail(ctx context.Context, exec sqlExecutor, state auditChainState) error {
	if state.TotalEventCount != state.TailChainIndex {
		return domain.ErrAuditChainConflict
	}
	if state.TailChainIndex == 0 {
		if state.TailEventID != "" || state.TailEventHash != "" || state.TotalEventCount != 0 {
			return domain.ErrAuditChainConflict
		}
		return nil
	}
	var chainIndex int64
	var eventHash string
	err := exec.QueryRowContext(ctx, `
SELECT chain_index, event_hash
FROM audit_events
WHERE id = $1`, state.TailEventID).Scan(&chainIndex, &eventHash)
	if errors.Is(err, sql.ErrNoRows) {
		var checkpointIndex int64
		var checkpointHash string
		err = exec.QueryRowContext(ctx, `
SELECT through_chain_index, through_event_hash
FROM audit_chain_checkpoints
WHERE through_event_id = $1
ORDER BY through_chain_index DESC
LIMIT 1`, state.TailEventID).Scan(&checkpointIndex, &checkpointHash)
		if err != nil || checkpointIndex != state.TailChainIndex || checkpointHash != state.TailEventHash {
			return domain.ErrAuditChainConflict
		}
		return nil
	}
	if err != nil || chainIndex != state.TailChainIndex || eventHash != state.TailEventHash {
		return domain.ErrAuditChainConflict
	}
	return nil
}

func (r sqlRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	state, err := readAuditChainState(ctx, r.exec)
	if err != nil {
		return err
	}
	if err := validateAuditTail(ctx, r.exec, state); err != nil {
		return err
	}
	hashed, err := withAuditEventHash(state.TailEventHash, state.TailChainIndex+1, event)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE audit_chain_state
SET tail_chain_index = $1, tail_event_id = $2, tail_event_hash = $3,
	total_event_count = total_event_count + 1, updated_at = $4
WHERE id = 1 AND tail_chain_index = $5 AND tail_event_id = $6 AND tail_event_hash = $7`,
		hashed.ChainIndex, hashed.ID, hashed.EventHash, formatSQLTime(time.Now()),
		state.TailChainIndex, state.TailEventID, state.TailEventHash)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return domain.ErrAuditChainConflict
	}
	if _, err := r.exec.ExecContext(ctx, `
INSERT INTO audit_events (
	id, actor, action, resource_type, resource_id, metadata_json,
	chain_index, hash_algorithm, previous_event_hash, event_hash, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)`, hashed.ID, hashed.Actor, hashed.Action, hashed.ResourceType, hashed.ResourceID, hashed.MetadataJSON,
		hashed.ChainIndex, hashed.HashAlgorithm, hashed.PreviousEventHash, hashed.EventHash, formatSQLTime(hashed.CreatedAt)); err != nil {
		return err
	}
	return nil
}

const auditEventSelectColumns = `id, actor, action, resource_type, resource_id, metadata_json,
	chain_index, hash_algorithm, previous_event_hash, event_hash, created_at`

func (r sqlRepository) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := r.exec.QueryContext(ctx, `SELECT `+auditEventSelectColumns+`
FROM audit_events
ORDER BY chain_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuditEvents(rows)
}

func scanAuditEvents(rows *sql.Rows) ([]domain.AuditEvent, error) {
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
	sqlQuery.WriteString(`SELECT ` + auditEventSelectColumns + `
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
	return scanAuditEvents(rows)
}

func latestAuditCheckpoint(ctx context.Context, exec sqlExecutor) (domain.AuditChainCheckpoint, error) {
	var checkpoint domain.AuditChainCheckpoint
	var cutoff any
	var createdAt any
	err := exec.QueryRowContext(ctx, `
SELECT id, through_chain_index, through_event_id, through_event_hash, retention_cutoff, created_at
FROM audit_chain_checkpoints
ORDER BY through_chain_index DESC
LIMIT 1`).Scan(&checkpoint.ID, &checkpoint.ThroughChainIndex, &checkpoint.ThroughEventID, &checkpoint.ThroughEventHash, &cutoff, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AuditChainCheckpoint{}, nil
	}
	if err != nil {
		return domain.AuditChainCheckpoint{}, err
	}
	checkpoint.RetentionCutoff, err = parseSQLTime(cutoff)
	if err != nil {
		return domain.AuditChainCheckpoint{}, err
	}
	checkpoint.CreatedAt, err = parseSQLTime(createdAt)
	if err != nil {
		return domain.AuditChainCheckpoint{}, err
	}
	return checkpoint, nil
}

func (r sqlRepository) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	verification, err := r.VerifyAuditChain(ctx)
	if err != nil {
		return 0, err
	}
	if !verification.Verified {
		return 0, domain.ErrAuditChainConflict
	}
	events, err := r.ListAuditEvents(ctx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for deleted < len(events) && events[deleted].CreatedAt.Before(before) {
		deleted++
	}
	if deleted == 0 {
		return 0, nil
	}
	through := events[deleted-1]
	checkpoint := domain.AuditChainCheckpoint{
		ID:                auditCheckpointID(through.ChainIndex, through.ID, through.EventHash, before),
		ThroughChainIndex: through.ChainIndex, ThroughEventID: through.ID, ThroughEventHash: through.EventHash,
		RetentionCutoff: before.UTC(), CreatedAt: time.Now().UTC(),
	}
	if _, err := r.exec.ExecContext(ctx, `
INSERT INTO audit_chain_checkpoints (
	id, through_chain_index, through_event_id, through_event_hash, retention_cutoff, created_at
) VALUES ($1, $2, $3, $4, $5, $6)`, checkpoint.ID, checkpoint.ThroughChainIndex, checkpoint.ThroughEventID,
		checkpoint.ThroughEventHash, formatSQLTime(checkpoint.RetentionCutoff), formatSQLTime(checkpoint.CreatedAt)); err != nil {
		return 0, err
	}
	result, err := r.exec.ExecContext(ctx, `DELETE FROM audit_events WHERE chain_index <= $1`, through.ChainIndex)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if int(rows) != deleted {
		return 0, domain.ErrAuditChainConflict
	}
	return deleted, nil
}

func (r sqlRepository) VerifyAuditChain(ctx context.Context) (domain.AuditChainVerification, error) {
	state, err := readAuditChainState(ctx, r.exec)
	if err != nil {
		return domain.AuditChainVerification{}, err
	}
	checkpoint, err := latestAuditCheckpoint(ctx, r.exec)
	if err != nil {
		return domain.AuditChainVerification{}, err
	}
	events, err := r.ListAuditEvents(ctx)
	if err != nil {
		return domain.AuditChainVerification{}, err
	}
	return verifyAuditChain(events, checkpoint, state.TailChainIndex, state.TailEventID, state.TailEventHash, state.TotalEventCount), nil
}
