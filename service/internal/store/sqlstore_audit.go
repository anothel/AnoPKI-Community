// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func (s *SQLStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return s.repository().CreateAuditEvent(ctx, event)
}

func (s *SQLStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEvents(ctx)
}

func (s *SQLStore) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEventsQuery(ctx, query)
}

func (s *SQLStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	return s.repository().DeleteAuditEventsBefore(ctx, before)
}

func (r sqlRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO audit_events (
	id, actor, action, resource_type, resource_id, metadata_json, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7
)`,
		event.ID,
		event.Actor,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.MetadataJSON,
		formatSQLTime(event.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, actor, action, resource_type, resource_id, metadata_json, created_at
FROM audit_events
ORDER BY created_at, id`)
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
	sqlQuery.WriteString(`SELECT id, actor, action, resource_type, resource_id, metadata_json, created_at
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

func (r sqlRepository) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	result, err := r.exec.ExecContext(ctx, `
DELETE FROM audit_events
WHERE created_at < $1`, formatSQLTime(before))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}
