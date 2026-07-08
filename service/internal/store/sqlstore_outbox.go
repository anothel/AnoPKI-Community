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

func (s *SQLStore) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	return s.repository().CreateOutboxMessage(ctx, message)
}

func (s *SQLStore) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	return s.repository().GetOutboxMessage(ctx, id)
}

func (s *SQLStore) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	return s.repository().ListOutboxMessages(ctx, status)
}

func (s *SQLStore) ListOutboxMessagesQuery(ctx context.Context, query OutboxMessageQuery) ([]domain.OutboxMessage, error) {
	return s.repository().ListOutboxMessagesQuery(ctx, query)
}

func (s *SQLStore) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	return s.repository().ListDueOutboxMessages(ctx, now, limit)
}

func (s *SQLStore) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	return s.repository().UpdateOutboxMessageStatusIfStatus(ctx, message, currentStatus)
}

func (s *SQLStore) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	return s.repository().UpdateOutboxMessageIfCurrent(ctx, message, current)
}

func (s *SQLStore) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	return s.repository().CreateJobAttempt(ctx, attempt)
}

func (s *SQLStore) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	return s.repository().ListJobAttemptsByOutboxMessage(ctx, outboxMessageID)
}

func (s *SQLStore) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	return s.repository().GetWebhookDelivery(ctx, outboxMessageID, endpointID)
}

func (s *SQLStore) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	return s.repository().UpsertWebhookDelivery(ctx, delivery)
}

func (r sqlRepository) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO outbox_messages (
	id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)`,
		message.ID,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	message, err := scanOutboxMessage(r.exec.QueryRowContext(ctx, `
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OutboxMessage{}, domain.ErrOutboxMessageNotFound
	}
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	return message, nil
}

func (r sqlRepository) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	query := `
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages`
	args := []any{}
	if status != "" {
		query += " WHERE status = $1"
		args = append(args, string(status))
	}
	query += " ORDER BY created_at, id"

	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]domain.OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutboxMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r sqlRepository) ListOutboxMessagesQuery(ctx context.Context, query OutboxMessageQuery) ([]domain.OutboxMessage, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	if query.Status != "" {
		addSQLStringCondition(&args, &conditions, "status", string(query.Status))
	}
	addSQLStringCondition(&args, &conditions, "type", query.Type)
	if !query.CreatedFrom.IsZero() {
		args = append(args, formatSQLTime(query.CreatedFrom))
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.CreatedTo.IsZero() {
		args = append(args, formatSQLTime(query.CreatedTo))
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]domain.OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutboxMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r sqlRepository) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	if limit <= 0 {
		return nil, nil
	}

	rows, err := r.exec.QueryContext(ctx, `
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE (status = $1 AND available_at <= $3)
	OR (status = $2 AND processing_deadline_at IS NOT NULL AND processing_deadline_at <= $3)
ORDER BY CASE WHEN status = $1 THEN available_at ELSE processing_deadline_at END, created_at, id
LIMIT $4`, string(domain.OutboxPending), string(domain.OutboxProcessing), formatSQLTime(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]domain.OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutboxMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r sqlRepository) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE outbox_messages
SET type = $1,
	payload_json = $2,
	status = $3,
	available_at = $4,
	processing_deadline_at = $5,
	attempt_count = $6,
	max_attempts = $7,
	last_error = $8,
	created_at = $9,
	updated_at = $10
WHERE id = $11 AND status = $12`,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
		message.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := scanOutboxMessage(r.exec.QueryRowContext(ctx, `
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, message.ID)); errors.Is(err, sql.ErrNoRows) {
		return domain.ErrOutboxMessageNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	currentProcessingDeadlineAt := formatNullableSQLTime(current.ProcessingDeadlineAt)
	result, err := r.exec.ExecContext(ctx, `
UPDATE outbox_messages
SET type = $1,
	payload_json = $2,
	status = $3,
	available_at = $4,
	processing_deadline_at = $5,
	attempt_count = $6,
	max_attempts = $7,
	last_error = $8,
	created_at = $9,
	updated_at = $10
WHERE id = $11
	AND status = $12
	AND updated_at = $13
	AND ((processing_deadline_at IS NULL AND $14 IS NULL) OR processing_deadline_at = $14)`,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
		message.ID,
		string(current.Status),
		formatSQLTime(current.UpdatedAt),
		currentProcessingDeadlineAt,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := scanOutboxMessage(r.exec.QueryRowContext(ctx, `
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, message.ID)); errors.Is(err, sql.ErrNoRows) {
		return domain.ErrOutboxMessageNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO job_attempts (
	id, outbox_message_id, status, error, started_at, finished_at, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7
)`,
		attempt.ID,
		attempt.OutboxMessageID,
		string(attempt.Status),
		attempt.Error,
		formatSQLTime(attempt.StartedAt),
		formatSQLTime(attempt.FinishedAt),
		formatSQLTime(attempt.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, outbox_message_id, status, error, started_at, finished_at, created_at
FROM job_attempts
WHERE outbox_message_id = $1
ORDER BY created_at, id`, outboxMessageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	attempts := make([]domain.JobAttempt, 0)
	for rows.Next() {
		attempt, err := scanJobAttempt(rows)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return attempts, nil
}

func (r sqlRepository) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	delivery, err := scanWebhookDelivery(r.exec.QueryRowContext(ctx, `
SELECT outbox_message_id, endpoint_id, status, attempt_count, last_error, last_attempted_at, created_at, updated_at
FROM webhook_deliveries
WHERE outbox_message_id = $1 AND endpoint_id = $2`, outboxMessageID, endpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WebhookDelivery{}, domain.ErrWebhookDeliveryNotFound
	}
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	return delivery, nil
}

func (r sqlRepository) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO webhook_deliveries (
	outbox_message_id, endpoint_id, status, attempt_count, last_error, last_attempted_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (outbox_message_id, endpoint_id) DO UPDATE SET
	status = excluded.status,
	attempt_count = excluded.attempt_count,
	last_error = excluded.last_error,
	last_attempted_at = excluded.last_attempted_at,
	updated_at = excluded.updated_at`,
		delivery.OutboxMessageID,
		delivery.EndpointID,
		string(delivery.Status),
		delivery.AttemptCount,
		delivery.LastError,
		formatSQLTime(delivery.LastAttemptedAt),
		formatSQLTime(delivery.CreatedAt),
		formatSQLTime(delivery.UpdatedAt),
	)
	return err
}
