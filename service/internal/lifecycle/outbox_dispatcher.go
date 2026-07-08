// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

const (
	defaultOutboxMaxAttempts     = 5
	defaultOutboxProcessingLease = 10 * time.Minute
)

var outboxRetryDelays = []time.Duration{
	time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	time.Hour,
}

type OutboxHandler interface {
	HandleOutboxMessage(context.Context, domain.OutboxMessage) error
}

type OutboxHandlerFunc func(context.Context, domain.OutboxMessage) error

func (fn OutboxHandlerFunc) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	return fn(ctx, message)
}

type OutboxDispatcher struct {
	repo    store.Repository
	handler OutboxHandler
	clock   Clock
	idgen   IDGenerator
}

func NewOutboxDispatcher(repo store.Repository, handler OutboxHandler, clock Clock, idgen IDGenerator) *OutboxDispatcher {
	return &OutboxDispatcher{
		repo:    repo,
		handler: handler,
		clock:   clock,
		idgen:   idgen,
	}
}

func (d *OutboxDispatcher) RunOnce(ctx context.Context, limit int) (int, error) {
	messages, err := d.repo.ListDueOutboxMessages(ctx, d.clock.Now(), limit)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, message := range messages {
		claimed, ok, err := d.claim(ctx, message)
		if err != nil {
			return processed, err
		}
		if !ok {
			continue
		}

		startedAt := d.clock.Now()
		handlerErr := d.handler.HandleOutboxMessage(ctx, claimed)
		finishedAt := d.clock.Now()

		attemptStatus := domain.JobAttemptSucceeded
		nextStatus := domain.OutboxCompleted
		errorMessage := ""
		if handlerErr != nil {
			attemptStatus = domain.JobAttemptFailed
			errorMessage = handlerErr.Error()
			claimed.AttemptCount++
			claimed.MaxAttempts = effectiveOutboxMaxAttempts(claimed)
			claimed.LastError = errorMessage
			if claimed.AttemptCount >= claimed.MaxAttempts {
				nextStatus = domain.OutboxDeadLetter
			} else {
				nextStatus = domain.OutboxPending
				claimed.AvailableAt = finishedAt.Add(outboxRetryDelayForMessage(claimed))
			}
		} else {
			claimed.LastError = ""
		}

		if err := d.finish(ctx, claimed, nextStatus, domain.JobAttempt{
			ID:              d.idgen.NewID(),
			OutboxMessageID: claimed.ID,
			Status:          attemptStatus,
			Error:           errorMessage,
			StartedAt:       startedAt,
			FinishedAt:      finishedAt,
			CreatedAt:       finishedAt,
		}); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func effectiveOutboxMaxAttempts(message domain.OutboxMessage) int {
	if message.MaxAttempts > 0 {
		return message.MaxAttempts
	}
	return defaultOutboxMaxAttempts
}

func outboxRetryDelayForAttempt(attemptCount int) time.Duration {
	if attemptCount <= 1 {
		return outboxRetryDelays[0]
	}
	index := attemptCount - 1
	if index >= len(outboxRetryDelays) {
		index = len(outboxRetryDelays) - 1
	}
	return outboxRetryDelays[index]
}

func outboxRetryDelayForMessage(message domain.OutboxMessage) time.Duration {
	base := outboxRetryDelayForAttempt(message.AttemptCount)
	jitterMax := base / 10
	if jitterMax <= 0 {
		return base
	}
	hash := fnv.New32a()
	var attempt [8]byte
	binary.LittleEndian.PutUint64(attempt[:], nonNegativeUint64(message.AttemptCount))
	_, _ = hash.Write([]byte(message.ID))
	_, _ = hash.Write(attempt[:])
	return base + time.Duration(hash.Sum32())%(jitterMax+1)
}

func nonNegativeUint64(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func (d *OutboxDispatcher) claim(ctx context.Context, message domain.OutboxMessage) (domain.OutboxMessage, bool, error) {
	currentStatus := message.Status
	if currentStatus != domain.OutboxPending && currentStatus != domain.OutboxProcessing {
		return domain.OutboxMessage{}, false, nil
	}
	now := d.clock.Now()
	if currentStatus == domain.OutboxProcessing {
		recovered := message
		recovered.Status = domain.OutboxPending
		recovered.ProcessingDeadlineAt = time.Time{}
		recovered.UpdatedAt = now
		err := d.repo.UpdateOutboxMessageIfCurrent(ctx, recovered, message)
		if errors.Is(err, domain.ErrInvalidTransition) || errors.Is(err, domain.ErrOutboxMessageNotFound) {
			return domain.OutboxMessage{}, false, nil
		}
		if err != nil {
			return domain.OutboxMessage{}, false, err
		}
		message = recovered
	}
	claimed := message
	claimed.Status = domain.OutboxProcessing
	claimed.ProcessingDeadlineAt = now.Add(defaultOutboxProcessingLease)
	claimed.UpdatedAt = now
	err := d.repo.UpdateOutboxMessageIfCurrent(ctx, claimed, message)
	if errors.Is(err, domain.ErrInvalidTransition) || errors.Is(err, domain.ErrOutboxMessageNotFound) {
		return domain.OutboxMessage{}, false, nil
	}
	if err != nil {
		return domain.OutboxMessage{}, false, err
	}
	return claimed, true, nil
}

func (d *OutboxDispatcher) finish(ctx context.Context, message domain.OutboxMessage, status domain.OutboxMessageStatus, attempt domain.JobAttempt) error {
	return d.repo.WithinTx(ctx, func(repo store.Repository) error {
		finished := message
		finished.Status = status
		finished.ProcessingDeadlineAt = time.Time{}
		finished.UpdatedAt = attempt.FinishedAt
		if err := repo.UpdateOutboxMessageIfCurrent(ctx, finished, message); err != nil {
			return err
		}
		return repo.CreateJobAttempt(ctx, attempt)
	})
}
