// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

func TestOutboxDispatcherCompletesHandledMessage(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: clock.now.Add(-time.Minute),
		CreatedAt:   clock.now.Add(-time.Minute),
		UpdatedAt:   clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	handled := make([]domain.OutboxMessage, 0)
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		handled = append(handled, message)
		return nil
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	if len(handled) != 1 || handled[0].ID != message.ID {
		t.Fatalf("handled messages = %#v", handled)
	}
	due, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due messages after success = %#v, want none", due)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != domain.JobAttemptSucceeded || attempts[0].Error != "" {
		t.Fatalf("attempts = %#v, want one success", attempts)
	}
}

func TestOutboxDispatcherRecordsFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: clock.now.Add(-time.Minute),
		CreatedAt:   clock.now.Add(-time.Minute),
		UpdatedAt:   clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	errNotify := errors.New("notify failed")
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		return errNotify
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	due, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due messages after failure = %#v, want none", due)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != domain.JobAttemptFailed || attempts[0].Error != "notify failed" {
		t.Fatalf("attempts = %#v, want one failed attempt", attempts)
	}
	failed := message
	failed.AttemptCount = 1
	retryDelay := outboxRetryDelayForMessage(failed)
	retryDue, err := repo.ListDueOutboxMessages(ctx, clock.now.Add(retryDelay), 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages retry returned error: %v", err)
	}
	if len(retryDue) != 1 || retryDue[0].ID != message.ID || retryDue[0].Status != domain.OutboxPending {
		t.Fatalf("retry due messages = %#v, want pending message", retryDue)
	}
	if retryDue[0].AttemptCount != 1 || retryDue[0].LastError != "notify failed" {
		t.Fatalf("retry metadata = %#v", retryDue[0])
	}
	if !retryDue[0].AvailableAt.Equal(clock.now.Add(retryDelay)) {
		t.Fatalf("retry available_at = %s, want %s", retryDue[0].AvailableAt, clock.now.Add(retryDelay))
	}
}

func TestOutboxDispatcherUsesCappedBackoff(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:           "outbox-1",
		Type:         "certificate.expiring",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxPending,
		AvailableAt:  clock.now.Add(-time.Minute),
		AttemptCount: 2,
		MaxAttempts:  5,
		CreatedAt:    clock.now.Add(-time.Minute),
		UpdatedAt:    clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		return errors.New("still down")
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	failed := message
	failed.AttemptCount = 3
	retryDelay := outboxRetryDelayForMessage(failed)
	retryDue, err := repo.ListDueOutboxMessages(ctx, clock.now.Add(retryDelay), 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages retry returned error: %v", err)
	}
	if len(retryDue) != 1 || retryDue[0].AttemptCount != 3 || retryDue[0].LastError != "still down" {
		t.Fatalf("retry due = %#v", retryDue)
	}
	if !retryDue[0].AvailableAt.Equal(clock.now.Add(retryDelay)) {
		t.Fatalf("retry available_at = %s, want %s", retryDue[0].AvailableAt, clock.now.Add(retryDelay))
	}
}

func TestOutboxDispatcherJittersRetryBackoff(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	for _, id := range []string{"outbox-a", "outbox-b"} {
		if err := repo.CreateOutboxMessage(ctx, domain.OutboxMessage{
			ID:          id,
			Type:        "certificate.expiring",
			PayloadJSON: `{"certificate_id":"cert-1"}`,
			Status:      domain.OutboxPending,
			AvailableAt: clock.now.Add(-time.Minute),
			CreatedAt:   clock.now.Add(-time.Minute),
			UpdatedAt:   clock.now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("CreateOutboxMessage(%s) returned error: %v", id, err)
		}
	}
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		return errors.New("notify failed")
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 2 {
		t.Fatalf("processed = %d, want 2", processed)
	}
	messages, err := repo.ListOutboxMessages(ctx, domain.OutboxPending)
	if err != nil {
		t.Fatalf("ListOutboxMessages returned error: %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("pending messages = %#v, want 2", messages)
	}
	base := clock.now.Add(outboxRetryDelayForAttempt(1))
	max := base.Add(outboxRetryDelayForAttempt(1) / 10)
	if messages[0].AvailableAt.Equal(messages[1].AvailableAt) {
		t.Fatalf("retry available_at values were not jittered: %s", messages[0].AvailableAt)
	}
	for _, message := range messages {
		if message.AvailableAt.Before(base) || message.AvailableAt.After(max) {
			t.Fatalf("message %s available_at = %s, want within [%s, %s]", message.ID, message.AvailableAt, base, max)
		}
	}
}

func TestOutboxRetryDelayTreatsNegativeAttemptCountAsZero(t *testing.T) {
	message := domain.OutboxMessage{ID: "outbox-1", AttemptCount: -1}
	zeroAttempt := message
	zeroAttempt.AttemptCount = 0

	if got, want := outboxRetryDelayForMessage(message), outboxRetryDelayForMessage(zeroAttempt); got != want {
		t.Fatalf("retry delay for negative attempt = %s, want %s", got, want)
	}
}

func TestOutboxDispatcherDeadLettersAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:           "outbox-1",
		Type:         "certificate.expiring",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxPending,
		AvailableAt:  clock.now.Add(-time.Minute),
		AttemptCount: 4,
		MaxAttempts:  5,
		CreatedAt:    clock.now.Add(-time.Minute),
		UpdatedAt:    clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		return errors.New("permanent failure")
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	dead, err := repo.ListOutboxMessages(ctx, domain.OutboxDeadLetter)
	if err != nil {
		t.Fatalf("ListOutboxMessages dead letter returned error: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != message.ID || dead[0].AttemptCount != 5 || dead[0].LastError != "permanent failure" {
		t.Fatalf("dead letter messages = %#v", dead)
	}
}

func TestOutboxDispatcherRetriesAndDeadLettersWebhookFailures(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "ops",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		Secret:    "secret-1",
		CreatedAt: clock.now,
		UpdatedAt: clock.now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: clock.now,
		MaxAttempts: 2,
		CreatedAt:   clock.now,
		UpdatedAt:   clock.now,
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	dispatcher := NewOutboxDispatcher(repo, handler, clock, &fakeIDGenerator{})
	if processed, err := dispatcher.RunOnce(ctx, 10); err != nil || processed != 1 {
		t.Fatalf("first RunOnce processed=%d error=%v, want 1 nil", processed, err)
	}
	pending, err := repo.ListOutboxMessages(ctx, domain.OutboxPending)
	if err != nil {
		t.Fatalf("ListOutboxMessages pending returned error: %v", err)
	}
	if len(pending) != 1 || pending[0].AttemptCount != 1 || pending[0].LastError == "" {
		t.Fatalf("pending retry message = %#v, want one failed retry", pending)
	}

	retryClock := fixedClock{now: pending[0].AvailableAt}
	dispatcher = NewOutboxDispatcher(repo, handler, retryClock, &fakeIDGenerator{})
	if processed, err := dispatcher.RunOnce(ctx, 10); err != nil || processed != 1 {
		t.Fatalf("second RunOnce processed=%d error=%v, want 1 nil", processed, err)
	}
	dead, err := repo.ListOutboxMessages(ctx, domain.OutboxDeadLetter)
	if err != nil {
		t.Fatalf("ListOutboxMessages dead letter returned error: %v", err)
	}
	if len(dead) != 1 || dead[0].AttemptCount != 2 || dead[0].LastError == "" {
		t.Fatalf("dead-letter message = %#v, want failed webhook after retry", dead)
	}
	delivery, err := repo.GetWebhookDelivery(ctx, message.ID, "endpoint-1")
	if err != nil {
		t.Fatalf("GetWebhookDelivery returned error: %v", err)
	}
	if delivery.Status != domain.JobAttemptFailed || delivery.AttemptCount != 2 || requests != 2 {
		t.Fatalf("delivery=%#v requests=%d, want two failed webhook attempts", delivery, requests)
	}
}

func TestOutboxDispatcherReclaimsExpiredProcessingMessage(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:                   "outbox-1",
		Type:                 "certificate.expiring",
		PayloadJSON:          `{"certificate_id":"cert-1"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          clock.now.Add(-time.Hour),
		ProcessingDeadlineAt: clock.now.Add(-time.Minute),
		CreatedAt:            clock.now.Add(-time.Hour),
		UpdatedAt:            clock.now.Add(-time.Hour),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	handled := 0
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		handled++
		return nil
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 || handled != 1 {
		t.Fatalf("processed = %d handled = %d, want 1/1", processed, handled)
	}
	completed, err := repo.ListOutboxMessages(ctx, domain.OutboxCompleted)
	if err != nil {
		t.Fatalf("ListOutboxMessages completed returned error: %v", err)
	}
	if len(completed) != 1 || completed[0].ID != message.ID || !completed[0].ProcessingDeadlineAt.IsZero() {
		t.Fatalf("completed messages = %#v", completed)
	}
}

func TestOutboxDispatcherDoesNotStealRenewedProcessingLease(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	stale := domain.OutboxMessage{
		ID:                   "outbox-1",
		Type:                 "certificate.expiring",
		PayloadJSON:          `{"certificate_id":"cert-1"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          clock.now.Add(-time.Hour),
		ProcessingDeadlineAt: clock.now.Add(-time.Minute),
		CreatedAt:            clock.now.Add(-time.Hour),
		UpdatedAt:            clock.now.Add(-time.Hour),
	}
	if err := repo.CreateOutboxMessage(ctx, stale); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	dispatcher := NewOutboxDispatcher(repo, NoopOutboxHandler{}, clock, &fakeIDGenerator{})
	claimed, ok, err := dispatcher.claim(ctx, stale)
	if err != nil {
		t.Fatalf("first claim returned error: %v", err)
	}
	if !ok {
		t.Fatal("first claim returned ok=false, want true")
	}
	if !claimed.ProcessingDeadlineAt.After(clock.now) {
		t.Fatalf("first claim deadline = %s, want after %s", claimed.ProcessingDeadlineAt, clock.now)
	}

	_, ok, err = dispatcher.claim(ctx, stale)
	if err != nil {
		t.Fatalf("stale second claim returned error: %v", err)
	}
	if ok {
		t.Fatal("stale second claim returned ok=true, want false")
	}
}
