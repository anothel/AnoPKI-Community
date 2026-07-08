// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestOutboxHandlerRegistryRoutesByMessageType(t *testing.T) {
	ctx := context.Background()
	var handled []string
	registry := NewOutboxHandlerRegistry(map[string]OutboxHandler{
		"certificate.revoked": OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
			handled = append(handled, message.ID)
			return nil
		}),
	})

	err := registry.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.revoked",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxProcessing,
		AvailableAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		CreatedAt:   time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		UpdatedAt:   time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if len(handled) != 1 || handled[0] != "outbox-1" {
		t.Fatalf("handled = %#v, want outbox-1", handled)
	}
}

func TestOutboxHandlerRegistryRejectsUnknownMessageType(t *testing.T) {
	err := NewOutboxHandlerRegistry(nil).HandleOutboxMessage(context.Background(), domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "unknown.event",
		PayloadJSON: `{}`,
	})
	if !errors.Is(err, ErrOutboxHandlerNotFound) {
		t.Fatalf("HandleOutboxMessage error = %v, want ErrOutboxHandlerNotFound", err)
	}
}

func TestLifecycleOutboxHandlerAcceptsKnownLifecycleTypes(t *testing.T) {
	ctx := context.Background()
	handler := NewLifecycleOutboxHandler()

	for _, messageType := range []string{
		"certificate.suspended",
		"certificate.resumed",
		"certificate.renewal_requested",
		"certificate.reissue_requested",
		"certificate.expiration_warning",
		"certificate.expired",
		"certificate.revoked",
		"certificate.force_revoked",
	} {
		err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
			ID:          "outbox-" + messageType,
			Type:        messageType,
			PayloadJSON: `{"certificate_id":"cert-1"}`,
		})
		if err != nil {
			t.Fatalf("HandleOutboxMessage(%s) returned error: %v", messageType, err)
		}
	}
}

func TestLifecycleOutboxHandlerRoutesLifecycleTypesToWebhook(t *testing.T) {
	ctx := context.Background()
	handled := make([]string, 0)
	handler := NewLifecycleOutboxHandlerWithWebhook(OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		handled = append(handled, message.Type)
		return nil
	}))

	for _, messageType := range []string{
		"certificate.expiration_warning",
		"certificate.expired",
		"certificate.revoked",
	} {
		if err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
			ID:          "outbox-" + messageType,
			Type:        messageType,
			PayloadJSON: `{"certificate_id":"cert-1"}`,
		}); err != nil {
			t.Fatalf("HandleOutboxMessage(%s) returned error: %v", messageType, err)
		}
	}
	if len(handled) != 3 {
		t.Fatalf("handled types = %#v, want three webhook deliveries", handled)
	}
}
