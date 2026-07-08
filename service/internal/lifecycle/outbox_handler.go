// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"fmt"

	"github.com/anothel/anopki/service/internal/domain"
)

var ErrOutboxHandlerNotFound = errors.New("outbox handler not found")

type OutboxHandlerRegistry struct {
	handlers map[string]OutboxHandler
}

func NewOutboxHandlerRegistry(handlers map[string]OutboxHandler) *OutboxHandlerRegistry {
	copied := make(map[string]OutboxHandler, len(handlers))
	for messageType, handler := range handlers {
		copied[messageType] = handler
	}
	return &OutboxHandlerRegistry{handlers: copied}
}

func (r *OutboxHandlerRegistry) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	handler, ok := r.handlers[message.Type]
	if !ok {
		return fmt.Errorf("%w: %s", ErrOutboxHandlerNotFound, message.Type)
	}
	return handler.HandleOutboxMessage(ctx, message)
}

type NoopOutboxHandler struct{}

func (NoopOutboxHandler) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	return nil
}

func NewLifecycleOutboxHandler() OutboxHandler {
	noop := NoopOutboxHandler{}
	return NewOutboxHandlerRegistry(map[string]OutboxHandler{
		"certificate.suspended":          noop,
		"certificate.resumed":            noop,
		"certificate.renewal_requested":  noop,
		"certificate.reissue_requested":  noop,
		"certificate.expiration_warning": noop,
		"certificate.expired":            noop,
		"certificate.revoked":            noop,
		"certificate.force_revoked":      noop,
	})
}

func NewLifecycleOutboxHandlerWithWebhook(webhook OutboxHandler) OutboxHandler {
	if webhook == nil {
		return NewLifecycleOutboxHandler()
	}
	return NewOutboxHandlerRegistry(map[string]OutboxHandler{
		"certificate.suspended":          webhook,
		"certificate.resumed":            webhook,
		"certificate.renewal_requested":  webhook,
		"certificate.reissue_requested":  webhook,
		"certificate.expiration_warning": webhook,
		"certificate.expired":            webhook,
		"certificate.revoked":            webhook,
		"certificate.force_revoked":      webhook,
	})
}
