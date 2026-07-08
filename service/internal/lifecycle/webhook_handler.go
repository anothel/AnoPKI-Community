// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

type webhookDeliveryRequest struct {
	SchemaVersion   int            `json:"schema_version"`
	OutboxMessageID string         `json:"outbox_message_id"`
	EventType       string         `json:"event_type"`
	Payload         map[string]any `json:"payload"`
	CreatedAt       time.Time      `json:"created_at"`
}

type WebhookOutboxHandler struct {
	repo       webhookRepository
	httpClient *http.Client
}

type webhookRepository interface {
	store.NotificationEndpointRepository
	GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error)
	UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error
}

func NewWebhookOutboxHandler(repo webhookRepository, httpClient *http.Client) *WebhookOutboxHandler {
	if httpClient == nil {
		httpClient = newACMEHTTP01Client(true)
	}
	return &WebhookOutboxHandler{
		repo:       repo,
		httpClient: httpClient,
	}
}

func (h *WebhookOutboxHandler) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	endpoints, err := h.repo.ListNotificationEndpoints(ctx)
	if err != nil {
		return err
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(message.PayloadJSON), &payload); err != nil {
		return fmt.Errorf("decode outbox payload: %w", err)
	}
	body := webhookDeliveryRequest{
		SchemaVersion:   1,
		OutboxMessageID: message.ID,
		EventType:       message.Type,
		Payload:         payload,
		CreatedAt:       message.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	for _, endpoint := range endpoints {
		if !webhookEndpointMatches(endpoint, message.Type) {
			continue
		}
		delivery, err := h.repo.GetWebhookDelivery(ctx, message.ID, endpoint.ID)
		if err != nil && !errors.Is(err, domain.ErrWebhookDeliveryNotFound) {
			return err
		}
		if delivery.Status == domain.JobAttemptSucceeded {
			continue
		}
		if err := h.postWebhook(ctx, endpoint, message, data); err != nil {
			if updateErr := h.recordWebhookDelivery(ctx, message, endpoint, delivery, domain.JobAttemptFailed, err.Error()); updateErr != nil {
				return updateErr
			}
			return err
		}
		if err := h.recordWebhookDelivery(ctx, message, endpoint, delivery, domain.JobAttemptSucceeded, ""); err != nil {
			return err
		}
	}
	return nil
}

func (h *WebhookOutboxHandler) recordWebhookDelivery(ctx context.Context, message domain.OutboxMessage, endpoint domain.NotificationEndpoint, current domain.WebhookDelivery, status domain.JobAttemptStatus, lastError string) error {
	now := time.Now().UTC()
	createdAt := current.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	return h.repo.UpsertWebhookDelivery(ctx, domain.WebhookDelivery{
		OutboxMessageID: message.ID,
		EndpointID:      endpoint.ID,
		Status:          status,
		AttemptCount:    current.AttemptCount + 1,
		LastError:       lastError,
		LastAttemptedAt: now,
		CreatedAt:       createdAt,
		UpdatedAt:       now,
	})
}

func (h *WebhookOutboxHandler) postWebhook(ctx context.Context, endpoint domain.NotificationEndpoint, message domain.OutboxMessage, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AnoPKI-Event", message.Type)
	req.Header.Set("X-AnoPKI-Delivery", message.ID)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	req.Header.Set("X-AnoPKI-Timestamp", timestamp)
	if endpoint.Secret != "" {
		req.Header.Set("X-AnoPKI-Signature", signWebhookPayload(endpoint.Secret, timestamp, data))
	}

	res, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("webhook delivery failed: %s", res.Status)
	}
	return nil
}

func signWebhookPayload(secret string, timestamp string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(data)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func webhookEndpointMatches(endpoint domain.NotificationEndpoint, eventType string) bool {
	if endpoint.Type != domain.NotificationEndpointWebhook || endpoint.Status != domain.NotificationEndpointActive {
		return false
	}
	if len(endpoint.EventTypes) == 0 {
		return true
	}
	for _, candidate := range endpoint.EventTypes {
		if candidate == eventType {
			return true
		}
	}
	return false
}
