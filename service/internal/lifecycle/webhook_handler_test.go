// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

func TestWebhookOutboxHandlerPostsMatchingActiveEndpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()

	var received webhookDeliveryRequest
	var signature string
	var timestamp string
	var eventType string
	var deliveryID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		signature = r.Header.Get("X-AnoPKI-Signature")
		timestamp = r.Header.Get("X-AnoPKI-Timestamp")
		eventType = r.Header.Get("X-AnoPKI-Event")
		deliveryID = r.Header.Get("X-AnoPKI-Delivery")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read webhook body: %v", err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		wantSignature := webhookSignature("secret-1", timestamp, body)
		if signature != wantSignature {
			t.Fatalf("signature = %q, want %q", signature, wantSignature)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:         "endpoint-1",
		Name:       "ops",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        server.URL,
		Secret:     "secret-1",
		EventTypes: []string{"certificate.expiration_warning"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if received.OutboxMessageID != "outbox-1" ||
		received.EventType != "certificate.expiration_warning" ||
		received.SchemaVersion != 1 ||
		received.CreatedAt != now {
		t.Fatalf("webhook body = %#v", received)
	}
	if eventType != "certificate.expiration_warning" || deliveryID != "outbox-1" || timestamp == "" {
		t.Fatalf("webhook headers event=%q delivery=%q timestamp=%q", eventType, deliveryID, timestamp)
	}
	if got := received.Payload["certificate_id"]; got != "cert-1" {
		t.Fatalf("payload certificate_id = %#v, want cert-1", got)
	}
}

func TestWebhookOutboxHandlerAllowsLegacyEndpointWithoutSecret(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-AnoPKI-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "legacy",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if signature != "" {
		t.Fatalf("legacy endpoint signature = %q, want empty", signature)
	}
}

func TestWebhookOutboxHandlerSkipsDisabledAndFilteredEndpoints(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	endpoints := []domain.NotificationEndpoint{
		{
			ID:         "disabled",
			Name:       "disabled",
			Type:       domain.NotificationEndpointWebhook,
			Status:     domain.NotificationEndpointDisabled,
			URL:        server.URL,
			Secret:     "secret-disabled",
			EventTypes: nil,
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		{
			ID:         "filtered",
			Name:       "filtered",
			Type:       domain.NotificationEndpointWebhook,
			Status:     domain.NotificationEndpointActive,
			URL:        server.URL,
			Secret:     "secret-filtered",
			EventTypes: []string{"certificate.expired"},
			CreatedAt:  now.Add(time.Second),
			UpdatedAt:  now.Add(time.Second),
		},
	}
	for _, endpoint := range endpoints {
		if err := repo.CreateNotificationEndpoint(ctx, endpoint); err != nil {
			t.Fatalf("CreateNotificationEndpoint(%s) returned error: %v", endpoint.ID, err)
		}
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if requests != 0 {
		t.Fatalf("webhook request count = %d, want 0", requests)
	}
}

func TestWebhookOutboxHandlerReturnsErrorOnHTTPFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("HandleOutboxMessage error = %v, want HTTP 500 error", err)
	}
}

func TestWebhookOutboxHandlerRecordsTimeoutFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-timeout",
		Name:      "timeout",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		Secret:    "secret-1",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, &http.Client{Timeout: 10 * time.Millisecond})
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-timeout",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err == nil {
		t.Fatal("HandleOutboxMessage returned nil error, want timeout error")
	}
	delivery, err := repo.GetWebhookDelivery(ctx, "outbox-timeout", "endpoint-timeout")
	if err != nil {
		t.Fatalf("GetWebhookDelivery returned error: %v", err)
	}
	if delivery.Status != domain.JobAttemptFailed || delivery.AttemptCount != 1 || delivery.LastError == "" {
		t.Fatalf("timeout delivery = %#v, want failed attempt with error", delivery)
	}
}

func TestWebhookOutboxHandlerSkipsEndpointAlreadyDeliveredForMessage(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	okRequests := 0
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okRequests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okServer.Close()
	flakyRequests := 0
	flakyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flakyRequests++
		if flakyRequests == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer flakyServer.Close()

	for _, endpoint := range []domain.NotificationEndpoint{
		{
			ID:        "endpoint-ok",
			Name:      "ok",
			Type:      domain.NotificationEndpointWebhook,
			Status:    domain.NotificationEndpointActive,
			URL:       okServer.URL,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "endpoint-flaky",
			Name:      "flaky",
			Type:      domain.NotificationEndpointWebhook,
			Status:    domain.NotificationEndpointActive,
			URL:       flakyServer.URL,
			CreatedAt: now.Add(time.Second),
			UpdatedAt: now.Add(time.Second),
		},
	} {
		if err := repo.CreateNotificationEndpoint(ctx, endpoint); err != nil {
			t.Fatalf("CreateNotificationEndpoint(%s) returned error: %v", endpoint.ID, err)
		}
	}

	handler := NewWebhookOutboxHandler(repo, okServer.Client())
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	}
	if err := handler.HandleOutboxMessage(ctx, message); err == nil {
		t.Fatal("first HandleOutboxMessage returned nil error, want flaky endpoint failure")
	}
	if err := handler.HandleOutboxMessage(ctx, message); err != nil {
		t.Fatalf("second HandleOutboxMessage returned error: %v", err)
	}
	if okRequests != 1 {
		t.Fatalf("ok endpoint requests = %d, want 1", okRequests)
	}
	if flakyRequests != 2 {
		t.Fatalf("flaky endpoint requests = %d, want 2", flakyRequests)
	}
}

func TestWebhookOutboxHandlerDefaultClientRejectsUnsafeEndpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "unsafe",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		Secret:    "secret-1",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, nil)
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err == nil {
		t.Fatal("HandleOutboxMessage returned nil error, want unsafe target rejection")
	}
	if requests != 0 {
		t.Fatalf("unsafe webhook requests = %d, want 0", requests)
	}
}

func TestWebhookOutboxHandlerDefaultClientRejectsUnsafeRedirectTarget(t *testing.T) {
	redirectURL, err := url.Parse("http://127.0.0.1/private")
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}

	client := newACMEHTTP01Client(true)
	err = client.CheckRedirect(&http.Request{URL: redirectURL}, nil)
	if err == nil {
		t.Fatal("CheckRedirect returned nil error, want unsafe redirect target rejection")
	}
}

func webhookSignature(secret string, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
