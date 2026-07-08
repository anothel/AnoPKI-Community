// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

func TestLifecycleOperationsCreateOutboxMessages(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, &fakeIssuer{}, clock, &fakeIDGenerator{})

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	if _, err := service.SuspendCertificate(ctx, "operator", certificate.ID); err != nil {
		t.Fatalf("SuspendCertificate returned error: %v", err)
	}
	if _, err := service.ResumeCertificate(ctx, "operator", certificate.ID); err != nil {
		t.Fatalf("ResumeCertificate returned error: %v", err)
	}
	renewal, err := service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: clock.now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("RenewCertificate returned error: %v", err)
	}
	reissue, err := service.ReissueCertificate(ctx, "operator", certificate.ID, ReissueCertificateRequest{
		CSRPEM: "reissue-csr-pem",
	})
	if err != nil {
		t.Fatalf("ReissueCertificate returned error: %v", err)
	}
	if _, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}

	messages, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	wantTypes := []string{
		"certificate.suspended",
		"certificate.resumed",
		"certificate.renewal_requested",
		"certificate.reissue_requested",
		"certificate.revoked",
	}
	if len(messages) != len(wantTypes) {
		t.Fatalf("outbox message count = %d, want %d: %#v", len(messages), len(wantTypes), messages)
	}
	for i, want := range wantTypes {
		if messages[i].Type != want || messages[i].Status != domain.OutboxPending {
			t.Fatalf("message %d = %#v, want type %q pending", i, messages[i], want)
		}
		payload := outboxPayload(t, messages[i])
		if payload["certificate_id"] != certificate.ID || payload["serial_number"] != certificate.SerialNumber {
			t.Fatalf("message %d payload = %#v, want certificate fields", i, payload)
		}
		if want == "certificate.renewal_requested" && payload["enrollment_id"] != renewal.ID {
			t.Fatalf("renewal payload = %#v, want enrollment_id %q", payload, renewal.ID)
		}
		if want == "certificate.reissue_requested" && payload["enrollment_id"] != reissue.ID {
			t.Fatalf("reissue payload = %#v, want enrollment_id %q", payload, reissue.ID)
		}
	}
}

func outboxPayload(t *testing.T, message domain.OutboxMessage) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal([]byte(message.PayloadJSON), &payload); err != nil {
		t.Fatalf("unmarshal outbox payload for %s: %v", message.Type, err)
	}
	return payload
}
