// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/store"
)

func TestRevocationWithoutReasonPreservesMarkerAndRollback(t *testing.T) {
	for _, mode := range []string{"success", "audit rollback", "outbox rollback"} {
		fail := mode != "success"
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			repo := store.NewMemoryStore()
			var repository store.Repository = repo
			failure := errors.New("audit failure")
			if mode == "outbox rollback" {
				repository = &failRevocationOutbox{repo, failure}
			}
			if mode == "audit rollback" {
				repository = &failAuditRepository{Repository: repo, action: "certificate.revoked", err: failure}
			}
			svc := New(repository, &fakeIssuer{}, fixedClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, &fakeIDGenerator{})
			enrollment := createPendingEnrollment(t, ctx, svc)
			if _, err := svc.ApproveEnrollment(ctx, "operator", enrollment.ID); err != nil {
				t.Fatal(err)
			}
			cert, err := svc.IssueCertificate(ctx, "operator", enrollment.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, reason := range []domain.RevocationReason{"", "not_provided"} {
				if _, err := svc.RevokeCertificate(ctx, "legacy", cert.ID, reason); !errors.Is(err, domain.ErrInvalidRequest) {
					t.Fatal("legacy accepted absent reason marker")
				}
			}
			if _, err := svc.ForceRevokeCertificate(ctx, "legacy", cert.ID, domain.RevocationNotProvided); !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatal("legacy force accepted marker")
			}
			_, err = svc.RevokeCertificateWithoutReason(ctx, "acme", cert.ID)
			got, _ := repo.GetCertificate(ctx, cert.ID)
			entries, _ := repo.ListRevocationsByIssuer(ctx, cert.IssuerID)
			if fail {
				if !errors.Is(err, failure) || got.Status != domain.CertificateValid || len(entries) != 0 {
					t.Fatal("absence revocation not rolled back")
				}
				events, _ := repo.ListAuditEvents(ctx)
				for _, event := range events {
					if event.Action == "certificate.revoked" {
						t.Fatal("success audit escaped rollback")
					}
				}
				messages, _ := repo.ListOutboxMessages(ctx, domain.OutboxPending)
				for _, message := range messages {
					if message.Type == "certificate.revoked" {
						t.Fatal("outbox escaped rollback")
					}
				}
				return
			}
			if err != nil || got.Status != domain.CertificateRevoked || len(entries) != 1 || entries[0].Reason != "not_provided" {
				t.Fatal("absence marker lost")
			}
			events, _ := repo.ListAuditEvents(ctx)
			found := false
			for _, event := range events {
				if event.Action == "certificate.revoked" {
					found = true
					if auditMetadata(t, event)["revocation_reason"] != "not_provided" {
						t.Fatal("audit lost marker")
					}
				}
			}
			if !found {
				t.Fatal("missing revocation audit")
			}
			messages, _ := repo.ListOutboxMessages(ctx, domain.OutboxPending)
			found = false
			for _, message := range messages {
				if message.Type == "certificate.revoked" {
					found = true
					if outboxPayload(t, message)["revocation_reason"] != "not_provided" {
						t.Fatal("outbox lost marker")
					}
				}
			}
			if !found {
				t.Fatal("missing transactional outbox")
			}
		})
	}
}

type failRevocationOutbox struct {
	store.Repository
	failure error
}

func (f *failRevocationOutbox) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return f.Repository.WithinTx(ctx, func(tx store.Repository) error { return fn(&failRevocationOutbox{tx, f.failure}) })
}
func (f *failRevocationOutbox) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	if message.Type == "certificate.revoked" {
		return f.failure
	}
	return f.Repository.CreateOutboxMessage(ctx, message)
}
