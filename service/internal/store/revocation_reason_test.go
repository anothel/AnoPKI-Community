// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestRevocationReasonRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo Repository
	}{{"memory", NewMemoryStore()}, {"sqlite", newTestSQLiteRepository(t)}} {
		t.Run(tc.name, func(t *testing.T) { testRevocationReasonRoundTrip(t, tc.repo) })
	}
}
func testRevocationReasonRoundTrip(t *testing.T, repo Repository) {
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i, reason := range []domain.RevocationReason{"not_provided", "unspecified", ""} {
		id := fmt.Sprintf("reason-%d", i)
		seedEnrollmentParents(t, repo, "identity", "issuer", "profile", id, now)
		certificate := domain.Certificate{ID: id, IdentityID: "identity", IssuerID: "issuer", CertificateProfileID: "profile", EnrollmentID: id, SerialNumber: fmt.Sprint(i + 1), Status: domain.CertificateRevoked, CertificatePEM: "pem", NotBefore: now, NotAfter: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			t.Fatal(err)
		}
		if err := repo.WithinTx(ctx, func(tx Repository) error {
			if err := tx.CreateRevocation(ctx, domain.Revocation{ID: id, CertificateID: id, Reason: reason, RevokedBy: "test", RevokedAt: now, CreatedAt: now}); err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]string{"certificate_id": id, "revocation_reason": string(reason)})
			if err := tx.CreateAuditEvent(ctx, domain.AuditEvent{ID: id, Actor: "test", Action: "certificate.revoked", ResourceType: "certificate", ResourceID: id, MetadataJSON: string(payload), CreatedAt: now}); err != nil {
				return err
			}
			return tx.CreateOutboxMessage(ctx, domain.OutboxMessage{ID: id, Type: "certificate.revoked", PayloadJSON: string(payload), Status: domain.OutboxPending, AvailableAt: now, CreatedAt: now, UpdatedAt: now})
		}); err != nil {
			t.Fatal(err)
		}
		got, err := repo.GetCertificateByIssuerSerial(ctx, "issuer", certificate.SerialNumber)
		if err != nil || got.ID != id {
			t.Fatal("scoped lookup failed")
		}
		if _, err := repo.GetCertificateByIssuerSerial(ctx, "foreign", certificate.SerialNumber); !errors.Is(err, domain.ErrCertificateNotFound) {
			t.Fatal("lookup crossed issuer")
		}
	}
	entries, err := repo.ListRevocationsByIssuer(ctx, "issuer")
	if err != nil || len(entries) != 3 {
		t.Fatal("round trip count")
	}
	expected := map[string]domain.RevocationReason{"reason-0": "not_provided", "reason-1": "unspecified", "reason-2": ""}
	for _, entry := range entries {
		if expected[entry.CertificateID] != entry.Reason {
			t.Fatal("marker or historical reason reinterpreted")
		}
	}
	events, err := repo.ListAuditEvents(ctx)
	if err != nil || len(events) != 3 {
		t.Fatal("audit persistence")
	}
	for _, event := range events {
		assertReasonJSON(t, event.MetadataJSON, expected)
	}
	messages, err := repo.ListOutboxMessages(ctx, domain.OutboxPending)
	if err != nil || len(messages) != 3 {
		t.Fatal("outbox persistence")
	}
	for _, message := range messages {
		assertReasonJSON(t, message.PayloadJSON, expected)
	}
	stop := errors.New("rollback")
	err = repo.WithinTx(ctx, func(tx Repository) error {
		if err := tx.CreateRevocation(ctx, domain.Revocation{ID: "rollback", CertificateID: "reason-0", Reason: domain.RevocationNotProvided, RevokedBy: "test", RevokedAt: now, CreatedAt: now}); err != nil {
			return err
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatal("expected transaction rollback")
	}
	entries, err = repo.ListRevocationsByIssuer(ctx, "issuer")
	if err != nil || len(entries) != 3 {
		t.Fatal("marker escaped rolled back transaction")
	}

}

func assertReasonJSON(t *testing.T, raw string, expected map[string]domain.RevocationReason) {
	t.Helper()
	var data map[string]string
	if json.Unmarshal([]byte(raw), &data) != nil || data["revocation_reason"] != string(expected[data["certificate_id"]]) {
		t.Fatal("reason serialization changed")
	}
}

func TestSQLiteRevocationIdentityLookupUsesUniqueIndex(t *testing.T) {
	repo := newTestSQLiteRepository(t).(*SQLStore)
	rows, err := repo.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+certificateByIssuerSerialQuery, "issuer", "123")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "idx_certificates_issuer_serial") && strings.Contains(detail, "issuer_id=? AND serial_number=?") {
			indexed = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !indexed {
		t.Fatal("revocation identity query does not use two-column unique index")
	}
}
