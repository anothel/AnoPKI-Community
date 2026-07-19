// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	_ "modernc.org/sqlite"
)

func TestMemoryStoreWithinTxRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	errStop := errors.New("stop")

	err := repo.WithinTx(ctx, func(tx Repository) error {
		if err := tx.CreateIdentity(ctx, domain.Identity{
			ID:        "identity-1",
			Type:      domain.IdentityMachine,
			Name:      "edge-01",
			Status:    domain.IdentityActive,
			CreatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			UpdatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		}); err != nil {
			return err
		}
		return errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("WithinTx error = %v, want %v", err, errStop)
	}

	if _, err := repo.GetIdentity(ctx, "identity-1"); !errors.Is(err, domain.ErrIdentityNotFound) {
		t.Fatalf("GetIdentity error = %v, want ErrIdentityNotFound", err)
	}
}

func TestSQLStoreWithinTxRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	repo := newTestSQLiteRepository(t)
	errStop := errors.New("stop")

	err := repo.WithinTx(ctx, func(tx Repository) error {
		if err := tx.CreateIdentity(ctx, domain.Identity{
			ID:        "identity-1",
			Type:      domain.IdentityMachine,
			Name:      "edge-01",
			Status:    domain.IdentityActive,
			CreatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			UpdatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		}); err != nil {
			return err
		}
		return errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("WithinTx error = %v, want %v", err, errStop)
	}

	if _, err := repo.GetIdentity(ctx, "identity-1"); !errors.Is(err, domain.ErrIdentityNotFound) {
		t.Fatalf("GetIdentity error = %v, want ErrIdentityNotFound", err)
	}
}

func TestMemoryStoreNestedWithinTxUsesSameTransaction(t *testing.T) {
	testNestedWithinTxUsesSameTransaction(t, NewMemoryStore())
}

func TestSQLStoreNestedWithinTxUsesSameTransaction(t *testing.T) {
	testNestedWithinTxUsesSameTransaction(t, newTestSQLiteRepository(t))
}

func TestCertificateProfileIssuerConditionalUpdate(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testCertificateProfileIssuerConditionalUpdate(t, tt.repo)
		})
	}
}

func testCertificateProfileIssuerConditionalUpdate(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for _, issuerID := range []string{"issuer-old", "issuer-new"} {
		if err := repo.CreateIssuer(ctx, domain.Issuer{
			ID:             issuerID,
			Name:           issuerID,
			Kind:           domain.IssuerIntermediateCA,
			Status:         domain.IssuerActive,
			CertificatePEM: "certificate",
			KeyRef:         "file:key.pem",
			CreatedAt:      base,
			UpdatedAt:      base,
		}); err != nil {
			t.Fatalf("CreateIssuer(%s) returned error: %v", issuerID, err)
		}
	}

	profile := domain.CertificateProfile{
		ID:                         "profile-issuer-transition",
		Name:                       "profile",
		Description:                "profile",
		IssuerID:                   "issuer-old",
		ValidityPeriodSeconds:      int64((24 * time.Hour).Seconds()),
		AllowedDNSPatterns:         []string{"*.example.test"},
		AllowedKeyAlgorithms:       []string{"rsa"},
		MinKeySizeBits:             2048,
		AllowedSignatureAlgorithms: []string{"sha256WithRSAEncryption"},
		CreatedAt:                  base,
		UpdatedAt:                  base,
	}
	if err := repo.CreateCertificateProfile(ctx, profile); err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	updated := profile
	updated.IssuerID = "issuer-new"
	updated.UpdatedAt = base.Add(time.Minute)
	if err := repo.UpdateCertificateProfileIssuerIfCurrent(ctx, updated, profile.IssuerID, profile.UpdatedAt); err != nil {
		t.Fatalf("UpdateCertificateProfileIssuerIfCurrent returned error: %v", err)
	}
	stored, err := repo.GetCertificateProfile(ctx, profile.ID)
	if err != nil {
		t.Fatalf("GetCertificateProfile returned error: %v", err)
	}
	if stored.IssuerID != updated.IssuerID || !stored.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Fatalf("stored profile = %#v, want issuer %q updated_at %s", stored, updated.IssuerID, updated.UpdatedAt)
	}

	if err := repo.UpdateCertificateProfileIssuerIfCurrent(ctx, profile, "issuer-old", base); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateCertificateProfileIssuerIfCurrent error = %v, want ErrInvalidTransition", err)
	}
	if err := repo.UpdateCertificateProfileIssuerIfCurrent(ctx, domain.CertificateProfile{ID: "missing"}, "issuer-old", base); !errors.Is(err, domain.ErrCertificateProfileNotFound) {
		t.Fatalf("missing UpdateCertificateProfileIssuerIfCurrent error = %v, want ErrCertificateProfileNotFound", err)
	}
}

func testNestedWithinTxUsesSameTransaction(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()

	err := repo.WithinTx(ctx, func(tx Repository) error {
		return tx.WithinTx(ctx, func(nested Repository) error {
			return nested.CreateAuditEvent(ctx, domain.AuditEvent{
				ID:           "audit-1",
				Actor:        "admin",
				Action:       "identity.created",
				ResourceType: "identity",
				ResourceID:   "identity-1",
				MetadataJSON: "{}",
				CreatedAt:    time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			})
		})
	})
	if err != nil {
		t.Fatalf("WithinTx returned error: %v", err)
	}

	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
}

func TestAuditEventQueryAndRetention(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testAuditEventQueryAndRetention(t, tt.repo)
		})
	}
}

func TestMemoryStoreAuditEventHashChain(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	first := testAuditEvent("audit-1", "alice", "identity.created", "identity", "identity-1", base)
	second := testAuditEvent("audit-2", "alice", "enrollment.created", "enrollment", "enrollment-1", base.Add(time.Minute))
	for _, event := range []domain.AuditEvent{first, second} {
		if err := repo.CreateAuditEvent(ctx, event); err != nil {
			t.Fatalf("CreateAuditEvent(%s) returned error: %v", event.ID, err)
		}
	}

	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	firstHash, err := auditEventHash("", events[0])
	if err != nil {
		t.Fatalf("auditEventHash(first) returned error: %v", err)
	}
	if events[0].Sequence != 1 || events[0].HashAlgorithm != AuditHashAlgorithmSHA256V1 || events[0].PreviousEventHash != "" || events[0].EventHash != firstHash {
		t.Fatalf("first event hashes = %#v", events[0])
	}
	secondHash, err := auditEventHash(events[0].EventHash, events[1])
	if err != nil {
		t.Fatalf("auditEventHash(second) returned error: %v", err)
	}
	if events[1].Sequence != 2 || events[1].HashAlgorithm != AuditHashAlgorithmSHA256V1 || events[1].PreviousEventHash != events[0].EventHash || events[1].EventHash != secondHash {
		t.Fatalf("second event hashes = %#v after %#v", events[1], events[0])
	}
}

func TestMemoryStoreIdentityPolicyFieldsRoundTrip(t *testing.T) {
	repo := NewMemoryStore()
	testIdentityPolicyFieldsRoundTrip(t, repo)
}

func testAuditEventQueryAndRetention(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for _, event := range []domain.AuditEvent{
		testAuditEvent("audit-1", "alice", "identity.created", "identity", "identity-1", base),
		testAuditEvent("audit-2", "bob", "enrollment.created", "enrollment", "enrollment-1", base.Add(time.Minute)),
		testAuditEvent("audit-3", "alice", "enrollment.rejected", "enrollment", "enrollment-1", base.Add(2*time.Minute)),
		testAuditEvent("audit-4", "alice", "certificate.revoked", "certificate", "certificate-1", base.Add(3*time.Minute)),
	} {
		if err := repo.CreateAuditEvent(ctx, event); err != nil {
			t.Fatalf("CreateAuditEvent(%s) returned error: %v", event.ID, err)
		}
	}

	filtered, err := repo.ListAuditEventsQuery(ctx, AuditEventQuery{
		Actor:        "alice",
		ResourceType: "enrollment",
		Sort:         "desc",
		Limit:        1,
	})
	if err != nil {
		t.Fatalf("ListAuditEventsQuery returned error: %v", err)
	}
	if got := auditEventIDs(filtered); !reflect.DeepEqual(got, []string{"audit-3"}) {
		t.Fatalf("filtered audit IDs = %#v", got)
	}

	deleted, err := repo.DeleteAuditEventsBefore(ctx, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("DeleteAuditEventsBefore returned error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted audit events = %d, want 2", deleted)
	}
	remaining, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if got := auditEventIDs(remaining); !reflect.DeepEqual(got, []string{"audit-3", "audit-4"}) {
		t.Fatalf("remaining audit IDs = %#v", got)
	}
}

func testIdentityPolicyFieldsRoundTrip(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	identity := domain.Identity{
		ID:                 "identity-1",
		Type:               domain.IdentityWorkload,
		Name:               "payments-api",
		ExternalID:         "k8s:prod:payments:payments-api",
		Owner:              "platform",
		Team:               "payments",
		Service:            "payments-api",
		Environment:        "prod",
		DeploymentTarget:   "k8s/payments-api",
		LastSeenAt:         now.Add(-time.Hour),
		MetadataJSON:       `{"namespace":"prod"}`,
		AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
		AllowedIPAddresses: []string{"192.0.2.42"},
		Status:             domain.IdentityActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := repo.CreateIdentity(ctx, identity); err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	identity.AllowedDNSNames[0] = "mutated.example.test"
	identity.AllowedIPAddresses[0] = "192.0.2.99"

	stored, err := repo.GetIdentity(ctx, "identity-1")
	if err != nil {
		t.Fatalf("GetIdentity returned error: %v", err)
	}
	if stored.Owner != "platform" ||
		stored.Team != "payments" ||
		stored.Service != "payments-api" ||
		stored.Environment != "prod" ||
		stored.DeploymentTarget != "k8s/payments-api" ||
		!stored.LastSeenAt.Equal(now.Add(-time.Hour)) ||
		stored.MetadataJSON != `{"namespace":"prod"}` ||
		!reflect.DeepEqual(stored.AllowedDNSNames, []string{"payments.prod.svc.cluster.local"}) ||
		!reflect.DeepEqual(stored.AllowedIPAddresses, []string{"192.0.2.42"}) {
		t.Fatalf("stored identity = %#v", stored)
	}

	emptyIdentity := domain.Identity{
		ID:        "identity-2",
		Type:      domain.IdentityMachine,
		Name:      "edge-02",
		Status:    domain.IdentityActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repo.CreateIdentity(ctx, emptyIdentity); err != nil {
		t.Fatalf("CreateIdentity empty returned error: %v", err)
	}
	storedEmpty, err := repo.GetIdentity(ctx, "identity-2")
	if err != nil {
		t.Fatalf("GetIdentity empty returned error: %v", err)
	}
	if !reflect.DeepEqual(storedEmpty.AllowedDNSNames, []string{}) ||
		!reflect.DeepEqual(storedEmpty.AllowedIPAddresses, []string{}) {
		t.Fatalf("stored empty identity allow lists = %#v", storedEmpty)
	}
}

func TestMemoryStoreUpdateEnrollmentIfStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	enrollment := domain.Enrollment{
		ID:                "enrollment-1",
		IdentityID:        "identity-1",
		IssuerID:          "issuer-1",
		CSRPEM:            "csr-pem",
		Status:            domain.EnrollmentPending,
		RequestedSubject:  "CN=edge-01",
		RequestedNotAfter: createdAt.Add(time.Hour),
		CreatedAt:         createdAt,
		UpdatedAt:         createdAt,
	}
	if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}

	approved := enrollment
	approved.Status = domain.EnrollmentApproved
	approved.UpdatedAt = createdAt.Add(time.Minute)
	if err := repo.UpdateEnrollmentIfStatus(ctx, approved, domain.EnrollmentPending); err != nil {
		t.Fatalf("UpdateEnrollmentIfStatus returned error: %v", err)
	}

	rejected := enrollment
	rejected.Status = domain.EnrollmentRejected
	rejected.UpdatedAt = createdAt.Add(2 * time.Minute)
	err := repo.UpdateEnrollmentIfStatus(ctx, rejected, domain.EnrollmentPending)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateEnrollmentIfStatus error = %v, want ErrInvalidTransition", err)
	}

	stored, err := repo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if stored.Status != domain.EnrollmentApproved {
		t.Fatalf("stored enrollment status = %q, want %q", stored.Status, domain.EnrollmentApproved)
	}
}

func TestMemoryStoreUpdateCertificateIfStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	certificate := domain.Certificate{
		ID:             "certificate-1",
		IdentityID:     "identity-1",
		IssuerID:       "issuer-1",
		EnrollmentID:   "enrollment-1",
		SerialNumber:   "01",
		Subject:        "CN=edge-01",
		NotBefore:      createdAt,
		NotAfter:       createdAt.Add(time.Hour),
		Status:         domain.CertificateValid,
		CertificatePEM: "cert-pem",
		CreatedAt:      createdAt,
		UpdatedAt:      createdAt,
	}
	if err := repo.CreateCertificate(ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	revoked := certificate
	revoked.Status = domain.CertificateRevoked
	revoked.UpdatedAt = createdAt.Add(time.Minute)
	if err := repo.UpdateCertificateIfStatus(ctx, revoked, domain.CertificateValid); err != nil {
		t.Fatalf("UpdateCertificateIfStatus returned error: %v", err)
	}

	validAgain := certificate
	validAgain.UpdatedAt = createdAt.Add(2 * time.Minute)
	err := repo.UpdateCertificateIfStatus(ctx, validAgain, domain.CertificateValid)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateCertificateIfStatus error = %v, want ErrInvalidTransition", err)
	}

	stored, err := repo.GetCertificate(ctx, certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if stored.Status != domain.CertificateRevoked {
		t.Fatalf("stored certificate status = %q, want %q", stored.Status, domain.CertificateRevoked)
	}
}

func TestMemoryStoreListCertificatesExpiringWithin(t *testing.T) {
	testListCertificatesExpiringWithin(t, NewMemoryStore())
}

func testListCertificatesExpiringWithin(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	for _, certificate := range []domain.Certificate{
		testStoreCertificate("certificate-3", now.Add(72*time.Hour), domain.CertificateValid),
		testStoreCertificate("certificate-1", now.Add(24*time.Hour), domain.CertificateValid),
		testStoreCertificate("certificate-2", now.Add(48*time.Hour), domain.CertificateValid),
		testStoreCertificate("certificate-expired", now.Add(-time.Hour), domain.CertificateValid),
		testStoreCertificate("certificate-revoked", now.Add(12*time.Hour), domain.CertificateRevoked),
	} {
		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	certificates, err := repo.ListCertificatesExpiringWithin(ctx, now, now.Add(7*24*time.Hour), 2, 1)
	if err != nil {
		t.Fatalf("ListCertificatesExpiringWithin returned error: %v", err)
	}
	if got := storeCertificateIDs(certificates); !reflect.DeepEqual(got, []string{"certificate-2", "certificate-3"}) {
		t.Fatalf("expiring certificate IDs = %#v", got)
	}
}

func TestStoreRejectsDuplicateCertificateFinalizationKeys(t *testing.T) {
	for _, tt := range []struct {
		name string
		repo Repository
	}{
		{name: "memory", repo: NewMemoryStore()},
		{name: "sqlite", repo: newTestSQLiteRepository(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testRejectsDuplicateCertificateFinalizationKeys(t, tt.repo)
		})
	}
}

func testRejectsDuplicateCertificateFinalizationKeys(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	seedEnrollmentParents(t, repo, "identity-1", "issuer-1", "profile-1", "enrollment-1", createdAt)
	seedEnrollmentParents(t, repo, "identity-1", "issuer-1", "profile-1", "enrollment-2", createdAt)
	certificate := domain.Certificate{
		ID:                   "certificate-1",
		IdentityID:           "identity-1",
		IssuerID:             "issuer-1",
		EnrollmentID:         "enrollment-1",
		CertificateProfileID: "profile-1",
		SerialNumber:         "01",
		Subject:              "CN=edge-01",
		NotBefore:            createdAt,
		NotAfter:             createdAt.Add(time.Hour),
		Status:               domain.CertificateValid,
		CertificatePEM:       "cert-pem",
		CreatedAt:            createdAt,
		UpdatedAt:            createdAt,
	}
	if err := repo.CreateCertificate(ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	duplicateEnrollment := certificate
	duplicateEnrollment.ID = "certificate-2"
	duplicateEnrollment.SerialNumber = "02"
	if err := repo.CreateCertificate(ctx, duplicateEnrollment); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate enrollment CreateCertificate error = %v, want ErrInvalidTransition", err)
	}

	duplicateSerial := certificate
	duplicateSerial.ID = "certificate-3"
	duplicateSerial.EnrollmentID = "enrollment-2"
	if err := repo.CreateCertificate(ctx, duplicateSerial); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate issuer serial CreateCertificate error = %v, want ErrInvalidTransition", err)
	}
}

func TestMemoryStoreOCSPResponders(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	issuer := domain.Issuer{
		ID:             "issuer-1",
		Name:           "Issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-pem",
		KeyRef:         "issuer-key",
		CreatedAt:      time.Unix(10, 0),
		UpdatedAt:      time.Unix(10, 0),
	}
	if err := s.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	first := domain.OCSPResponder{
		ID:             "responder-1",
		IssuerID:       issuer.ID,
		Name:           "old",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "old-pem",
		KeyRef:         "old-key",
		CreatedAt:      time.Unix(20, 0),
		UpdatedAt:      time.Unix(20, 0),
	}
	second := domain.OCSPResponder{
		ID:             "responder-2",
		IssuerID:       issuer.ID,
		Name:           "new",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "new-pem",
		KeyRef:         "new-key",
		CreatedAt:      time.Unix(30, 0),
		UpdatedAt:      time.Unix(30, 0),
	}
	if err := s.CreateOCSPResponder(ctx, first); err != nil {
		t.Fatalf("CreateOCSPResponder first returned error: %v", err)
	}
	if err := s.CreateOCSPResponder(ctx, second); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("CreateOCSPResponder second error = %v, want ErrInvalidTransition", err)
	}
	active, err := s.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != first.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, first.ID)
	}
	stored, err := s.GetOCSPResponder(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetOCSPResponder returned error: %v", err)
	}
	stored.Status = domain.OCSPResponderDisabled
	stored.UpdatedAt = time.Unix(25, 0)
	if err := s.UpdateOCSPResponderIfStatus(ctx, stored, domain.OCSPResponderActive); err != nil {
		t.Fatalf("UpdateOCSPResponderIfStatus returned error: %v", err)
	}
	if _, err := s.GetActiveOCSPResponderByIssuer(ctx, issuer.ID); !errors.Is(err, domain.ErrOCSPResponderNotFound) {
		t.Fatalf("GetActiveOCSPResponderByIssuer error = %v, want ErrOCSPResponderNotFound", err)
	}
	if err := s.CreateOCSPResponder(ctx, second); err != nil {
		t.Fatalf("CreateOCSPResponder second after disable returned error: %v", err)
	}
	list, err := s.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("responder count = %d, want 2", len(list))
	}
	if list[0].Status != domain.OCSPResponderDisabled || list[1].Status != domain.OCSPResponderActive {
		t.Fatalf("responder statuses = %#v", list)
	}
}

func testStoreCertificate(id string, notAfter time.Time, status domain.CertificateStatus) domain.Certificate {
	return domain.Certificate{
		ID:             id,
		IdentityID:     "identity-" + id,
		IssuerID:       "issuer-" + id,
		EnrollmentID:   "enrollment-" + id,
		SerialNumber:   "serial-" + id,
		Subject:        "CN=" + id,
		NotBefore:      notAfter.Add(-24 * time.Hour),
		NotAfter:       notAfter,
		Status:         status,
		CertificatePEM: "cert-pem",
		CreatedAt:      notAfter,
		UpdatedAt:      notAfter,
	}
}

func storeCertificateIDs(certificates []domain.Certificate) []string {
	ids := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		ids = append(ids, certificate.ID)
	}
	return ids
}

func newTestSQLiteRepository(t *testing.T) Repository {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	if err := ApplyInitialMigration(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	return NewSQLStore(db)
}

func testAuditEvent(id string, actor string, action string, resourceType string, resourceID string, createdAt time.Time) domain.AuditEvent {
	return domain.AuditEvent{
		ID:           id,
		Actor:        actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		MetadataJSON: "{}",
		CreatedAt:    createdAt,
	}
}

func auditEventIDs(events []domain.AuditEvent) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	return ids
}
