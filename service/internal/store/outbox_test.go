// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	_ "modernc.org/sqlite"
)

func TestMemoryStoreOutboxAndJobAttempts(t *testing.T) {
	testOutboxAndJobAttempts(t, NewMemoryStore())
}

func TestSQLStoreOutboxAndJobAttempts(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxAndJobAttempts(t, NewSQLStore(db))
}

func TestSQLStoreIdentityPolicyFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testIdentityPolicyFieldsRoundTrip(t, NewSQLStore(db))
}

func TestSQLStoreListCertificatesExpiringWithin(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testListCertificatesExpiringWithin(t, NewSQLStore(db))
}

func TestSQLStoreListCertificateInventoryFiltersInRepository(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	repo := NewSQLStore(db)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	issuer := domain.Issuer{
		ID:             "issuer-inventory",
		Name:           "Inventory Issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-pem",
		KeyRef:         "keyref://inventory",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profile := domain.CertificateProfile{
		ID:                    "profile-inventory",
		Name:                  "inventory-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		AllowedDNSPatterns:    []string{},
		AllowedIPRanges:       []string{},
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := repo.CreateCertificateProfile(ctx, profile); err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	matchingIdentity := domain.Identity{
		ID:          "identity-match",
		Type:        domain.IdentityService,
		Name:        "payments",
		Owner:       "platform",
		Team:        "edge",
		Service:     "pay-api",
		Environment: "prod",
		LastSeenAt:  now.Add(-time.Hour),
		Status:      domain.IdentityActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	otherIdentity := matchingIdentity
	otherIdentity.ID = "identity-other"
	otherIdentity.Name = "billing"
	otherIdentity.Owner = "finance"
	otherIdentity.Service = "billing-api"
	if err := repo.CreateIdentity(ctx, matchingIdentity); err != nil {
		t.Fatalf("CreateIdentity matching returned error: %v", err)
	}
	if err := repo.CreateIdentity(ctx, otherIdentity); err != nil {
		t.Fatalf("CreateIdentity other returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:                   "cert-match",
		IdentityID:           matchingIdentity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		SerialNumber:         "1001",
		Subject:              "CN=pay-api",
		Status:               domain.CertificateValid,
		NotBefore:            now,
		NotAfter:             now.Add(24 * time.Hour),
		CreatedAt:            now,
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("CreateCertificate matching returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:                   "cert-other",
		IdentityID:           otherIdentity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		SerialNumber:         "1002",
		Subject:              "CN=billing-api",
		Status:               domain.CertificateRevoked,
		NotBefore:            now,
		NotAfter:             now.Add(24 * time.Hour),
		CreatedAt:            now.Add(time.Second),
		UpdatedAt:            now.Add(time.Second),
	}); err != nil {
		t.Fatalf("CreateCertificate other returned error: %v", err)
	}

	records, err := repo.ListCertificateInventory(ctx, CertificateInventoryFilter{
		Owner:           "platform",
		Service:         "pay-api",
		Environment:     "prod",
		RevocationState: string(domain.CertificateValid),
		Limit:           1,
	})
	if err != nil {
		t.Fatalf("ListCertificateInventory returned error: %v", err)
	}
	if len(records) != 1 || records[0].Certificate.ID != "cert-match" {
		t.Fatalf("records = %#v, want cert-match only", records)
	}
	if records[0].Identity.Owner != "platform" || records[0].Issuer.KeyRef != issuer.KeyRef {
		t.Fatalf("inventory join record = %#v", records[0])
	}
}

func TestSQLStoreLargeListQueriesFilterSortAndPage(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	repo := NewSQLStore(db)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	issuer := domain.Issuer{
		ID:             "issuer-list",
		Name:           "List Issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-pem",
		KeyRef:         "keyref://list",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profile := domain.CertificateProfile{
		ID:                    "profile-list",
		Name:                  "list-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		AllowedDNSPatterns:    []string{},
		AllowedIPRanges:       []string{},
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := repo.CreateCertificateProfile(ctx, profile); err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	for i := 0; i < 600; i++ {
		createdAt := now.Add(time.Duration(i) * time.Second)
		owner := "platform"
		serviceName := "pay-api"
		environment := "prod"
		status := domain.EnrollmentPending
		certificateStatus := domain.CertificateValid
		if i%2 == 1 {
			owner = "finance"
			serviceName = "billing-api"
			environment = "dev"
			status = domain.EnrollmentRejected
			certificateStatus = domain.CertificateRevoked
		}
		identityID := fmt.Sprintf("identity-list-%03d", i)
		if err := repo.CreateIdentity(ctx, domain.Identity{
			ID:          identityID,
			Type:        domain.IdentityService,
			Name:        identityID,
			Owner:       owner,
			Team:        "edge",
			Service:     serviceName,
			Environment: environment,
			Status:      domain.IdentityActive,
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		}); err != nil {
			t.Fatalf("CreateIdentity(%d) returned error: %v", i, err)
		}
		enrollmentID := fmt.Sprintf("enrollment-list-%03d", i)
		if err := repo.CreateEnrollment(ctx, domain.Enrollment{
			ID:                   enrollmentID,
			IdentityID:           identityID,
			IssuerID:             issuer.ID,
			CertificateProfileID: profile.ID,
			Status:               status,
			CreatedAt:            createdAt,
			UpdatedAt:            createdAt,
		}); err != nil {
			t.Fatalf("CreateEnrollment(%d) returned error: %v", i, err)
		}
		renewalNotifiedAt := time.Time{}
		if i == 596 {
			renewalNotifiedAt = createdAt
		}
		if err := repo.CreateCertificate(ctx, domain.Certificate{
			ID:                   fmt.Sprintf("certificate-list-%03d", i),
			IdentityID:           identityID,
			IssuerID:             issuer.ID,
			EnrollmentID:         enrollmentID,
			CertificateProfileID: profile.ID,
			SerialNumber:         fmt.Sprintf("serial-list-%03d", i),
			Subject:              fmt.Sprintf("CN=service-%03d", i),
			DNSNames:             []string{fmt.Sprintf("service-%03d.example.test", i)},
			NotBefore:            createdAt,
			NotAfter:             now.Add(time.Duration(i+1) * time.Hour),
			Status:               certificateStatus,
			RenewalNotifiedAt:    renewalNotifiedAt,
			CreatedAt:            createdAt,
			UpdatedAt:            createdAt,
		}); err != nil {
			t.Fatalf("CreateCertificate(%d) returned error: %v", i, err)
		}
		outboxStatus := domain.OutboxCompleted
		if i%2 == 0 {
			outboxStatus = domain.OutboxPending
		}
		if err := repo.CreateOutboxMessage(ctx, domain.OutboxMessage{
			ID:          fmt.Sprintf("outbox-list-%03d", i),
			Type:        "certificate.issued",
			PayloadJSON: "{}",
			Status:      outboxStatus,
			AvailableAt: createdAt,
			MaxAttempts: 3,
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		}); err != nil {
			t.Fatalf("CreateOutboxMessage(%d) returned error: %v", i, err)
		}
	}

	start := time.Now()
	identities, err := repo.ListIdentitiesQuery(ctx, IdentityQuery{Owner: "platform", Service: "pay-api", Environment: "prod", Sort: "desc", Limit: 3, Offset: 1})
	if err != nil {
		t.Fatalf("ListIdentitiesQuery returned error: %v", err)
	}
	enrollments, err := repo.ListEnrollmentsQuery(ctx, EnrollmentQuery{IssuerID: issuer.ID, ProfileID: profile.ID, Status: domain.EnrollmentPending, Sort: "desc", Limit: 3})
	if err != nil {
		t.Fatalf("ListEnrollmentsQuery returned error: %v", err)
	}
	certificates, err := repo.ListCertificatesQuery(ctx, CertificateQuery{
		Owner:           "platform",
		Service:         "pay-api",
		IssuerID:        issuer.ID,
		ProfileID:       profile.ID,
		SAN:             "service-596.example.test",
		RevocationState: string(domain.CertificateValid),
		RenewalState:    "notified",
		ExpiresAfter:    now,
		ExpiresBefore:   now.Add(30 * 24 * time.Hour),
		Sort:            "desc",
		Limit:           1,
	})
	if err != nil {
		t.Fatalf("ListCertificatesQuery returned error: %v", err)
	}
	messages, err := repo.ListOutboxMessagesQuery(ctx, OutboxMessageQuery{Status: domain.OutboxPending, Type: "certificate.issued", CreatedFrom: now.Add(590 * time.Second), Sort: "asc", Limit: 3})
	if err != nil {
		t.Fatalf("ListOutboxMessagesQuery returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("large list queries took %s, want <= 2s", elapsed)
	}
	if got := identityIDs(identities); fmt.Sprint(got) != "[identity-list-596 identity-list-594 identity-list-592]" {
		t.Fatalf("identity IDs = %#v", got)
	}
	if got := enrollmentIDs(enrollments); fmt.Sprint(got) != "[enrollment-list-598 enrollment-list-596 enrollment-list-594]" {
		t.Fatalf("enrollment IDs = %#v", got)
	}
	if len(certificates) != 1 || certificates[0].ID != "certificate-list-596" {
		t.Fatalf("certificates = %#v, want certificate-list-596", certificates)
	}
	if got := outboxMessageIDs(messages); fmt.Sprint(got) != "[outbox-list-590 outbox-list-592 outbox-list-594]" {
		t.Fatalf("outbox IDs = %#v", got)
	}
}

func identityIDs(identities []domain.Identity) []string {
	ids := make([]string, 0, len(identities))
	for _, identity := range identities {
		ids = append(ids, identity.ID)
	}
	return ids
}

func enrollmentIDs(enrollments []domain.Enrollment) []string {
	ids := make([]string, 0, len(enrollments))
	for _, enrollment := range enrollments {
		ids = append(ids, enrollment.ID)
	}
	return ids
}

func outboxMessageIDs(messages []domain.OutboxMessage) []string {
	ids := make([]string, 0, len(messages))
	for _, message := range messages {
		ids = append(ids, message.ID)
	}
	return ids
}

func TestSQLStoreRestoreDrillPreservesOperationalState(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "restore-drill.db")
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	repo := NewSQLStore(db)
	issuer := domain.Issuer{
		ID:             "issuer-restore",
		Name:           "Restore Issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-pem",
		KeyRef:         "kms://issuer-restore",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateAuditEvent(ctx, domain.AuditEvent{
		ID:           "audit-restore",
		Actor:        "operator",
		Action:       "restore.seeded",
		ResourceType: "issuer",
		ResourceID:   issuer.ID,
		MetadataJSON: `{"restore_drill":true}`,
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("CreateAuditEvent returned error: %v", err)
	}
	if err := repo.CreateCRLPublication(ctx, domain.CRLPublication{
		ID:                "crl-restore",
		IssuerID:          issuer.ID,
		DistributionPoint: "https://pki.example/crl.pem",
		CRLNumber:         7,
		ThisUpdate:        now,
		NextUpdate:        now.Add(24 * time.Hour),
		Status:            domain.CRLPublicationPublished,
		CRLPEM:            "crl-pem",
		CreatedAt:         now,
		UpdatedAt:         now,
	}); err != nil {
		t.Fatalf("CreateCRLPublication returned error: %v", err)
	}
	if err := repo.CreateOCSPResponder(ctx, domain.OCSPResponder{
		ID:             "ocsp-restore",
		IssuerID:       issuer.ID,
		Name:           "Restore OCSP",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "ocsp-pem",
		KeyRef:         "kms://ocsp-restore",
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}
	outboxMessage := domain.OutboxMessage{
		ID:          "outbox-restore",
		Type:        "restore.drill",
		PayloadJSON: `{"restore":true}`,
		Status:      domain.OutboxDeadLetter,
		AvailableAt: now,
		MaxAttempts: 3,
		LastError:   "seeded",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateOutboxMessage(ctx, outboxMessage); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	if err := repo.CreateJobAttempt(ctx, domain.JobAttempt{
		ID:              "job-restore",
		OutboxMessageID: outboxMessage.ID,
		Status:          domain.JobAttemptFailed,
		Error:           "seeded failure",
		StartedAt:       now,
		FinishedAt:      now.Add(time.Second),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("CreateJobAttempt returned error: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seeded db: %v", err)
	}

	restoredDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open restored sqlite: %v", err)
	}
	defer restoredDB.Close()
	if err := CheckInitialMigration(ctx, restoredDB, "sqlite"); err != nil {
		t.Fatalf("CheckInitialMigration restored db returned error: %v", err)
	}
	restored := NewSQLStore(restoredDB)
	restoredIssuer, err := restored.GetIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetIssuer restored returned error: %v", err)
	}
	if restoredIssuer.KeyRef != issuer.KeyRef {
		t.Fatalf("restored issuer key ref = %q, want %q", restoredIssuer.KeyRef, issuer.KeyRef)
	}
	auditEvents, err := restored.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents restored returned error: %v", err)
	}
	if len(auditEvents) != 1 || auditEvents[0].Action != "restore.seeded" {
		t.Fatalf("restored audit events = %#v", auditEvents)
	}
	crl, err := restored.GetLatestCRLPublicationByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetLatestCRLPublicationByIssuer restored returned error: %v", err)
	}
	if crl.CRLNumber != 7 || crl.CRLPEM != "crl-pem" {
		t.Fatalf("restored CRL = %#v", crl)
	}
	ocsp, err := restored.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer restored returned error: %v", err)
	}
	if ocsp.KeyRef != "kms://ocsp-restore" {
		t.Fatalf("restored OCSP = %#v", ocsp)
	}
	messages, err := restored.ListOutboxMessages(ctx, domain.OutboxDeadLetter)
	if err != nil {
		t.Fatalf("ListOutboxMessages restored returned error: %v", err)
	}
	if len(messages) != 1 || messages[0].ID != outboxMessage.ID {
		t.Fatalf("restored outbox messages = %#v", messages)
	}
	attempts, err := restored.ListJobAttemptsByOutboxMessage(ctx, outboxMessage.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage restored returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != domain.JobAttemptFailed {
		t.Fatalf("restored job attempts = %#v", attempts)
	}
}

func TestMemoryStoreAPIKeys(t *testing.T) {
	testAPIKeys(t, NewMemoryStore())
}

func TestSQLStoreAPIKeys(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testAPIKeys(t, NewSQLStore(db))
}

func TestMemoryStoreOutboxRetryMetadata(t *testing.T) {
	testOutboxRetryMetadata(t, NewMemoryStore())
}

func TestSQLStoreOutboxRetryMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxRetryMetadata(t, NewSQLStore(db))
}

func TestMemoryStoreOutboxLeaseRecovery(t *testing.T) {
	testOutboxLeaseRecovery(t, NewMemoryStore())
}

func TestSQLStoreOutboxLeaseRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxLeaseRecovery(t, NewSQLStore(db))
}

func TestMemoryStoreIssuanceAttempts(t *testing.T) {
	testIssuanceAttempts(t, NewMemoryStore())
}

func TestSQLStoreIssuanceAttempts(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testIssuanceAttempts(t, NewSQLStore(db))
}

func TestMemoryStoreWebhookDeliveryTracking(t *testing.T) {
	testWebhookDeliveryTracking(t, NewMemoryStore())
}

func TestSQLStoreWebhookDeliveryTracking(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testWebhookDeliveryTracking(t, NewSQLStore(db))
}

func TestSQLStoreOCSPResponders(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	repo := NewSQLStore(db)
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
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
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
	if err := repo.CreateOCSPResponder(ctx, first); err != nil {
		t.Fatalf("CreateOCSPResponder first returned error: %v", err)
	}
	if err := repo.CreateOCSPResponder(ctx, second); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("CreateOCSPResponder second error = %v, want ErrInvalidTransition", err)
	}

	active, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != first.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, first.ID)
	}
	stored, err := repo.GetOCSPResponder(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetOCSPResponder returned error: %v", err)
	}
	stored.Status = domain.OCSPResponderDisabled
	stored.UpdatedAt = time.Unix(25, 0)
	if err := repo.UpdateOCSPResponderIfStatus(ctx, stored, domain.OCSPResponderActive); err != nil {
		t.Fatalf("UpdateOCSPResponderIfStatus returned error: %v", err)
	}
	if _, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID); !errors.Is(err, domain.ErrOCSPResponderNotFound) {
		t.Fatalf("GetActiveOCSPResponderByIssuer error = %v, want ErrOCSPResponderNotFound", err)
	}
	if err := repo.CreateOCSPResponder(ctx, second); err != nil {
		t.Fatalf("CreateOCSPResponder second after disable returned error: %v", err)
	}

	list, err := repo.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("responder count = %d, want 2", len(list))
	}
	if list[0].ID != first.ID || list[1].ID != second.ID {
		t.Fatalf("responders = %#v, want creation order [%q, %q]", list, first.ID, second.ID)
	}
	if list[0].Status != domain.OCSPResponderDisabled || list[1].Status != domain.OCSPResponderActive {
		t.Fatalf("responder statuses = %#v", list)
	}
}

func TestMemoryStoreIssuerTrustMetadata(t *testing.T) {
	testIssuerTrustMetadata(t, NewMemoryStore())
}

func TestSQLStoreIssuerTrustMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testIssuerTrustMetadata(t, NewSQLStore(db))
}

func TestMemoryStoreACMEState(t *testing.T) {
	testACMEState(t, NewMemoryStore())
}

func TestSQLStoreACMEState(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testACMEState(t, NewSQLStore(db))
}

func TestMemoryStoreRejectsDuplicateACMEAccountThumbprint(t *testing.T) {
	testRejectsDuplicateACMEAccountThumbprint(t, NewMemoryStore())
}

func TestSQLStoreRejectsDuplicateACMEAccountThumbprint(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testRejectsDuplicateACMEAccountThumbprint(t, NewSQLStore(db))
}

func TestMemoryStoreRejectsDuplicateCRLPublicationNumber(t *testing.T) {
	testRejectsDuplicateCRLPublicationNumber(t, NewMemoryStore())
}

func TestSQLStoreRejectsDuplicateCRLPublicationNumber(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testRejectsDuplicateCRLPublicationNumber(t, NewSQLStore(db))
}

func TestMemoryStoreCertificateExpirationScan(t *testing.T) {
	testCertificateExpirationScan(t, NewMemoryStore())
}

func TestSQLStoreCertificateExpirationScan(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testCertificateExpirationScan(t, NewSQLStore(db))
}

func TestMemoryStoreNotificationEndpoints(t *testing.T) {
	testNotificationEndpoints(t, NewMemoryStore())
}

func TestSQLStoreNotificationEndpoints(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testNotificationEndpoints(t, NewSQLStore(db))
}

func testOutboxAndJobAttempts(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	ready := domain.OutboxMessage{
		ID:          "outbox-ready",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now.Add(-time.Minute),
		CreatedAt:   now.Add(-time.Minute),
		UpdatedAt:   now.Add(-time.Minute),
	}
	future := domain.OutboxMessage{
		ID:          "outbox-future",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-2"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now.Add(time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateOutboxMessage(ctx, future); err != nil {
		t.Fatalf("CreateOutboxMessage future returned error: %v", err)
	}
	if err := repo.CreateOutboxMessage(ctx, ready); err != nil {
		t.Fatalf("CreateOutboxMessage ready returned error: %v", err)
	}

	due, err := repo.ListDueOutboxMessages(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 1 || due[0].ID != ready.ID {
		t.Fatalf("due messages = %#v, want only ready", due)
	}

	processing := ready
	processing.Status = domain.OutboxProcessing
	processing.UpdatedAt = now
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, processing, domain.OutboxPending); err != nil {
		t.Fatalf("UpdateOutboxMessageStatusIfStatus returned error: %v", err)
	}
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, ready, domain.OutboxPending); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateOutboxMessageStatusIfStatus error = %v, want ErrInvalidTransition", err)
	}

	attempt := domain.JobAttempt{
		ID:              "attempt-1",
		OutboxMessageID: ready.ID,
		Status:          domain.JobAttemptFailed,
		Error:           "timeout",
		StartedAt:       now,
		FinishedAt:      now.Add(time.Second),
		CreatedAt:       now,
	}
	if err := repo.CreateJobAttempt(ctx, attempt); err != nil {
		t.Fatalf("CreateJobAttempt returned error: %v", err)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, ready.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].ID != attempt.ID || attempts[0].Error != "timeout" {
		t.Fatalf("job attempts = %#v", attempts)
	}
}

func testOutboxRetryMetadata(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	message := domain.OutboxMessage{
		ID:           "outbox-retry",
		Type:         "certificate.expiration_warning",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxPending,
		AvailableAt:  now,
		AttemptCount: 2,
		MaxAttempts:  5,
		LastError:    "previous failure",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	stored, err := repo.GetOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("GetOutboxMessage returned error: %v", err)
	}
	if stored.AttemptCount != 2 || stored.MaxAttempts != 5 || stored.LastError != "previous failure" {
		t.Fatalf("stored retry metadata = %#v", stored)
	}

	stored.Status = domain.OutboxDeadLetter
	stored.AttemptCount = 5
	stored.LastError = "max attempts exceeded"
	stored.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, stored, domain.OutboxPending); err != nil {
		t.Fatalf("UpdateOutboxMessageStatusIfStatus returned error: %v", err)
	}

	pending, err := repo.ListOutboxMessages(ctx, domain.OutboxPending)
	if err != nil {
		t.Fatalf("ListOutboxMessages pending returned error: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending messages = %#v, want none", pending)
	}
	dead, err := repo.ListOutboxMessages(ctx, domain.OutboxDeadLetter)
	if err != nil {
		t.Fatalf("ListOutboxMessages dead_letter returned error: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != message.ID || dead[0].AttemptCount != 5 || dead[0].LastError != "max attempts exceeded" {
		t.Fatalf("dead letter messages = %#v", dead)
	}
}

func testWebhookDeliveryTracking(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	seedOutboxDeliveryParents(t, repo, "outbox-1", "endpoint-1", now)
	delivery := domain.WebhookDelivery{
		OutboxMessageID: "outbox-1",
		EndpointID:      "endpoint-1",
		Status:          domain.JobAttemptFailed,
		AttemptCount:    1,
		LastError:       "500",
		LastAttemptedAt: now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if _, err := repo.GetWebhookDelivery(ctx, delivery.OutboxMessageID, delivery.EndpointID); !errors.Is(err, domain.ErrWebhookDeliveryNotFound) {
		t.Fatalf("missing GetWebhookDelivery error = %v, want ErrWebhookDeliveryNotFound", err)
	}
	if err := repo.UpsertWebhookDelivery(ctx, delivery); err != nil {
		t.Fatalf("UpsertWebhookDelivery insert returned error: %v", err)
	}
	stored, err := repo.GetWebhookDelivery(ctx, delivery.OutboxMessageID, delivery.EndpointID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery returned error: %v", err)
	}
	if stored.Status != domain.JobAttemptFailed || stored.AttemptCount != 1 || stored.LastError != "500" {
		t.Fatalf("stored delivery = %#v", stored)
	}
	delivery.Status = domain.JobAttemptSucceeded
	delivery.AttemptCount = 2
	delivery.LastError = ""
	delivery.LastAttemptedAt = now.Add(time.Minute)
	delivery.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpsertWebhookDelivery(ctx, delivery); err != nil {
		t.Fatalf("UpsertWebhookDelivery update returned error: %v", err)
	}
	updated, err := repo.GetWebhookDelivery(ctx, delivery.OutboxMessageID, delivery.EndpointID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery after update returned error: %v", err)
	}
	if updated.Status != domain.JobAttemptSucceeded || updated.AttemptCount != 2 || updated.LastError != "" || !updated.CreatedAt.Equal(now) {
		t.Fatalf("updated delivery = %#v", updated)
	}
}

func testOutboxLeaseRecovery(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	active := domain.OutboxMessage{
		ID:                   "outbox-active",
		Type:                 "certificate.expiration_warning",
		PayloadJSON:          `{"certificate_id":"cert-active"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          now.Add(-time.Hour),
		ProcessingDeadlineAt: now.Add(time.Minute),
		CreatedAt:            now.Add(-time.Hour),
		UpdatedAt:            now.Add(-time.Minute),
	}
	expired := domain.OutboxMessage{
		ID:                   "outbox-expired",
		Type:                 "certificate.expiration_warning",
		PayloadJSON:          `{"certificate_id":"cert-expired"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          now.Add(-time.Hour),
		ProcessingDeadlineAt: now.Add(-time.Minute),
		CreatedAt:            now.Add(-2 * time.Hour),
		UpdatedAt:            now.Add(-time.Hour),
	}
	if err := repo.CreateOutboxMessage(ctx, active); err != nil {
		t.Fatalf("CreateOutboxMessage active returned error: %v", err)
	}
	if err := repo.CreateOutboxMessage(ctx, expired); err != nil {
		t.Fatalf("CreateOutboxMessage expired returned error: %v", err)
	}

	due, err := repo.ListDueOutboxMessages(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 1 || due[0].ID != expired.ID || due[0].Status != domain.OutboxProcessing {
		t.Fatalf("due messages = %#v, want only expired processing message", due)
	}
}

func testIssuanceAttempts(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	seedEnrollmentParents(t, repo, "identity-1", "issuer-1", "profile-1", "enrollment-1", now)
	attempt := domain.IssuanceAttempt{
		EnrollmentID:     "enrollment-1",
		Status:           domain.IssuanceAttemptSigning,
		LeaseExpiresAt:   now.Add(5 * time.Minute),
		CreatedAt:        now,
		UpdatedAt:        now,
		SigningStartedAt: now,
	}
	if _, err := repo.GetIssuanceAttempt(ctx, attempt.EnrollmentID); !errors.Is(err, domain.ErrIssuanceAttemptNotFound) {
		t.Fatalf("missing GetIssuanceAttempt error = %v, want ErrIssuanceAttemptNotFound", err)
	}
	if err := repo.CreateIssuanceAttempt(ctx, attempt); err != nil {
		t.Fatalf("CreateIssuanceAttempt returned error: %v", err)
	}
	if err := repo.CreateIssuanceAttempt(ctx, attempt); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate CreateIssuanceAttempt error = %v, want ErrInvalidTransition", err)
	}
	stored, err := repo.GetIssuanceAttempt(ctx, attempt.EnrollmentID)
	if err != nil {
		t.Fatalf("GetIssuanceAttempt returned error: %v", err)
	}
	if stored.Status != domain.IssuanceAttemptSigning || !stored.LeaseExpiresAt.Equal(attempt.LeaseExpiresAt) {
		t.Fatalf("stored attempt = %#v, want signing lease", stored)
	}

	signed := stored
	signed.Status = domain.IssuanceAttemptSigned
	signed.CertificateID = "certificate-1"
	signed.SerialNumber = "serial-1"
	signed.Subject = "CN=edge-01"
	signed.CertificatePEM = "cert-pem"
	signed.NotBefore = now
	signed.NotAfter = now.Add(time.Hour)
	signed.SignedAt = now.Add(time.Second)
	signed.SigningEvidenceJSON = `{"schema_version":1,"evidence_source":"core_signing"}`
	signed.UpdatedAt = signed.SignedAt
	if err := repo.UpdateIssuanceAttemptIfCurrent(ctx, signed, stored); err != nil {
		t.Fatalf("UpdateIssuanceAttemptIfCurrent returned error: %v", err)
	}
	if err := repo.UpdateIssuanceAttemptIfCurrent(ctx, stored, stored); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateIssuanceAttemptIfCurrent error = %v, want ErrInvalidTransition", err)
	}
	got, err := repo.GetIssuanceAttempt(ctx, attempt.EnrollmentID)
	if err != nil {
		t.Fatalf("GetIssuanceAttempt signed returned error: %v", err)
	}
	if got.Status != domain.IssuanceAttemptSigned ||
		got.CertificateID != signed.CertificateID ||
		got.CertificatePEM != signed.CertificatePEM ||
		got.SigningEvidenceJSON != signed.SigningEvidenceJSON ||
		!got.SignedAt.Equal(signed.SignedAt) {
		t.Fatalf("signed attempt = %#v, want %#v", got, signed)
	}

	finalized := got
	finalized.Status = domain.IssuanceAttemptFinalized
	finalized.FinalizedAt = now.Add(2 * time.Second)
	finalized.UpdatedAt = finalized.FinalizedAt
	if err := repo.UpdateIssuanceAttemptIfCurrent(ctx, finalized, got); err != nil {
		t.Fatalf("finalize UpdateIssuanceAttemptIfCurrent returned error: %v", err)
	}
	if err := repo.UpdateIssuanceAttemptIfCurrent(ctx, signed, got); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale signed UpdateIssuanceAttemptIfCurrent error = %v, want ErrInvalidTransition", err)
	}
	got, err = repo.GetIssuanceAttempt(ctx, attempt.EnrollmentID)
	if err != nil {
		t.Fatalf("GetIssuanceAttempt finalized returned error: %v", err)
	}
	if got.Status != domain.IssuanceAttemptFinalized ||
		!got.FinalizedAt.Equal(finalized.FinalizedAt) ||
		got.CertificateID != signed.CertificateID ||
		got.CertificatePEM != signed.CertificatePEM {
		t.Fatalf("finalized attempt = %#v, want %#v", got, finalized)
	}
}

func testNotificationEndpoints(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	first := domain.NotificationEndpoint{
		ID:         "endpoint-1",
		Name:       "ops",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        "https://ops.example.test/hooks/pki",
		Secret:     "secret-1",
		EventTypes: []string{"certificate.expiration_warning", "certificate.expired"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	second := domain.NotificationEndpoint{
		ID:         "endpoint-2",
		Name:       "all-events",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        "https://ops.example.test/hooks/all",
		Secret:     "secret-2",
		EventTypes: nil,
		CreatedAt:  now.Add(time.Second),
		UpdatedAt:  now.Add(time.Second),
	}
	if err := repo.CreateNotificationEndpoint(ctx, second); err != nil {
		t.Fatalf("CreateNotificationEndpoint second returned error: %v", err)
	}
	if err := repo.CreateNotificationEndpoint(ctx, first); err != nil {
		t.Fatalf("CreateNotificationEndpoint first returned error: %v", err)
	}

	listed, err := repo.ListNotificationEndpoints(ctx)
	if err != nil {
		t.Fatalf("ListNotificationEndpoints returned error: %v", err)
	}
	if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
		t.Fatalf("notification endpoints = %#v, want creation order", listed)
	}
	listed[0].EventTypes[0] = "mutated"
	stored, err := repo.GetNotificationEndpoint(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetNotificationEndpoint returned error: %v", err)
	}
	if stored.EventTypes[0] != "certificate.expiration_warning" {
		t.Fatalf("stored event types mutated through list: %#v", stored.EventTypes)
	}
	if stored.Secret != "secret-1" {
		t.Fatalf("stored secret = %q, want secret-1", stored.Secret)
	}

	stored.Status = domain.NotificationEndpointDisabled
	stored.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateNotificationEndpointIfStatus(ctx, stored, domain.NotificationEndpointActive); err != nil {
		t.Fatalf("UpdateNotificationEndpointIfStatus returned error: %v", err)
	}
	if err := repo.UpdateNotificationEndpointIfStatus(ctx, first, domain.NotificationEndpointActive); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateNotificationEndpointIfStatus error = %v, want ErrInvalidTransition", err)
	}
	disabled, err := repo.GetNotificationEndpoint(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetNotificationEndpoint disabled returned error: %v", err)
	}
	if disabled.Status != domain.NotificationEndpointDisabled {
		t.Fatalf("disabled status = %q, want %q", disabled.Status, domain.NotificationEndpointDisabled)
	}
}

func testCertificateExpirationScan(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	warningBefore := now.Add(24 * time.Hour)

	certificates := []domain.Certificate{
		expirationScanCertificate("expired-suspended", domain.CertificateSuspended, now.Add(-2*time.Hour), time.Time{}),
		expirationScanCertificate("expired-valid", domain.CertificateValid, now.Add(-time.Hour), time.Time{}),
		expirationScanCertificate("warning-valid", domain.CertificateValid, now.Add(2*time.Hour), time.Time{}),
		expirationScanCertificate("warning-notified", domain.CertificateValid, now.Add(3*time.Hour), now.Add(-time.Hour)),
		expirationScanCertificate("outside-valid", domain.CertificateValid, now.Add(72*time.Hour), time.Time{}),
		expirationScanCertificate("expired-revoked", domain.CertificateRevoked, now.Add(-time.Hour), time.Time{}),
	}
	for _, certificate := range certificates {
		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	candidates, err := repo.ListCertificatesForExpirationScan(ctx, now, warningBefore, 10)
	if err != nil {
		t.Fatalf("ListCertificatesForExpirationScan returned error: %v", err)
	}
	wantIDs := []string{"expired-suspended", "expired-valid", "warning-valid"}
	if len(candidates) != len(wantIDs) {
		t.Fatalf("candidate count = %d, want %d: %#v", len(candidates), len(wantIDs), candidates)
	}
	for i, want := range wantIDs {
		if candidates[i].ID != want {
			t.Fatalf("candidate %d ID = %q, want %q; candidates=%#v", i, candidates[i].ID, want, candidates)
		}
	}

	limited, err := repo.ListCertificatesForExpirationScan(ctx, now, warningBefore, 2)
	if err != nil {
		t.Fatalf("limited ListCertificatesForExpirationScan returned error: %v", err)
	}
	if len(limited) != 2 || limited[0].ID != "expired-suspended" || limited[1].ID != "expired-valid" {
		t.Fatalf("limited candidates = %#v", limited)
	}

	warning := candidates[2]
	warning.RenewalNotifiedAt = now
	warning.UpdatedAt = now
	if err := repo.UpdateCertificateIfStatus(ctx, warning, domain.CertificateValid); err != nil {
		t.Fatalf("UpdateCertificateIfStatus warning returned error: %v", err)
	}
	stored, err := repo.GetCertificate(ctx, warning.ID)
	if err != nil {
		t.Fatalf("GetCertificate warning returned error: %v", err)
	}
	if !stored.RenewalNotifiedAt.Equal(now) {
		t.Fatalf("RenewalNotifiedAt = %s, want %s", stored.RenewalNotifiedAt, now)
	}
}

func expirationScanCertificate(id string, status domain.CertificateStatus, notAfter time.Time, renewalNotifiedAt time.Time) domain.Certificate {
	createdAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return domain.Certificate{
		ID:                id,
		IdentityID:        "identity-" + id,
		IssuerID:          "issuer-1",
		EnrollmentID:      "enrollment-" + id,
		SerialNumber:      "serial-" + id,
		Subject:           "CN=" + id,
		NotBefore:         createdAt,
		NotAfter:          notAfter,
		Status:            status,
		CertificatePEM:    "cert-pem-" + id,
		RenewalNotifiedAt: renewalNotifiedAt,
		CreatedAt:         createdAt,
		UpdatedAt:         createdAt,
	}
}

func testAPIKeys(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(10, 0)
	key := domain.APIKey{
		ID:         "key-1",
		Name:       "admin",
		TokenHash:  "sha256:abc",
		Status:     domain.APIKeyActive,
		Actor:      "api-admin",
		Scopes:     []domain.APIKeyScope{domain.APIKeyScopeOperator},
		ExpiresAt:  now.Add(time.Hour),
		LastUsedAt: now.Add(time.Minute),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := repo.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}
	got, err := repo.GetAPIKeyByTokenHash(ctx, key.TokenHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByTokenHash returned error: %v", err)
	}
	if got.ID != key.ID || got.Actor != key.Actor || got.Status != key.Status ||
		len(got.Scopes) != 1 || got.Scopes[0] != domain.APIKeyScopeOperator ||
		!got.ExpiresAt.Equal(key.ExpiresAt) || !got.LastUsedAt.Equal(key.LastUsedAt) {
		t.Fatalf("api key = %#v, want %#v", got, key)
	}
	listed, err := repo.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys returned error: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != key.ID {
		t.Fatalf("api keys = %#v, want key-1", listed)
	}
	key.Status = domain.APIKeyDisabled
	key.LastUsedAt = now.Add(2 * time.Minute)
	key.UpdatedAt = now.Add(time.Second)
	if err := repo.UpdateAPIKeyIfStatus(ctx, key, domain.APIKeyActive); err != nil {
		t.Fatalf("UpdateAPIKeyIfStatus returned error: %v", err)
	}
	disabled, err := repo.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned error: %v", err)
	}
	if disabled.Status != domain.APIKeyDisabled {
		t.Fatalf("api key status = %q, want disabled", disabled.Status)
	}
	if !disabled.LastUsedAt.Equal(key.LastUsedAt) {
		t.Fatalf("LastUsedAt = %s, want %s", disabled.LastUsedAt, key.LastUsedAt)
	}
	if _, err := repo.GetAPIKeyByTokenHash(ctx, "sha256:missing"); !errors.Is(err, domain.ErrAPIKeyNotFound) {
		t.Fatalf("GetAPIKeyByTokenHash missing error = %v, want ErrAPIKeyNotFound", err)
	}
}

func testIssuerTrustMetadata(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(10, 0)
	issuer := domain.Issuer{
		ID:                    "issuer-1",
		Name:                  "intermediate",
		Kind:                  domain.IssuerIntermediateCA,
		Status:                domain.IssuerActive,
		ParentIssuerID:        "root-1",
		CertificatePEM:        "issuer-pem",
		KeyRef:                "issuer-key",
		AIAURL:                "https://pki.example.test/issuers/intermediate.pem",
		CRLDistributionPoints: []string{"https://pki.example.test/crl/intermediate.pem"},
		TrustAnchor:           false,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	got, err := repo.GetIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetIssuer returned error: %v", err)
	}
	if got.ParentIssuerID != issuer.ParentIssuerID ||
		got.AIAURL != issuer.AIAURL ||
		got.TrustAnchor != issuer.TrustAnchor ||
		len(got.CRLDistributionPoints) != 1 ||
		got.CRLDistributionPoints[0] != issuer.CRLDistributionPoints[0] {
		t.Fatalf("issuer metadata = %#v, want %#v", got, issuer)
	}
}

func testACMEState(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	seedCertificateParents(t, repo, "identity-1", "issuer-1", "profile-1", now)
	account := domain.ACMEAccount{
		ID:                   "account-1",
		Contacts:             []string{"mailto:ops@example.test"},
		Status:               domain.ACMEAccountValid,
		TermsOfServiceAgreed: true,
		KeyThumbprint:        "thumbprint-1",
		KeyJWKJSON:           `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateACMEAccount(ctx, account); err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	gotAccount, err := repo.GetACMEAccount(ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	if gotAccount.Status != account.Status ||
		gotAccount.KeyThumbprint != account.KeyThumbprint ||
		gotAccount.KeyJWKJSON != account.KeyJWKJSON ||
		len(gotAccount.Contacts) != 1 ||
		gotAccount.Contacts[0] != account.Contacts[0] {
		t.Fatalf("account = %#v, want %#v", gotAccount, account)
	}

	order := domain.ACMEOrder{
		ID:                   "order-1",
		AccountID:            account.ID,
		IdentityID:           "identity-1",
		IssuerID:             "issuer-1",
		CertificateProfileID: "profile-1",
		Status:               domain.ACMEOrderPending,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ExpiresAt:            now.Add(2 * time.Hour),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateACMEOrder(ctx, order); err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	order.Status = domain.ACMEOrderReady
	order.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); err != nil {
		t.Fatalf("UpdateACMEOrderIfStatus returned error: %v", err)
	}
	if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateACMEOrderIfStatus error = %v, want ErrInvalidTransition", err)
	}
	orders, err := repo.ListACMEOrdersByAccount(ctx, account.ID)
	if err != nil {
		t.Fatalf("ListACMEOrdersByAccount returned error: %v", err)
	}
	if len(orders) != 1 || orders[0].Status != domain.ACMEOrderReady || !orders[0].ExpiresAt.Equal(order.ExpiresAt) {
		t.Fatalf("orders = %#v", orders)
	}

	authz := domain.ACMEAuthorization{
		ID:                       "authz-1",
		OrderID:                  order.ID,
		IdentifierType:           "dns",
		IdentifierValue:          "edge-01.example.test",
		Status:                   domain.ACMEAuthorizationPending,
		ExpiresAt:                now.Add(2 * time.Hour),
		ValidationReuseExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	if err := repo.CreateACMEAuthorization(ctx, authz); err != nil {
		t.Fatalf("CreateACMEAuthorization returned error: %v", err)
	}
	authz.Status = domain.ACMEAuthorizationValid
	authz.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEAuthorizationIfStatus(ctx, authz, domain.ACMEAuthorizationPending); err != nil {
		t.Fatalf("UpdateACMEAuthorizationIfStatus returned error: %v", err)
	}
	authzs, err := repo.ListACMEAuthorizationsByOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizationsByOrder returned error: %v", err)
	}
	if len(authzs) != 1 || authzs[0].Status != domain.ACMEAuthorizationValid ||
		!authzs[0].ExpiresAt.Equal(authz.ExpiresAt) ||
		!authzs[0].ValidationReuseExpiresAt.Equal(authz.ValidationReuseExpiresAt) {
		t.Fatalf("authorizations = %#v", authzs)
	}

	challenge := domain.ACMEChallenge{
		ID:              "challenge-1",
		AuthorizationID: authz.ID,
		Type:            domain.ACMEChallengeHTTP01,
		Token:           "token-1",
		Status:          domain.ACMEChallengePending,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := repo.CreateACMEChallenge(ctx, challenge); err != nil {
		t.Fatalf("CreateACMEChallenge returned error: %v", err)
	}
	challenge.Status = domain.ACMEChallengeValid
	challenge.ValidatedAt = now.Add(time.Minute)
	challenge.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEChallengeIfStatus(ctx, challenge, domain.ACMEChallengePending); err != nil {
		t.Fatalf("UpdateACMEChallengeIfStatus returned error: %v", err)
	}
	challenges, err := repo.ListACMEChallengesByAuthorization(ctx, authz.ID)
	if err != nil {
		t.Fatalf("ListACMEChallengesByAuthorization returned error: %v", err)
	}
	if len(challenges) != 1 || challenges[0].Status != domain.ACMEChallengeValid || !challenges[0].ValidatedAt.Equal(challenge.ValidatedAt) {
		t.Fatalf("challenges = %#v", challenges)
	}
}

func seedCertificateParents(t *testing.T, repo Repository, identityID, issuerID, profileID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.GetIdentity(ctx, identityID); errors.Is(err, domain.ErrIdentityNotFound) {
		if err := repo.CreateIdentity(ctx, domain.Identity{
			ID:        identityID,
			Type:      domain.IdentityService,
			Name:      identityID,
			Status:    domain.IdentityActive,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateIdentity parent returned error: %v", err)
		}
	} else if err != nil {
		t.Fatalf("GetIdentity parent returned error: %v", err)
	}
	if _, err := repo.GetIssuer(ctx, issuerID); errors.Is(err, domain.ErrIssuerNotFound) {
		if err := repo.CreateIssuer(ctx, domain.Issuer{
			ID:             issuerID,
			Name:           issuerID,
			Kind:           domain.IssuerIntermediateCA,
			Status:         domain.IssuerActive,
			CertificatePEM: "issuer-pem",
			KeyRef:         "issuer-key",
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			t.Fatalf("CreateIssuer parent returned error: %v", err)
		}
	} else if err != nil {
		t.Fatalf("GetIssuer parent returned error: %v", err)
	}
	if _, err := repo.GetCertificateProfile(ctx, profileID); errors.Is(err, domain.ErrCertificateProfileNotFound) {
		if err := repo.CreateCertificateProfile(ctx, domain.CertificateProfile{
			ID:                    profileID,
			Name:                  profileID,
			IssuerID:              issuerID,
			ValidityPeriodSeconds: int64(time.Hour.Seconds()),
			CreatedAt:             now,
			UpdatedAt:             now,
		}); err != nil {
			t.Fatalf("CreateCertificateProfile parent returned error: %v", err)
		}
	} else if err != nil {
		t.Fatalf("GetCertificateProfile parent returned error: %v", err)
	}
}

func seedEnrollmentParents(t *testing.T, repo Repository, identityID, issuerID, profileID, enrollmentID string, now time.Time) {
	t.Helper()
	seedCertificateParents(t, repo, identityID, issuerID, profileID, now)
	if _, err := repo.GetEnrollment(context.Background(), enrollmentID); err == nil {
		return
	} else if !errors.Is(err, domain.ErrEnrollmentNotFound) {
		t.Fatalf("GetEnrollment parent returned error: %v", err)
	}
	if err := repo.CreateEnrollment(context.Background(), domain.Enrollment{
		ID:                   enrollmentID,
		IdentityID:           identityID,
		IssuerID:             issuerID,
		CertificateProfileID: profileID,
		Status:               domain.EnrollmentApproved,
		CreatedAt:            now,
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("CreateEnrollment parent returned error: %v", err)
	}
}

func seedOutboxDeliveryParents(t *testing.T, repo Repository, outboxID, endpointID string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.GetOutboxMessage(ctx, outboxID); err != nil {
		if !errors.Is(err, domain.ErrOutboxMessageNotFound) {
			t.Fatalf("GetOutboxMessage parent returned error: %v", err)
		}
		if err := repo.CreateOutboxMessage(ctx, domain.OutboxMessage{
			ID:          outboxID,
			Type:        "certificate.issued",
			PayloadJSON: "{}",
			Status:      domain.OutboxPending,
			AvailableAt: now,
			MaxAttempts: 3,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("CreateOutboxMessage parent returned error: %v", err)
		}
	}
	if _, err := repo.GetNotificationEndpoint(ctx, endpointID); err == nil {
		return
	} else if !errors.Is(err, domain.ErrNotificationEndpointNotFound) {
		t.Fatalf("GetNotificationEndpoint parent returned error: %v", err)
	}
	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        endpointID,
		Name:      endpointID,
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       "https://ops.example.test/hooks/pki",
		Secret:    "secret",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint parent returned error: %v", err)
	}
}

func testRejectsDuplicateACMEAccountThumbprint(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	account := domain.ACMEAccount{
		ID:            "account-1",
		Status:        domain.ACMEAccountValid,
		KeyThumbprint: "thumbprint-1",
		KeyJWKJSON:    `{"kty":"EC"}`,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := repo.CreateACMEAccount(ctx, account); err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	account.ID = "account-2"
	if err := repo.CreateACMEAccount(ctx, account); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate CreateACMEAccount error = %v, want ErrInvalidTransition", err)
	}
}

func testRejectsDuplicateCRLPublicationNumber(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	publication := domain.CRLPublication{
		ID:                "crl-1",
		IssuerID:          "issuer-1",
		DistributionPoint: "https://pki.example.test/crl/issuer-1.pem",
		CRLNumber:         7,
		ThisUpdate:        now,
		NextUpdate:        now.Add(time.Hour),
		Status:            domain.CRLPublicationPublished,
		CRLPEM:            "crl-pem-1",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := repo.CreateCRLPublication(ctx, publication); err != nil {
		t.Fatalf("CreateCRLPublication returned error: %v", err)
	}
	publication.ID = "crl-2"
	publication.CRLPEM = "crl-pem-2"
	if err := repo.CreateCRLPublication(ctx, publication); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate CreateCRLPublication error = %v, want ErrInvalidTransition", err)
	}
}
