// SPDX-License-Identifier: MPL-2.0
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/keyref"
	"github.com/anothel/anopki/service/internal/observability"
	"github.com/anothel/anopki/service/internal/store"
)

func TestManualEnrollmentLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, issuerClient, clock, &fakeIDGenerator{})

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:       domain.IdentityMachine,
		Name:       "edge-01",
		ExternalID: "asset-123",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	if identity.Status != domain.IdentityActive {
		t.Fatalf("identity status = %q, want %q", identity.Status, domain.IdentityActive)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:                  "intermediate-ca",
		Kind:                  domain.IssuerIntermediateCA,
		CertificatePEM:        "issuer-cert-pem",
		KeyRef:                "issuer-key-ref",
		AIAURL:                "https://pki.example.test/issuers/intermediate-ca.pem",
		CRLDistributionPoints: []string{"https://pki.example.test/crl/intermediate-ca.crl"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if issuer.Status != domain.IssuerActive {
		t.Fatalf("issuer status = %q, want %q", issuer.Status, domain.IssuerActive)
	}

	requestedNotAfter := clock.now.Add(24 * time.Hour)
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    requestedNotAfter,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if enrollment.Status != domain.EnrollmentPending {
		t.Fatalf("enrollment status = %q, want %q", enrollment.Status, domain.EnrollmentPending)
	}

	approved, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID)
	if err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	if approved.Status != domain.EnrollmentApproved {
		t.Fatalf("approved enrollment status = %q, want %q", approved.Status, domain.EnrollmentApproved)
	}
	if approved.ApprovedBy != "approver" {
		t.Fatalf("ApprovedBy = %q, want %q", approved.ApprovedBy, "approver")
	}

	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if certificate.Status != domain.CertificateValid {
		t.Fatalf("certificate status = %q, want %q", certificate.Status, domain.CertificateValid)
	}
	if certificate.Subject != "CN=edge-01" {
		t.Fatalf("certificate subject = %q, want %q", certificate.Subject, "CN=edge-01")
	}
	if certificate.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", certificate.CertificatePEM, "issued:csr-pem")
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	issueRequest := issuerClient.requests[0]
	if issueRequest.CSRPEM != "csr-pem" {
		t.Fatalf("Issue CSRPEM = %q, want %q", issueRequest.CSRPEM, "csr-pem")
	}
	if issueRequest.IssuerCertificatePEM != "issuer-cert-pem" {
		t.Fatalf("Issue IssuerCertificatePEM = %q, want %q", issueRequest.IssuerCertificatePEM, "issuer-cert-pem")
	}
	if issueRequest.IssuerKeyRef != "issuer-key-ref" {
		t.Fatalf("Issue IssuerKeyRef = %q, want %q", issueRequest.IssuerKeyRef, "issuer-key-ref")
	}
	if issueRequest.AIAURL != issuer.AIAURL || !reflect.DeepEqual(issueRequest.CRLDistributionPoints, issuer.CRLDistributionPoints) {
		t.Fatalf("Issue issuer distribution metadata = aia:%q crl:%#v", issueRequest.AIAURL, issueRequest.CRLDistributionPoints)
	}
	if issueRequest.SignatureAlgorithm != "ecdsa_with_sha256" {
		t.Fatalf("Issue SignatureAlgorithm = %q, want %q", issueRequest.SignatureAlgorithm, "ecdsa_with_sha256")
	}

	issuedEnrollment, err := repo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if issuedEnrollment.Status != domain.EnrollmentIssued {
		t.Fatalf("issued enrollment status = %q, want %q", issuedEnrollment.Status, domain.EnrollmentIssued)
	}

	revoked, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationKeyCompromise)
	if err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}

	rejectedEnrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "rejected-csr-pem",
		RequestedSubject:     "CN=rejected",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    requestedNotAfter,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment for rejection returned error: %v", err)
	}
	rejected, err := service.RejectEnrollment(ctx, "operator", rejectedEnrollment.ID)
	if err != nil {
		t.Fatalf("RejectEnrollment returned error: %v", err)
	}
	if rejected.Status != domain.EnrollmentRejected {
		t.Fatalf("rejected enrollment status = %q, want %q", rejected.Status, domain.EnrollmentRejected)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	wantActions := []string{
		"identity.created",
		"issuer.created",
		"enrollment.created",
		"enrollment.approved",
		"certificate.issued",
		"certificate.revoked",
		"enrollment.created",
		"enrollment.rejected",
	}
	if len(events) != len(wantActions) {
		t.Fatalf("audit event count = %d, want %d", len(events), len(wantActions))
	}
	for i, want := range wantActions {
		if events[i].Action != want {
			t.Fatalf("audit event %d action = %q, want %q", i, events[i].Action, want)
		}
	}
	identityMetadata := auditMetadata(t, events[0])
	if identityMetadata["identity_id"] != identity.ID || identityMetadata["result_code"] != "ok" {
		t.Fatalf("identity audit metadata = %#v", identityMetadata)
	}
	issuerMetadata := auditMetadata(t, events[1])
	if issuerMetadata["key_provider_class"] != "file" ||
		issuerMetadata["key_provider_exportability"] != "exportable" {
		t.Fatalf("issuer audit key provider metadata = %#v", issuerMetadata)
	}
	enrollmentMetadata := auditMetadata(t, events[2])
	if enrollmentMetadata["identity_id"] != identity.ID ||
		enrollmentMetadata["issuer_id"] != issuer.ID ||
		enrollmentMetadata["enrollment_id"] != enrollment.ID ||
		enrollmentMetadata["policy_decision"] != "allow" ||
		enrollmentMetadata["policy_decision_reason"] != "enrollment_policy_passed" {
		t.Fatalf("enrollment audit metadata = %#v", enrollmentMetadata)
	}
	assertPolicyEvidenceRefs(t, enrollmentMetadata, identity.ID, issuer.ID, "")
	certificateMetadata := auditMetadata(t, events[4])
	if certificateMetadata["identity_id"] != identity.ID ||
		certificateMetadata["issuer_id"] != issuer.ID ||
		certificateMetadata["enrollment_id"] != enrollment.ID ||
		certificateMetadata["certificate_id"] != certificate.ID ||
		certificateMetadata["serial_number"] != certificate.SerialNumber ||
		certificateMetadata["key_provider_class"] != "file" ||
		certificateMetadata["key_provider_exportability"] != "exportable" ||
		certificateMetadata["key_provider_operation"] != "certificate_issue" ||
		certificateMetadata["key_provider_evidence_source"] != "core_signing" ||
		certificateMetadata["key_provider_signing_proven"] != true ||
		certificateMetadata["key_provider_binding_verified"] != true ||
		certificateMetadata["key_provider_fallback_used"] != false ||
		certificateMetadata["key_provider_result_code"] != "ok" ||
		certificateMetadata["policy_decision"] != "allow" ||
		certificateMetadata["policy_decision_reason"] != "issuance_policy_passed" {
		t.Fatalf("certificate audit metadata = %#v", certificateMetadata)
	}
	assertPolicyEvidenceRefs(t, certificateMetadata, identity.ID, issuer.ID, "")
}

func TestIssueCertificateRecordsSignerMetrics(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, issuerClient, clock, &fakeIDGenerator{})

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{Type: domain.IdentityMachine, Name: "edge-01"})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "issuer",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert",
		KeyRef:         "issuer-key",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    clock.now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	before := observability.OperationMetricValue("signer:issue:success")
	if _, err := service.IssueCertificate(ctx, "issuer", enrollment.ID); err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if got := observability.OperationMetricValue("signer:issue:success") - before; got != 1 {
		t.Fatalf("signer issue metric increment = %d, want 1", got)
	}
}

func TestAuditErrorCodeMapsPublicErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "acme account deactivated", err: domain.ErrACMEAccountDeactivated, want: "acme_account_deactivated"},
		{name: "acme account not found", err: domain.ErrACMEAccountNotFound, want: "acme_account_not_found"},
		{name: "acme authorization not found", err: domain.ErrACMEAuthorizationNotFound, want: "acme_authorization_not_found"},
		{name: "acme challenge not found", err: domain.ErrACMEChallengeNotFound, want: "acme_challenge_not_found"},
		{name: "acme order not found", err: domain.ErrACMEOrderNotFound, want: "acme_order_not_found"},
		{name: "api key not found", err: domain.ErrAPIKeyNotFound, want: "api_key_not_found"},
		{name: "certificate issuance failed", err: domain.ErrCertificateIssuanceFailed, want: "certificate_issuance_failed"},
		{name: "certificate not found", err: domain.ErrCertificateNotFound, want: "certificate_not_found"},
		{name: "certificate profile not found", err: domain.ErrCertificateProfileNotFound, want: "certificate_profile_not_found"},
		{name: "certificate parse failed", err: domain.ErrCSRParseFailed, want: "csr_parse_failed"},
		{name: "crl publication not found", err: domain.ErrCRLPublicationNotFound, want: "crl_publication_not_found"},
		{name: "crl generation failed", err: domain.ErrCRLGenerationFailed, want: "crl_generation_failed"},
		{name: "enrollment not found", err: domain.ErrEnrollmentNotFound, want: "enrollment_not_found"},
		{name: "forbidden", err: domain.ErrForbidden, want: "forbidden"},
		{name: "identity not found", err: domain.ErrIdentityNotFound, want: "identity_not_found"},
		{name: "invalid request", err: domain.ErrInvalidRequest, want: "invalid_request"},
		{name: "invalid lifecycle transition", err: domain.ErrInvalidTransition, want: "invalid_lifecycle_transition"},
		{name: "issuance attempt not found", err: domain.ErrIssuanceAttemptNotFound, want: "internal"},
		{name: "issuer not found", err: domain.ErrIssuerNotFound, want: "issuer_not_found"},
		{name: "invalid media type", err: domain.ErrUnsupportedMediaType, want: "unsupported_media_type"},
		{name: "ocsp decode failed", err: domain.ErrOCSPDecodeFailed, want: "ocsp_decode_failed"},
		{name: "ocsp responder not found", err: domain.ErrOCSPResponderNotFound, want: "ocsp_responder_not_found"},
		{name: "ocsp responder validation failed", err: domain.ErrOCSPResponderValidationFailed, want: "ocsp_responder_validation_failed"},
		{name: "ocsp response failed", err: domain.ErrOCSPResponseFailed, want: "ocsp_response_failed"},
		{name: "notification endpoint not found", err: domain.ErrNotificationEndpointNotFound, want: "notification_endpoint_not_found"},
		{name: "outbox message not found", err: domain.ErrOutboxMessageNotFound, want: "outbox_message_not_found"},
		{name: "rate limited", err: domain.ErrRateLimited, want: "rate_limited"},
		{name: "storage failure", err: domain.ErrStorageFailure, want: "storage_failure"},
		{name: "unauthorized", err: domain.ErrUnauthorized, want: "unauthorized"},
		{name: "webhook delivery not found", err: domain.ErrWebhookDeliveryNotFound, want: "internal"},
		{name: "wrapped invalid request", err: fmt.Errorf("wrapped: %w", domain.ErrInvalidRequest), want: "invalid_request"},
		{name: "wrapped unrecognized error", err: fmt.Errorf("wrapped: %w", errors.New("other-error")), want: "internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auditErrorCode(tt.err); got != tt.want {
				t.Fatalf("auditErrorCode(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestAuditMetadataRedactsSensitiveFields(t *testing.T) {
	metadataJSON := auditMetadataJSON(context.Background(), map[string]any{
		"webhook_secret":      "secret-value",
		"api_token":           "token-value",
		"password":            "password-value",
		"private_key_pem":     "private-key-value",
		"api_key_fingerprint": "sha256:1234567890abcdef",
		"identity_id":         "identity-1",
	}, "ok", "")

	for _, leaked := range []string{"secret-value", "token-value", "password-value", "private-key-value"} {
		if strings.Contains(metadataJSON, leaked) {
			t.Fatalf("audit metadata leaked sensitive value %q: %s", leaked, metadataJSON)
		}
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	for _, key := range []string{"webhook_secret", "api_token", "password", "private_key_pem"} {
		if metadata[key] != "[redacted]" {
			t.Fatalf("metadata[%s] = %#v, want [redacted]; metadata=%#v", key, metadata[key], metadata)
		}
	}
	if metadata["api_key_fingerprint"] != "sha256:1234567890abcdef" || metadata["identity_id"] != "identity-1" {
		t.Fatalf("audit metadata redacted non-secret fields: %#v", metadata)
	}
}

func TestIssueRequiresApprovedEnrollment(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidTransition", err)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("issuer request count = %d, want 0", len(issuerClient.requests))
	}
}

func TestIssueCertificateReturnsExistingCertificateForIssuedEnrollment(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	first, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate first returned error: %v", err)
	}

	second, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate second returned error: %v", err)
	}
	if second.ID != first.ID || second.CertificatePEM != first.CertificatePEM {
		t.Fatalf("second certificate = %#v, want existing %#v", second, first)
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
}

func TestIssueCertificateRejectsDuplicateIssuerSerialWithoutIssuingEnrollment(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	first := createDuplicateSerialEnrollment(t, ctx, service, identity.ID, issuer.ID)
	second := createDuplicateSerialEnrollment(t, ctx, service, identity.ID, issuer.ID)
	if _, err := service.ApproveEnrollment(ctx, "approver", first.ID); err != nil {
		t.Fatalf("ApproveEnrollment first returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", second.ID); err != nil {
		t.Fatalf("ApproveEnrollment second returned error: %v", err)
	}
	firstCertificate, err := service.IssueCertificate(ctx, "issuer", first.ID)
	if err != nil {
		t.Fatalf("IssueCertificate first returned error: %v", err)
	}

	_, err = service.IssueCertificate(ctx, "issuer", second.ID)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("IssueCertificate duplicate serial error = %v, want ErrInvalidTransition", err)
	}
	if len(issuerClient.requests) != 2 {
		t.Fatalf("issuer request count = %d, want 2", len(issuerClient.requests))
	}
	if _, err := repo.GetCertificateByEnrollmentID(ctx, second.ID); !errors.Is(err, domain.ErrCertificateNotFound) {
		t.Fatalf("second enrollment certificate error = %v, want ErrCertificateNotFound", err)
	}
	secondEnrollment, err := repo.GetEnrollment(ctx, second.ID)
	if err != nil {
		t.Fatalf("GetEnrollment second returned error: %v", err)
	}
	if secondEnrollment.Status != domain.EnrollmentApproved {
		t.Fatalf("second enrollment status = %q, want %q", secondEnrollment.Status, domain.EnrollmentApproved)
	}
	attempt, err := repo.GetIssuanceAttempt(ctx, second.ID)
	if err != nil {
		t.Fatalf("GetIssuanceAttempt second returned error: %v", err)
	}
	if attempt.Status != domain.IssuanceAttemptFailed || attempt.LastError == "" {
		t.Fatalf("second issuance attempt = %#v, want failed with last_error", attempt)
	}
	if attempt.SerialNumber != firstCertificate.SerialNumber {
		t.Fatalf("failed attempt serial = %q, want duplicate %q", attempt.SerialNumber, firstCertificate.SerialNumber)
	}
}

func TestIssueCertificateConcurrentFinalizeReturnsExistingCertificate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := newBlockingIssueIssuer(1)
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&threadSafeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	const workers = 2
	start := make(chan struct{})
	results := make(chan issueCertificateResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
			results <- issueCertificateResult{certificate: certificate, err: err}
		}()
	}
	close(start)
	select {
	case <-issuerClient.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first signing request")
	}
	time.Sleep(100 * time.Millisecond)
	close(issuerClient.release)
	wg.Wait()
	close(results)

	var certificates []domain.Certificate
	for result := range results {
		if result.err != nil {
			t.Fatalf("IssueCertificate concurrent error: %v", result.err)
		}
		certificates = append(certificates, result.certificate)
	}
	if len(certificates) != workers {
		t.Fatalf("certificate result count = %d, want %d", len(certificates), workers)
	}
	if certificates[0].ID != certificates[1].ID || certificates[0].CertificatePEM != certificates[1].CertificatePEM {
		t.Fatalf("certificates = %#v, want same certificate", certificates)
	}
	stored, err := repo.ListCertificates(ctx)
	if err != nil {
		t.Fatalf("ListCertificates returned error: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored certificate count = %d, want 1", len(stored))
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
}

func TestIssueCertificateUsesEnrollmentProfile(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		KeyUsage: domain.StringListExtensionPolicy{
			Critical: true,
			Values:   []string{"digital_signature", "key_encipherment"},
		},
		ExtendedKeyUsage: domain.StringListExtensionPolicy{
			Values: []string{"server_auth"},
		},
		AllowedSignatureAlgorithms: []string{"sha384"},
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical: true,
			CA:       false,
		},
		SubjectKeyIdentifier:   true,
		AuthorityKeyIdentifier: true,
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err = service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	req := issuerClient.requests[0]
	if req.ProfileID != profile.ID {
		t.Fatalf("IssueRequest ProfileID = %q, want %q", req.ProfileID, profile.ID)
	}
	if !req.BasicConstraintsCritical || req.BasicConstraintsCA {
		t.Fatalf("IssueRequest basic constraints = critical:%t ca:%t", req.BasicConstraintsCritical, req.BasicConstraintsCA)
	}
	if !req.KeyUsageCritical || !reflect.DeepEqual(req.KeyUsage, []string{"digital_signature", "key_encipherment"}) {
		t.Fatalf("IssueRequest key usage = critical:%t values:%#v", req.KeyUsageCritical, req.KeyUsage)
	}
	if !reflect.DeepEqual(req.ExtendedKeyUsage, []string{"server_auth"}) {
		t.Fatalf("IssueRequest extended key usage = %#v", req.ExtendedKeyUsage)
	}
	if req.SignatureAlgorithm != "sha384" {
		t.Fatalf("IssueRequest SignatureAlgorithm = %q, want sha384", req.SignatureAlgorithm)
	}
	if !req.SubjectKeyIdentifier || !req.AuthorityKeyIdentifier {
		t.Fatalf("IssueRequest key identifiers = ski:%t aki:%t", req.SubjectKeyIdentifier, req.AuthorityKeyIdentifier)
	}
	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, findAuditEvent(t, events, "certificate.issued"))
	if metadata["key_provider_result_code"] != "ok" ||
		metadata["key_provider_operation"] != "certificate_issue" ||
		metadata["key_provider_signature_algorithm"] != "sha384" ||
		metadata["key_provider_evidence_source"] != "core_signing" ||
		metadata["key_provider_signing_proven"] != true {
		t.Fatalf("certificate provider evidence metadata = %#v", metadata)
	}
}

func TestIssueCertificatePreservesZeroProfilePathLen(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:     "CN=edge-ca",
		DNSNames:    []string{"edge-ca.example.test"},
		IPAddresses: []string{"127.0.0.1"},
	}}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-ca",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "root-ca",
		Kind:           domain.IssuerRootCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	maxPathLen := 0
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "intermediate-ca",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical:   true,
			CA:         true,
			MaxPathLen: &maxPathLen,
		},
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-ca",
		RequestedDNSNames:    []string{"edge-ca.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	if _, err := service.IssueCertificate(ctx, "issuer", enrollment.ID); err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	got := issuerClient.requests[0].BasicConstraintsMaxPathLen
	if got == nil || *got != 0 {
		t.Fatalf("IssueRequest BasicConstraintsMaxPathLen = %#v, want pointer to 0", got)
	}
}

func TestAuditMetadataContractForProfileCertificateLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:             domain.IdentityMachine,
		Name:             "edge-01",
		DeploymentTarget: "k8s/prod/edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    clock.now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
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
	if _, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	for _, event := range events {
		metadata := auditMetadata(t, event)
		if metadata["result_code"] != "ok" {
			t.Fatalf("%s result_code = %#v, want ok", event.Action, metadata["result_code"])
		}
		if _, ok := metadata["error_code"]; ok {
			t.Fatalf("%s has unexpected error_code: %#v", event.Action, metadata)
		}
	}

	required := map[string]map[string]string{
		"identity.created": {
			"identity_id": identity.ID,
		},
		"issuer.created": {
			"issuer_id": issuer.ID,
		},
		"certificate_profile.created": {
			"issuer_id":  issuer.ID,
			"profile_id": profile.ID,
		},
		"enrollment.created": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
		"enrollment.approved": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
		"certificate.issued": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"certificate_id":    certificate.ID,
			"serial_number":     certificate.SerialNumber,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
		"certificate.suspended": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"certificate_id":    certificate.ID,
			"serial_number":     certificate.SerialNumber,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
		"certificate.resumed": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"certificate_id":    certificate.ID,
			"serial_number":     certificate.SerialNumber,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
		"certificate.revoked": {
			"identity_id":       identity.ID,
			"issuer_id":         issuer.ID,
			"enrollment_id":     enrollment.ID,
			"certificate_id":    certificate.ID,
			"serial_number":     certificate.SerialNumber,
			"profile_id":        profile.ID,
			"deployment_target": identity.DeploymentTarget,
		},
	}
	for action, fields := range required {
		event := findAuditEvent(t, events, action)
		metadata := auditMetadata(t, event)
		for key, want := range fields {
			if metadata[key] != want {
				t.Fatalf("%s metadata[%s] = %#v, want %q; metadata=%#v", action, key, metadata[key], want, metadata)
			}
		}
	}
}

func TestPublishCRLSelectsRevokedCertificatesAndPersistsArtifact(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{crlResult: corecli.GenerateCRLResult{CRLPEM: "crl-pem"}}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	otherIssuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "other-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "other-cert-pem",
		KeyRef:         "other-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer other returned error: %v", err)
	}

	revokedAt := clock.now.Add(-time.Hour)
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:             "cert-1",
		IssuerID:       issuer.ID,
		SerialNumber:   "1234",
		Status:         domain.CertificateRevoked,
		CertificatePEM: "cert-pem",
		CreatedAt:      revokedAt,
		UpdatedAt:      revokedAt,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	if err := repo.CreateRevocation(ctx, domain.Revocation{
		ID:            "revocation-1",
		CertificateID: "cert-1",
		Reason:        domain.RevocationKeyCompromise,
		RevokedBy:     "operator",
		RevokedAt:     revokedAt,
		CreatedAt:     revokedAt,
	}); err != nil {
		t.Fatalf("CreateRevocation returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:             "cert-other",
		IssuerID:       otherIssuer.ID,
		SerialNumber:   "9999",
		Status:         domain.CertificateRevoked,
		CertificatePEM: "cert-pem",
		CreatedAt:      revokedAt,
		UpdatedAt:      revokedAt,
	}); err != nil {
		t.Fatalf("CreateCertificate other returned error: %v", err)
	}
	if err := repo.CreateRevocation(ctx, domain.Revocation{
		ID:            "revocation-other",
		CertificateID: "cert-other",
		Reason:        domain.RevocationSuperseded,
		RevokedBy:     "operator",
		RevokedAt:     revokedAt,
		CreatedAt:     revokedAt,
	}); err != nil {
		t.Fatalf("CreateRevocation other returned error: %v", err)
	}

	nextUpdate := clock.now.Add(24 * time.Hour)
	publication, err := service.PublishCRL(ctx, "operator", PublishCRLRequest{
		IssuerID:          issuer.ID,
		DistributionPoint: "https://pki.example.test/intermediate.crl",
		NextUpdate:        nextUpdate,
	})
	if err != nil {
		t.Fatalf("PublishCRL returned error: %v", err)
	}

	if publication.IssuerID != issuer.ID || publication.CRLNumber != 1 || publication.CRLPEM != "crl-pem" {
		t.Fatalf("publication = %#v", publication)
	}
	if len(coreClient.crlRequests) != 1 {
		t.Fatalf("CRL request count = %d, want 1", len(coreClient.crlRequests))
	}
	req := coreClient.crlRequests[0]
	if req.IssuerCertificatePEM != "issuer-cert-pem" || req.IssuerKeyRef != "issuer-key-ref" {
		t.Fatalf("CRL issuer material = %#v", req)
	}
	if req.CRLNumber != 1 || !req.ThisUpdate.Equal(clock.now) || !req.NextUpdate.Equal(nextUpdate) {
		t.Fatalf("CRL timing/number = %#v", req)
	}
	if len(req.RevokedCertificates) != 1 {
		t.Fatalf("revoked entry count = %d, want 1", len(req.RevokedCertificates))
	}
	entry := req.RevokedCertificates[0]
	if entry.SerialNumber != "1234" || entry.Reason != string(domain.RevocationKeyCompromise) || !entry.RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked entry = %#v", entry)
	}

	latest, err := service.GetLatestCRLPublication(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetLatestCRLPublication returned error: %v", err)
	}
	if latest.ID != publication.ID {
		t.Fatalf("latest CRL ID = %q, want %q", latest.ID, publication.ID)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "crl.published" {
		t.Fatalf("last audit action = %q, want crl.published", last.Action)
	}
	metadata := auditMetadata(t, last)
	if metadata["result_code"] != "ok" ||
		metadata["issuer_id"] != issuer.ID ||
		metadata["crl_publication_id"] != publication.ID ||
		metadata["distribution_point"] != publication.DistributionPoint ||
		metadata["key_provider_class"] != "file" ||
		metadata["key_provider_exportability"] != "exportable" ||
		metadata["key_provider_operation"] != "crl_generate_sign" ||
		metadata["key_provider_evidence_source"] != "core_signing" ||
		metadata["key_provider_signing_proven"] != true ||
		metadata["key_provider_binding_verified"] != true ||
		metadata["key_provider_fallback_used"] != false ||
		metadata["crl_number"].(float64) != float64(publication.CRLNumber) {
		t.Fatalf("CRL audit metadata = %#v", metadata)
	}
}

func TestPublishCRLMapsCoreFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{crlErr: errors.New("crl signer unavailable")}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.PublishCRL(ctx, "operator", PublishCRLRequest{
		IssuerID:          issuer.ID,
		DistributionPoint: "https://pki.example.test/intermediate.crl",
		NextUpdate:        clock.now.Add(24 * time.Hour),
	})
	if !errors.Is(err, domain.ErrCRLGenerationFailed) {
		t.Fatalf("PublishCRL error = %v, want ErrCRLGenerationFailed", err)
	}
	if len(coreClient.crlRequests) != 1 {
		t.Fatalf("CRL request count = %d, want 1", len(coreClient.crlRequests))
	}
	publications, err := repo.ListCRLPublicationsByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListCRLPublicationsByIssuer returned error: %v", err)
	}
	if len(publications) != 0 {
		t.Fatalf("CRL publications = %#v, want none after failed generation", publications)
	}
}

func TestPublishCRLOutageRecoversWithoutPhantomPublication(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{crlErr: errors.New("crl signer unavailable")}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	request := PublishCRLRequest{
		IssuerID:          issuer.ID,
		DistributionPoint: "https://pki.example.test/intermediate.crl",
		NextUpdate:        clock.now.Add(24 * time.Hour),
	}
	if _, err := service.PublishCRL(ctx, "operator", request); !errors.Is(err, domain.ErrCRLGenerationFailed) {
		t.Fatalf("PublishCRL outage error = %v, want ErrCRLGenerationFailed", err)
	}
	publications, err := repo.ListCRLPublicationsByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListCRLPublicationsByIssuer returned error: %v", err)
	}
	if len(publications) != 0 {
		t.Fatalf("CRL publications during outage = %#v, want none", publications)
	}
	for _, event := range mustListAuditEvents(t, service, ctx) {
		if event.Action == "crl.published" {
			t.Fatalf("success audit written during CRL outage: %#v", event)
		}
	}

	coreClient.crlErr = nil
	coreClient.crlResult = corecli.GenerateCRLResult{CRLPEM: "recovered-crl-pem"}
	publication, err := service.PublishCRL(ctx, "operator", request)
	if err != nil {
		t.Fatalf("PublishCRL after recovery returned error: %v", err)
	}
	if publication.CRLNumber != 1 || publication.CRLPEM != "recovered-crl-pem" {
		t.Fatalf("recovered CRL publication = %#v", publication)
	}
	publications, err = repo.ListCRLPublicationsByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListCRLPublicationsByIssuer after recovery returned error: %v", err)
	}
	if len(publications) != 1 || publications[0].CRLNumber != 1 {
		t.Fatalf("CRL publications after recovery = %#v", publications)
	}
	publishedAudits := 0
	for _, event := range mustListAuditEvents(t, service, ctx) {
		if event.Action == "crl.published" {
			publishedAudits++
		}
	}
	if publishedAudits != 1 {
		t.Fatalf("crl.published audit count = %d, want 1", publishedAudits)
	}
	if len(coreClient.crlRequests) != 2 {
		t.Fatalf("CRL request count = %d, want 2", len(coreClient.crlRequests))
	}
}

func TestPublishCRLRejectsReadinessWithoutCoreSigningEvidence(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	missingEvidence := corecli.SigningEvidence{}
	coreClient := &fakeIssuer{
		crlResult:          corecli.GenerateCRLResult{CRLPEM: "crl-pem"},
		crlSigningEvidence: &missingEvidence,
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "issuer", Kind: domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert", KeyRef: "issuer-key",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.PublishCRL(ctx, "operator", PublishCRLRequest{
		IssuerID: issuer.ID, DistributionPoint: "https://pki.example.test/issuer.crl",
		NextUpdate: clock.now.Add(24 * time.Hour),
	})
	if !errors.Is(err, domain.ErrCRLGenerationFailed) {
		t.Fatalf("PublishCRL error = %v, want ErrCRLGenerationFailed", err)
	}
	if publications, listErr := repo.ListCRLPublicationsByIssuer(ctx, issuer.ID); listErr != nil || len(publications) != 0 {
		t.Fatalf("CRL publications after missing evidence = %#v, err=%v", publications, listErr)
	}
}

func TestPublishCRLChecksKeyProviderBeforeSigning(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{crlResult: corecli.GenerateCRLResult{CRLPEM: "crl-pem"}}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	provider := &fakeKeyProvider{err: domain.ErrInvalidRequest}
	if err := service.SetKeyProvider(provider); err != nil {
		t.Fatalf("SetKeyProvider returned error: %v", err)
	}

	_, err = service.PublishCRL(ctx, "operator", PublishCRLRequest{
		IssuerID:          issuer.ID,
		DistributionPoint: "https://pki.example.test/intermediate.crl",
		NextUpdate:        clock.now.Add(24 * time.Hour),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("PublishCRL error = %v, want ErrInvalidRequest", err)
	}
	if len(provider.refs) != 1 || provider.refs[0] != "issuer-key-ref" {
		t.Fatalf("provider refs = %#v, want issuer-key-ref", provider.refs)
	}
	if len(coreClient.crlRequests) != 0 {
		t.Fatalf("CRL request count = %d, want 0", len(coreClient.crlRequests))
	}
}

func TestRespondOCSPMapsCertificateStatesAndAudits(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			HasNonce: true,
			NonceHex: "01020304a5",
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "1001", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
				{SerialNumber: "1002", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
				{SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-valid",
		IdentityID:   "identity-1",
		IssuerID:     issuer.ID,
		SerialNumber: "1001",
		Status:       domain.CertificateValid,
		CreatedAt:    clock.now,
		UpdatedAt:    clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate valid returned error: %v", err)
	}
	revokedAt := clock.now.Add(-time.Hour)
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-revoked",
		IdentityID:   "identity-2",
		IssuerID:     issuer.ID,
		SerialNumber: "1002",
		Status:       domain.CertificateRevoked,
		CreatedAt:    revokedAt,
		UpdatedAt:    revokedAt,
	}); err != nil {
		t.Fatalf("CreateCertificate revoked returned error: %v", err)
	}
	if err := repo.CreateRevocation(ctx, domain.Revocation{
		ID:            "revocation-1",
		CertificateID: "cert-revoked",
		Reason:        domain.RevocationKeyCompromise,
		RevokedBy:     "operator",
		RevokedAt:     revokedAt,
		CreatedAt:     revokedAt,
	}); err != nil {
		t.Fatalf("CreateRevocation returned error: %v", err)
	}

	response, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der"))
	if err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	if string(response.ResponseDER) != "ocsp-response-der" {
		t.Fatalf("OCSP response DER = %q", string(response.ResponseDER))
	}
	if len(coreClient.ocspResponses) != 1 {
		t.Fatalf("OCSP response request count = %d, want 1", len(coreClient.ocspResponses))
	}
	gotStatuses := coreClient.ocspResponses[0].Certificates
	wantStatuses := []corecli.OCSPCertificateStatus{
		{SerialNumber: "1001", Status: "good"},
		{SerialNumber: "1002", Status: "revoked", RevokedAt: revokedAt, RevocationReason: string(domain.RevocationKeyCompromise)},
		{SerialNumber: "4040", Status: "unknown"},
	}
	for i, want := range wantStatuses {
		if gotStatuses[i].SerialNumber != want.SerialNumber ||
			gotStatuses[i].Status != want.Status ||
			gotStatuses[i].RevocationReason != want.RevocationReason ||
			!gotStatuses[i].RevokedAt.Equal(want.RevokedAt) {
			t.Fatalf("OCSP status %d = %#v, want %#v", i, gotStatuses[i], want)
		}
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "ocsp.requested" {
		t.Fatalf("last audit action = %q, want ocsp.requested", last.Action)
	}
	metadata := auditMetadata(t, last)
	if metadata["request_type"] != "ocsp" ||
		metadata["issuer_id"] != issuer.ID ||
		metadata["result_code"] != "ok" ||
		metadata["nonce_present"] != true ||
		metadata["requested_cert_count"].(float64) != 3 ||
		metadata["key_provider_class"] != "file" ||
		metadata["key_provider_exportability"] != "exportable" ||
		metadata["key_provider_operation"] != "ocsp_response_sign" ||
		metadata["key_provider_evidence_source"] != "core_signing" ||
		metadata["key_provider_signing_proven"] != true ||
		metadata["key_provider_binding_verified"] != true ||
		metadata["key_provider_fallback_used"] != false ||
		metadata["response_status"] != "successful" {
		t.Fatalf("OCSP audit metadata = %#v", metadata)
	}
	auditCertificates, ok := metadata["certificates"].([]any)
	if !ok || len(auditCertificates) != 3 {
		t.Fatalf("OCSP audit certificates = %#v", metadata["certificates"])
	}
	revokedAudit, ok := auditCertificates[1].(map[string]any)
	if !ok {
		t.Fatalf("OCSP revoked audit entry = %#v", auditCertificates[1])
	}
	if revokedAudit["serial_number"] != "1002" ||
		revokedAudit["issuer_name_hash"] != "name-hash" ||
		revokedAudit["issuer_key_hash"] != "key-hash" ||
		revokedAudit["status"] != "revoked" ||
		revokedAudit["reason"] != string(domain.RevocationKeyCompromise) ||
		revokedAudit["revoked_at"] != revokedAt.Format(time.RFC3339) {
		t.Fatalf("OCSP revoked audit entry = %#v", revokedAudit)
	}
}

func TestRespondOCSPMapsResponseFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "1001", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseErr: errors.New("ocsp signer unavailable"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-valid",
		IdentityID:   "identity-1",
		IssuerID:     issuer.ID,
		SerialNumber: "1001",
		Status:       domain.CertificateValid,
		CreatedAt:    clock.now,
		UpdatedAt:    clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	_, err = service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der"))
	if !errors.Is(err, domain.ErrOCSPResponseFailed) {
		t.Fatalf("RespondOCSP error = %v, want ErrOCSPResponseFailed", err)
	}
	if len(coreClient.ocspResponses) != 1 {
		t.Fatalf("OCSP response request count = %d, want 1", len(coreClient.ocspResponses))
	}
}

func TestRespondOCSPOutageRecoversWithoutSuccessAudit(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{Certificates: []corecli.OCSPCertificateID{{
			SerialNumber: "1001", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash",
		}}},
		ocspResponseErr: errors.New("ocsp signer unavailable"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "intermediate-ca", Kind: domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem", KeyRef: "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID: "cert-valid", IdentityID: "identity-1", IssuerID: issuer.ID,
		SerialNumber: "1001", Status: domain.CertificateValid,
		CreatedAt: clock.now, UpdatedAt: clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); !errors.Is(err, domain.ErrOCSPResponseFailed) {
		t.Fatalf("RespondOCSP outage error = %v, want ErrOCSPResponseFailed", err)
	}
	for _, event := range mustListAuditEvents(t, service, ctx) {
		if event.Action == "ocsp.requested" {
			t.Fatalf("success audit written during OCSP outage: %#v", event)
		}
	}

	coreClient.ocspResponseErr = nil
	coreClient.ocspResponseDER = []byte("recovered-ocsp-response")
	response, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der"))
	if err != nil {
		t.Fatalf("RespondOCSP after recovery returned error: %v", err)
	}
	if string(response.ResponseDER) != "recovered-ocsp-response" {
		t.Fatalf("recovered OCSP response = %q", response.ResponseDER)
	}
	successAudits := 0
	for _, event := range mustListAuditEvents(t, service, ctx) {
		if event.Action == "ocsp.requested" {
			successAudits++
		}
	}
	if successAudits != 1 {
		t.Fatalf("ocsp.requested audit count = %d, want 1", successAudits)
	}
	if len(coreClient.ocspResponses) != 2 {
		t.Fatalf("OCSP response request count = %d, want 2", len(coreClient.ocspResponses))
	}
}

func TestRespondOCSPRejectsReadinessWithoutCoreSigningEvidence(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	missingEvidence := corecli.SigningEvidence{}
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{Certificates: []corecli.OCSPCertificateID{{
			SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash",
		}}},
		ocspResponseDER:     []byte("ocsp-response-der"),
		ocspSigningEvidence: &missingEvidence,
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})
	if _, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "issuer", Kind: domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert", KeyRef: "issuer-key",
	}); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request"))
	if !errors.Is(err, domain.ErrOCSPResponseFailed) {
		t.Fatalf("RespondOCSP error = %v, want ErrOCSPResponseFailed", err)
	}
	events, listErr := service.ListAuditEvents(ctx)
	if listErr != nil {
		t.Fatalf("ListAuditEvents returned error: %v", listErr)
	}
	for _, event := range events {
		if event.Action == "ocsp.requested" {
			t.Fatalf("OCSP success audit written without signing evidence: %#v", event)
		}
	}
}

func TestRespondOCSPChecksKeyProviderBeforeSigning(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	_, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	provider := &fakeKeyProvider{err: domain.ErrInvalidRequest}
	if err := service.SetKeyProvider(provider); err != nil {
		t.Fatalf("SetKeyProvider returned error: %v", err)
	}

	_, err = service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der"))
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("RespondOCSP error = %v, want ErrInvalidRequest", err)
	}
	if len(provider.refs) != 1 || provider.refs[0] != "issuer-key-ref" {
		t.Fatalf("provider refs = %#v, want issuer-key-ref", provider.refs)
	}
	if len(coreClient.ocspResponses) != 0 {
		t.Fatalf("OCSP response request count = %d, want 0", len(coreClient.ocspResponses))
	}
}

func TestCreateOCSPResponderValidatesStoresAndAudits(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	responder, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-pem",
		KeyRef:         "responder-key",
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}
	if responder.Status != domain.OCSPResponderActive {
		t.Fatalf("responder status = %q, want %q", responder.Status, domain.OCSPResponderActive)
	}
	if len(coreClient.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(coreClient.ocspResponderValidationRequests))
	}
	validationReq := coreClient.ocspResponderValidationRequests[0]
	if validationReq.issuerCertificatePEM != issuer.CertificatePEM {
		t.Fatalf("validation issuer PEM = %q, want %q", validationReq.issuerCertificatePEM, issuer.CertificatePEM)
	}
	if validationReq.responderCertificatePEM != responder.CertificatePEM {
		t.Fatalf("validation responder PEM = %q, want %q", validationReq.responderCertificatePEM, responder.CertificatePEM)
	}

	stored, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if stored.ID != responder.ID {
		t.Fatalf("stored responder ID = %q, want %q", stored.ID, responder.ID)
	}

	list, err := service.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 1 || list[0].ID != responder.ID {
		t.Fatalf("ListOCSPRespondersByIssuer = %#v, want responder %q", list, responder.ID)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "ocsp_responder.created" {
		t.Fatalf("last audit action = %q, want ocsp_responder.created", last.Action)
	}
	metadata := auditMetadata(t, last)
	if metadata["issuer_id"] != issuer.ID ||
		metadata["ocsp_responder_id"] != responder.ID ||
		metadata["key_provider_class"] != "file" ||
		metadata["key_provider_exportability"] != "exportable" ||
		metadata["result_code"] != "ok" {
		t.Fatalf("OCSP responder audit metadata = %#v", metadata)
	}
}

func TestOCSPResponderLifecycleRejectsBlankFields(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	_, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateOCSPResponder error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.ListOCSPRespondersByIssuer(ctx, " ")
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("ListOCSPRespondersByIssuer error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.DisableOCSPResponder(ctx, "admin", "", "")
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("DisableOCSPResponder error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateOCSPResponderRejectsUnsupportedKeyProvider(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true}},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-pem",
		KeyRef:         "kms:provider/key/version",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateOCSPResponder error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateOCSPResponderProductionPolicyRejectsFileKey(t *testing.T) {
	ctx := context.Background()
	coreClient := &fakeIssuer{ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true}}
	service := New(
		store.NewMemoryStore(),
		coreClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	service.EnableProductionPolicy()

	_, err = service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-pem",
		KeyRef:         "file:/var/lib/anopki/ocsp-responder.key",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateOCSPResponder error = %v, want ErrInvalidRequest", err)
	}
	if len(coreClient.ocspResponderValidationRequests) != 0 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 0", len(coreClient.ocspResponderValidationRequests))
	}
}

func TestCreateOCSPResponderRejectsInvalidValidationResult(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: false},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-pem",
		KeyRef:         "responder-key",
	})
	if !errors.Is(err, domain.ErrOCSPResponderValidationFailed) {
		t.Fatalf("CreateOCSPResponder error = %v, want ErrOCSPResponderValidationFailed", err)
	}

	if responders, err := service.ListOCSPRespondersByIssuer(ctx, issuer.ID); err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	} else if len(responders) != 0 {
		t.Fatalf("stored responders = %#v, want none", responders)
	}
}

func TestCreateOCSPResponderRequiresDisableBeforeReplacement(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if _, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-a-pem",
		KeyRef:         "responder-a-key",
	}); err != nil {
		t.Fatalf("first CreateOCSPResponder returned error: %v", err)
	}

	_, err = service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-b-ocsp",
		CertificatePEM: "responder-b-pem",
		KeyRef:         "responder-b-key",
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("second CreateOCSPResponder error = %v, want ErrInvalidTransition", err)
	}
	if len(coreClient.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(coreClient.ocspResponderValidationRequests))
	}
}

func TestDisableOCSPResponderDisablesAndAllowsReplacement(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	first, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-a-pem",
		KeyRef:         "responder-a-key",
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}

	disabled, err := service.DisableOCSPResponder(ctx, "admin", issuer.ID, first.ID)
	if err != nil {
		t.Fatalf("DisableOCSPResponder returned error: %v", err)
	}
	if disabled.Status != domain.OCSPResponderDisabled {
		t.Fatalf("disabled responder status = %q, want %q", disabled.Status, domain.OCSPResponderDisabled)
	}
	if _, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID); !errors.Is(err, domain.ErrOCSPResponderNotFound) {
		t.Fatalf("GetActiveOCSPResponderByIssuer error = %v, want ErrOCSPResponderNotFound", err)
	}

	second, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-b-ocsp",
		CertificatePEM: "responder-b-pem",
		KeyRef:         "responder-b-key",
	})
	if err != nil {
		t.Fatalf("replacement CreateOCSPResponder returned error: %v", err)
	}
	active, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != second.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, second.ID)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	foundDisabled := false
	for _, event := range events {
		if event.Action != "ocsp_responder.disabled" {
			continue
		}
		metadata := auditMetadata(t, event)
		if metadata["issuer_id"] == issuer.ID && metadata["ocsp_responder_id"] == first.ID {
			foundDisabled = true
			break
		}
	}
	if !foundDisabled {
		t.Fatal("ocsp_responder.disabled audit event not found")
	}
}

func TestRotateOCSPResponderDisablesCurrentAndCreatesNewActive(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	first, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-a-pem",
		KeyRef:         "responder-a-key",
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}

	rotated, err := service.RotateOCSPResponder(ctx, "admin", RotateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-b-ocsp",
		CertificatePEM: "responder-b-pem",
		KeyRef:         "responder-b-key",
	})
	if err != nil {
		t.Fatalf("RotateOCSPResponder returned error: %v", err)
	}
	if rotated.ID == "" || rotated.ID == first.ID {
		t.Fatalf("rotated responder ID = %q, first ID = %q", rotated.ID, first.ID)
	}
	if rotated.Status != domain.OCSPResponderActive ||
		rotated.CertificatePEM != "responder-b-pem" ||
		rotated.KeyRef != "responder-b-key" {
		t.Fatalf("rotated responder = %#v", rotated)
	}
	if len(coreClient.ocspResponderValidationRequests) != 2 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 2", len(coreClient.ocspResponderValidationRequests))
	}
	if got := coreClient.ocspResponderValidationRequests[1].responderCertificatePEM; got != "responder-b-pem" {
		t.Fatalf("rotation validation responder PEM = %q, want responder-b-pem", got)
	}

	active, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != rotated.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, rotated.ID)
	}
	list, err := service.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	statuses := map[string]domain.OCSPResponderStatus{}
	for _, responder := range list {
		statuses[responder.ID] = responder.Status
	}
	if statuses[first.ID] != domain.OCSPResponderDisabled || statuses[rotated.ID] != domain.OCSPResponderActive {
		t.Fatalf("responder statuses = %#v", statuses)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("audit event count = %d, want at least 2", len(events))
	}
	disabled := events[len(events)-2]
	created := events[len(events)-1]
	if disabled.Action != "ocsp_responder.disabled" || created.Action != "ocsp_responder.created" {
		t.Fatalf("rotation audit actions = %q, %q", disabled.Action, created.Action)
	}
	disabledMetadata := auditMetadata(t, disabled)
	if disabledMetadata["issuer_id"] != issuer.ID || disabledMetadata["ocsp_responder_id"] != first.ID {
		t.Fatalf("disabled audit metadata = %#v", disabledMetadata)
	}
	createdMetadata := auditMetadata(t, created)
	if createdMetadata["issuer_id"] != issuer.ID || createdMetadata["ocsp_responder_id"] != rotated.ID {
		t.Fatalf("created audit metadata = %#v", createdMetadata)
	}
}

func TestRotateOCSPResponderRequiresActiveResponder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.RotateOCSPResponder(ctx, "admin", RotateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-b-ocsp",
		CertificatePEM: "responder-b-pem",
		KeyRef:         "responder-b-key",
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RotateOCSPResponder error = %v, want ErrInvalidTransition", err)
	}
	if len(coreClient.ocspResponderValidationRequests) != 0 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 0", len(coreClient.ocspResponderValidationRequests))
	}
}

func TestRotateOCSPResponderValidationFailureLeavesCurrentActive(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		ocspResponderValidationResult: corecli.ValidateOCSPResponderResult{Valid: true},
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	first, err := service.CreateOCSPResponder(ctx, "admin", CreateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		CertificatePEM: "responder-a-pem",
		KeyRef:         "responder-a-key",
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}
	coreClient.ocspResponderValidationResult = corecli.ValidateOCSPResponderResult{Valid: false}

	_, err = service.RotateOCSPResponder(ctx, "admin", RotateOCSPResponderRequest{
		IssuerID:       issuer.ID,
		Name:           "issuer-b-ocsp",
		CertificatePEM: "responder-b-pem",
		KeyRef:         "responder-b-key",
	})
	if !errors.Is(err, domain.ErrOCSPResponderValidationFailed) {
		t.Fatalf("RotateOCSPResponder error = %v, want ErrOCSPResponderValidationFailed", err)
	}

	active, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != first.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, first.ID)
	}
	list, err := service.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 1 || list[0].ID != first.ID || list[0].Status != domain.OCSPResponderActive {
		t.Fatalf("responders after failed rotation = %#v", list)
	}
}

func TestRespondOCSPUsesDelegatedResponderWhenActiveResponderExists(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateOCSPResponder(ctx, domain.OCSPResponder{
		ID:             "responder-1",
		IssuerID:       issuer.ID,
		Name:           "issuer-a-ocsp",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "responder-pem",
		KeyRef:         "responder-key",
		CreatedAt:      clock.now,
		UpdatedAt:      clock.now,
	}); err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	if len(coreClient.ocspResponses) != 1 {
		t.Fatalf("OCSP response request count = %d, want 1", len(coreClient.ocspResponses))
	}
	req := coreClient.ocspResponses[0]
	if req.IssuerCertificatePEM != "responder-pem" {
		t.Fatalf("OCSP signer certificate = %q, want responder-pem", req.IssuerCertificatePEM)
	}
	if req.IssuerKeyRef != "responder-key" {
		t.Fatalf("OCSP signer key = %q, want responder-key", req.IssuerKeyRef)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, events[len(events)-1])
	if metadata["responder_mode"] != "delegated" {
		t.Fatalf("responder_mode = %v, want delegated", metadata["responder_mode"])
	}
	if metadata["responder_id"] != "responder-1" {
		t.Fatalf("responder_id = %v, want responder-1", metadata["responder_id"])
	}
}

func TestRespondOCSPFallsBackToIssuerDirectWhenNoActiveResponderExists(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	if len(coreClient.ocspResponses) != 1 {
		t.Fatalf("OCSP response request count = %d, want 1", len(coreClient.ocspResponses))
	}
	req := coreClient.ocspResponses[0]
	if req.IssuerCertificatePEM != issuer.CertificatePEM {
		t.Fatalf("OCSP signer certificate = %q, want %q", req.IssuerCertificatePEM, issuer.CertificatePEM)
	}
	if req.IssuerKeyRef != issuer.KeyRef {
		t.Fatalf("OCSP signer key = %q, want %q", req.IssuerKeyRef, issuer.KeyRef)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, events[len(events)-1])
	if metadata["responder_mode"] != "issuer_direct" {
		t.Fatalf("responder_mode = %v, want issuer_direct", metadata["responder_mode"])
	}
	if _, ok := metadata["responder_id"]; ok {
		t.Fatalf("responder_id present for issuer_direct fallback: %#v", metadata)
	}
}

func TestRespondOCSPTreatsIssuerHashMismatchAsUnknown(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfos: map[string]corecli.OCSPIssuerInfo{
			"issuer-cert-pem":       {IssuerNameHash: "expected-name-hash", IssuerKeyHash: "expected-key-hash"},
			"other-issuer-cert-pem": {IssuerNameHash: "wrong-name-hash", IssuerKeyHash: "wrong-key-hash"},
		},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "1001", IssuerNameHash: "wrong-name-hash", IssuerKeyHash: "wrong-key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	otherIssuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "other-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "other-issuer-cert-pem",
		KeyRef:         "other-issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer other returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-valid",
		IssuerID:     issuer.ID,
		SerialNumber: "1001",
		Status:       domain.CertificateValid,
		CreatedAt:    clock.now,
		UpdatedAt:    clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	gotStatuses := coreClient.ocspResponses[0].Certificates
	if len(gotStatuses) != 1 || gotStatuses[0].SerialNumber != "1001" || gotStatuses[0].Status != "unknown" {
		t.Fatalf("OCSP statuses = %#v, want mismatched serial unknown", gotStatuses)
	}
	if coreClient.ocspResponses[0].IssuerCertificatePEM != otherIssuer.CertificatePEM {
		t.Fatalf("OCSP signer = %q, want other issuer", coreClient.ocspResponses[0].IssuerCertificatePEM)
	}
}

func TestRespondOCSPSignsUnknownOnlyRequestByIssuerHash(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "4040", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	req := coreClient.ocspResponses[0]
	if req.IssuerCertificatePEM != issuer.CertificatePEM || req.IssuerKeyRef != issuer.KeyRef {
		t.Fatalf("OCSP issuer material = %#v", req)
	}
	if len(req.Certificates) != 1 || req.Certificates[0].SerialNumber != "4040" || req.Certificates[0].Status != "unknown" {
		t.Fatalf("OCSP statuses = %#v, want unknown-only response", req.Certificates)
	}
}

func TestRespondOCSPTreatsSuspendedCertificateAsUnknown(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfo: corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{SerialNumber: "1001", IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-suspended",
		IssuerID:     issuer.ID,
		SerialNumber: "1001",
		Status:       domain.CertificateSuspended,
		CreatedAt:    clock.now,
		UpdatedAt:    clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	gotStatuses := coreClient.ocspResponses[0].Certificates
	if len(gotStatuses) != 1 || gotStatuses[0].SerialNumber != "1001" || gotStatuses[0].Status != "unknown" {
		t.Fatalf("OCSP statuses = %#v, want suspended serial unknown", gotStatuses)
	}
}

func TestRespondOCSPMatchesIssuerAndStatusByHashAlgorithm(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{
		issuerOCSPInfos: map[string]corecli.OCSPIssuerInfo{
			"issuer-cert-pem": {
				IssuerNameHash: "sha256-name-hash",
				IssuerKeyHash:  "sha256-key-hash",
				HashAlgorithm:  "sha256",
			},
		},
		ocspInfo: corecli.OCSPRequestInfo{
			Certificates: []corecli.OCSPCertificateID{
				{
					SerialNumber:   "1001",
					IssuerNameHash: "sha256-name-hash",
					IssuerKeyHash:  "sha256-key-hash",
					HashAlgorithm:  "sha256",
				},
			},
		},
		ocspResponseDER: []byte("ocsp-response-der"),
	}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateCertificate(ctx, domain.Certificate{
		ID:           "cert-valid",
		IssuerID:     issuer.ID,
		SerialNumber: "1001",
		Status:       domain.CertificateValid,
		CreatedAt:    clock.now,
		UpdatedAt:    clock.now,
	}); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	if _, err := service.RespondOCSP(ctx, "ocsp-client", []byte("ocsp-request-der")); err != nil {
		t.Fatalf("RespondOCSP returned error: %v", err)
	}
	if len(coreClient.ocspResponses) != 1 {
		t.Fatalf("OCSP response request count = %d, want 1", len(coreClient.ocspResponses))
	}
	statuses := coreClient.ocspResponses[0].Certificates
	if len(statuses) != 1 {
		t.Fatalf("OCSP statuses = %#v, want 1 status", statuses)
	}
	status := statuses[0]
	if status.SerialNumber != "1001" ||
		status.Status != "good" ||
		status.HashAlgorithm != "sha256" ||
		status.IssuerNameHash != "sha256-name-hash" ||
		status.IssuerKeyHash != "sha256-key-hash" {
		t.Fatalf("OCSP status = %#v, want hash-aware good status", status)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, events[len(events)-1])
	auditCertificates, ok := metadata["certificates"].([]any)
	if !ok || len(auditCertificates) != 1 {
		t.Fatalf("OCSP audit certificates = %#v", metadata["certificates"])
	}
	entry, ok := auditCertificates[0].(map[string]any)
	if !ok {
		t.Fatalf("OCSP audit entry = %#v", auditCertificates[0])
	}
	if entry["hash_algorithm"] != "sha256" {
		t.Fatalf("OCSP audit entry = %#v, want hash_algorithm sha256", entry)
	}
}

func TestCreateIdentityRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		req  CreateIdentityRequest
	}{
		{
			name: "invalid type",
			req: CreateIdentityRequest{
				Type: domain.IdentityType("device"),
				Name: "edge-01",
			},
		},
		{
			name: "empty name",
			req: CreateIdentityRequest{
				Type: domain.IdentityMachine,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{},
				fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
				&fakeIDGenerator{},
			)

			_, err := service.CreateIdentity(ctx, "admin", tt.req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateIdentity error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateIdentityRecordsMachineMetadata(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:               domain.IdentityWorkload,
		Name:               "payments-api",
		ExternalID:         "k8s:prod:payments:payments-api",
		Owner:              "platform",
		DeploymentTarget:   "k8s/prod/payments",
		MetadataJSON:       `{"namespace":"prod","service_account":"payments"}`,
		AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
		AllowedIPAddresses: []string{"192.0.2.42"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}

	if identity.Owner != "platform" ||
		identity.DeploymentTarget != "k8s/prod/payments" ||
		identity.MetadataJSON != `{"namespace":"prod","service_account":"payments"}` ||
		!reflect.DeepEqual(identity.AllowedDNSNames, []string{"payments.prod.svc.cluster.local"}) ||
		!reflect.DeepEqual(identity.AllowedIPAddresses, []string{"192.0.2.42"}) {
		t.Fatalf("identity machine metadata = %#v", identity)
	}
	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, events[0])
	if metadata["deployment_target"] != "k8s/prod/payments" {
		t.Fatalf("identity audit metadata = %#v", metadata)
	}
}

func TestProductionPolicyRequiresIdentityOwner(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	service.EnableProductionPolicy()

	_, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityWorkload,
		Name: "payments-api",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateIdentity error = %v, want ErrInvalidRequest", err)
	}
}

func TestProductionPolicyRejectsCertificateForIncompleteIdentity(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:  domain.IdentityMachine,
		Name:  "edge-01",
		Owner: "platform",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	service.EnableProductionPolicy()
	_, err = service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateIssuerRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	valid := CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	}
	tests := []struct {
		name   string
		mutate func(*CreateIssuerRequest)
	}{
		{name: "empty name", mutate: func(req *CreateIssuerRequest) { req.Name = "" }},
		{name: "invalid kind", mutate: func(req *CreateIssuerRequest) { req.Kind = domain.IssuerKind("leaf") }},
		{name: "empty certificate", mutate: func(req *CreateIssuerRequest) { req.CertificatePEM = "" }},
		{name: "empty key ref", mutate: func(req *CreateIssuerRequest) { req.KeyRef = "" }},
		{name: "unsupported key provider", mutate: func(req *CreateIssuerRequest) { req.KeyRef = "pkcs11:token=ca;object=issuer-a" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid
			tt.mutate(&req)
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{},
				fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
				&fakeIDGenerator{},
			)

			_, err := service.CreateIssuer(ctx, "admin", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateIssuer error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateIssuerProductionPolicyRejectsFileKey(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	service.EnableProductionPolicy()

	_, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "file:/var/lib/anopki/issuer.key",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateIssuer error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateNotificationEndpointProductionPolicy(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	service.EnableProductionPolicy()

	_, err := service.CreateNotificationEndpoint(ctx, "admin", CreateNotificationEndpointRequest{
		Name:   "ops",
		URL:    "http://ops.example.test/hooks/pki",
		Secret: "webhook-secret-0123456789abcdefghi",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateNotificationEndpoint HTTP error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateNotificationEndpoint(ctx, "admin", CreateNotificationEndpointRequest{
		Name:   "ops",
		URL:    "https://ops.example.test/hooks/pki",
		Secret: "short",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateNotificationEndpoint weak secret error = %v, want ErrInvalidRequest", err)
	}

	endpoint, err := service.CreateNotificationEndpoint(ctx, "admin", CreateNotificationEndpointRequest{
		Name:   "ops",
		URL:    "https://ops.example.test/hooks/pki",
		Secret: "webhook-secret-0123456789abcdefghi",
	})
	if err != nil {
		t.Fatalf("CreateNotificationEndpoint strong HTTPS returned error: %v", err)
	}
	if endpoint.URL != "https://ops.example.test/hooks/pki" {
		t.Fatalf("endpoint URL = %q", endpoint.URL)
	}
}

func TestCreateIssuerRecordsTrustDistributionMetadata(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	root, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "root-ca",
		Kind:           domain.IssuerRootCA,
		CertificatePEM: "root-cert-pem",
		KeyRef:         "root-key-ref",
		TrustAnchor:    true,
	})
	if err != nil {
		t.Fatalf("CreateIssuer root returned error: %v", err)
	}

	intermediate, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:                  "intermediate-ca",
		Kind:                  domain.IssuerIntermediateCA,
		ParentIssuerID:        root.ID,
		CertificatePEM:        "intermediate-cert-pem",
		KeyRef:                "intermediate-key-ref",
		AIAURL:                "https://pki.example.test/issuers/intermediate-ca.pem",
		CRLDistributionPoints: []string{"https://pki.example.test/crl/intermediate-ca.pem"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer intermediate returned error: %v", err)
	}
	if intermediate.ParentIssuerID != root.ID || intermediate.AIAURL == "" ||
		!reflect.DeepEqual(intermediate.CRLDistributionPoints, []string{"https://pki.example.test/crl/intermediate-ca.pem"}) {
		t.Fatalf("intermediate issuer metadata = %#v", intermediate)
	}
}

func TestCreateIssuerRejectsInvalidParent(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	root, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "root-ca",
		Kind:           domain.IssuerRootCA,
		CertificatePEM: "root-cert-pem",
		KeyRef:         "root-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer root returned error: %v", err)
	}

	_, err = service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "bad-root",
		Kind:           domain.IssuerRootCA,
		ParentIssuerID: root.ID,
		CertificatePEM: "bad-root-cert-pem",
		KeyRef:         "bad-root-key-ref",
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("root parent error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "missing-parent",
		Kind:           domain.IssuerIntermediateCA,
		ParentIssuerID: "missing",
		CertificatePEM: "intermediate-cert-pem",
		KeyRef:         "intermediate-key-ref",
	})
	if !errors.Is(err, domain.ErrIssuerNotFound) {
		t.Fatalf("missing parent error = %v, want ErrIssuerNotFound", err)
	}
}

func TestIssuerChainAndTrustAnchors(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	root, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "root-ca",
		Kind:           domain.IssuerRootCA,
		CertificatePEM: "root-cert-pem",
		KeyRef:         "root-key-ref",
		TrustAnchor:    true,
	})
	if err != nil {
		t.Fatalf("CreateIssuer root returned error: %v", err)
	}
	intermediate, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		ParentIssuerID: root.ID,
		CertificatePEM: "intermediate-cert-pem",
		KeyRef:         "intermediate-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer intermediate returned error: %v", err)
	}

	chain, err := service.GetIssuerChain(ctx, intermediate.ID)
	if err != nil {
		t.Fatalf("GetIssuerChain returned error: %v", err)
	}
	if len(chain) != 2 || chain[0].ID != intermediate.ID || chain[1].ID != root.ID {
		t.Fatalf("issuer chain = %#v", chain)
	}

	anchors, err := service.ListTrustAnchors(ctx)
	if err != nil {
		t.Fatalf("ListTrustAnchors returned error: %v", err)
	}
	if len(anchors) != 1 || anchors[0].ID != root.ID {
		t.Fatalf("trust anchors = %#v", anchors)
	}
}

func TestCreateCertificateProfile(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		Description:           "Machine TLS server profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		SubjectTemplate:       "CN={{identity.name}}",
		AllowedDNSPatterns:    []string{"*.example.test"},
		KeyUsage: domain.StringListExtensionPolicy{
			Critical: true,
			Values:   []string{"digital_signature", "key_encipherment"},
		},
		ExtendedKeyUsage: domain.StringListExtensionPolicy{
			Critical: false,
			Values:   []string{"server_auth"},
		},
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical: true,
			CA:       false,
		},
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	if profile.Name != "machine-server" {
		t.Fatalf("profile name = %q, want machine-server", profile.Name)
	}
	if profile.IssuerID != issuer.ID {
		t.Fatalf("profile issuer ID = %q, want %q", profile.IssuerID, issuer.ID)
	}
	if !profile.KeyUsage.Critical || !reflect.DeepEqual(profile.KeyUsage.Values, []string{"digital_signature", "key_encipherment"}) {
		t.Fatalf("profile key usage = %#v", profile.KeyUsage)
	}

	got, err := service.GetCertificateProfile(ctx, profile.ID)
	if err != nil {
		t.Fatalf("GetCertificateProfile returned error: %v", err)
	}
	if got.ID != profile.ID {
		t.Fatalf("got profile ID = %q, want %q", got.ID, profile.ID)
	}

	profiles, err := service.ListCertificateProfiles(ctx)
	if err != nil {
		t.Fatalf("ListCertificateProfiles returned error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profile count = %d, want 1", len(profiles))
	}
}

func TestCreateCertificateProfileRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})

	_, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              "missing-issuer",
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
	})
	if !errors.Is(err, domain.ErrIssuerNotFound) {
		t.Fatalf("missing issuer error = %v, want ErrIssuerNotFound", err)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("invalid profile error = %v, want ErrInvalidRequest", err)
	}

	negativePathLen := -1
	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-ca-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA:         true,
			MaxPathLen: &negativePathLen,
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("negative max path len error = %v, want ErrInvalidRequest", err)
	}

	zeroPathLen := 0
	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-leaf-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA:         false,
			MaxPathLen: &zeroPathLen,
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("leaf max path len error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-leaf-key-usage",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA: false,
		},
		KeyUsage: domain.StringListExtensionPolicy{
			Values: []string{"digital_signature", "key_cert_sign"},
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("leaf keyCertSign error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-ca-eku",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA: true,
		},
		ExtendedKeyUsage: domain.StringListExtensionPolicy{
			Values: []string{"server_auth"},
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CA serverAuth error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateCertificateProfileEnforcesPublicTLSValidityCeiling(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		now        time.Time
		validity   time.Duration
		wantReject bool
	}{
		{name: "200 day era allows 200 days", now: time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC), validity: 200 * 24 * time.Hour},
		{name: "100 day era rejects 101 days", now: time.Date(2027, time.March, 15, 0, 0, 0, 0, time.UTC), validity: 101 * 24 * time.Hour, wantReject: true},
		{name: "47 day era rejects 48 days", now: time.Date(2029, time.March, 15, 0, 0, 0, 0, time.UTC), validity: 48 * 24 * time.Hour, wantReject: true},
		{name: "private profile may exceed public ceiling", now: time.Date(2029, time.March, 15, 0, 0, 0, 0, time.UTC), validity: 90 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: tt.now}, &fakeIDGenerator{})
			issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
				Name:           "intermediate-ca",
				Kind:           domain.IssuerIntermediateCA,
				CertificatePEM: "issuer-cert-pem",
				KeyRef:         "issuer-key-ref",
			})
			if err != nil {
				t.Fatalf("CreateIssuer returned error: %v", err)
			}

			_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
				Name:                  "server",
				IssuerID:              issuer.ID,
				ValidityPeriodSeconds: int64(tt.validity.Seconds()),
				PublicTLS:             tt.name != "private profile may exceed public ceiling",
			})
			if tt.wantReject {
				if !errors.Is(err, domain.ErrInvalidRequest) {
					t.Fatalf("CreateCertificateProfile error = %v, want ErrInvalidRequest", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateCertificateProfile returned error: %v", err)
			}
		})
	}
}

func TestCreateCertificateProfileUsesConfiguredPublicTLSValidityCeiling(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC)
	service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	if err := service.SetPublicTLSMaxValidity(30 * 24 * time.Hour); err != nil {
		t.Fatalf("SetPublicTLSMaxValidity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((31 * 24 * time.Hour).Seconds()),
		PublicTLS:             true,
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateCertificateProfile error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateEnrollmentRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*CreateEnrollmentRequest)
	}{
		{name: "empty identity", mutate: func(req *CreateEnrollmentRequest) { req.IdentityID = "" }},
		{name: "empty issuer", mutate: func(req *CreateEnrollmentRequest) { req.IssuerID = "" }},
		{name: "empty csr", mutate: func(req *CreateEnrollmentRequest) { req.CSRPEM = "" }},
		{name: "empty subject", mutate: func(req *CreateEnrollmentRequest) { req.RequestedSubject = "" }},
		{name: "not after is not future", mutate: func(req *CreateEnrollmentRequest) { req.RequestedNotAfter = now }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
			identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
				Type: domain.IdentityMachine,
				Name: "edge-01",
			})
			if err != nil {
				t.Fatalf("CreateIdentity returned error: %v", err)
			}
			issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
				Name:           "intermediate-ca",
				Kind:           domain.IssuerIntermediateCA,
				CertificatePEM: "issuer-cert-pem",
				KeyRef:         "issuer-key-ref",
			})
			if err != nil {
				t.Fatalf("CreateIssuer returned error: %v", err)
			}

			req := CreateEnrollmentRequest{
				IdentityID:        identity.ID,
				IssuerID:          issuer.ID,
				CSRPEM:            "csr-pem",
				RequestedSubject:  "CN=edge-01",
				RequestedNotAfter: now.Add(time.Hour),
			}
			tt.mutate(&req)

			_, err = service.CreateEnrollment(ctx, "operator", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestPolicyValidationEvidenceRefsAreDeterministicAndRedacted(t *testing.T) {
	now := time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)
	reqA := CreateEnrollmentRequest{
		IdentityID:           "identity-1",
		IssuerID:             "issuer-1",
		CertificateProfileID: "profile-1",
		CSRPEM:               "sensitive-csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"b.example.test", "a.example.test"},
		RequestedIPAddresses: []string{"192.0.2.20", "192.0.2.10"},
		RequestedNotAfter:    now,
	}
	reqB := reqA
	reqB.RequestedDNSNames = []string{"a.example.test", "b.example.test"}
	reqB.RequestedIPAddresses = []string{"192.0.2.10", "192.0.2.20"}
	profileA := domain.CertificateProfile{
		ID:                         "profile-1",
		ValidityPeriodSeconds:      86400,
		AllowedDNSPatterns:         []string{"*.b.example.test", "*.a.example.test"},
		AllowedIPRanges:            []string{"192.0.2.0/25", "192.0.2.128/25"},
		AllowedKeyAlgorithms:       []string{"rsa", "ecdsa"},
		AllowedSignatureAlgorithms: []string{"rsa_with_sha256", "ecdsa_with_sha256"},
	}
	profileB := profileA
	profileB.AllowedDNSPatterns = []string{"*.a.example.test", "*.b.example.test"}
	profileB.AllowedIPRanges = []string{"192.0.2.128/25", "192.0.2.0/25"}
	profileB.AllowedKeyAlgorithms = []string{"ecdsa", "rsa"}
	profileB.AllowedSignatureAlgorithms = []string{"ecdsa_with_sha256", "rsa_with_sha256"}
	identityA := domain.Identity{
		ID:                 "identity-1",
		AllowedDNSNames:    []string{"b.example.test", "a.example.test"},
		AllowedIPAddresses: []string{"192.0.2.20", "192.0.2.10"},
	}
	identityB := identityA
	identityB.AllowedDNSNames = []string{"a.example.test", "b.example.test"}
	identityB.AllowedIPAddresses = []string{"192.0.2.10", "192.0.2.20"}

	refsA := policyValidationEvidenceRefs(reqA, profileA, identityA)
	refsB := policyValidationEvidenceRefs(reqB, profileB, identityB)
	if !reflect.DeepEqual(refsA, refsB) {
		t.Fatalf("policy evidence refs differ after list reordering:\nA=%#v\nB=%#v", refsA, refsB)
	}
	encoded, err := json.Marshal(refsA)
	if err != nil {
		t.Fatalf("marshal policy evidence refs: %v", err)
	}
	for _, raw := range []string{"sensitive-csr-pem", "a.example.test", "192.0.2.10"} {
		if strings.Contains(string(encoded), raw) {
			t.Fatalf("policy evidence refs expose %q: %s", raw, encoded)
		}
	}
}

func TestCreateEnrollmentStoresCSRSANs(t *testing.T) {
	ctx := context.Background()
	coreClient := &fakeIssuer{
		csrInfo: corecli.CSRInfo{
			Subject:     "CN=edge-01",
			DNSNames:    []string{"edge-01.example.test", "edge-01.internal.test"},
			IPAddresses: []string{"127.0.0.1"},
		},
	}
	service := New(
		store.NewMemoryStore(),
		coreClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.internal.test", "edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}

	if !reflect.DeepEqual(enrollment.CSRDNSNames, coreClient.csrInfo.DNSNames) {
		t.Fatalf("CSRDNSNames = %#v, want %#v", enrollment.CSRDNSNames, coreClient.csrInfo.DNSNames)
	}
	if !reflect.DeepEqual(enrollment.CSRIPAddresses, coreClient.csrInfo.IPAddresses) {
		t.Fatalf("CSRIPAddresses = %#v, want %#v", enrollment.CSRIPAddresses, coreClient.csrInfo.IPAddresses)
	}
}

func TestCreateEnrollmentRejectsSANMismatch(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"csr.example.test"},
				IPAddresses: []string{"127.0.0.1"},
			},
		},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"request.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateEnrollmentEnforcesIdentitySANPolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name    string
		csrInfo corecli.CSRInfo
		mutate  func(*CreateEnrollmentRequest)
	}{
		{
			name: "dns outside identity allow list",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=payments-api",
				DNSNames:    []string{"other.prod.svc.cluster.local"},
				IPAddresses: []string{"192.0.2.42"},
			},
			mutate: func(req *CreateEnrollmentRequest) {
				req.RequestedDNSNames = []string{"other.prod.svc.cluster.local"}
			},
		},
		{
			name: "ip outside identity allow list",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=payments-api",
				DNSNames:    []string{"payments.prod.svc.cluster.local"},
				IPAddresses: []string{"192.0.2.99"},
			},
			mutate: func(req *CreateEnrollmentRequest) {
				req.RequestedIPAddresses = []string{"192.0.2.99"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{csrInfo: tt.csrInfo},
				fixedClock{now: now},
				&fakeIDGenerator{},
			)
			identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
				Type:               domain.IdentityWorkload,
				Name:               "payments-api",
				ExternalID:         "k8s:prod:payments:payments-api",
				Owner:              "platform",
				AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
				AllowedIPAddresses: []string{"192.0.2.42"},
			})
			if err != nil {
				t.Fatalf("CreateIdentity returned error: %v", err)
			}
			issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
				Name:           "intermediate-ca",
				Kind:           domain.IssuerIntermediateCA,
				CertificatePEM: "issuer-cert-pem",
				KeyRef:         "issuer-key-ref",
			})
			if err != nil {
				t.Fatalf("CreateIssuer returned error: %v", err)
			}
			req := CreateEnrollmentRequest{
				IdentityID:           identity.ID,
				IssuerID:             issuer.ID,
				CSRPEM:               "csr-pem",
				RequestedSubject:     "CN=payments-api",
				RequestedDNSNames:    []string{"payments.prod.svc.cluster.local"},
				RequestedIPAddresses: []string{"192.0.2.42"},
				RequestedNotAfter:    now.Add(24 * time.Hour),
			}
			tt.mutate(&req)

			_, err = service.CreateEnrollment(ctx, "operator", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateEnrollmentEnforcesCertificateProfilePolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	for _, tt := range []struct {
		name    string
		csrInfo corecli.CSRInfo
		mutate  func(*CreateEnrollmentRequest)
	}{
		{
			name: "dns outside allowed pattern",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"edge-01.other.test"},
				IPAddresses: []string{"192.0.2.10"},
			},
			mutate: func(req *CreateEnrollmentRequest) {
				req.RequestedDNSNames = []string{"edge-01.other.test"}
			},
		},
		{
			name: "ip outside allowed range",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"edge-01.example.test"},
				IPAddresses: []string{"10.0.0.10"},
			},
			mutate: func(req *CreateEnrollmentRequest) {
				req.RequestedIPAddresses = []string{"10.0.0.10"}
			},
		},
		{
			name: "not after exceeds profile validity",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"edge-01.example.test"},
				IPAddresses: []string{"192.0.2.10"},
			},
			mutate: func(req *CreateEnrollmentRequest) {
				req.RequestedNotAfter = now.Add(25 * time.Hour)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{
					csrInfo: tt.csrInfo,
				},
				fixedClock{now: now},
				&fakeIDGenerator{},
			)
			identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
			req := CreateEnrollmentRequest{
				IdentityID:           identity.ID,
				IssuerID:             issuer.ID,
				CertificateProfileID: profile.ID,
				CSRPEM:               "csr-pem",
				RequestedSubject:     "CN=edge-01",
				RequestedDNSNames:    []string{"edge-01.example.test"},
				RequestedIPAddresses: []string{"192.0.2.10"},
				RequestedNotAfter:    now.Add(24 * time.Hour),
			}
			tt.mutate(&req)

			_, err := service.CreateEnrollment(ctx, "operator", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateEnrollmentRejectsCSRPolicyViolations(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	oversizedDNS := make([]string, 101)
	for i := range oversizedDNS {
		oversizedDNS[i] = fmt.Sprintf("host-%03d.example.test", i)
	}

	for _, tt := range []struct {
		name          string
		csrInfo       corecli.CSRInfo
		mutateRequest func(*CreateEnrollmentRequest)
		mutateProfile func(*CreateCertificateProfileRequest)
	}{
		{
			name:    "missing san",
			csrInfo: corecli.CSRInfo{Subject: "CN=edge-01"},
			mutateRequest: func(req *CreateEnrollmentRequest) {
				req.RequestedDNSNames = nil
				req.RequestedIPAddresses = nil
			},
		},
		{
			name: "forbidden extension",
			csrInfo: corecli.CSRInfo{
				Subject:       "CN=edge-01",
				DNSNames:      []string{"edge-01.example.test"},
				IPAddresses:   []string{"192.0.2.10"},
				ExtensionOIDs: []string{"2.5.29.15"},
			},
		},
		{
			name: "wildcard without wildcard profile",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"*.example.test"},
				IPAddresses: []string{"192.0.2.10"},
			},
			mutateRequest: func(req *CreateEnrollmentRequest) {
				req.RequestedDNSNames = []string{"*.example.test"}
			},
			mutateProfile: func(profileReq *CreateCertificateProfileRequest) {
				profileReq.AllowedDNSPatterns = nil
			},
		},
		{
			name: "ip san without profile range",
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"edge-01.example.test"},
				IPAddresses: []string{"192.0.2.10"},
			},
			mutateProfile: func(profileReq *CreateCertificateProfileRequest) {
				profileReq.PublicTLS = true
				profileReq.AllowedIPRanges = nil
			},
		},
		{
			name: "oversized san list",
			csrInfo: corecli.CSRInfo{
				Subject:  "CN=edge-01",
				DNSNames: oversizedDNS,
			},
			mutateRequest: func(req *CreateEnrollmentRequest) {
				req.RequestedDNSNames = oversizedDNS
				req.RequestedIPAddresses = nil
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := New(store.NewMemoryStore(), &fakeIssuer{csrInfo: tt.csrInfo}, fixedClock{now: now}, &fakeIDGenerator{})
			identity, issuer, profile := createProfilePolicyFixtureWithProfileMutation(t, ctx, service, tt.mutateProfile)
			req := CreateEnrollmentRequest{
				IdentityID:           identity.ID,
				IssuerID:             issuer.ID,
				CertificateProfileID: profile.ID,
				CSRPEM:               "csr-pem",
				RequestedSubject:     "CN=edge-01",
				RequestedDNSNames:    []string{"edge-01.example.test"},
				RequestedIPAddresses: []string{"192.0.2.10"},
				RequestedNotAfter:    now.Add(24 * time.Hour),
			}
			if tt.mutateRequest != nil {
				tt.mutateRequest(&req)
			}

			_, err := service.CreateEnrollment(ctx, "operator", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestIssueCertificateEnforcesProfilePolicyBeforeSigning(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(repo, issuerClient, fixedClock{now: now}, &fakeIDGenerator{})
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	enrollment := domain.Enrollment{
		ID:                   "enrollment-1",
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		Status:               domain.EnrollmentApproved,
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.other.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ApprovedBy:           "approver",
		ApprovedAt:           now,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("CreateEnrollment fixture returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidRequest", err)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("Issue call count = %d, want 0", len(issuerClient.requests))
	}
}

func TestIssueCertificateRequiresPublicTLSLintHookBeforeSigning(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.March, 15, 1, 2, 3, 0, time.UTC)
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:            "CN=edge-01",
		DNSNames:           []string{"edge-01.example.test"},
		PublicKeyAlgorithm: "rsa",
		PublicKeySizeBits:  2048,
		SignatureAlgorithm: "sha256",
	}}
	service := New(repo, issuerClient, fixedClock{now: now}, &fakeIDGenerator{})
	identity, issuer, profile := createProfilePolicyFixtureWithProfileMutation(t, ctx, service, func(req *CreateCertificateProfileRequest) {
		req.PublicTLS = true
		req.AllowedIPRanges = nil
	})
	enrollment := domain.Enrollment{
		ID:                   "enrollment-1",
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		Status:               domain.EnrollmentApproved,
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ApprovedBy:           "approver",
		ApprovedAt:           now,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("CreateEnrollment fixture returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("IssueCertificate without lint hook error = %v, want ErrInvalidRequest", err)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("Issue call count without lint hook = %d, want 0", len(issuerClient.requests))
	}

	lintErr := errors.New("lint failed")
	if err := service.SetPublicTLSLintHook(&fakePublicTLSLintHook{err: lintErr}); err != nil {
		t.Fatalf("SetPublicTLSLintHook returned error: %v", err)
	}
	_, err = service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, lintErr) {
		t.Fatalf("IssueCertificate lint error = %v, want %v", err, lintErr)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("Issue call count after lint failure = %d, want 0", len(issuerClient.requests))
	}

	hook := &fakePublicTLSLintHook{}
	if err := service.SetPublicTLSLintHook(hook); err != nil {
		t.Fatalf("SetPublicTLSLintHook success returned error: %v", err)
	}
	if _, err := service.IssueCertificate(ctx, "issuer", enrollment.ID); err != nil {
		t.Fatalf("IssueCertificate with lint hook returned error: %v", err)
	}
	if hook.request.Profile.ID != profile.ID || hook.request.Enrollment.ID != enrollment.ID || hook.request.CSRInfo.Subject != "CN=edge-01" {
		t.Fatalf("lint request = %#v", hook.request)
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("Issue call count after lint success = %d, want 1", len(issuerClient.requests))
	}
}

func TestCreateEnrollmentEnforcesProfileAlgorithmPolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	for _, tt := range []struct {
		name    string
		csrInfo corecli.CSRInfo
		mutate  func(*CreateCertificateProfileRequest)
	}{
		{
			name: "key algorithm outside profile allow list",
			csrInfo: corecli.CSRInfo{
				Subject:            "CN=edge-01",
				DNSNames:           []string{"edge-01.example.test"},
				IPAddresses:        []string{"192.0.2.10"},
				PublicKeyAlgorithm: "rsa",
				PublicKeySizeBits:  2048,
				SignatureAlgorithm: "sha256",
			},
			mutate: func(req *CreateCertificateProfileRequest) {
				req.AllowedKeyAlgorithms = []string{"ecdsa"}
			},
		},
		{
			name: "key size below profile floor",
			csrInfo: corecli.CSRInfo{
				Subject:            "CN=edge-01",
				DNSNames:           []string{"edge-01.example.test"},
				IPAddresses:        []string{"192.0.2.10"},
				PublicKeyAlgorithm: "rsa",
				PublicKeySizeBits:  1024,
				SignatureAlgorithm: "sha256",
			},
			mutate: func(req *CreateCertificateProfileRequest) {
				req.MinKeySizeBits = 2048
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{csrInfo: tt.csrInfo},
				fixedClock{now: now},
				&fakeIDGenerator{},
			)
			identity, issuer, profile := createProfilePolicyFixtureWithProfileMutation(t, ctx, service, tt.mutate)
			_, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
				IdentityID:           identity.ID,
				IssuerID:             issuer.ID,
				CertificateProfileID: profile.ID,
				CSRPEM:               "csr-pem",
				RequestedSubject:     "CN=edge-01",
				RequestedDNSNames:    []string{"edge-01.example.test"},
				RequestedIPAddresses: []string{"192.0.2.10"},
				RequestedNotAfter:    now.Add(24 * time.Hour),
			})
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateCertificateProfileRejectsUnsupportedAlgorithmPolicy(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	for _, tt := range []struct {
		name   string
		mutate func(*CreateCertificateProfileRequest)
	}{
		{name: "unsupported key algorithm", mutate: func(req *CreateCertificateProfileRequest) {
			req.AllowedKeyAlgorithms = []string{"md5_rsa"}
		}},
		{name: "unsupported signature algorithm", mutate: func(req *CreateCertificateProfileRequest) {
			req.AllowedSignatureAlgorithms = []string{"md5"}
		}},
		{name: "negative min key size", mutate: func(req *CreateCertificateProfileRequest) {
			req.MinKeySizeBits = -1
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := CreateCertificateProfileRequest{
				Name:                  "machine-server",
				IssuerID:              issuer.ID,
				ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
			}
			tt.mutate(&req)
			_, err := service.CreateCertificateProfile(ctx, "admin", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateCertificateProfile error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestIssueCertificateEnforcesIdentitySANPolicyBeforeSigning(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(repo, issuerClient, fixedClock{now: now}, &fakeIDGenerator{})
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:               domain.IdentityWorkload,
		Name:               "payments-api",
		AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
		AllowedIPAddresses: []string{"192.0.2.42"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	enrollment := domain.Enrollment{
		ID:                   "enrollment-1",
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		Status:               domain.EnrollmentApproved,
		RequestedSubject:     "CN=payments-api",
		RequestedDNSNames:    []string{"other.prod.svc.cluster.local"},
		RequestedIPAddresses: []string{"192.0.2.42"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ApprovedBy:           "approver",
		ApprovedAt:           now,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("CreateEnrollment fixture returned error: %v", err)
	}

	_, err = service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidRequest", err)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("Issue call count = %d, want 0", len(issuerClient.requests))
	}
}

func TestIssueCertificateMapsCSRParseFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{
		err: &corecli.CommandError{
			Code:    "issue.csr_parse_failed",
			Message: "bad csr",
			Err:     errors.New("exit status 1"),
		},
	}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrCSRParseFailed) {
		t.Fatalf("IssueCertificate error = %v, want ErrCSRParseFailed", err)
	}
	if errors.Is(err, domain.ErrCertificateIssuanceFailed) {
		t.Fatalf("IssueCertificate error = %v, did not want ErrCertificateIssuanceFailed", err)
	}
}

func TestIssueCertificateRejectsReadinessWithoutCoreSigningEvidence(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	missingEvidence := corecli.SigningEvidence{}
	issuerClient := &fakeIssuer{issueSigningEvidence: &missingEvidence}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrCertificateIssuanceFailed) {
		t.Fatalf("IssueCertificate error = %v, want ErrCertificateIssuanceFailed", err)
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	if certificates, listErr := repo.ListCertificates(ctx); listErr != nil || len(certificates) != 0 {
		t.Fatalf("certificates after missing evidence = %#v, err=%v", certificates, listErr)
	}
}

func TestIssueCertificateChecksKeyProviderBeforeSigning(t *testing.T) {
	ctx := context.Background()
	coreClient := &fakeIssuer{}
	service := New(
		store.NewMemoryStore(),
		coreClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	provider := &fakeKeyProvider{err: domain.ErrInvalidRequest}
	if err := service.SetKeyProvider(provider); err != nil {
		t.Fatalf("SetKeyProvider returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidRequest", err)
	}
	if len(provider.refs) != 1 || provider.refs[0] != "issuer-key-ref" {
		t.Fatalf("provider refs = %#v, want issuer-key-ref", provider.refs)
	}
	if len(coreClient.requests) != 0 {
		t.Fatalf("issuer request count = %d, want 0", len(coreClient.requests))
	}
}

func TestIssueCertificateDoesNotCreateCertificateAfterStaleTransition(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	staleRepo := &staleTransitionRepository{Repository: repo}
	service := New(
		staleRepo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	staleRepo.failConditionalUpdate = true

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidTransition", err)
	}
	if staleRepo.createCertificateCalled {
		t.Fatal("CreateCertificate called after stale enrollment transition")
	}
}

func TestRevokeCertificateRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	tests := []struct {
		name          string
		certificateID string
		reason        domain.RevocationReason
	}{
		{name: "empty certificate", certificateID: "", reason: domain.RevocationSuperseded},
		{name: "invalid reason", certificateID: "certificate-1", reason: domain.RevocationReason("bad")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.RevokeCertificate(ctx, "operator", tt.certificateID, tt.reason)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("RevokeCertificate error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestSuspendResumeAndForceRevokeCertificate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	suspended, err := service.SuspendCertificate(ctx, "operator", certificate.ID)
	if err != nil {
		t.Fatalf("SuspendCertificate returned error: %v", err)
	}
	if suspended.Status != domain.CertificateSuspended {
		t.Fatalf("suspended certificate status = %q, want %q", suspended.Status, domain.CertificateSuspended)
	}

	resumed, err := service.ResumeCertificate(ctx, "operator", certificate.ID)
	if err != nil {
		t.Fatalf("ResumeCertificate returned error: %v", err)
	}
	if resumed.Status != domain.CertificateValid {
		t.Fatalf("resumed certificate status = %q, want %q", resumed.Status, domain.CertificateValid)
	}

	suspended, err = service.SuspendCertificate(ctx, "operator", certificate.ID)
	if err != nil {
		t.Fatalf("second SuspendCertificate returned error: %v", err)
	}
	revoked, err := service.ForceRevokeCertificate(ctx, "operator", suspended.ID, domain.RevocationSuperseded)
	if err != nil {
		t.Fatalf("ForceRevokeCertificate returned error: %v", err)
	}
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("force revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	wantTail := []string{"certificate.suspended", "certificate.resumed", "certificate.suspended", "certificate.force_revoked"}
	if len(events) < len(wantTail) {
		t.Fatalf("audit event count = %d", len(events))
	}
	for i, want := range wantTail {
		event := events[len(events)-len(wantTail)+i]
		got := event.Action
		if got != want {
			t.Fatalf("audit event tail %d action = %q, want %q", i, got, want)
		}
		metadata := map[string]any{}
		if err := json.Unmarshal([]byte(event.MetadataJSON), &metadata); err != nil {
			t.Fatalf("unmarshal audit metadata: %v", err)
		}
		previousStatus, previousOK := metadata["previous_status"].(string)
		newStatus, newOK := metadata["new_status"].(string)
		if !previousOK || previousStatus == "" || !newOK || newStatus == "" {
			t.Fatalf("transition audit metadata missing state fields for %s: %#v", event.Action, metadata)
		}
	}
}

func TestSuspendResumeRejectInvalidTransitions(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if _, err := service.ResumeCertificate(ctx, "operator", certificate.ID); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("ResumeCertificate valid error = %v, want ErrInvalidTransition", err)
	}
	if _, err := service.SuspendCertificate(ctx, "operator", certificate.ID); err != nil {
		t.Fatalf("SuspendCertificate returned error: %v", err)
	}
	if _, err := service.SuspendCertificate(ctx, "operator", certificate.ID); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("SuspendCertificate suspended error = %v, want ErrInvalidTransition", err)
	}
}

func TestRevokeCertificateDoesNotCreateRevocationAfterStaleTransition(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	staleRepo := &staleRevocationRepository{Repository: repo}
	service := New(
		staleRepo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	staleRepo.failConditionalUpdate = true

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RevokeCertificate error = %v, want ErrInvalidTransition", err)
	}
	if staleRepo.createRevocationCalled {
		t.Fatal("CreateRevocation called after stale certificate transition")
	}
}

func TestOnlyValidCertificateCanBeRevoked(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if _, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("first RevokeCertificate returned error: %v", err)
	}

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("second RevokeCertificate error = %v, want ErrInvalidTransition", err)
	}
}

func TestRenewCertificateCreatesPendingEnrollmentFromCertificate(t *testing.T) {
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
	requestedNotAfter := clock.now.Add(90 * 24 * time.Hour)

	renewal, err := service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: requestedNotAfter,
	})
	if err != nil {
		t.Fatalf("RenewCertificate returned error: %v", err)
	}
	if renewal.Status != domain.EnrollmentPending {
		t.Fatalf("renewal status = %q, want %q", renewal.Status, domain.EnrollmentPending)
	}
	if renewal.IdentityID != certificate.IdentityID ||
		renewal.IssuerID != certificate.IssuerID ||
		renewal.CertificateProfileID != certificate.CertificateProfileID ||
		renewal.RequestedSubject != certificate.Subject ||
		renewal.CSRPEM != "renewal-csr-pem" ||
		!renewal.RequestedNotAfter.Equal(requestedNotAfter) {
		t.Fatalf("renewal enrollment = %#v, certificate = %#v", renewal, certificate)
	}
	if !reflect.DeepEqual(renewal.RequestedDNSNames, certificate.DNSNames) ||
		!reflect.DeepEqual(renewal.RequestedIPAddresses, certificate.IPAddresses) ||
		!reflect.DeepEqual(renewal.CSRDNSNames, certificate.DNSNames) ||
		!reflect.DeepEqual(renewal.CSRIPAddresses, certificate.IPAddresses) {
		t.Fatalf("renewal SAN fields = %#v", renewal)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "certificate.renewal_requested" {
		t.Fatalf("last audit action = %q, want certificate.renewal_requested", last.Action)
	}
	metadata := auditMetadata(t, last)
	if metadata["certificate_id"] != certificate.ID ||
		metadata["enrollment_id"] != renewal.ID ||
		metadata["previous_serial_number"] != certificate.SerialNumber {
		t.Fatalf("renewal audit metadata = %#v", metadata)
	}
}

func TestIssueReplacementCertificateAuditsSerialLinkage(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, &sequencedSerialIssuer{fakeIssuer: &fakeIssuer{}}, clock, &fakeIDGenerator{})

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	renewal, err := service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: clock.now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("RenewCertificate returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", renewal.ID); err != nil {
		t.Fatalf("ApproveEnrollment renewal returned error: %v", err)
	}
	successor, err := service.IssueCertificate(ctx, "issuer", renewal.ID)
	if err != nil {
		t.Fatalf("IssueCertificate renewal returned error: %v", err)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	event := findAuditEventForResource(t, events, "certificate.issued", successor.ID)
	metadata := auditMetadata(t, event)
	if metadata["source_certificate_id"] != certificate.ID ||
		metadata["previous_serial_number"] != certificate.SerialNumber ||
		metadata["successor_serial_number"] != successor.SerialNumber {
		t.Fatalf("successor audit metadata = %#v", metadata)
	}
}

func TestRenewCertificateEnforcesIdentitySANPolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{csrInfo: corecli.CSRInfo{
			Subject:     "CN=payments-api",
			DNSNames:    []string{"other.prod.svc.cluster.local"},
			IPAddresses: []string{"192.0.2.42"},
		}},
		fixedClock{now: now},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:               domain.IdentityWorkload,
		Name:               "payments-api",
		AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
		AllowedIPAddresses: []string{"192.0.2.42"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	certificate := domain.Certificate{
		ID:             "certificate-1",
		IdentityID:     identity.ID,
		IssuerID:       issuer.ID,
		EnrollmentID:   "enrollment-1",
		SerialNumber:   "123",
		Subject:        "CN=payments-api",
		DNSNames:       []string{"other.prod.svc.cluster.local"},
		IPAddresses:    []string{"192.0.2.42"},
		NotBefore:      now,
		NotAfter:       now.Add(24 * time.Hour),
		Status:         domain.CertificateValid,
		CertificatePEM: "cert-pem",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateCertificate(ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate fixture returned error: %v", err)
	}

	_, err = service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: now.Add(48 * time.Hour),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("RenewCertificate error = %v, want ErrInvalidRequest", err)
	}
}

func TestRenewCertificateEnforcesProfileValidity(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"edge-01.example.test"},
				IPAddresses: []string{"192.0.2.10"},
			},
		},
		fixedClock{now: now},
		&fakeIDGenerator{},
	)
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	_, err = service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: now.Add(25 * time.Hour),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("RenewCertificate error = %v, want ErrInvalidRequest", err)
	}
}

func TestOnlyValidCertificateCanBeRenewed(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if _, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}

	_, err = service.RenewCertificate(ctx, "operator", certificate.ID, RenewCertificateRequest{
		CSRPEM:            "renewal-csr-pem",
		RequestedNotAfter: time.Date(2026, time.April, 2, 3, 4, 5, 0, time.UTC),
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RenewCertificate revoked error = %v, want ErrInvalidTransition", err)
	}
}

func TestScanCertificateExpirationsExpiresAndWarnsOnce(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, &fakeIssuer{}, clock, &fakeIDGenerator{})

	certificates := []domain.Certificate{
		expirationLifecycleCertificate("expired-valid", domain.CertificateValid, clock.now.Add(-time.Hour), time.Time{}),
		expirationLifecycleCertificate("expired-suspended", domain.CertificateSuspended, clock.now.Add(-2*time.Hour), time.Time{}),
		expirationLifecycleCertificate("warning-valid", domain.CertificateValid, clock.now.Add(2*time.Hour), time.Time{}),
		expirationLifecycleCertificate("warning-notified", domain.CertificateValid, clock.now.Add(3*time.Hour), clock.now.Add(-time.Hour)),
		expirationLifecycleCertificate("outside-valid", domain.CertificateValid, clock.now.Add(72*time.Hour), time.Time{}),
		expirationLifecycleCertificate("expired-revoked", domain.CertificateRevoked, clock.now.Add(-time.Hour), time.Time{}),
	}
	for _, certificate := range certificates {
		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	result, err := service.ScanCertificateExpirations(ctx, "scanner", ScanCertificateExpirationsRequest{
		WarningWindow: 24 * time.Hour,
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("ScanCertificateExpirations returned error: %v", err)
	}
	if len(result.Expired) != 2 || result.Expired[0].ID != "expired-suspended" || result.Expired[1].ID != "expired-valid" {
		t.Fatalf("expired result = %#v", result.Expired)
	}
	if len(result.ExpirationWarnings) != 1 || result.ExpirationWarnings[0].ID != "warning-valid" {
		t.Fatalf("warning result = %#v", result.ExpirationWarnings)
	}

	for _, id := range []string{"expired-valid", "expired-suspended"} {
		stored, err := repo.GetCertificate(ctx, id)
		if err != nil {
			t.Fatalf("GetCertificate(%s) returned error: %v", id, err)
		}
		if stored.Status != domain.CertificateExpired {
			t.Fatalf("%s status = %q, want expired", id, stored.Status)
		}
	}
	warning, err := repo.GetCertificate(ctx, "warning-valid")
	if err != nil {
		t.Fatalf("GetCertificate warning-valid returned error: %v", err)
	}
	if warning.Status != domain.CertificateValid || !warning.RenewalNotifiedAt.Equal(clock.now) {
		t.Fatalf("warning-valid after scan = %#v", warning)
	}
	alreadyNotified, err := repo.GetCertificate(ctx, "warning-notified")
	if err != nil {
		t.Fatalf("GetCertificate warning-notified returned error: %v", err)
	}
	if !alreadyNotified.RenewalNotifiedAt.Equal(clock.now.Add(-time.Hour)) {
		t.Fatalf("warning-notified RenewalNotifiedAt = %s", alreadyNotified.RenewalNotifiedAt)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	wantActions := []string{"certificate.expired", "certificate.expired", "certificate.expiration_warning"}
	if len(events) != len(wantActions) {
		t.Fatalf("audit event count = %d, want %d: %#v", len(events), len(wantActions), events)
	}
	for i, want := range wantActions {
		if events[i].Action != want {
			t.Fatalf("audit event %d action = %q, want %q", i, events[i].Action, want)
		}
		metadata := auditMetadata(t, events[i])
		if metadata["certificate_id"] == "" || metadata["serial_number"] == "" || metadata["not_after"] == "" {
			t.Fatalf("audit event %d metadata = %#v", i, metadata)
		}
	}

	messages, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(messages) != len(wantActions) {
		t.Fatalf("outbox message count = %d, want %d: %#v", len(messages), len(wantActions), messages)
	}
	for i, want := range wantActions {
		if messages[i].Type != want {
			t.Fatalf("outbox message %d type = %q, want %q", i, messages[i].Type, want)
		}
	}

	second, err := service.ScanCertificateExpirations(ctx, "scanner", ScanCertificateExpirationsRequest{
		WarningWindow: 24 * time.Hour,
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("second ScanCertificateExpirations returned error: %v", err)
	}
	if len(second.Expired) != 0 || len(second.ExpirationWarnings) != 0 {
		t.Fatalf("second scan result = %#v", second)
	}
	messages, err = repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("second ListDueOutboxMessages returned error: %v", err)
	}
	if len(messages) != len(wantActions) {
		t.Fatalf("outbox messages after second scan = %#v", messages)
	}
}

func TestScanCertificateExpirationsRejectsInvalidRequest(t *testing.T) {
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	_, err := service.ScanCertificateExpirations(context.Background(), "scanner", ScanCertificateExpirationsRequest{
		WarningWindow: -time.Second,
		Limit:         10,
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("negative window error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.ScanCertificateExpirations(context.Background(), "scanner", ScanCertificateExpirationsRequest{
		WarningWindow: 24 * time.Hour,
		Limit:         0,
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("zero limit error = %v, want ErrInvalidRequest", err)
	}
}

func TestReissueCertificateCreatesPendingEnrollmentWithOriginalNotAfter(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	reissue, err := service.ReissueCertificate(ctx, "operator", certificate.ID, ReissueCertificateRequest{
		CSRPEM: "reissue-csr-pem",
	})
	if err != nil {
		t.Fatalf("ReissueCertificate returned error: %v", err)
	}
	if reissue.Status != domain.EnrollmentPending {
		t.Fatalf("reissue status = %q, want %q", reissue.Status, domain.EnrollmentPending)
	}
	if reissue.IdentityID != certificate.IdentityID ||
		reissue.IssuerID != certificate.IssuerID ||
		reissue.CertificateProfileID != certificate.CertificateProfileID ||
		reissue.RequestedSubject != certificate.Subject ||
		reissue.CSRPEM != "reissue-csr-pem" ||
		!reissue.RequestedNotAfter.Equal(certificate.NotAfter) {
		t.Fatalf("reissue enrollment = %#v, certificate = %#v", reissue, certificate)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	last := events[len(events)-1]
	if last.Action != "certificate.reissue_requested" {
		t.Fatalf("last audit action = %q, want certificate.reissue_requested", last.Action)
	}
	metadata := auditMetadata(t, last)
	if metadata["certificate_id"] != certificate.ID ||
		metadata["enrollment_id"] != reissue.ID ||
		metadata["previous_serial_number"] != certificate.SerialNumber {
		t.Fatalf("reissue audit metadata = %#v", metadata)
	}
}

func TestACMEOrderLifecycleFinalizesToCertificate(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:     "CN=edge-01",
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []string{"192.0.2.10"},
	}}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	if account.Status != domain.ACMEAccountValid {
		t.Fatalf("account status = %q, want %q", account.Status, domain.ACMEAccountValid)
	}

	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	if order.Status != domain.ACMEOrderPending {
		t.Fatalf("order status = %q, want %q", order.Status, domain.ACMEOrderPending)
	}

	authzs, err := service.ListACMEAuthorizations(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizations returned error: %v", err)
	}
	if len(authzs) != 2 {
		t.Fatalf("authorization count = %d, want 2", len(authzs))
	}
	for _, authz := range authzs {
		challenges, err := service.ListACMEChallenges(ctx, authz.ID)
		if err != nil {
			t.Fatalf("ListACMEChallenges returned error: %v", err)
		}
		if len(challenges) != 1 || challenges[0].Token == "" || challenges[0].Status != domain.ACMEChallengePending {
			t.Fatalf("challenges for %s = %#v", authz.ID, challenges)
		}
		if _, err := service.CompleteACMEChallenge(ctx, "validator", challenges[0].ID); err != nil {
			t.Fatalf("CompleteACMEChallenge returned error: %v", err)
		}
	}

	ready, err := service.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if ready.Status != domain.ACMEOrderReady {
		t.Fatalf("order status after challenges = %q, want %q", ready.Status, domain.ACMEOrderReady)
	}

	finalized, err := service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if err != nil {
		t.Fatalf("FinalizeACMEOrder returned error: %v", err)
	}
	if finalized.Status != domain.ACMEOrderValid || finalized.EnrollmentID == "" || finalized.CertificateID == "" {
		t.Fatalf("finalized order = %#v", finalized)
	}
	certificate, err := service.GetCertificate(ctx, finalized.CertificateID)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if certificate.Status != domain.CertificateValid || certificate.EnrollmentID != finalized.EnrollmentID {
		t.Fatalf("certificate = %#v, finalized order = %#v", certificate, finalized)
	}
	if len(coreClient.requests) != 1 || coreClient.requests[0].CSRPEM != "csr-pem" {
		t.Fatalf("issuer requests = %#v", coreClient.requests)
	}

	second, err := service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if err != nil {
		t.Fatalf("FinalizeACMEOrder retry returned error: %v", err)
	}
	if second.ID != finalized.ID || second.EnrollmentID != finalized.EnrollmentID || second.CertificateID != finalized.CertificateID {
		t.Fatalf("retry order = %#v, want finalized %#v", second, finalized)
	}
	if len(coreClient.requests) != 1 {
		t.Fatalf("issuer request count after retry = %d, want 1", len(coreClient.requests))
	}
}

func TestFinalizeACMEOrderKeepsFinalizedStateWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	baseRepo := store.NewMemoryStore()
	errAudit := errors.New("audit failed")
	repo := &failAuditRepository{Repository: baseRepo, action: "acme.order.finalized", err: errAudit}
	coreClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:     "CN=edge-01",
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []string{"192.0.2.10"},
	}}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	authzs, err := service.ListACMEAuthorizations(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizations returned error: %v", err)
	}
	for _, authz := range authzs {
		challenges, err := service.ListACMEChallenges(ctx, authz.ID)
		if err != nil {
			t.Fatalf("ListACMEChallenges returned error: %v", err)
		}
		if _, err := service.CompleteACMEChallenge(ctx, "validator", challenges[0].ID); err != nil {
			t.Fatalf("CompleteACMEChallenge returned error: %v", err)
		}
	}

	_, err = service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if !errors.Is(err, errAudit) {
		t.Fatalf("FinalizeACMEOrder error = %v, want audit error", err)
	}

	stored, err := baseRepo.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if stored.Status != domain.ACMEOrderValid || stored.EnrollmentID == "" || stored.CertificateID == "" {
		t.Fatalf("stored order = %#v, want finalized order", stored)
	}
	if len(coreClient.requests) != 1 {
		t.Fatalf("issuer request count after failed audit = %d, want 1", len(coreClient.requests))
	}

	retry, err := service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if err != nil {
		t.Fatalf("FinalizeACMEOrder retry returned error: %v", err)
	}
	if retry.ID != stored.ID || retry.EnrollmentID != stored.EnrollmentID || retry.CertificateID != stored.CertificateID {
		t.Fatalf("retry order = %#v, want stored %#v", retry, stored)
	}
	if len(coreClient.requests) != 1 {
		t.Fatalf("issuer request count after retry = %d, want 1", len(coreClient.requests))
	}
}

func TestFinalizeACMEOrderRejectsExpiredPublicTLSValidationEvidence(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:  "CN=edge-01",
		DNSNames: []string{"edge-01.example.test"},
	}}
	now := time.Date(2029, time.March, 15, 1, 2, 3, 0, time.UTC)
	service := New(repo, coreClient, fixedClock{now: now}, &fakeIDGenerator{})
	if err := service.SetPublicTLSCAAPolicy(PublicTLSCAAPolicy{
		IssuerDomain:     "ca.example",
		AccountURI:       "https://ca.example/acct/1",
		ValidationMethod: "http-01",
		Lookup: &fakeCAALookup{result: CAALookupResult{
			Records: []CAARecord{{
				Tag:   "issue",
				Value: "ca.example",
			}},
			DNSSECStatus: CAADNSSECSecure,
		}},
	}); err != nil {
		t.Fatalf("SetPublicTLSCAAPolicy returned error: %v", err)
	}

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	publicProfile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "public-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		PublicTLS:             true,
		AllowedDNSPatterns:    profile.AllowedDNSPatterns,
		AllowedIPRanges:       profile.AllowedIPRanges,
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile public returned error: %v", err)
	}
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: publicProfile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	authzs, err := service.ListACMEAuthorizations(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizations returned error: %v", err)
	}
	challenges, err := service.ListACMEChallenges(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("ListACMEChallenges returned error: %v", err)
	}
	if _, err := service.CompleteACMEChallenge(ctx, "validator", challenges[0].ID); err != nil {
		t.Fatalf("CompleteACMEChallenge returned error: %v", err)
	}
	authz, err := service.GetACMEAuthorization(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("GetACMEAuthorization returned error: %v", err)
	}
	authz.ValidationReuseExpiresAt = now.Add(-time.Minute)
	if err := repo.UpdateACMEAuthorizationIfStatus(ctx, authz, domain.ACMEAuthorizationValid); err != nil {
		t.Fatalf("UpdateACMEAuthorizationIfStatus returned error: %v", err)
	}

	_, err = service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("FinalizeACMEOrder error = %v, want ErrInvalidTransition", err)
	}
	if len(coreClient.requests) != 0 {
		t.Fatalf("issuer request count = %d, want 0", len(coreClient.requests))
	}
}

func TestCreateACMEOrderEnforcesIdentitySANPolicyBeforeAuthorization(t *testing.T) {
	ctx := context.Background()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(store.NewMemoryStore(), &fakeIssuer{}, clock, &fakeIDGenerator{})
	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:               domain.IdentityWorkload,
		Name:               "payments-api",
		AllowedDNSNames:    []string{"payments.prod.svc.cluster.local"},
		AllowedIPAddresses: []string{"192.0.2.42"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		RequestedDNSNames:    []string{"other.prod.svc.cluster.local"},
		RequestedIPAddresses: []string{"192.0.2.42"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateACMEOrder error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateACMEOrderEnforcesPublicTLSCAAPolicy(t *testing.T) {
	ctx := context.Background()
	clock := fixedClock{now: time.Date(2026, time.March, 15, 1, 2, 3, 0, time.UTC)}
	lookup := &fakeCAALookup{
		result: CAALookupResult{
			Records: []CAARecord{{
				Flag:  0,
				Tag:   "issue",
				Value: `ca.example; accounturi=https://ca.example/acct/1; validationmethods=http-01,dns-01`,
			}},
			DNSSECStatus: CAADNSSECSecure,
		},
	}
	service := New(store.NewMemoryStore(), &fakeIssuer{}, clock, &fakeIDGenerator{})
	if err := service.SetPublicTLSCAAPolicy(PublicTLSCAAPolicy{
		IssuerDomain:     "ca.example",
		AccountURI:       "https://ca.example/acct/1",
		ValidationMethod: "http-01",
		Lookup:           lookup,
	}); err != nil {
		t.Fatalf("SetPublicTLSCAAPolicy returned error: %v", err)
	}
	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	publicProfile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "public-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		PublicTLS:             true,
		AllowedDNSPatterns:    profile.AllowedDNSPatterns,
		AllowedIPRanges:       profile.AllowedIPRanges,
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile public returned error: %v", err)
	}

	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: publicProfile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	if order.ID == "" || len(lookup.domains) != 1 || lookup.domains[0] != "edge-01.example.test" {
		t.Fatalf("order = %#v, CAA lookup domains = %#v", order, lookup.domains)
	}
}

func TestCreateACMEOrderRejectsPublicTLSCAAFailure(t *testing.T) {
	ctx := context.Background()
	clock := fixedClock{now: time.Date(2026, time.March, 15, 1, 2, 3, 0, time.UTC)}
	service := New(store.NewMemoryStore(), &fakeIssuer{}, clock, &fakeIDGenerator{})
	if err := service.SetPublicTLSCAAPolicy(PublicTLSCAAPolicy{
		IssuerDomain:     "ca.example",
		AccountURI:       "https://ca.example/acct/1",
		ValidationMethod: "http-01",
		Lookup: &fakeCAALookup{result: CAALookupResult{
			Records: []CAARecord{{
				Flag:  0,
				Tag:   "issue",
				Value: `ca.example; accounturi=https://other.example/acct/2; validationmethods=http-01`,
			}},
			DNSSECStatus: CAADNSSECSecure,
		}},
	}); err != nil {
		t.Fatalf("SetPublicTLSCAAPolicy returned error: %v", err)
	}
	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	publicProfile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "public-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		PublicTLS:             true,
		AllowedDNSPatterns:    profile.AllowedDNSPatterns,
		AllowedIPRanges:       profile.AllowedIPRanges,
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile public returned error: %v", err)
	}

	_, err = service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: publicProfile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateACMEOrder error = %v, want ErrInvalidRequest", err)
	}
}

func TestValidateACMEHTTP01ChallengeVerifiesKeyAuthorizationAndPromotesOrder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	verifier := &fakeACMEHTTP01Verifier{}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := NewWithACMEHTTP01Verifier(repo, &fakeIssuer{}, clock, &fakeIDGenerator{}, verifier)

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
		KeyThumbprint:        "thumbprint-1",
		KeyJWKJSON:           `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	authzs, err := service.ListACMEAuthorizations(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizations returned error: %v", err)
	}
	challenges, err := service.ListACMEChallenges(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("ListACMEChallenges returned error: %v", err)
	}

	challenge, err := service.ValidateACMEHTTP01Challenge(ctx, "acme-client", challenges[0].ID)
	if err != nil {
		t.Fatalf("ValidateACMEHTTP01Challenge returned error: %v", err)
	}
	if challenge.Status != domain.ACMEChallengeValid || challenge.ValidatedAt.IsZero() {
		t.Fatalf("challenge = %#v", challenge)
	}
	if len(verifier.requests) != 1 ||
		verifier.requests[0].Identifier != "edge-01.example.test" ||
		verifier.requests[0].Token != challenges[0].Token ||
		verifier.requests[0].KeyAuthorization != challenges[0].Token+".thumbprint-1" {
		t.Fatalf("verifier requests = %#v", verifier.requests)
	}
	ready, err := service.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if ready.Status != domain.ACMEOrderReady {
		t.Fatalf("order status = %q, want %q", ready.Status, domain.ACMEOrderReady)
	}
	authz, err := service.GetACMEAuthorization(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("GetACMEAuthorization returned error: %v", err)
	}
	if !authz.ValidationReuseExpiresAt.Equal(clock.now.Add(200 * 24 * time.Hour)) {
		t.Fatalf("validation reuse expires at = %s, want %s", authz.ValidationReuseExpiresAt, clock.now.Add(200*24*time.Hour))
	}
	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	metadata := auditMetadata(t, findAuditEvent(t, events, "acme.challenge.completed"))
	if metadata["identifier_type"] != "dns" ||
		metadata["identifier_value"] != "edge-01.example.test" ||
		metadata["challenge_type"] != "http-01" ||
		metadata["validation_method"] != "http-01" ||
		metadata["validated_at"] != clock.now.Format(time.RFC3339) ||
		metadata["validation_reuse_expires_at"] != clock.now.Add(200*24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("challenge audit metadata = %#v", metadata)
	}
}

func TestValidateACMEHTTP01ChallengeKeepsAuthorizationPendingForRetry(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	verifier := &fakeACMEHTTP01Verifier{err: errors.New("token mismatch")}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := NewWithACMEHTTP01Verifier(repo, &fakeIssuer{}, clock, &fakeIDGenerator{}, verifier)

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
		KeyThumbprint:        "thumbprint-1",
		KeyJWKJSON:           `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	authzs, err := service.ListACMEAuthorizations(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizations returned error: %v", err)
	}
	challenges, err := service.ListACMEChallenges(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("ListACMEChallenges returned error: %v", err)
	}

	challenge, err := service.ValidateACMEHTTP01Challenge(ctx, "acme-client", challenges[0].ID)
	if err != nil {
		t.Fatalf("ValidateACMEHTTP01Challenge returned error: %v", err)
	}
	if challenge.Status != domain.ACMEChallengeProcessing {
		t.Fatalf("challenge status = %q, want %q", challenge.Status, domain.ACMEChallengeProcessing)
	}
	storedChallenge, err := service.GetACMEChallenge(ctx, challenges[0].ID)
	if err != nil {
		t.Fatalf("GetACMEChallenge returned error: %v", err)
	}
	if storedChallenge.Status != domain.ACMEChallengeProcessing {
		t.Fatalf("stored challenge status = %q, want %q", storedChallenge.Status, domain.ACMEChallengeProcessing)
	}
	storedAuthz, err := service.GetACMEAuthorization(ctx, authzs[0].ID)
	if err != nil {
		t.Fatalf("GetACMEAuthorization returned error: %v", err)
	}
	if storedAuthz.Status != domain.ACMEAuthorizationPending {
		t.Fatalf("authorization status = %q, want %q", storedAuthz.Status, domain.ACMEAuthorizationPending)
	}
	storedOrder, err := service.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if storedOrder.Status != domain.ACMEOrderPending {
		t.Fatalf("order status = %q, want %q", storedOrder.Status, domain.ACMEOrderPending)
	}

	verifier.err = nil
	challenge, err = service.ValidateACMEHTTP01Challenge(ctx, "acme-client", challenges[0].ID)
	if err != nil {
		t.Fatalf("ValidateACMEHTTP01Challenge retry returned error: %v", err)
	}
	if challenge.Status != domain.ACMEChallengeValid {
		t.Fatalf("challenge status after retry = %q, want %q", challenge.Status, domain.ACMEChallengeValid)
	}
	ready, err := service.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if ready.Status != domain.ACMEOrderReady {
		t.Fatalf("order status after retry = %q, want %q", ready.Status, domain.ACMEOrderReady)
	}
}

func TestACMEHTTP01VerifierUsesOverrideBaseURL(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("token-1.thumbprint-1"))
	}))
	defer server.Close()

	verifier, err := NewACMEHTTP01Verifier(server.URL)
	if err != nil {
		t.Fatalf("NewACMEHTTP01Verifier returned error: %v", err)
	}
	err = verifier.VerifyHTTP01(context.Background(), "edge-01.example.test", "token-1", "token-1.thumbprint-1")
	if err != nil {
		t.Fatalf("VerifyHTTP01 returned error: %v", err)
	}
	if gotPath != "/.well-known/acme-challenge/token-1" {
		t.Fatalf("challenge path = %q", gotPath)
	}
}

func TestACMEHTTP01VerifierRejectsLoopbackIdentifierBeforeFetch(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte("token-1.thumbprint-1"))
	}))
	defer server.Close()

	verifier, err := NewACMEHTTP01Verifier("")
	if err != nil {
		t.Fatalf("NewACMEHTTP01Verifier returned error: %v", err)
	}
	err = verifier.VerifyHTTP01(context.Background(), strings.TrimPrefix(server.URL, "http://"), "token-1", "token-1.thumbprint-1")
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("VerifyHTTP01 error = %v, want ErrInvalidRequest", err)
	}
	if requests != 0 {
		t.Fatalf("loopback challenge server requests = %d, want 0", requests)
	}
}

func TestACMEHTTP01VerifierRejectsLocalhostIdentifierBeforeFetch(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte("token-1.thumbprint-1"))
	}))
	defer server.Close()

	verifier, err := NewACMEHTTP01Verifier("")
	if err != nil {
		t.Fatalf("NewACMEHTTP01Verifier returned error: %v", err)
	}
	identifier := strings.Replace(strings.TrimPrefix(server.URL, "http://"), "127.0.0.1", "localhost", 1)
	err = verifier.VerifyHTTP01(context.Background(), identifier, "token-1", "token-1.thumbprint-1")
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("VerifyHTTP01 error = %v, want ErrInvalidRequest", err)
	}
	if requests != 0 {
		t.Fatalf("localhost challenge server requests = %d, want 0", requests)
	}
}

func TestACMEHTTP01VerifierAllowsOverrideBaseURLToLoopback(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte("token-1.thumbprint-1"))
	}))
	defer server.Close()

	verifier, err := NewACMEHTTP01Verifier(server.URL)
	if err != nil {
		t.Fatalf("NewACMEHTTP01Verifier returned error: %v", err)
	}
	err = verifier.VerifyHTTP01(context.Background(), "edge-01.example.test", "token-1", "token-1.thumbprint-1")
	if err != nil {
		t.Fatalf("VerifyHTTP01 returned error: %v", err)
	}
	if requests != 1 {
		t.Fatalf("override challenge server requests = %d, want 1", requests)
	}
}

func TestACMEHTTP01GuardRejectsUnsafeRedirectTarget(t *testing.T) {
	redirectURL, err := url.Parse("http://127.0.0.1/.well-known/acme-challenge/token-1")
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}
	if err := validateACMEHTTP01FetchURL(redirectURL); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("validateACMEHTTP01FetchURL error = %v, want ErrInvalidRequest", err)
	}
}

func TestACMEHTTP01ClientPolicyIsExplicit(t *testing.T) {
	client := newACMEHTTP01Client(true)
	if client.Timeout != acmeHTTP01ClientTimeout {
		t.Fatalf("client timeout = %s, want %s", client.Timeout, acmeHTTP01ClientTimeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout != acmeHTTP01ResponseHeaderTimeout {
		t.Fatalf("response header timeout = %s, want %s", transport.ResponseHeaderTimeout, acmeHTTP01ResponseHeaderTimeout)
	}
	req := httptest.NewRequest(http.MethodGet, "http://edge-01.example.test/.well-known/acme-challenge/token-1", nil)
	via := make([]*http.Request, acmeHTTP01RedirectLimit)
	if err := client.CheckRedirect(req, via); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CheckRedirect error = %v, want ErrInvalidRequest", err)
	}
}

func TestACMEHTTP01GuardRejectsUnsafeScheme(t *testing.T) {
	fetchURL, err := url.Parse("ftp://edge-01.example.test/.well-known/acme-challenge/token-1")
	if err != nil {
		t.Fatalf("url.Parse returned error: %v", err)
	}
	if err := validateACMEHTTP01FetchURL(fetchURL); !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("validateACMEHTTP01FetchURL error = %v, want ErrInvalidRequest", err)
	}
}

func TestACMEHTTP01DialTargetsUseSafeResolverResultsOnly(t *testing.T) {
	targets, err := acmeHTTP01DialTargets(context.Background(), "edge-01.example.test", "80", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("93.184.216.34")},
		}, nil
	})
	if err != nil {
		t.Fatalf("acmeHTTP01DialTargets returned error: %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"93.184.216.34:80"}) {
		t.Fatalf("dial targets = %#v", targets)
	}

	_, err = acmeHTTP01DialTargets(context.Background(), "edge-01.example.test", "80", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("unsafe-only dial targets error = %v, want ErrInvalidRequest", err)
	}
}

func TestACMEHTTP01DialTargetsAllowSafeIPv6(t *testing.T) {
	targets, err := acmeHTTP01DialTargets(context.Background(), "edge-01.example.test", "80", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2001:4860:4860::8888")}}, nil
	})
	if err != nil {
		t.Fatalf("acmeHTTP01DialTargets returned error: %v", err)
	}
	if !reflect.DeepEqual(targets, []string{"[2001:4860:4860::8888]:80"}) {
		t.Fatalf("dial targets = %#v", targets)
	}
}

func TestACMEHTTP01GuardRejectsUnsafeResolvedIPs(t *testing.T) {
	for _, ip := range []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"169.254.169.254",
		"100.100.100.200",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
		"2001:db8::1",
		"0.0.0.0",
	} {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q) returned error: %v", ip, err)
		}
		if acmeHTTP01SafeIP(addr) {
			t.Fatalf("acmeHTTP01SafeIP(%q) = true, want false", ip)
		}
	}
}

func TestACMEHTTP01VerifierRejectsInvalidOverrideBaseURL(t *testing.T) {
	_, err := NewACMEHTTP01Verifier("://bad-url")
	if err == nil {
		t.Fatal("NewACMEHTTP01Verifier returned nil error")
	}
}

func TestFinalizeACMEOrderRequiresReadyOrder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, &fakeIssuer{}, clock, &fakeIDGenerator{})
	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}

	_, err = service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("FinalizeACMEOrder error = %v, want ErrInvalidTransition", err)
	}
}

func TestFinalizeACMEOrderRejectsExpiredReadyOrder(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, &fakeIssuer{}, clock, &fakeIDGenerator{})

	account, err := service.CreateACMEAccount(ctx, "acme-client", CreateACMEAccountRequest{
		Contacts:             []string{"mailto:ops@example.test"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	identity, issuer, profile := createProfilePolicyFixture(t, ctx, service)
	order, err := service.CreateACMEOrder(ctx, "acme-client", CreateACMEOrderRequest{
		AccountID:            account.ID,
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedNotAfter:    clock.now.Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	order.Status = domain.ACMEOrderReady
	order.ExpiresAt = clock.now.Add(-time.Minute)
	if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); err != nil {
		t.Fatalf("UpdateACMEOrderIfStatus returned error: %v", err)
	}

	_, err = service.FinalizeACMEOrder(ctx, "acme-client", order.ID, FinalizeACMEOrderRequest{
		CSRPEM:           "csr-pem",
		RequestedSubject: "CN=edge-01",
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("FinalizeACMEOrder error = %v, want ErrInvalidTransition", err)
	}
	stored, err := service.GetACMEOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if stored.Status != domain.ACMEOrderInvalid {
		t.Fatalf("order status = %q, want %q", stored.Status, domain.ACMEOrderInvalid)
	}
}

func expirationLifecycleCertificate(id string, status domain.CertificateStatus, notAfter time.Time, renewalNotifiedAt time.Time) domain.Certificate {
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

func TestIssueCertificateKeepsIssuedStateWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	baseRepo := store.NewMemoryStore()
	errAudit := errors.New("audit failed")
	repo := &failAuditRepository{Repository: baseRepo, action: "certificate.issued", err: errAudit}
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, errAudit) {
		t.Fatalf("IssueCertificate error = %v, want audit error", err)
	}

	certificates, err := baseRepo.ListCertificates(ctx)
	if err != nil {
		t.Fatalf("ListCertificates returned error: %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(certificates))
	}
	storedEnrollment, err := baseRepo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if storedEnrollment.Status != domain.EnrollmentIssued {
		t.Fatalf("enrollment status = %q, want %q", storedEnrollment.Status, domain.EnrollmentIssued)
	}

	repo.err = nil
	retry, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate retry returned error: %v", err)
	}
	if retry.ID != certificates[0].ID {
		t.Fatalf("retry certificate ID = %q, want %q", retry.ID, certificates[0].ID)
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count after retry = %d, want 1", len(issuerClient.requests))
	}
	events, err := baseRepo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if findAuditEvent(t, events, "certificate.issued").ID == "" {
		t.Fatal("certificate.issued audit event was not repaired on retry")
	}
}

func TestIssueCertificateReusesSignedResultAfterFinalizationFailure(t *testing.T) {
	ctx := context.Background()
	baseRepo := store.NewMemoryStore()
	errFinalize := errors.New("finalization failed")
	repo := &failCreateCertificateOnceRepository{Repository: baseRepo, err: errFinalize}
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, errFinalize) {
		t.Fatalf("IssueCertificate error = %v, want finalization error", err)
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count after failed finalization = %d, want 1", len(issuerClient.requests))
	}

	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate retry returned error: %v", err)
	}
	if certificate.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", certificate.CertificatePEM, "issued:csr-pem")
	}
	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count after retry = %d, want 1", len(issuerClient.requests))
	}
}

func TestIssueCertificateReusesDurableSignedResultAfterRestart(t *testing.T) {
	ctx := context.Background()
	baseRepo := store.NewMemoryStore()
	errFinalize := errors.New("finalization failed")
	firstRepo := &failCreateCertificateOnceRepository{Repository: baseRepo, err: errFinalize}
	firstIssuer := &fakeIssuer{}
	firstService := New(
		firstRepo,
		firstIssuer,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, firstService)
	if _, err := firstService.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	if _, err := firstService.IssueCertificate(ctx, "issuer", enrollment.ID); !errors.Is(err, errFinalize) {
		t.Fatalf("IssueCertificate error = %v, want finalization error", err)
	}
	if len(firstIssuer.requests) != 1 {
		t.Fatalf("first issuer request count = %d, want 1", len(firstIssuer.requests))
	}

	secondIssuer := &fakeIssuer{}
	secondService := New(
		baseRepo,
		secondIssuer,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 6, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	certificate, err := secondService.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate after restart returned error: %v", err)
	}
	if certificate.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", certificate.CertificatePEM, "issued:csr-pem")
	}
	if len(secondIssuer.requests) != 0 {
		t.Fatalf("second issuer request count = %d, want 0", len(secondIssuer.requests))
	}
}

func TestIssueCertificateActiveClaimPreventsSecondServiceSigning(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	firstIssuer := newBlockingIssueIssuer(1)
	firstService := New(
		repo,
		firstIssuer,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&threadSafeIDGenerator{},
	)
	secondIssuer := &fakeIssuer{}
	secondService := New(
		repo,
		secondIssuer,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 6, 0, time.UTC)},
		&threadSafeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, firstService)
	if _, err := firstService.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	result := make(chan issueCertificateResult, 1)
	go func() {
		certificate, err := firstService.IssueCertificate(ctx, "issuer", enrollment.ID)
		result <- issueCertificateResult{certificate: certificate, err: err}
	}()
	select {
	case <-firstIssuer.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first signing request")
	}

	if _, err := secondService.IssueCertificate(ctx, "issuer", enrollment.ID); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("second IssueCertificate error = %v, want ErrInvalidTransition", err)
	}
	if len(secondIssuer.requests) != 0 {
		t.Fatalf("second issuer request count = %d, want 0", len(secondIssuer.requests))
	}

	close(firstIssuer.release)
	first := <-result
	if first.err != nil {
		t.Fatalf("first IssueCertificate returned error: %v", first.err)
	}
}

func TestRevokeCertificateRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	errAudit := errors.New("audit failed")
	service := New(
		&failAuditRepository{Repository: repo, action: "certificate.revoked", err: errAudit},
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, errAudit) {
		t.Fatalf("RevokeCertificate error = %v, want audit error", err)
	}

	storedCertificate, err := repo.GetCertificate(ctx, certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if storedCertificate.Status != domain.CertificateValid {
		t.Fatalf("certificate status = %q, want %q", storedCertificate.Status, domain.CertificateValid)
	}
}

func TestRepairMissingIssuanceAuditEvents(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	issuer := domain.Issuer{
		ID:             "issuer-1",
		Name:           "issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	certificate := domain.Certificate{
		ID:                   "certificate-1",
		IdentityID:           "identity-1",
		IssuerID:             "issuer-1",
		EnrollmentID:         "enrollment-1",
		CertificateProfileID: "profile-1",
		SerialNumber:         "serial-1",
		Subject:              "CN=edge-01",
		Status:               domain.CertificateValid,
		CertificatePEM:       "cert-pem",
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateCertificate(ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	repaired, err := service.RepairMissingIssuanceAuditEvents(ctx, "operator")
	if err != nil {
		t.Fatalf("RepairMissingIssuanceAuditEvents returned error: %v", err)
	}
	if repaired != 1 {
		t.Fatalf("repaired count = %d, want 1", repaired)
	}
	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	event := findAuditEvent(t, events, "certificate.issued")
	if event.Actor != "operator" || event.ResourceID != certificate.ID {
		t.Fatalf("repair audit event = %#v", event)
	}
	metadata := auditMetadata(t, event)
	if metadata["key_provider_class"] != "file" ||
		metadata["key_provider_exportability"] != "exportable" ||
		metadata["policy_decision"] != "unknown" ||
		metadata["policy_decision_reason"] != "legacy_policy_evidence_unavailable" {
		t.Fatalf("repair audit metadata = %#v", metadata)
	}
	assertPolicyEvidenceRefs(t, metadata, certificate.IdentityID, certificate.IssuerID, certificate.CertificateProfileID)

	repaired, err = service.RepairMissingIssuanceAuditEvents(ctx, "operator")
	if err != nil {
		t.Fatalf("RepairMissingIssuanceAuditEvents second returned error: %v", err)
	}
	if repaired != 0 {
		t.Fatalf("second repaired count = %d, want 0", repaired)
	}
}

func TestRepairMissingIssuanceAuditEventsPreservesCurrentEvidenceAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})

	identity := domain.Identity{
		ID:              "identity-repair-current",
		Type:            domain.IdentityMachine,
		Name:            "edge-01",
		AllowedDNSNames: []string{"edge-01.example.test"},
		Status:          domain.IdentityActive,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	issuer := domain.Issuer{
		ID:             "issuer-repair-current",
		Name:           "issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "file:/sensitive/issuer-repair-current.key",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	profile := domain.CertificateProfile{
		ID:                         "profile-repair-current",
		Name:                       "repair-profile",
		IssuerID:                   issuer.ID,
		ValidityPeriodSeconds:      int64((24 * time.Hour).Seconds()),
		AllowedDNSPatterns:         []string{"edge-01.example.test"},
		AllowedKeyAlgorithms:       []string{"rsa"},
		MinKeySizeBits:             2048,
		AllowedSignatureAlgorithms: []string{"rsa-sha256"},
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
	enrollment := domain.Enrollment{
		ID:                   "enrollment-repair-current",
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem-sensitive-repair-current",
		Status:               domain.EnrollmentIssued,
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		CSRDNSNames:          []string{"edge-01.example.test"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ApprovedBy:           "approver",
		ApprovedAt:           now,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	certificate := domain.Certificate{
		ID:                   "certificate-repair-current",
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		EnrollmentID:         enrollment.ID,
		CertificateProfileID: profile.ID,
		SerialNumber:         "serial-repair-current",
		Subject:              "CN=edge-01",
		DNSNames:             []string{"edge-01.example.test"},
		NotBefore:            now,
		NotAfter:             now.Add(24 * time.Hour),
		Status:               domain.CertificateValid,
		CertificatePEM:       "cert-pem",
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	for name, create := range map[string]func() error{
		"identity":    func() error { return repo.CreateIdentity(ctx, identity) },
		"issuer":      func() error { return repo.CreateIssuer(ctx, issuer) },
		"profile":     func() error { return repo.CreateCertificateProfile(ctx, profile) },
		"enrollment":  func() error { return repo.CreateEnrollment(ctx, enrollment) },
		"certificate": func() error { return repo.CreateCertificate(ctx, certificate) },
	} {
		if err := create(); err != nil {
			t.Fatalf("create %s returned error: %v", name, err)
		}
	}
	evidenceJSON, err := json.Marshal(corecli.SigningEvidence{
		SchemaVersion:               1,
		EvidenceSource:              "core_signing",
		Operation:                   "certificate_issue",
		ProviderID:                  "file",
		ProviderClass:               "file",
		ProviderReadiness:           "ready",
		ProviderExportability:       "exportable",
		ReferenceClass:              "file",
		KeyAlgorithm:                "rsa",
		RequestedSignatureAlgorithm: "rsa-sha256",
		IssuerBindingVerified:       true,
		FallbackUsed:                false,
		ResultCode:                  "ok",
	})
	if err != nil {
		t.Fatalf("marshal signing evidence: %v", err)
	}
	if err := repo.CreateIssuanceAttempt(ctx, domain.IssuanceAttempt{
		EnrollmentID:        enrollment.ID,
		Status:              domain.IssuanceAttemptFinalized,
		CertificateID:       certificate.ID,
		CertificatePEM:      certificate.CertificatePEM,
		SerialNumber:        certificate.SerialNumber,
		Subject:             certificate.Subject,
		NotBefore:           certificate.NotBefore,
		NotAfter:            certificate.NotAfter,
		SigningStartedAt:    now,
		SignedAt:            now,
		FinalizedAt:         now,
		SigningEvidenceJSON: string(evidenceJSON),
		CreatedAt:           now,
		UpdatedAt:           now,
	}); err != nil {
		t.Fatalf("CreateIssuanceAttempt returned error: %v", err)
	}

	repaired, err := service.RepairMissingIssuanceAuditEvents(ctx, "repair-operator")
	if err != nil {
		t.Fatalf("RepairMissingIssuanceAuditEvents returned error: %v", err)
	}
	if repaired != 1 {
		t.Fatalf("repaired count = %d, want 1", repaired)
	}
	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	event := findAuditEventForResource(t, events, "certificate.issued", certificate.ID)
	metadata := auditMetadata(t, event)
	if metadata["key_provider_evidence_source"] != "core_signing" ||
		metadata["key_provider_signing_proven"] != true ||
		metadata["key_provider_fallback_used"] != false ||
		metadata["policy_decision"] != "allow" ||
		metadata["policy_decision_reason"] != "issuance_policy_passed" {
		t.Fatalf("repaired audit metadata = %#v", metadata)
	}
	assertPolicyEvidenceRefs(t, metadata, identity.ID, issuer.ID, profile.ID)
	if strings.Contains(event.MetadataJSON, issuer.KeyRef) ||
		strings.Contains(event.MetadataJSON, enrollment.CSRPEM) ||
		strings.Contains(event.MetadataJSON, "edge-01.example.test") {
		t.Fatalf("repaired audit metadata exposes sensitive policy/key input: %s", event.MetadataJSON)
	}

	repaired, err = service.RepairMissingIssuanceAuditEvents(ctx, "repair-operator")
	if err != nil {
		t.Fatalf("second RepairMissingIssuanceAuditEvents returned error: %v", err)
	}
	if repaired != 0 {
		t.Fatalf("second repaired count = %d, want 0", repaired)
	}
	events, err = repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("second ListAuditEvents returned error: %v", err)
	}
	count := 0
	for _, candidate := range events {
		if candidate.Action == "certificate.issued" && candidate.ResourceID == certificate.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("certificate.issued audit count = %d, want 1", count)
	}
}

func TestReplayDeadLetterOutboxMessagesPreservesHistoryAndCompletesAfterRecovery(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	endpoint := domain.NotificationEndpoint{
		ID:         "endpoint-replay-recovery",
		Name:       "recovered receiver",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        server.URL,
		Secret:     "test-secret-not-evidence",
		EventTypes: []string{"certificate.issued"},
		CreatedAt:  now.Add(-3 * time.Hour),
		UpdatedAt:  now.Add(-3 * time.Hour),
	}
	if err := repo.CreateNotificationEndpoint(ctx, endpoint); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}
	message := domain.OutboxMessage{
		ID:                   "outbox-replay-recovery",
		Type:                 "certificate.issued",
		PayloadJSON:          `{"certificate_id":"certificate-replay-recovery"}`,
		Status:               domain.OutboxDeadLetter,
		AvailableAt:          now.Add(-time.Hour),
		ProcessingDeadlineAt: time.Time{},
		AttemptCount:         2,
		MaxAttempts:          2,
		LastError:            "receiver unavailable",
		CreatedAt:            now.Add(-2 * time.Hour),
		UpdatedAt:            now.Add(-time.Hour),
	}
	other := message
	other.ID = "outbox-replay-unrelated"
	other.Type = "certificate.revoked"
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	if err := repo.CreateOutboxMessage(ctx, other); err != nil {
		t.Fatalf("CreateOutboxMessage unrelated returned error: %v", err)
	}
	for index := 1; index <= 2; index++ {
		if err := repo.CreateJobAttempt(ctx, domain.JobAttempt{
			ID:              fmt.Sprintf("attempt-replay-%d", index),
			OutboxMessageID: message.ID,
			Status:          domain.JobAttemptFailed,
			Error:           "receiver unavailable",
			StartedAt:       now.Add(time.Duration(index-3) * time.Hour),
			FinishedAt:      now.Add(time.Duration(index-3)*time.Hour + time.Minute),
			CreatedAt:       now.Add(time.Duration(index-3)*time.Hour + time.Minute),
		}); err != nil {
			t.Fatalf("CreateJobAttempt(%d) returned error: %v", index, err)
		}
	}
	if err := repo.UpsertWebhookDelivery(ctx, domain.WebhookDelivery{
		OutboxMessageID: message.ID,
		EndpointID:      endpoint.ID,
		Status:          domain.JobAttemptFailed,
		AttemptCount:    2,
		LastError:       "receiver unavailable",
		LastAttemptedAt: now.Add(-time.Hour),
		CreatedAt:       now.Add(-2 * time.Hour),
		UpdatedAt:       now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("UpsertWebhookDelivery returned error: %v", err)
	}

	result, err := service.ReplayDeadLetterOutboxMessages(ctx, "recovery-operator", ReplayDeadLetterOutboxRequest{
		EventType:   message.Type,
		CreatedFrom: now.Add(-3 * time.Hour),
		CreatedTo:   now,
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("ReplayDeadLetterOutboxMessages returned error: %v", err)
	}
	if len(result.ReplayedMessages) != 1 || result.ReplayedMessages[0].ID != message.ID {
		t.Fatalf("replayed messages = %#v", result.ReplayedMessages)
	}
	replayed, err := repo.GetOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("GetOutboxMessage returned error: %v", err)
	}
	if replayed.Status != domain.OutboxPending || replayed.AttemptCount != 0 || replayed.LastError != "" ||
		replayed.MaxAttempts != message.MaxAttempts || !replayed.AvailableAt.Equal(now) {
		t.Fatalf("replayed message = %#v", replayed)
	}
	unchanged, err := repo.GetOutboxMessage(ctx, other.ID)
	if err != nil {
		t.Fatalf("GetOutboxMessage unrelated returned error: %v", err)
	}
	if unchanged.Status != domain.OutboxDeadLetter || unchanged.AttemptCount != other.AttemptCount || unchanged.LastError != other.LastError {
		t.Fatalf("unrelated message changed = %#v", unchanged)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 2 || attempts[0].Status != domain.JobAttemptFailed || attempts[1].Status != domain.JobAttemptFailed {
		t.Fatalf("preserved attempts = %#v", attempts)
	}
	delivery, err := repo.GetWebhookDelivery(ctx, message.ID, endpoint.ID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery returned error: %v", err)
	}
	if delivery.Status != domain.JobAttemptFailed || delivery.AttemptCount != 2 || delivery.LastError == "" {
		t.Fatalf("preserved delivery = %#v", delivery)
	}

	dispatcher := NewOutboxDispatcher(repo, NewWebhookOutboxHandler(repo, server.Client()), fixedClock{now: now}, &fakeIDGenerator{})
	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce after recovery returned error: %v", err)
	}
	if processed != 1 || requests != 1 {
		t.Fatalf("processed=%d requests=%d, want 1/1", processed, requests)
	}
	completed, err := repo.GetOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("GetOutboxMessage completed returned error: %v", err)
	}
	if completed.Status != domain.OutboxCompleted || completed.AttemptCount != 0 || completed.LastError != "" {
		t.Fatalf("completed message = %#v", completed)
	}
	attempts, err = repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage after recovery returned error: %v", err)
	}
	if len(attempts) != 3 || attempts[2].Status != domain.JobAttemptSucceeded || attempts[2].Error != "" {
		t.Fatalf("attempt history after recovery = %#v", attempts)
	}
	delivery, err = repo.GetWebhookDelivery(ctx, message.ID, endpoint.ID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery after recovery returned error: %v", err)
	}
	if delivery.Status != domain.JobAttemptSucceeded || delivery.AttemptCount != 3 || delivery.LastError != "" {
		t.Fatalf("delivery after recovery = %#v", delivery)
	}
	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	event := findAuditEvent(t, events, "outbox.bulk_replay_requested")
	metadata := auditMetadata(t, event)
	if metadata["outbox_message_type"] != message.Type || metadata["replayed_count"] != "1" {
		t.Fatalf("bulk replay audit metadata = %#v", metadata)
	}
	if strings.Contains(event.MetadataJSON, message.PayloadJSON) || strings.Contains(event.MetadataJSON, endpoint.Secret) {
		t.Fatalf("bulk replay audit exposes payload or secret: %s", event.MetadataJSON)
	}
}

func createPendingEnrollment(t *testing.T, ctx context.Context, service *Service) domain.Enrollment {
	t.Helper()

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	return enrollment
}

func createDuplicateSerialEnrollment(t *testing.T, ctx context.Context, service *Service, identityID string, issuerID string) domain.Enrollment {
	t.Helper()

	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identityID,
		IssuerID:             issuerID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	return enrollment
}

func createProfilePolicyFixture(t *testing.T, ctx context.Context, service *Service) (domain.Identity, domain.Issuer, domain.CertificateProfile) {
	return createProfilePolicyFixtureWithProfileMutation(t, ctx, service, nil)
}

func createProfilePolicyFixtureWithProfileMutation(t *testing.T, ctx context.Context, service *Service, mutate func(*CreateCertificateProfileRequest)) (domain.Identity, domain.Issuer, domain.CertificateProfile) {
	t.Helper()

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profileReq := CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		AllowedDNSPatterns:    []string{"*.example.test"},
		AllowedIPRanges:       []string{"192.0.2.0/24"},
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA: false,
		},
	}
	if mutate != nil {
		mutate(&profileReq)
	}
	profile, err := service.CreateCertificateProfile(ctx, "admin", profileReq)
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	return identity, issuer, profile
}

func TestAuthenticateAPIKeyRejectsExpiredKey(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})

	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "expired",
		TokenHash: HashAPIKeyToken("expired-token"),
		Status:    domain.APIKeyActive,
		Actor:     "api-admin",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		ExpiresAt: now.Add(-time.Second),
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	if _, err := service.AuthenticateAPIKey(ctx, "expired-token"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("AuthenticateAPIKey error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthenticateAPIKeyRecordsLastUsedAt(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})

	key := domain.APIKey{
		ID:        "key-1",
		Name:      "operator",
		TokenHash: HashAPIKeyToken("operator-token"),
		Status:    domain.APIKeyActive,
		Actor:     "api-admin",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour),
	}
	if err := repo.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	authenticated, err := service.AuthenticateAPIKey(ctx, "operator-token")
	if err != nil {
		t.Fatalf("AuthenticateAPIKey returned error: %v", err)
	}
	if !authenticated.LastUsedAt.Equal(now) {
		t.Fatalf("authenticated LastUsedAt = %s, want %s", authenticated.LastUsedAt, now)
	}
	stored, err := repo.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned error: %v", err)
	}
	if !stored.LastUsedAt.Equal(now) || !stored.UpdatedAt.Equal(now) {
		t.Fatalf("stored timestamps LastUsedAt=%s UpdatedAt=%s, want %s", stored.LastUsedAt, stored.UpdatedAt, now)
	}
}

func TestAuthenticateAPIKeyUsesPepperedHashAndFallsBackToLegacyHash(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := NewWithAPIKeyPepper(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{}, "pepper-secret-0123456789abcdef")
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "legacy-key",
		Name:      "legacy",
		TokenHash: HashAPIKeyToken("legacy-token"),
		Status:    domain.APIKeyActive,
		Actor:     "legacy-client",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey legacy returned error: %v", err)
	}
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "peppered-key",
		Name:      "peppered",
		TokenHash: HashAPIKeyTokenWithPepper("peppered-token", "pepper-secret-0123456789abcdef"),
		Status:    domain.APIKeyActive,
		Actor:     "peppered-client",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey peppered returned error: %v", err)
	}

	legacy, err := service.AuthenticateAPIKey(ctx, "legacy-token")
	if err != nil {
		t.Fatalf("AuthenticateAPIKey legacy returned error: %v", err)
	}
	if legacy.ID != "legacy-key" {
		t.Fatalf("legacy auth ID = %q, want legacy-key", legacy.ID)
	}
	peppered, err := service.AuthenticateAPIKey(ctx, "peppered-token")
	if err != nil {
		t.Fatalf("AuthenticateAPIKey peppered returned error: %v", err)
	}
	if peppered.ID != "peppered-key" {
		t.Fatalf("peppered auth ID = %q, want peppered-key", peppered.ID)
	}
}

func TestAuthenticateAPIKeyPrefersPepperedHashWhenBothExist(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	pepper := "pepper-secret-0123456789abcdef"
	service := NewWithAPIKeyPepper(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{}, pepper)
	for _, key := range []domain.APIKey{
		{
			ID:        "legacy-key",
			Name:      "legacy",
			TokenHash: HashAPIKeyToken("shared-token"),
			Status:    domain.APIKeyActive,
			Actor:     "legacy-client",
			Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "peppered-key",
			Name:      "peppered",
			TokenHash: HashAPIKeyTokenWithPepper("shared-token", pepper),
			Status:    domain.APIKeyActive,
			Actor:     "peppered-client",
			Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
			CreatedAt: now,
			UpdatedAt: now,
		},
	} {
		if err := repo.CreateAPIKey(ctx, key); err != nil {
			t.Fatalf("CreateAPIKey returned error: %v", err)
		}
	}

	key, err := service.AuthenticateAPIKey(ctx, "shared-token")
	if err != nil {
		t.Fatalf("AuthenticateAPIKey returned error: %v", err)
	}
	if key.ID != "peppered-key" {
		t.Fatalf("authenticated key ID = %q, want peppered-key", key.ID)
	}
}

func TestCreateAPIKeyStoresPepperedHashWhenConfigured(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	pepper := "pepper-secret-0123456789abcdef"
	service := NewWithAPIKeyPepper(repo, &fakeIssuer{}, fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}, &fakeIDGenerator{}, pepper)

	result, err := service.CreateAPIKey(ctx, "admin", CreateAPIKeyRequest{
		Name:   "reader",
		Actor:  "read-client",
		Scopes: []domain.APIKeyScope{domain.APIKeyScopeRead},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}
	stored, err := repo.GetAPIKey(ctx, result.Key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned error: %v", err)
	}
	if stored.TokenHash != HashAPIKeyTokenWithPepper(result.Token, pepper) || !strings.HasPrefix(stored.TokenHash, "hmac-sha256:") {
		t.Fatalf("TokenHash = %q, want peppered hash", stored.TokenHash)
	}
}

func TestEnsureAPIKeyFindsLegacyHashWhenPepperConfigured(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := NewWithAPIKeyPepper(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{}, "pepper-secret-0123456789abcdef")
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "legacy-key",
		Name:      "bootstrap",
		TokenHash: HashAPIKeyToken("bootstrap-token"),
		Status:    domain.APIKeyActive,
		Actor:     "bootstrap",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	key, err := service.EnsureAPIKey(ctx, "system", EnsureAPIKeyRequest{
		Name:   "bootstrap",
		Token:  "bootstrap-token",
		Actor:  "bootstrap",
		Scopes: []domain.APIKeyScope{domain.APIKeyScopeOperator},
	})
	if err != nil {
		t.Fatalf("EnsureAPIKey returned error: %v", err)
	}
	if key.ID != "legacy-key" {
		t.Fatalf("EnsureAPIKey ID = %q, want legacy-key", key.ID)
	}
	keys, err := repo.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys returned error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("api key count = %d, want 1", len(keys))
	}
}

func TestCreateAPIKeyRejectsPastExpiry(t *testing.T) {
	service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}, &fakeIDGenerator{})

	_, err := service.CreateAPIKey(context.Background(), "admin", CreateAPIKeyRequest{
		Name:      "expired",
		Actor:     "api-admin",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		ExpiresAt: time.Date(2026, time.January, 2, 3, 4, 4, 0, time.UTC),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateAPIKey error = %v, want ErrInvalidRequest", err)
	}
}

func TestRotateAPIKeyDisablesOldKeyAndReturnsNewToken(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	expiresAt := now.Add(24 * time.Hour)
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "reader",
		TokenHash: HashAPIKeyToken("old-token"),
		Status:    domain.APIKeyActive,
		Actor:     "read-client",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
		ExpiresAt: expiresAt,
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	rotated, err := service.RotateAPIKey(ctx, "ops-admin", "key-1")
	if err != nil {
		t.Fatalf("RotateAPIKey returned error: %v", err)
	}
	if rotated.Token == "" || rotated.Key.ID == "key-1" {
		t.Fatalf("rotated result = %#v", rotated)
	}
	if rotated.Key.Name != "reader" || rotated.Key.Actor != "read-client" ||
		len(rotated.Key.Scopes) != 1 || rotated.Key.Scopes[0] != domain.APIKeyScopeRead ||
		!rotated.Key.ExpiresAt.Equal(expiresAt) || rotated.Key.Status != domain.APIKeyActive {
		t.Fatalf("rotated key = %#v", rotated.Key)
	}
	oldKey, err := repo.GetAPIKey(ctx, "key-1")
	if err != nil {
		t.Fatalf("GetAPIKey old returned error: %v", err)
	}
	if oldKey.Status != domain.APIKeyDisabled {
		t.Fatalf("old key status = %q, want disabled", oldKey.Status)
	}
	if _, err := service.AuthenticateAPIKey(ctx, "old-token"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("old token auth error = %v, want ErrUnauthorized", err)
	}
	if _, err := service.AuthenticateAPIKey(ctx, rotated.Token); err != nil {
		t.Fatalf("new token auth returned error: %v", err)
	}
}

func TestRotateAPIKeyStoresPepperedHashWhenConfigured(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	pepper := "pepper-secret-0123456789abcdef"
	service := NewWithAPIKeyPepper(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{}, pepper)
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "reader",
		TokenHash: HashAPIKeyToken("old-token"),
		Status:    domain.APIKeyActive,
		Actor:     "read-client",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	rotated, err := service.RotateAPIKey(ctx, "ops-admin", "key-1")
	if err != nil {
		t.Fatalf("RotateAPIKey returned error: %v", err)
	}
	stored, err := repo.GetAPIKey(ctx, rotated.Key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned error: %v", err)
	}
	if stored.TokenHash != HashAPIKeyTokenWithPepper(rotated.Token, pepper) || !strings.HasPrefix(stored.TokenHash, "hmac-sha256:") {
		t.Fatalf("rotated TokenHash = %q, want peppered hash", stored.TokenHash)
	}
}

func TestRotateAPIKeyRejectsInactiveKey(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "disabled",
		TokenHash: HashAPIKeyToken("old-token"),
		Status:    domain.APIKeyDisabled,
		Actor:     "api-admin",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	_, err := service.RotateAPIKey(ctx, "ops-admin", "key-1")
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RotateAPIKey error = %v, want ErrInvalidTransition", err)
	}
}

func TestRotateAPIKeyRejectsExpiredKey(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "expired",
		TokenHash: HashAPIKeyToken("old-token"),
		Status:    domain.APIKeyActive,
		Actor:     "api-admin",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		ExpiresAt: now.Add(-time.Second),
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	_, err := service.RotateAPIKey(ctx, "ops-admin", "key-1")
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RotateAPIKey error = %v, want ErrInvalidTransition", err)
	}
}

func TestEnsureAPIKeyRejectsDisabledExistingKey(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "bootstrap",
		TokenHash: HashAPIKeyToken("bootstrap-token"),
		Status:    domain.APIKeyDisabled,
		Actor:     "bootstrap",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeOperator},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	_, err := service.EnsureAPIKey(ctx, "system", EnsureAPIKeyRequest{
		Name:   "bootstrap",
		Token:  "bootstrap-token",
		Actor:  "bootstrap",
		Scopes: []domain.APIKeyScope{domain.APIKeyScopeOperator},
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("EnsureAPIKey error = %v, want ErrInvalidTransition", err)
	}
}

func TestEnsureAPIKeyRejectsExistingKeyWithoutOperatorScope(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(repo, &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
	if err := repo.CreateAPIKey(ctx, domain.APIKey{
		ID:        "key-1",
		Name:      "bootstrap",
		TokenHash: HashAPIKeyToken("bootstrap-token"),
		Status:    domain.APIKeyActive,
		Actor:     "bootstrap",
		Scopes:    []domain.APIKeyScope{domain.APIKeyScopeRead},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}

	_, err := service.EnsureAPIKey(ctx, "system", EnsureAPIKeyRequest{
		Name:   "bootstrap",
		Token:  "bootstrap-token",
		Actor:  "bootstrap",
		Scopes: []domain.APIKeyScope{domain.APIKeyScopeOperator},
	})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("EnsureAPIKey error = %v, want ErrInvalidTransition", err)
	}
}

func TestCertificateProfileIssuerRolloverAndRollbackPreservesOverlap(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	coreClient := &fakeIssuer{crlResult: corecli.GenerateCRLResult{CRLPEM: "crl-pem"}}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, coreClient, clock, &fakeIDGenerator{})

	root, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "root", Kind: domain.IssuerRootCA, CertificatePEM: "root-cert", KeyRef: "root-key", TrustAnchor: true,
	})
	if err != nil {
		t.Fatalf("CreateIssuer root returned error: %v", err)
	}
	oldIssuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "intermediate-old", Kind: domain.IssuerIntermediateCA, ParentIssuerID: root.ID,
		CertificatePEM: "old-cert", KeyRef: "old-key", CRLDistributionPoints: []string{"https://pki.example.test/old.crl"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer old returned error: %v", err)
	}
	newIssuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name: "intermediate-new", Kind: domain.IssuerIntermediateCA, ParentIssuerID: root.ID,
		CertificatePEM: "new-cert", KeyRef: "new-key", CRLDistributionPoints: []string{"https://pki.example.test/new.crl"},
	})
	if err != nil {
		t.Fatalf("CreateIssuer new returned error: %v", err)
	}
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name: "machine", IssuerID: oldIssuer.ID, ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		AllowedSignatureAlgorithms: []string{"sha256"}, BasicConstraints: domain.BasicConstraintsPolicy{Critical: true},
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{Type: domain.IdentityMachine, Name: "edge-01"})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}

	issue := func(issuerID string, csr string) domain.Certificate {
		enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
			IdentityID: identity.ID, IssuerID: issuerID, CertificateProfileID: profile.ID,
			CSRPEM: csr, RequestedSubject: "CN=edge-01", RequestedDNSNames: []string{"edge-01.example.test"},
			RequestedIPAddresses: []string{"127.0.0.1"}, RequestedNotAfter: clock.now.Add(12 * time.Hour),
		})
		if err != nil {
			t.Fatalf("CreateEnrollment(%s) returned error: %v", issuerID, err)
		}
		if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
			t.Fatalf("ApproveEnrollment returned error: %v", err)
		}
		certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
		if err != nil {
			t.Fatalf("IssueCertificate returned error: %v", err)
		}
		return certificate
	}

	oldCertificate := issue(oldIssuer.ID, "csr-old")
	if got := coreClient.requests[len(coreClient.requests)-1]; got.IssuerCertificatePEM != "old-cert" || got.IssuerKeyRef != "old-key" {
		t.Fatalf("old issuer request = %#v", got)
	}

	rolled, err := service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{
		ProfileID: profile.ID, CurrentIssuerID: oldIssuer.ID, NextIssuerID: newIssuer.ID,
		Transition: CertificateProfileIssuerRollover, Reason: "planned intermediate rotation",
	})
	if err != nil {
		t.Fatalf("TransitionCertificateProfileIssuer rollover returned error: %v", err)
	}
	if rolled.IssuerID != newIssuer.ID {
		t.Fatalf("rolled profile issuer = %q, want %q", rolled.IssuerID, newIssuer.ID)
	}

	_ = issue(newIssuer.ID, "csr-new")
	if got := coreClient.requests[len(coreClient.requests)-1]; got.IssuerCertificatePEM != "new-cert" || got.IssuerKeyRef != "new-key" {
		t.Fatalf("new issuer request = %#v", got)
	}

	if _, err := service.RevokeCertificate(ctx, "operator", oldCertificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("RevokeCertificate old certificate returned error: %v", err)
	}
	publication, err := service.PublishCRL(ctx, "operator", PublishCRLRequest{
		IssuerID: oldIssuer.ID, DistributionPoint: oldIssuer.CRLDistributionPoints[0], NextUpdate: clock.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("PublishCRL old issuer after rollover returned error: %v", err)
	}
	if publication.IssuerID != oldIssuer.ID || publication.CRLNumber != 1 {
		t.Fatalf("old issuer publication = %#v", publication)
	}

	rolledBack, err := service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{
		ProfileID: profile.ID, CurrentIssuerID: newIssuer.ID, NextIssuerID: oldIssuer.ID,
		Transition: CertificateProfileIssuerRollback, Reason: "new intermediate validation failed",
	})
	if err != nil {
		t.Fatalf("TransitionCertificateProfileIssuer rollback returned error: %v", err)
	}
	if rolledBack.IssuerID != oldIssuer.ID {
		t.Fatalf("rolled-back profile issuer = %q, want %q", rolledBack.IssuerID, oldIssuer.ID)
	}

	events := mustListAuditEvents(t, service, ctx)
	var transitions []domain.AuditEvent
	for _, event := range events {
		if event.Action == "certificate_profile.issuer_rolled_over" || event.Action == "certificate_profile.issuer_rolled_back" {
			transitions = append(transitions, event)
		}
	}
	if len(transitions) != 2 {
		t.Fatalf("profile issuer transition audit count = %d, want 2", len(transitions))
	}
	first := auditMetadata(t, transitions[0])
	if first["previous_issuer_id"] != oldIssuer.ID || first["next_issuer_id"] != newIssuer.ID || first["parent_issuer_id"] != root.ID || first["transition"] != "rollover" {
		t.Fatalf("rollover audit metadata = %#v", first)
	}
	second := auditMetadata(t, transitions[1])
	if second["previous_issuer_id"] != newIssuer.ID || second["next_issuer_id"] != oldIssuer.ID || second["transition"] != "rollback" {
		t.Fatalf("rollback audit metadata = %#v", second)
	}
	messages, err := repo.ListOutboxMessages(ctx, "")
	if err != nil {
		t.Fatalf("ListOutboxMessages returned error: %v", err)
	}
	transitionMessages := 0
	for _, message := range messages {
		if message.Type == "certificate_profile.issuer_rolled_over" || message.Type == "certificate_profile.issuer_rolled_back" {
			transitionMessages++
		}
	}
	if transitionMessages != 2 {
		t.Fatalf("profile issuer transition outbox count = %d, want 2", transitionMessages)
	}
}

func TestCertificateProfileIssuerRolloverRejectsDifferentParentAndStaleRetry(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(repo, &fakeIssuer{}, fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}, &fakeIDGenerator{})
	rootA, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "root-a", Kind: domain.IssuerRootCA, CertificatePEM: "root-a-cert", KeyRef: "root-a-key", TrustAnchor: true})
	rootB, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "root-b", Kind: domain.IssuerRootCA, CertificatePEM: "root-b-cert", KeyRef: "root-b-key", TrustAnchor: true})
	oldIssuer, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "old", Kind: domain.IssuerIntermediateCA, ParentIssuerID: rootA.ID, CertificatePEM: "old-cert", KeyRef: "old-key"})
	newIssuer, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "new", Kind: domain.IssuerIntermediateCA, ParentIssuerID: rootA.ID, CertificatePEM: "new-cert", KeyRef: "new-key"})
	otherIssuer, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "other", Kind: domain.IssuerIntermediateCA, ParentIssuerID: rootB.ID, CertificatePEM: "other-cert", KeyRef: "other-key"})
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{Name: "profile", IssuerID: oldIssuer.ID, ValidityPeriodSeconds: 3600, AllowedSignatureAlgorithms: []string{"sha256"}, BasicConstraints: domain.BasicConstraintsPolicy{Critical: true}})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	_, err = service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{ProfileID: profile.ID, CurrentIssuerID: oldIssuer.ID, NextIssuerID: otherIssuer.ID, Transition: CertificateProfileIssuerRollover, Reason: "different parent"})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("different-parent rollover error = %v, want ErrInvalidRequest", err)
	}
	stored, _ := repo.GetCertificateProfile(ctx, profile.ID)
	if stored.IssuerID != oldIssuer.ID {
		t.Fatalf("profile issuer changed after rejected transition: %q", stored.IssuerID)
	}

	if _, err := service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{ProfileID: profile.ID, CurrentIssuerID: oldIssuer.ID, NextIssuerID: newIssuer.ID, Transition: CertificateProfileIssuerRollover, Reason: "planned"}); err != nil {
		t.Fatalf("valid rollover returned error: %v", err)
	}
	_, err = service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{ProfileID: profile.ID, CurrentIssuerID: oldIssuer.ID, NextIssuerID: newIssuer.ID, Transition: CertificateProfileIssuerRollover, Reason: "duplicate"})
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale retry error = %v, want ErrInvalidTransition", err)
	}

	events := mustListAuditEvents(t, service, ctx)
	transitionCount := 0
	for _, event := range events {
		if event.Action == "certificate_profile.issuer_rolled_over" {
			transitionCount++
		}
	}
	if transitionCount != 1 {
		t.Fatalf("rollover audit count = %d, want 1", transitionCount)
	}
	messages, _ := repo.ListOutboxMessages(ctx, "")
	messageCount := 0
	for _, message := range messages {
		if message.Type == "certificate_profile.issuer_rolled_over" {
			messageCount++
		}
	}
	if messageCount != 1 {
		t.Fatalf("rollover outbox count = %d, want 1", messageCount)
	}
}

func TestCertificateProfileIssuerRolloverRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	base := store.NewMemoryStore()
	boom := errors.New("audit unavailable")
	repo := &failAuditRepository{Repository: base, action: "certificate_profile.issuer_rolled_over", err: boom}
	service := New(repo, &fakeIssuer{}, fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}, &fakeIDGenerator{})
	root, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "root", Kind: domain.IssuerRootCA, CertificatePEM: "root-cert", KeyRef: "root-key", TrustAnchor: true})
	oldIssuer, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "old", Kind: domain.IssuerIntermediateCA, ParentIssuerID: root.ID, CertificatePEM: "old-cert", KeyRef: "old-key"})
	newIssuer, _ := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{Name: "new", Kind: domain.IssuerIntermediateCA, ParentIssuerID: root.ID, CertificatePEM: "new-cert", KeyRef: "new-key"})
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{Name: "profile", IssuerID: oldIssuer.ID, ValidityPeriodSeconds: 3600, AllowedSignatureAlgorithms: []string{"sha256"}, BasicConstraints: domain.BasicConstraintsPolicy{Critical: true}})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	_, err = service.TransitionCertificateProfileIssuer(ctx, "operator", TransitionCertificateProfileIssuerRequest{ProfileID: profile.ID, CurrentIssuerID: oldIssuer.ID, NextIssuerID: newIssuer.ID, Transition: CertificateProfileIssuerRollover, Reason: "planned"})
	if !errors.Is(err, boom) {
		t.Fatalf("TransitionCertificateProfileIssuer error = %v, want audit error", err)
	}
	stored, err := base.GetCertificateProfile(ctx, profile.ID)
	if err != nil {
		t.Fatalf("GetCertificateProfile returned error: %v", err)
	}
	if stored.IssuerID != oldIssuer.ID {
		t.Fatalf("profile issuer after audit failure = %q, want %q", stored.IssuerID, oldIssuer.ID)
	}
	messages, err := base.ListOutboxMessages(ctx, "")
	if err != nil {
		t.Fatalf("ListOutboxMessages returned error: %v", err)
	}
	for _, message := range messages {
		if message.Type == "certificate_profile.issuer_rolled_over" {
			t.Fatalf("rollover outbox persisted after audit failure: %#v", message)
		}
	}
}

type fakeIssuer struct {
	requests                        []corecli.IssueRequest
	crlRequests                     []corecli.GenerateCRLRequest
	ocspResponses                   []corecli.GenerateOCSPResponseRequest
	ocspResponderValidationRequests []ocspResponderValidationRequest
	csrInfo                         corecli.CSRInfo
	crlResult                       corecli.GenerateCRLResult
	crlErr                          error
	issuerOCSPInfo                  corecli.OCSPIssuerInfo
	issuerOCSPInfos                 map[string]corecli.OCSPIssuerInfo
	ocspInfo                        corecli.OCSPRequestInfo
	ocspResponseDER                 []byte
	ocspResponseErr                 error
	ocspResponderValidationResult   corecli.ValidateOCSPResponderResult
	issueSigningEvidence            *corecli.SigningEvidence
	crlSigningEvidence              *corecli.SigningEvidence
	ocspSigningEvidence             *corecli.SigningEvidence
	err                             error
}

func mustListAuditEvents(t *testing.T, service *Service, ctx context.Context) []domain.AuditEvent {
	t.Helper()
	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	return events
}

func testSigningEvidence(operation string, algorithm string) corecli.SigningEvidence {
	return corecli.SigningEvidence{
		SchemaVersion:               1,
		EvidenceSource:              "core_signing",
		Operation:                   operation,
		ProviderID:                  "openssl.file",
		ProviderClass:               "file",
		ProviderReadiness:           "ready",
		ProviderExportability:       "exportable",
		ReferenceClass:              "file",
		KeyAlgorithm:                "rsa",
		RequestedSignatureAlgorithm: algorithm,
		IssuerBindingVerified:       true,
		FallbackUsed:                false,
		ResultCode:                  "ok",
	}
}

func (f *fakeIssuer) signingEvidence(operation string, algorithm string) corecli.SigningEvidence {
	var override *corecli.SigningEvidence
	switch operation {
	case "certificate_issue":
		override = f.issueSigningEvidence
	case "crl_generate_sign":
		override = f.crlSigningEvidence
	case "ocsp_response_sign":
		override = f.ocspSigningEvidence
	}
	if override != nil {
		return *override
	}
	return testSigningEvidence(operation, algorithm)
}

type fakePublicTLSLintHook struct {
	request PublicTLSLintRequest
	err     error
}

func (f *fakePublicTLSLintHook) CheckPublicTLS(_ context.Context, req PublicTLSLintRequest) error {
	f.request = req
	return f.err
}

type fakeKeyProvider struct {
	refs []string
	err  error
}

func (f *fakeKeyProvider) CheckReady(_ context.Context, ref string) (keyref.ProviderInfo, error) {
	f.refs = append(f.refs, ref)
	if f.err != nil {
		return keyref.ProviderInfo{}, f.err
	}
	return keyref.ProviderInfo{
		Class:         keyref.Class(ref),
		Exportability: keyref.Exportability(ref),
	}, nil
}

type issueCertificateResult struct {
	certificate domain.Certificate
	err         error
}

type sequencedSerialIssuer struct {
	*fakeIssuer
	next int
}

func (f *sequencedSerialIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return corecli.IssueResult{}, f.err
	}
	f.next++
	return corecli.IssueResult{
		CertificatePEM:  "issued:" + req.CSRPEM,
		SerialNumber:    fmt.Sprintf("serial-%d:%s", f.next, req.Subject),
		Subject:         req.Subject,
		NotBefore:       req.NotBefore,
		NotAfter:        req.NotAfter,
		SigningEvidence: f.fakeIssuer.signingEvidence("certificate_issue", req.SignatureAlgorithm),
	}, nil
}

type blockingIssueIssuer struct {
	*fakeIssuer
	mu      sync.Mutex
	waitFor int
	count   int
	ready   chan struct{}
	release chan struct{}
}

func newBlockingIssueIssuer(waitFor int) *blockingIssueIssuer {
	return &blockingIssueIssuer{
		fakeIssuer: &fakeIssuer{},
		waitFor:    waitFor,
		ready:      make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (f *blockingIssueIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	f.mu.Lock()
	f.count++
	if f.count == f.waitFor {
		close(f.ready)
	}
	f.mu.Unlock()

	select {
	case <-f.release:
	case <-ctx.Done():
		return corecli.IssueResult{}, ctx.Err()
	}
	f.mu.Lock()
	f.fakeIssuer.requests = append(f.fakeIssuer.requests, req)
	err := f.fakeIssuer.err
	f.mu.Unlock()
	if err != nil {
		return corecli.IssueResult{}, err
	}
	return corecli.IssueResult{
		CertificatePEM:  "issued:" + req.CSRPEM,
		SerialNumber:    "serial:" + req.Subject,
		Subject:         req.Subject,
		NotBefore:       req.NotBefore,
		NotAfter:        req.NotAfter,
		SigningEvidence: f.fakeIssuer.signingEvidence("certificate_issue", req.SignatureAlgorithm),
	}, nil
}

type threadSafeIDGenerator struct {
	mu   sync.Mutex
	next int
}

func (g *threadSafeIDGenerator) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	return fmt.Sprintf("id-%d", g.next)
}

func (f *fakeIssuer) InspectCSR(ctx context.Context, csrPEM string) (corecli.CSRInfo, error) {
	if f.csrInfo.Subject != "" || len(f.csrInfo.DNSNames) != 0 || len(f.csrInfo.IPAddresses) != 0 {
		return f.csrInfo, nil
	}
	return corecli.CSRInfo{
		Subject:     "CN=edge-01",
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []string{"127.0.0.1"},
	}, nil
}

func (f *fakeIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return corecli.IssueResult{}, f.err
	}
	return corecli.IssueResult{
		CertificatePEM:  "issued:" + req.CSRPEM,
		SerialNumber:    "serial:" + req.Subject,
		Subject:         req.Subject,
		NotBefore:       req.NotBefore,
		NotAfter:        req.NotAfter,
		SigningEvidence: f.signingEvidence("certificate_issue", req.SignatureAlgorithm),
	}, nil
}

func (f *fakeIssuer) GenerateCRL(ctx context.Context, req corecli.GenerateCRLRequest) (corecli.GenerateCRLResult, error) {
	f.crlRequests = append(f.crlRequests, req)
	if f.crlErr != nil {
		return corecli.GenerateCRLResult{}, f.crlErr
	}
	if f.err != nil {
		return corecli.GenerateCRLResult{}, f.err
	}
	result := f.crlResult
	if result.SigningEvidence.SchemaVersion == 0 || f.crlSigningEvidence != nil {
		result.SigningEvidence = f.signingEvidence("crl_generate_sign", "sha256")
	}
	return result, nil
}

func (f *fakeIssuer) InspectOCSPIssuer(ctx context.Context, issuerCertificatePEM string, hashAlgorithm string) (corecli.OCSPIssuerInfo, error) {
	if f.err != nil {
		return corecli.OCSPIssuerInfo{}, f.err
	}
	if f.issuerOCSPInfos != nil {
		info := f.issuerOCSPInfos[issuerCertificatePEM]
		if info.HashAlgorithm == "" {
			info.HashAlgorithm = hashAlgorithm
		}
		return info, nil
	}
	if f.issuerOCSPInfo.IssuerNameHash == "" && f.issuerOCSPInfo.IssuerKeyHash == "" {
		return corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash", HashAlgorithm: hashAlgorithm}, nil
	}
	info := f.issuerOCSPInfo
	if info.HashAlgorithm == "" {
		info.HashAlgorithm = hashAlgorithm
	}
	return info, nil
}

func (f *fakeIssuer) ValidateOCSPResponder(ctx context.Context, issuerCertificatePEM string, responderCertificatePEM string) (corecli.ValidateOCSPResponderResult, error) {
	f.ocspResponderValidationRequests = append(f.ocspResponderValidationRequests, ocspResponderValidationRequest{
		issuerCertificatePEM:    issuerCertificatePEM,
		responderCertificatePEM: responderCertificatePEM,
	})
	if f.err != nil {
		return corecli.ValidateOCSPResponderResult{}, f.err
	}
	return f.ocspResponderValidationResult, nil
}

func (f *fakeIssuer) InspectOCSP(ctx context.Context, requestDER []byte) (corecli.OCSPRequestInfo, error) {
	if f.err != nil {
		return corecli.OCSPRequestInfo{}, f.err
	}
	return f.ocspInfo, nil
}

func (f *fakeIssuer) GenerateOCSPResponse(ctx context.Context, req corecli.GenerateOCSPResponseRequest) (corecli.GenerateOCSPResponseResult, error) {
	f.ocspResponses = append(f.ocspResponses, req)
	if f.ocspResponseErr != nil {
		return corecli.GenerateOCSPResponseResult{}, f.ocspResponseErr
	}
	if f.err != nil {
		return corecli.GenerateOCSPResponseResult{}, f.err
	}
	return corecli.GenerateOCSPResponseResult{
		ResponseDER:     f.ocspResponseDER,
		SigningEvidence: f.signingEvidence("ocsp_response_sign", "sha256"),
	}, nil
}

type ocspResponderValidationRequest struct {
	issuerCertificatePEM    string
	responderCertificatePEM string
}

type fakeACMEHTTP01Verifier struct {
	err      error
	requests []fakeACMEHTTP01Request
}

type fakeACMEHTTP01Request struct {
	Identifier       string
	Token            string
	KeyAuthorization string
}

func (f *fakeACMEHTTP01Verifier) VerifyHTTP01(ctx context.Context, identifier string, token string, keyAuthorization string) error {
	f.requests = append(f.requests, fakeACMEHTTP01Request{
		Identifier:       identifier,
		Token:            token,
		KeyAuthorization: keyAuthorization,
	})
	return f.err
}

type fakeCAALookup struct {
	domains []string
	result  CAALookupResult
	err     error
}

func (f *fakeCAALookup) LookupCAA(ctx context.Context, domain string) (CAALookupResult, error) {
	f.domains = append(f.domains, domain)
	if f.err != nil {
		return CAALookupResult{}, f.err
	}
	return f.result, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type fakeIDGenerator struct {
	next int
}

func (g *fakeIDGenerator) NewID() string {
	g.next++
	return fmt.Sprintf("id-%d", g.next)
}

type failAuditRepository struct {
	store.Repository
	action string
	err    error
}

func (r *failAuditRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&failAuditRepository{
			Repository: tx,
			action:     r.action,
			err:        r.err,
		})
	})
}

func (r *failAuditRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	if event.Action == r.action && r.err != nil {
		return r.err
	}
	return r.Repository.CreateAuditEvent(ctx, event)
}

type failCreateCertificateOnceRepository struct {
	store.Repository
	err    error
	failed bool
}

func (r *failCreateCertificateOnceRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&failCreateCertificateOnceTx{
			Repository: tx,
			parent:     r,
		})
	})
}

type failCreateCertificateOnceTx struct {
	store.Repository
	parent *failCreateCertificateOnceRepository
}

func (tx *failCreateCertificateOnceTx) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	if !tx.parent.failed {
		tx.parent.failed = true
		return tx.parent.err
	}
	return tx.Repository.CreateCertificate(ctx, certificate)
}

type staleTransitionRepository struct {
	store.Repository
	createCertificateCalled bool
	failConditionalUpdate   bool
}

func (r *staleTransitionRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&staleTransitionTx{
			Repository: tx,
			parent:     r,
		})
	})
}

type staleTransitionTx struct {
	store.Repository
	parent *staleTransitionRepository
}

func (tx *staleTransitionTx) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	if tx.parent.failConditionalUpdate {
		return domain.ErrInvalidTransition
	}
	return tx.Repository.UpdateEnrollmentIfStatus(ctx, enrollment, currentStatus)
}

func (tx *staleTransitionTx) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	tx.parent.createCertificateCalled = true
	return errors.New("CreateCertificate should not be called")
}

type staleRevocationRepository struct {
	store.Repository
	createRevocationCalled bool
	failConditionalUpdate  bool
}

func (r *staleRevocationRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&staleRevocationTx{
			Repository: tx,
			parent:     r,
		})
	})
}

type staleRevocationTx struct {
	store.Repository
	parent *staleRevocationRepository
}

func (tx *staleRevocationTx) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	if tx.parent.failConditionalUpdate {
		return domain.ErrInvalidTransition
	}
	return tx.Repository.UpdateCertificateIfStatus(ctx, certificate, currentStatus)
}

func (tx *staleRevocationTx) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	tx.parent.createRevocationCalled = true
	return errors.New("CreateRevocation should not be called")
}

func assertPolicyEvidenceRefs(t *testing.T, metadata map[string]any, identityID string, issuerID string, profileID string) {
	t.Helper()
	values, ok := metadata["policy_validation_evidence_refs"].([]any)
	if !ok || len(values) < 4 {
		t.Fatalf("policy evidence refs = %#v; metadata=%#v", metadata["policy_validation_evidence_refs"], metadata)
	}
	refs := make([]string, 0, len(values))
	for _, value := range values {
		ref, ok := value.(string)
		if !ok {
			t.Fatalf("policy evidence ref = %#v, want string", value)
		}
		refs = append(refs, ref)
	}
	want := []string{"schema:" + policyValidationEvidenceSchema, "identity:" + identityID, "issuer:" + issuerID}
	if profileID != "" {
		want = append(want, "profile:"+profileID)
	}
	for _, expected := range want {
		found := false
		for _, ref := range refs {
			if ref == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing policy evidence ref %q in %#v", expected, refs)
		}
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		t.Fatalf("marshal policy evidence refs: %v", err)
	}
	if strings.Contains(string(encoded), "edge-01.example.test") || strings.Contains(string(encoded), "csr-pem") {
		t.Fatalf("policy evidence refs expose raw policy input: %s", encoded)
	}
}

func auditMetadata(t *testing.T, event domain.AuditEvent) map[string]any {
	t.Helper()

	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.MetadataJSON), &metadata); err != nil {
		t.Fatalf("unmarshal audit metadata for %s: %v", event.Action, err)
	}
	return metadata
}

func findAuditEvent(t *testing.T, events []domain.AuditEvent, action string) domain.AuditEvent {
	t.Helper()

	for _, event := range events {
		if event.Action == action {
			return event
		}
	}
	t.Fatalf("audit event %q not found in %#v", action, events)
	return domain.AuditEvent{}
}

func findAuditEventForResource(t *testing.T, events []domain.AuditEvent, action string, resourceID string) domain.AuditEvent {
	t.Helper()

	for _, event := range events {
		if event.Action == action && event.ResourceID == resourceID {
			return event
		}
	}
	t.Fatalf("audit event %q for resource %q not found in %#v", action, resourceID, events)
	return domain.AuditEvent{}
}
