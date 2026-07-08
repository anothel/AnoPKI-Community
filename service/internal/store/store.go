// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity domain.Identity) error
	GetIdentity(ctx context.Context, id string) (domain.Identity, error)
	ListIdentities(ctx context.Context) ([]domain.Identity, error)
}

type IssuerRepository interface {
	CreateIssuer(ctx context.Context, issuer domain.Issuer) error
	GetIssuer(ctx context.Context, id string) (domain.Issuer, error)
	ListIssuers(ctx context.Context) ([]domain.Issuer, error)
}

type OCSPResponderRepository interface {
	CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error
	GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error)
	ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error)
	GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error)
	UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error
}

type NotificationEndpointRepository interface {
	CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error
	GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error)
	ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error)
	UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error
}

type CertificateProfileRepository interface {
	CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error
	GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error)
	ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error)
}

type EnrollmentRepository interface {
	CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error
	GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error)
	ListEnrollments(ctx context.Context) ([]domain.Enrollment, error)
	UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error
	UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error
}

type CertificateRepository interface {
	CreateCertificate(ctx context.Context, certificate domain.Certificate) error
	GetCertificate(ctx context.Context, id string) (domain.Certificate, error)
	GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error)
	ListCertificates(ctx context.Context) ([]domain.Certificate, error)
	ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error)
	ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error)
	ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error)
	UpdateCertificate(ctx context.Context, certificate domain.Certificate) error
	UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error
}

type CertificateInventoryFilter struct {
	Owner           string
	Team            string
	Service         string
	Environment     string
	IssuerID        string
	ProfileID       string
	RevocationState string
	Sort            string
	Limit           int
	Offset          int
}

type IdentityQuery struct {
	Owner       string
	Team        string
	Service     string
	Environment string
	Sort        string
	Limit       int
	Offset      int
}

type EnrollmentQuery struct {
	IdentityID string
	IssuerID   string
	ProfileID  string
	Status     domain.EnrollmentStatus
	Sort       string
	Limit      int
	Offset     int
}

type CertificateQuery struct {
	Owner           string
	Team            string
	Service         string
	Environment     string
	IssuerID        string
	ProfileID       string
	SAN             string
	RevocationState string
	RenewalState    string
	ExpiresAfter    time.Time
	ExpiresBefore   time.Time
	Sort            string
	Limit           int
	Offset          int
}

type CertificateInventoryRecord struct {
	Certificate domain.Certificate
	Identity    domain.Identity
	Issuer      domain.Issuer
}

type IssuanceAttemptRepository interface {
	CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error
	GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error)
	UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error
}

type RevocationRepository interface {
	CreateRevocation(ctx context.Context, revocation domain.Revocation) error
	ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error)
}

type CRLPublicationRepository interface {
	CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error
	GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error)
	GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error)
	ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error)
}

type AuditRepository interface {
	CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
	ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error)
	DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error)
}

type AuditEventQuery struct {
	Actor        string
	Action       string
	ResourceType string
	ResourceID   string
	CreatedFrom  time.Time
	CreatedTo    time.Time
	Sort         string
	Limit        int
	Offset       int
}

type OutboxRepository interface {
	CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error
	GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error)
	ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error)
	ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error)
	UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error
	UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error
	CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error
	ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error)
	GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error)
	UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error
}

type OutboxMessageQuery struct {
	Status      domain.OutboxMessageStatus
	Type        string
	CreatedFrom time.Time
	CreatedTo   time.Time
	Sort        string
	Limit       int
	Offset      int
}

type APIKeyRepository interface {
	CreateAPIKey(ctx context.Context, key domain.APIKey) error
	GetAPIKey(ctx context.Context, id string) (domain.APIKey, error)
	GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error)
	ListAPIKeys(ctx context.Context) ([]domain.APIKey, error)
	UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error
}

type ACMERepository interface {
	CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error
	GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error)
	ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error)
	UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error
	CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error
	GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error)
	ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error)
	UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error
	CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error
	GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error)
	ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error)
	UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error
	CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error
	GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error)
	ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error)
	UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error
}

type Repository interface {
	IdentityRepository
	IssuerRepository
	OCSPResponderRepository
	NotificationEndpointRepository
	CertificateProfileRepository
	EnrollmentRepository
	CertificateRepository
	IssuanceAttemptRepository
	RevocationRepository
	CRLPublicationRepository
	AuditRepository
	OutboxRepository
	APIKeyRepository
	ACMERepository
	WithinTx(ctx context.Context, fn func(Repository) error) error
}
