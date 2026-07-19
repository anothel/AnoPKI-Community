// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type MemoryStore struct {
	mu sync.RWMutex

	identities        map[string]domain.Identity
	issuers           map[string]domain.Issuer
	ocspResponders    map[string]domain.OCSPResponder
	notifications     map[string]domain.NotificationEndpoint
	profiles          map[string]domain.CertificateProfile
	enrollments       map[string]domain.Enrollment
	certificates      map[string]domain.Certificate
	issuanceAttempts  map[string]domain.IssuanceAttempt
	revocations       map[string]domain.Revocation
	crls              map[string]domain.CRLPublication
	crlClaims         map[string]domain.CRLGenerationClaim
	auditEvents       []domain.AuditEvent
	auditState        auditChainState
	outbox            map[string]domain.OutboxMessage
	jobAttempts       map[string]domain.JobAttempt
	webhookDeliveries map[string]domain.WebhookDelivery
	apiKeys           map[string]domain.APIKey
	acmeAccounts      map[string]domain.ACMEAccount
	acmeOrders        map[string]domain.ACMEOrder
	acmeAuthzs        map[string]domain.ACMEAuthorization
	acmeChallenges    map[string]domain.ACMEChallenge
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities:        make(map[string]domain.Identity),
		issuers:           make(map[string]domain.Issuer),
		ocspResponders:    make(map[string]domain.OCSPResponder),
		notifications:     make(map[string]domain.NotificationEndpoint),
		profiles:          make(map[string]domain.CertificateProfile),
		enrollments:       make(map[string]domain.Enrollment),
		certificates:      make(map[string]domain.Certificate),
		issuanceAttempts:  make(map[string]domain.IssuanceAttempt),
		revocations:       make(map[string]domain.Revocation),
		crls:              make(map[string]domain.CRLPublication),
		crlClaims:         make(map[string]domain.CRLGenerationClaim),
		auditEvents:       make([]domain.AuditEvent, 0),
		auditState:        emptyAuditChainState(),
		outbox:            make(map[string]domain.OutboxMessage),
		jobAttempts:       make(map[string]domain.JobAttempt),
		webhookDeliveries: make(map[string]domain.WebhookDelivery),
		apiKeys:           make(map[string]domain.APIKey),
		acmeAccounts:      make(map[string]domain.ACMEAccount),
		acmeOrders:        make(map[string]domain.ACMEOrder),
		acmeAuthzs:        make(map[string]domain.ACMEAuthorization),
		acmeChallenges:    make(map[string]domain.ACMEChallenge),
	}
}

func (s *MemoryStore) WithinTx(ctx context.Context, fn func(Repository) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx := &memoryTx{
		identities:        cloneIdentities(s.identities),
		issuers:           cloneIssuers(s.issuers),
		ocspResponders:    cloneOCSPResponders(s.ocspResponders),
		notifications:     cloneNotificationEndpoints(s.notifications),
		profiles:          cloneCertificateProfiles(s.profiles),
		enrollments:       cloneEnrollments(s.enrollments),
		certificates:      cloneCertificates(s.certificates),
		issuanceAttempts:  cloneIssuanceAttempts(s.issuanceAttempts),
		revocations:       cloneRevocations(s.revocations),
		crls:              cloneCRLPublications(s.crls),
		crlClaims:         cloneCRLGenerationClaims(s.crlClaims),
		auditEvents:       cloneAuditEvents(s.auditEvents),
		auditState:        s.auditState,
		outbox:            cloneOutboxMessages(s.outbox),
		jobAttempts:       cloneJobAttempts(s.jobAttempts),
		webhookDeliveries: cloneWebhookDeliveries(s.webhookDeliveries),
		apiKeys:           cloneAPIKeys(s.apiKeys),
		acmeAccounts:      cloneACMEAccounts(s.acmeAccounts),
		acmeOrders:        cloneACMEOrders(s.acmeOrders),
		acmeAuthzs:        cloneACMEAuthorizations(s.acmeAuthzs),
		acmeChallenges:    cloneACMEChallenges(s.acmeChallenges),
	}
	if err := fn(tx); err != nil {
		return err
	}

	s.identities = tx.identities
	s.issuers = tx.issuers
	s.ocspResponders = tx.ocspResponders
	s.notifications = tx.notifications
	s.profiles = tx.profiles
	s.enrollments = tx.enrollments
	s.certificates = tx.certificates
	s.issuanceAttempts = tx.issuanceAttempts
	s.revocations = tx.revocations
	s.crls = tx.crls
	s.crlClaims = tx.crlClaims
	s.auditEvents = tx.auditEvents
	s.auditState = tx.auditState
	s.outbox = tx.outbox
	s.jobAttempts = tx.jobAttempts
	s.webhookDeliveries = tx.webhookDeliveries
	s.apiKeys = tx.apiKeys
	s.acmeAccounts = tx.acmeAccounts
	s.acmeOrders = tx.acmeOrders
	s.acmeAuthzs = tx.acmeAuthzs
	s.acmeChallenges = tx.acmeChallenges
	return nil
}

func (s *MemoryStore) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.identities[identity.ID] = copyIdentity(identity)
	return nil
}

func (s *MemoryStore) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, ok := s.identities[id]
	if !ok {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	return copyIdentity(identity), nil
}

func (s *MemoryStore) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]domain.Identity, 0, len(s.identities))
	for _, identity := range s.identities {
		identities = append(identities, copyIdentity(identity))
	}
	return identities, nil
}

func (s *MemoryStore) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.issuers[issuer.ID] = copyIssuer(issuer)
	return nil
}

func (s *MemoryStore) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuer, ok := s.issuers[id]
	if !ok {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	return copyIssuer(issuer), nil
}

func (s *MemoryStore) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuers := make([]domain.Issuer, 0, len(s.issuers))
	for _, issuer := range s.issuers {
		issuers = append(issuers, copyIssuer(issuer))
	}
	return issuers, nil
}

func (s *MemoryStore) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if responder.Status == domain.OCSPResponderActive {
		if _, err := activeOCSPResponderByIssuer(s.ocspResponders, responder.IssuerID); err == nil {
			return domain.ErrInvalidTransition
		}
	}
	s.ocspResponders[responder.ID] = responder
	return nil
}

func (s *MemoryStore) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	responder, ok := s.ocspResponders[id]
	if !ok {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return responder, nil
}

func (s *MemoryStore) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listOCSPRespondersByIssuer(s.ocspResponders, issuerID), nil
}

func (s *MemoryStore) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return activeOCSPResponderByIssuer(s.ocspResponders, issuerID)
}

func (s *MemoryStore) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateOCSPResponderIfStatus(s.ocspResponders, responder, currentStatus)
}

func (s *MemoryStore) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.notifications[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func (s *MemoryStore) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	endpoint, ok := s.notifications[id]
	if !ok {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	return copyNotificationEndpoint(endpoint), nil
}

func (s *MemoryStore) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listNotificationEndpoints(s.notifications), nil
}

func (s *MemoryStore) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateNotificationEndpointIfStatus(s.notifications, endpoint, currentStatus)
}

func (s *MemoryStore) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.profiles[profile.ID] = copyCertificateProfile(profile)
	return nil
}

func (s *MemoryStore) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.profiles[id]
	if !ok {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	return copyCertificateProfile(profile), nil
}

func (s *MemoryStore) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profiles := make([]domain.CertificateProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		profiles = append(profiles, copyCertificateProfile(profile))
	}
	return profiles, nil
}

func (s *MemoryStore) UpdateCertificateProfileIssuerIfCurrent(ctx context.Context, profile domain.CertificateProfile, currentIssuerID string, currentUpdatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateCertificateProfileIssuerIfCurrent(s.profiles, profile, currentIssuerID, currentUpdatedAt)
}

func (s *MemoryStore) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (s *MemoryStore) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollment, ok := s.enrollments[id]
	if !ok {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	return copyEnrollment(enrollment), nil
}

func (s *MemoryStore) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollments := make([]domain.Enrollment, 0, len(s.enrollments))
	for _, enrollment := range s.enrollments {
		enrollments = append(enrollments, copyEnrollment(enrollment))
	}
	return enrollments, nil
}

func (s *MemoryStore) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.enrollments[enrollment.ID]; !ok {
		return domain.ErrEnrollmentNotFound
	}
	s.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (s *MemoryStore) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateEnrollmentIfStatus(s.enrollments, enrollment, currentStatus)
}

func (s *MemoryStore) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ensureCertificateFinalizationKeysAvailable(s.certificates, certificate); err != nil {
		return err
	}
	s.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (s *MemoryStore) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certificate, ok := s.certificates[id]
	if !ok {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	return copyCertificate(certificate), nil
}

func (s *MemoryStore) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return certificateByEnrollmentID(s.certificates, enrollmentID)
}

func (s *MemoryStore) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certificates := make([]domain.Certificate, 0, len(s.certificates))
	for _, certificate := range s.certificates {
		certificates = append(certificates, copyCertificate(certificate))
	}
	return certificates, nil
}

func (s *MemoryStore) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCertificateInventory(s.certificates, s.identities, s.issuers, filter), nil
}

func (s *MemoryStore) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCertificatesExpiringWithin(s.certificates, now, cutoff, limit, offset), nil
}

func (s *MemoryStore) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCertificatesForExpirationScan(s.certificates, now, warningBefore, limit), nil
}

func (s *MemoryStore) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.certificates[certificate.ID]; !ok {
		return domain.ErrCertificateNotFound
	}
	s.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (s *MemoryStore) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateCertificateIfStatus(s.certificates, certificate, currentStatus)
}

func (s *MemoryStore) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return createIssuanceAttempt(s.issuanceAttempts, attempt)
}

func (s *MemoryStore) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return getIssuanceAttempt(s.issuanceAttempts, enrollmentID)
}

func (s *MemoryStore) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateIssuanceAttemptIfCurrent(s.issuanceAttempts, attempt, current)
}

func (s *MemoryStore) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.revocations[revocation.ID] = revocation
	return nil
}

func (s *MemoryStore) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listRevocationsByIssuer(s.certificates, s.revocations, issuerID), nil
}

func (s *MemoryStore) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ensureCRLPublicationNumberAvailable(s.crls, publication); err != nil {
		return err
	}
	s.crls[publication.ID] = publication
	return nil
}

func (s *MemoryStore) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	publication, ok := s.crls[id]
	if !ok {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return publication, nil
}

func (s *MemoryStore) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return latestCRLPublicationByIssuer(s.crls, issuerID)
}

func (s *MemoryStore) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCRLPublicationsByIssuer(s.crls, issuerID), nil
}

func (s *MemoryStore) CreateCRLGenerationClaim(ctx context.Context, claim domain.CRLGenerationClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return createCRLGenerationClaim(s.crlClaims, claim)
}

func (s *MemoryStore) GetCRLGenerationClaim(ctx context.Context, issuerID string, distributionPoint string) (domain.CRLGenerationClaim, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return getCRLGenerationClaim(s.crlClaims, issuerID, distributionPoint)
}

func (s *MemoryStore) UpdateCRLGenerationClaimIfCurrent(ctx context.Context, claim domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateCRLGenerationClaimIfCurrent(s.crlClaims, claim, current)
}

func (s *MemoryStore) DeleteCRLGenerationClaimIfCurrent(ctx context.Context, current domain.CRLGenerationClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return deleteCRLGenerationClaimIfCurrent(s.crlClaims, current)
}

func (s *MemoryStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return appendMemoryAuditEvent(&s.auditEvents, &s.auditState, event)
}

func (s *MemoryStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := make([]domain.AuditEvent, len(s.auditEvents))
	copy(events, s.auditEvents)
	return events, nil
}

func (s *MemoryStore) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listAuditEventsQuery(s.auditEvents, query), nil
}

func (s *MemoryStore) VerifyAuditChain(ctx context.Context) (domain.AuditIntegrity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return verifyAuditState(s.auditEvents, s.auditState), nil
}

func (s *MemoryStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return pruneMemoryAuditEvents(&s.auditEvents, &s.auditState, before)
}

func (s *MemoryStore) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.outbox[message.ID] = message
	return nil
}

func (s *MemoryStore) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	message, ok := s.outbox[id]
	if !ok {
		return domain.OutboxMessage{}, domain.ErrOutboxMessageNotFound
	}
	return message, nil
}

func (s *MemoryStore) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listOutboxMessages(s.outbox, status), nil
}

func (s *MemoryStore) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listDueOutboxMessages(s.outbox, now, limit), nil
}

func (s *MemoryStore) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateOutboxMessageStatusIfStatus(s.outbox, message, currentStatus)
}

func (s *MemoryStore) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateOutboxMessageIfCurrent(s.outbox, message, current)
}

func (s *MemoryStore) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobAttempts[attempt.ID] = attempt
	return nil
}

func (s *MemoryStore) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listJobAttemptsByOutboxMessage(s.jobAttempts, outboxMessageID), nil
}

func (s *MemoryStore) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return getWebhookDelivery(s.webhookDeliveries, outboxMessageID, endpointID)
}

func (s *MemoryStore) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.webhookDeliveries[webhookDeliveryKey(delivery.OutboxMessageID, delivery.EndpointID)] = delivery
	return nil
}

func (s *MemoryStore) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.apiKeys[key.ID] = copyAPIKey(key)
	return nil
}

func (s *MemoryStore) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.apiKeys[id]
	if !ok {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	return copyAPIKey(key), nil
}

func (s *MemoryStore) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return apiKeyByTokenHash(s.apiKeys, tokenHash)
}

func (s *MemoryStore) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listAPIKeys(s.apiKeys), nil
}

func (s *MemoryStore) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateAPIKeyIfStatus(s.apiKeys, key, currentStatus)
}

func (s *MemoryStore) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ensureACMEAccountThumbprintAvailable(s.acmeAccounts, account); err != nil {
		return err
	}
	s.acmeAccounts[account.ID] = copyACMEAccount(account)
	return nil
}

func (s *MemoryStore) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, ok := s.acmeAccounts[id]
	if !ok {
		return domain.ACMEAccount{}, domain.ErrACMEAccountNotFound
	}
	return copyACMEAccount(account), nil
}

func (s *MemoryStore) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listACMEAccounts(s.acmeAccounts), nil
}

func (s *MemoryStore) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateACMEAccountIfStatus(s.acmeAccounts, account, currentStatus)
}

func (s *MemoryStore) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.acmeOrders[order.ID] = copyACMEOrder(order)
	return nil
}

func (s *MemoryStore) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	order, ok := s.acmeOrders[id]
	if !ok {
		return domain.ACMEOrder{}, domain.ErrACMEOrderNotFound
	}
	return copyACMEOrder(order), nil
}

func (s *MemoryStore) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listACMEOrdersByAccount(s.acmeOrders, accountID), nil
}

func (s *MemoryStore) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateACMEOrderIfStatus(s.acmeOrders, order, currentStatus)
}

func (s *MemoryStore) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.acmeAuthzs[authorization.ID] = authorization
	return nil
}

func (s *MemoryStore) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authorization, ok := s.acmeAuthzs[id]
	if !ok {
		return domain.ACMEAuthorization{}, domain.ErrACMEAuthorizationNotFound
	}
	return authorization, nil
}

func (s *MemoryStore) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listACMEAuthorizationsByOrder(s.acmeAuthzs, orderID), nil
}

func (s *MemoryStore) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateACMEAuthorizationIfStatus(s.acmeAuthzs, authorization, currentStatus)
}

func (s *MemoryStore) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.acmeChallenges[challenge.ID] = challenge
	return nil
}

func (s *MemoryStore) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	challenge, ok := s.acmeChallenges[id]
	if !ok {
		return domain.ACMEChallenge{}, domain.ErrACMEChallengeNotFound
	}
	return challenge, nil
}

func (s *MemoryStore) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listACMEChallengesByAuthorization(s.acmeChallenges, authorizationID), nil
}

func (s *MemoryStore) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateACMEChallengeIfStatus(s.acmeChallenges, challenge, currentStatus)
}

func copyEnrollment(enrollment domain.Enrollment) domain.Enrollment {
	enrollment.RequestedDNSNames = append([]string(nil), enrollment.RequestedDNSNames...)
	enrollment.RequestedIPAddresses = append([]string(nil), enrollment.RequestedIPAddresses...)
	enrollment.CSRDNSNames = append([]string(nil), enrollment.CSRDNSNames...)
	enrollment.CSRIPAddresses = append([]string(nil), enrollment.CSRIPAddresses...)
	return enrollment
}

func copyIssuer(issuer domain.Issuer) domain.Issuer {
	issuer.CRLDistributionPoints = append([]string(nil), issuer.CRLDistributionPoints...)
	return issuer
}

func copyCertificateProfile(profile domain.CertificateProfile) domain.CertificateProfile {
	profile.AllowedDNSPatterns = append([]string(nil), profile.AllowedDNSPatterns...)
	profile.AllowedIPRanges = append([]string(nil), profile.AllowedIPRanges...)
	profile.AllowedKeyAlgorithms = append([]string(nil), profile.AllowedKeyAlgorithms...)
	profile.AllowedSignatureAlgorithms = append([]string(nil), profile.AllowedSignatureAlgorithms...)
	profile.KeyUsage.Values = append([]string(nil), profile.KeyUsage.Values...)
	profile.ExtendedKeyUsage.Values = append([]string(nil), profile.ExtendedKeyUsage.Values...)
	return profile
}

func copyCertificate(certificate domain.Certificate) domain.Certificate {
	certificate.DNSNames = append([]string(nil), certificate.DNSNames...)
	certificate.IPAddresses = append([]string(nil), certificate.IPAddresses...)
	return certificate
}

func copyIssuanceAttempt(attempt domain.IssuanceAttempt) domain.IssuanceAttempt {
	return attempt
}

func ensureCertificateFinalizationKeysAvailable(certificates map[string]domain.Certificate, certificate domain.Certificate) error {
	for _, existing := range certificates {
		if existing.ID == certificate.ID {
			continue
		}
		if certificate.EnrollmentID != "" && existing.EnrollmentID == certificate.EnrollmentID {
			return domain.ErrInvalidTransition
		}
		if certificate.IssuerID != "" && certificate.SerialNumber != "" &&
			existing.IssuerID == certificate.IssuerID && existing.SerialNumber == certificate.SerialNumber {
			return domain.ErrInvalidTransition
		}
	}
	return nil
}

func certificateByEnrollmentID(certificates map[string]domain.Certificate, enrollmentID string) (domain.Certificate, error) {
	for _, certificate := range certificates {
		if certificate.EnrollmentID == enrollmentID {
			return copyCertificate(certificate), nil
		}
	}
	return domain.Certificate{}, domain.ErrCertificateNotFound
}

func createIssuanceAttempt(attempts map[string]domain.IssuanceAttempt, attempt domain.IssuanceAttempt) error {
	if _, ok := attempts[attempt.EnrollmentID]; ok {
		return domain.ErrInvalidTransition
	}
	attempts[attempt.EnrollmentID] = copyIssuanceAttempt(attempt)
	return nil
}

func getIssuanceAttempt(attempts map[string]domain.IssuanceAttempt, enrollmentID string) (domain.IssuanceAttempt, error) {
	attempt, ok := attempts[enrollmentID]
	if !ok {
		return domain.IssuanceAttempt{}, domain.ErrIssuanceAttemptNotFound
	}
	return copyIssuanceAttempt(attempt), nil
}

func crlGenerationClaimKey(issuerID string, distributionPoint string) string {
	return issuerID + "\x00" + distributionPoint
}

func createCRLGenerationClaim(claims map[string]domain.CRLGenerationClaim, claim domain.CRLGenerationClaim) error {
	key := crlGenerationClaimKey(claim.IssuerID, claim.DistributionPoint)
	if _, ok := claims[key]; ok {
		return domain.ErrInvalidTransition
	}
	claims[key] = claim
	return nil
}

func getCRLGenerationClaim(claims map[string]domain.CRLGenerationClaim, issuerID string, distributionPoint string) (domain.CRLGenerationClaim, error) {
	claim, ok := claims[crlGenerationClaimKey(issuerID, distributionPoint)]
	if !ok {
		return domain.CRLGenerationClaim{}, domain.ErrCRLGenerationClaimNotFound
	}
	return claim, nil
}

func updateCRLGenerationClaimIfCurrent(claims map[string]domain.CRLGenerationClaim, claim domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	key := crlGenerationClaimKey(claim.IssuerID, claim.DistributionPoint)
	stored, ok := claims[key]
	if !ok {
		return domain.ErrCRLGenerationClaimNotFound
	}
	if stored.CRLNumber != current.CRLNumber ||
		!stored.LeaseExpiresAt.Equal(current.LeaseExpiresAt) ||
		!stored.UpdatedAt.Equal(current.UpdatedAt) {
		return domain.ErrInvalidTransition
	}
	claims[key] = claim
	return nil
}

func deleteCRLGenerationClaimIfCurrent(claims map[string]domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	key := crlGenerationClaimKey(current.IssuerID, current.DistributionPoint)
	stored, ok := claims[key]
	if !ok {
		return domain.ErrCRLGenerationClaimNotFound
	}
	if stored.CRLNumber != current.CRLNumber ||
		!stored.LeaseExpiresAt.Equal(current.LeaseExpiresAt) ||
		!stored.UpdatedAt.Equal(current.UpdatedAt) {
		return domain.ErrInvalidTransition
	}
	delete(claims, key)
	return nil
}

func cloneCRLGenerationClaims(values map[string]domain.CRLGenerationClaim) map[string]domain.CRLGenerationClaim {
	cloned := make(map[string]domain.CRLGenerationClaim, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func copyNotificationEndpoint(endpoint domain.NotificationEndpoint) domain.NotificationEndpoint {
	endpoint.EventTypes = append([]string(nil), endpoint.EventTypes...)
	return endpoint
}

func copyAPIKey(key domain.APIKey) domain.APIKey {
	key.Scopes = append([]domain.APIKeyScope(nil), key.Scopes...)
	return key
}

func copyACMEAccount(account domain.ACMEAccount) domain.ACMEAccount {
	account.Contacts = append([]string(nil), account.Contacts...)
	return account
}

func copyACMEOrder(order domain.ACMEOrder) domain.ACMEOrder {
	order.RequestedDNSNames = append([]string(nil), order.RequestedDNSNames...)
	order.RequestedIPAddresses = append([]string(nil), order.RequestedIPAddresses...)
	return order
}

func updateEnrollmentIfStatus(enrollments map[string]domain.Enrollment, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	current, ok := enrollments[enrollment.ID]
	if !ok {
		return domain.ErrEnrollmentNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func updateCertificateIfStatus(certificates map[string]domain.Certificate, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	current, ok := certificates[certificate.ID]
	if !ok {
		return domain.ErrCertificateNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func updateIssuanceAttemptIfCurrent(attempts map[string]domain.IssuanceAttempt, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	stored, ok := attempts[attempt.EnrollmentID]
	if !ok {
		return domain.ErrIssuanceAttemptNotFound
	}
	if stored.Status != current.Status ||
		!stored.LeaseExpiresAt.Equal(current.LeaseExpiresAt) ||
		!stored.UpdatedAt.Equal(current.UpdatedAt) {
		return domain.ErrInvalidTransition
	}
	attempts[attempt.EnrollmentID] = copyIssuanceAttempt(attempt)
	return nil
}

func updateOCSPResponderIfStatus(responders map[string]domain.OCSPResponder, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	current, ok := responders[responder.ID]
	if !ok {
		return domain.ErrOCSPResponderNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	if responder.Status == domain.OCSPResponderActive {
		if active, err := activeOCSPResponderByIssuer(responders, responder.IssuerID); err == nil && active.ID != responder.ID {
			return domain.ErrInvalidTransition
		}
	}
	responders[responder.ID] = responder
	return nil
}

func updateNotificationEndpointIfStatus(endpoints map[string]domain.NotificationEndpoint, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	current, ok := endpoints[endpoint.ID]
	if !ok {
		return domain.ErrNotificationEndpointNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	endpoints[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func listNotificationEndpoints(endpoints map[string]domain.NotificationEndpoint) []domain.NotificationEndpoint {
	result := make([]domain.NotificationEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		result = append(result, copyNotificationEndpoint(endpoint))
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listDueOutboxMessages(messages map[string]domain.OutboxMessage, now time.Time, limit int) []domain.OutboxMessage {
	if limit <= 0 {
		return nil
	}

	due := make([]domain.OutboxMessage, 0)
	for _, message := range messages {
		if !outboxMessageDue(message, now) {
			continue
		}
		due = append(due, message)
	}
	sort.Slice(due, func(i, j int) bool {
		left := outboxMessageDueAt(due[i])
		right := outboxMessageDueAt(due[j])
		if !left.Equal(right) {
			return left.Before(right)
		}
		if !due[i].CreatedAt.Equal(due[j].CreatedAt) {
			return due[i].CreatedAt.Before(due[j].CreatedAt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	return due
}

func updateCertificateProfileIssuerIfCurrent(profiles map[string]domain.CertificateProfile, profile domain.CertificateProfile, currentIssuerID string, currentUpdatedAt time.Time) error {
	stored, ok := profiles[profile.ID]
	if !ok {
		return domain.ErrCertificateProfileNotFound
	}
	if stored.IssuerID != currentIssuerID || !stored.UpdatedAt.Equal(currentUpdatedAt) {
		return domain.ErrInvalidTransition
	}
	profiles[profile.ID] = copyCertificateProfile(profile)
	return nil
}

func outboxMessageDue(message domain.OutboxMessage, now time.Time) bool {
	switch message.Status {
	case domain.OutboxPending:
		return !message.AvailableAt.After(now)
	case domain.OutboxProcessing:
		return !message.ProcessingDeadlineAt.IsZero() && !message.ProcessingDeadlineAt.After(now)
	default:
		return false
	}
}

func outboxMessageDueAt(message domain.OutboxMessage) time.Time {
	if message.Status == domain.OutboxProcessing {
		return message.ProcessingDeadlineAt
	}
	return message.AvailableAt
}

func listOutboxMessages(messages map[string]domain.OutboxMessage, status domain.OutboxMessageStatus) []domain.OutboxMessage {
	result := make([]domain.OutboxMessage, 0)
	for _, message := range messages {
		if status != "" && message.Status != status {
			continue
		}
		result = append(result, message)
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func updateOutboxMessageStatusIfStatus(messages map[string]domain.OutboxMessage, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	current, ok := messages[message.ID]
	if !ok {
		return domain.ErrOutboxMessageNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	messages[message.ID] = message
	return nil
}

func updateOutboxMessageIfCurrent(messages map[string]domain.OutboxMessage, message domain.OutboxMessage, current domain.OutboxMessage) error {
	stored, ok := messages[message.ID]
	if !ok {
		return domain.ErrOutboxMessageNotFound
	}
	if stored.Status != current.Status ||
		!stored.ProcessingDeadlineAt.Equal(current.ProcessingDeadlineAt) ||
		!stored.UpdatedAt.Equal(current.UpdatedAt) {
		return domain.ErrInvalidTransition
	}
	messages[message.ID] = message
	return nil
}

func listJobAttemptsByOutboxMessage(attempts map[string]domain.JobAttempt, outboxMessageID string) []domain.JobAttempt {
	result := make([]domain.JobAttempt, 0)
	for _, attempt := range attempts {
		if attempt.OutboxMessageID == outboxMessageID {
			result = append(result, attempt)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listAPIKeys(keys map[string]domain.APIKey) []domain.APIKey {
	result := make([]domain.APIKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, copyAPIKey(key))
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func updateAPIKeyIfStatus(keys map[string]domain.APIKey, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	current, ok := keys[key.ID]
	if !ok {
		return domain.ErrAPIKeyNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	keys[key.ID] = copyAPIKey(key)
	return nil
}

func updateACMEAccountIfStatus(accounts map[string]domain.ACMEAccount, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	current, ok := accounts[account.ID]
	if !ok {
		return domain.ErrACMEAccountNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	if err := ensureACMEAccountThumbprintAvailable(accounts, account); err != nil {
		return err
	}
	accounts[account.ID] = copyACMEAccount(account)
	return nil
}

func updateACMEOrderIfStatus(orders map[string]domain.ACMEOrder, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	current, ok := orders[order.ID]
	if !ok {
		return domain.ErrACMEOrderNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	orders[order.ID] = copyACMEOrder(order)
	return nil
}

func updateACMEAuthorizationIfStatus(authorizations map[string]domain.ACMEAuthorization, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	current, ok := authorizations[authorization.ID]
	if !ok {
		return domain.ErrACMEAuthorizationNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	authorizations[authorization.ID] = authorization
	return nil
}

func updateACMEChallengeIfStatus(challenges map[string]domain.ACMEChallenge, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	current, ok := challenges[challenge.ID]
	if !ok {
		return domain.ErrACMEChallengeNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	challenges[challenge.ID] = challenge
	return nil
}

func listACMEAccounts(accounts map[string]domain.ACMEAccount) []domain.ACMEAccount {
	result := make([]domain.ACMEAccount, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, copyACMEAccount(account))
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listACMEOrdersByAccount(orders map[string]domain.ACMEOrder, accountID string) []domain.ACMEOrder {
	result := make([]domain.ACMEOrder, 0)
	for _, order := range orders {
		if order.AccountID == accountID {
			result = append(result, copyACMEOrder(order))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listACMEAuthorizationsByOrder(authorizations map[string]domain.ACMEAuthorization, orderID string) []domain.ACMEAuthorization {
	result := make([]domain.ACMEAuthorization, 0)
	for _, authorization := range authorizations {
		if authorization.OrderID == orderID {
			result = append(result, authorization)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listACMEChallengesByAuthorization(challenges map[string]domain.ACMEChallenge, authorizationID string) []domain.ACMEChallenge {
	result := make([]domain.ACMEChallenge, 0)
	for _, challenge := range challenges {
		if challenge.AuthorizationID == authorizationID {
			result = append(result, challenge)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

type memoryTx struct {
	identities        map[string]domain.Identity
	issuers           map[string]domain.Issuer
	ocspResponders    map[string]domain.OCSPResponder
	notifications     map[string]domain.NotificationEndpoint
	profiles          map[string]domain.CertificateProfile
	enrollments       map[string]domain.Enrollment
	certificates      map[string]domain.Certificate
	issuanceAttempts  map[string]domain.IssuanceAttempt
	revocations       map[string]domain.Revocation
	crls              map[string]domain.CRLPublication
	crlClaims         map[string]domain.CRLGenerationClaim
	auditEvents       []domain.AuditEvent
	auditState        auditChainState
	outbox            map[string]domain.OutboxMessage
	jobAttempts       map[string]domain.JobAttempt
	webhookDeliveries map[string]domain.WebhookDelivery
	apiKeys           map[string]domain.APIKey
	acmeAccounts      map[string]domain.ACMEAccount
	acmeOrders        map[string]domain.ACMEOrder
	acmeAuthzs        map[string]domain.ACMEAuthorization
	acmeChallenges    map[string]domain.ACMEChallenge
}

func (tx *memoryTx) WithinTx(ctx context.Context, fn func(Repository) error) error {
	return fn(tx)
}

func (tx *memoryTx) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	tx.identities[identity.ID] = copyIdentity(identity)
	return nil
}

func (tx *memoryTx) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	identity, ok := tx.identities[id]
	if !ok {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	return copyIdentity(identity), nil
}

func (tx *memoryTx) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	identities := make([]domain.Identity, 0, len(tx.identities))
	for _, identity := range tx.identities {
		identities = append(identities, copyIdentity(identity))
	}
	return identities, nil
}

func (tx *memoryTx) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	tx.issuers[issuer.ID] = copyIssuer(issuer)
	return nil
}

func (tx *memoryTx) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	issuer, ok := tx.issuers[id]
	if !ok {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	return copyIssuer(issuer), nil
}

func (tx *memoryTx) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	issuers := make([]domain.Issuer, 0, len(tx.issuers))
	for _, issuer := range tx.issuers {
		issuers = append(issuers, copyIssuer(issuer))
	}
	return issuers, nil
}

func (tx *memoryTx) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	if responder.Status == domain.OCSPResponderActive {
		if _, err := activeOCSPResponderByIssuer(tx.ocspResponders, responder.IssuerID); err == nil {
			return domain.ErrInvalidTransition
		}
	}
	tx.ocspResponders[responder.ID] = responder
	return nil
}

func (tx *memoryTx) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	responder, ok := tx.ocspResponders[id]
	if !ok {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return responder, nil
}

func (tx *memoryTx) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	return listOCSPRespondersByIssuer(tx.ocspResponders, issuerID), nil
}

func (tx *memoryTx) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	return activeOCSPResponderByIssuer(tx.ocspResponders, issuerID)
}

func (tx *memoryTx) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	return updateOCSPResponderIfStatus(tx.ocspResponders, responder, currentStatus)
}

func (tx *memoryTx) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	tx.notifications[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func (tx *memoryTx) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	endpoint, ok := tx.notifications[id]
	if !ok {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	return copyNotificationEndpoint(endpoint), nil
}

func (tx *memoryTx) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	return listNotificationEndpoints(tx.notifications), nil
}

func (tx *memoryTx) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	return updateNotificationEndpointIfStatus(tx.notifications, endpoint, currentStatus)
}

func (tx *memoryTx) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	tx.profiles[profile.ID] = copyCertificateProfile(profile)
	return nil
}

func (tx *memoryTx) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	profile, ok := tx.profiles[id]
	if !ok {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	return copyCertificateProfile(profile), nil
}

func (tx *memoryTx) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	profiles := make([]domain.CertificateProfile, 0, len(tx.profiles))
	for _, profile := range tx.profiles {
		profiles = append(profiles, copyCertificateProfile(profile))
	}
	return profiles, nil
}

func (tx *memoryTx) UpdateCertificateProfileIssuerIfCurrent(ctx context.Context, profile domain.CertificateProfile, currentIssuerID string, currentUpdatedAt time.Time) error {
	return updateCertificateProfileIssuerIfCurrent(tx.profiles, profile, currentIssuerID, currentUpdatedAt)
}

func (tx *memoryTx) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	tx.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (tx *memoryTx) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	enrollment, ok := tx.enrollments[id]
	if !ok {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	return copyEnrollment(enrollment), nil
}

func (tx *memoryTx) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	enrollments := make([]domain.Enrollment, 0, len(tx.enrollments))
	for _, enrollment := range tx.enrollments {
		enrollments = append(enrollments, copyEnrollment(enrollment))
	}
	return enrollments, nil
}

func (tx *memoryTx) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	if _, ok := tx.enrollments[enrollment.ID]; !ok {
		return domain.ErrEnrollmentNotFound
	}
	tx.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (tx *memoryTx) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	return updateEnrollmentIfStatus(tx.enrollments, enrollment, currentStatus)
}

func (tx *memoryTx) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	if err := ensureCertificateFinalizationKeysAvailable(tx.certificates, certificate); err != nil {
		return err
	}
	tx.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (tx *memoryTx) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	certificate, ok := tx.certificates[id]
	if !ok {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	return copyCertificate(certificate), nil
}

func (tx *memoryTx) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	return certificateByEnrollmentID(tx.certificates, enrollmentID)
}

func (tx *memoryTx) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	certificates := make([]domain.Certificate, 0, len(tx.certificates))
	for _, certificate := range tx.certificates {
		certificates = append(certificates, copyCertificate(certificate))
	}
	return certificates, nil
}

func (tx *memoryTx) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	return listCertificateInventory(tx.certificates, tx.identities, tx.issuers, filter), nil
}

func (tx *memoryTx) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	return listCertificatesExpiringWithin(tx.certificates, now, cutoff, limit, offset), nil
}

func (tx *memoryTx) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	return listCertificatesForExpirationScan(tx.certificates, now, warningBefore, limit), nil
}

func (tx *memoryTx) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	if _, ok := tx.certificates[certificate.ID]; !ok {
		return domain.ErrCertificateNotFound
	}
	tx.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (tx *memoryTx) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	return updateCertificateIfStatus(tx.certificates, certificate, currentStatus)
}

func (tx *memoryTx) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	return createIssuanceAttempt(tx.issuanceAttempts, attempt)
}

func (tx *memoryTx) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	return getIssuanceAttempt(tx.issuanceAttempts, enrollmentID)
}

func (tx *memoryTx) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	return updateIssuanceAttemptIfCurrent(tx.issuanceAttempts, attempt, current)
}

func (tx *memoryTx) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	tx.revocations[revocation.ID] = revocation
	return nil
}

func (tx *memoryTx) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	return listRevocationsByIssuer(tx.certificates, tx.revocations, issuerID), nil
}

func (tx *memoryTx) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	if err := ensureCRLPublicationNumberAvailable(tx.crls, publication); err != nil {
		return err
	}
	tx.crls[publication.ID] = publication
	return nil
}

func (tx *memoryTx) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	publication, ok := tx.crls[id]
	if !ok {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return publication, nil
}

func (tx *memoryTx) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	return latestCRLPublicationByIssuer(tx.crls, issuerID)
}

func (tx *memoryTx) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	return listCRLPublicationsByIssuer(tx.crls, issuerID), nil
}

func (tx *memoryTx) CreateCRLGenerationClaim(ctx context.Context, claim domain.CRLGenerationClaim) error {
	return createCRLGenerationClaim(tx.crlClaims, claim)
}

func (tx *memoryTx) GetCRLGenerationClaim(ctx context.Context, issuerID string, distributionPoint string) (domain.CRLGenerationClaim, error) {
	return getCRLGenerationClaim(tx.crlClaims, issuerID, distributionPoint)
}

func (tx *memoryTx) UpdateCRLGenerationClaimIfCurrent(ctx context.Context, claim domain.CRLGenerationClaim, current domain.CRLGenerationClaim) error {
	return updateCRLGenerationClaimIfCurrent(tx.crlClaims, claim, current)
}

func (tx *memoryTx) DeleteCRLGenerationClaimIfCurrent(ctx context.Context, current domain.CRLGenerationClaim) error {
	return deleteCRLGenerationClaimIfCurrent(tx.crlClaims, current)
}

func (tx *memoryTx) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return appendMemoryAuditEvent(&tx.auditEvents, &tx.auditState, event)
}

func (tx *memoryTx) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	events := make([]domain.AuditEvent, len(tx.auditEvents))
	copy(events, tx.auditEvents)
	return events, nil
}

func (tx *memoryTx) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	return listAuditEventsQuery(tx.auditEvents, query), nil
}

func (tx *memoryTx) VerifyAuditChain(ctx context.Context) (domain.AuditIntegrity, error) {
	return verifyAuditState(tx.auditEvents, tx.auditState), nil
}

func (tx *memoryTx) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	return pruneMemoryAuditEvents(&tx.auditEvents, &tx.auditState, before)
}

func (tx *memoryTx) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	tx.outbox[message.ID] = message
	return nil
}

func (tx *memoryTx) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	message, ok := tx.outbox[id]
	if !ok {
		return domain.OutboxMessage{}, domain.ErrOutboxMessageNotFound
	}
	return message, nil
}

func (tx *memoryTx) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	return listOutboxMessages(tx.outbox, status), nil
}

func (tx *memoryTx) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	return listDueOutboxMessages(tx.outbox, now, limit), nil
}

func (tx *memoryTx) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	return updateOutboxMessageStatusIfStatus(tx.outbox, message, currentStatus)
}

func (tx *memoryTx) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	return updateOutboxMessageIfCurrent(tx.outbox, message, current)
}

func (tx *memoryTx) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	tx.jobAttempts[attempt.ID] = attempt
	return nil
}

func (tx *memoryTx) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	return listJobAttemptsByOutboxMessage(tx.jobAttempts, outboxMessageID), nil
}

func (tx *memoryTx) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	return getWebhookDelivery(tx.webhookDeliveries, outboxMessageID, endpointID)
}

func (tx *memoryTx) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	tx.webhookDeliveries[webhookDeliveryKey(delivery.OutboxMessageID, delivery.EndpointID)] = delivery
	return nil
}

func (tx *memoryTx) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	tx.apiKeys[key.ID] = copyAPIKey(key)
	return nil
}

func (tx *memoryTx) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	key, ok := tx.apiKeys[id]
	if !ok {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	return copyAPIKey(key), nil
}

func (tx *memoryTx) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	return apiKeyByTokenHash(tx.apiKeys, tokenHash)
}

func (tx *memoryTx) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	return listAPIKeys(tx.apiKeys), nil
}

func (tx *memoryTx) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	return updateAPIKeyIfStatus(tx.apiKeys, key, currentStatus)
}

func (tx *memoryTx) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	if err := ensureACMEAccountThumbprintAvailable(tx.acmeAccounts, account); err != nil {
		return err
	}
	tx.acmeAccounts[account.ID] = copyACMEAccount(account)
	return nil
}

func (tx *memoryTx) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	account, ok := tx.acmeAccounts[id]
	if !ok {
		return domain.ACMEAccount{}, domain.ErrACMEAccountNotFound
	}
	return copyACMEAccount(account), nil
}

func (tx *memoryTx) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	return listACMEAccounts(tx.acmeAccounts), nil
}

func (tx *memoryTx) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	return updateACMEAccountIfStatus(tx.acmeAccounts, account, currentStatus)
}

func (tx *memoryTx) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	tx.acmeOrders[order.ID] = copyACMEOrder(order)
	return nil
}

func (tx *memoryTx) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	order, ok := tx.acmeOrders[id]
	if !ok {
		return domain.ACMEOrder{}, domain.ErrACMEOrderNotFound
	}
	return copyACMEOrder(order), nil
}

func (tx *memoryTx) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	return listACMEOrdersByAccount(tx.acmeOrders, accountID), nil
}

func (tx *memoryTx) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	return updateACMEOrderIfStatus(tx.acmeOrders, order, currentStatus)
}

func (tx *memoryTx) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	tx.acmeAuthzs[authorization.ID] = authorization
	return nil
}

func (tx *memoryTx) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	authorization, ok := tx.acmeAuthzs[id]
	if !ok {
		return domain.ACMEAuthorization{}, domain.ErrACMEAuthorizationNotFound
	}
	return authorization, nil
}

func (tx *memoryTx) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	return listACMEAuthorizationsByOrder(tx.acmeAuthzs, orderID), nil
}

func (tx *memoryTx) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	return updateACMEAuthorizationIfStatus(tx.acmeAuthzs, authorization, currentStatus)
}

func (tx *memoryTx) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	tx.acmeChallenges[challenge.ID] = challenge
	return nil
}

func (tx *memoryTx) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	challenge, ok := tx.acmeChallenges[id]
	if !ok {
		return domain.ACMEChallenge{}, domain.ErrACMEChallengeNotFound
	}
	return challenge, nil
}

func (tx *memoryTx) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	return listACMEChallengesByAuthorization(tx.acmeChallenges, authorizationID), nil
}

func (tx *memoryTx) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	return updateACMEChallengeIfStatus(tx.acmeChallenges, challenge, currentStatus)
}

func cloneIdentities(src map[string]domain.Identity) map[string]domain.Identity {
	dst := make(map[string]domain.Identity, len(src))
	for id, identity := range src {
		dst[id] = copyIdentity(identity)
	}
	return dst
}

func copyIdentity(identity domain.Identity) domain.Identity {
	identity.AllowedDNSNames = copyStringSlice(identity.AllowedDNSNames)
	identity.AllowedIPAddresses = copyStringSlice(identity.AllowedIPAddresses)
	return identity
}

func copyStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}

func cloneIssuers(src map[string]domain.Issuer) map[string]domain.Issuer {
	dst := make(map[string]domain.Issuer, len(src))
	for id, issuer := range src {
		dst[id] = copyIssuer(issuer)
	}
	return dst
}

func cloneOCSPResponders(src map[string]domain.OCSPResponder) map[string]domain.OCSPResponder {
	dst := make(map[string]domain.OCSPResponder, len(src))
	for id, responder := range src {
		dst[id] = responder
	}
	return dst
}

func cloneNotificationEndpoints(src map[string]domain.NotificationEndpoint) map[string]domain.NotificationEndpoint {
	dst := make(map[string]domain.NotificationEndpoint, len(src))
	for id, endpoint := range src {
		dst[id] = copyNotificationEndpoint(endpoint)
	}
	return dst
}

func cloneCertificateProfiles(src map[string]domain.CertificateProfile) map[string]domain.CertificateProfile {
	dst := make(map[string]domain.CertificateProfile, len(src))
	for id, profile := range src {
		dst[id] = copyCertificateProfile(profile)
	}
	return dst
}

func cloneEnrollments(src map[string]domain.Enrollment) map[string]domain.Enrollment {
	dst := make(map[string]domain.Enrollment, len(src))
	for id, enrollment := range src {
		dst[id] = copyEnrollment(enrollment)
	}
	return dst
}

func cloneCertificates(src map[string]domain.Certificate) map[string]domain.Certificate {
	dst := make(map[string]domain.Certificate, len(src))
	for id, certificate := range src {
		dst[id] = copyCertificate(certificate)
	}
	return dst
}

func cloneIssuanceAttempts(src map[string]domain.IssuanceAttempt) map[string]domain.IssuanceAttempt {
	dst := make(map[string]domain.IssuanceAttempt, len(src))
	for enrollmentID, attempt := range src {
		dst[enrollmentID] = copyIssuanceAttempt(attempt)
	}
	return dst
}

func cloneRevocations(src map[string]domain.Revocation) map[string]domain.Revocation {
	dst := make(map[string]domain.Revocation, len(src))
	for id, revocation := range src {
		dst[id] = revocation
	}
	return dst
}

func cloneCRLPublications(src map[string]domain.CRLPublication) map[string]domain.CRLPublication {
	dst := make(map[string]domain.CRLPublication, len(src))
	for id, publication := range src {
		dst[id] = publication
	}
	return dst
}

func listRevocationsByIssuer(certificates map[string]domain.Certificate, revocations map[string]domain.Revocation, issuerID string) []domain.RevokedCertificateEntry {
	entries := make([]domain.RevokedCertificateEntry, 0)
	for _, revocation := range revocations {
		certificate, ok := certificates[revocation.CertificateID]
		if !ok || certificate.IssuerID != issuerID || certificate.Status != domain.CertificateRevoked {
			continue
		}
		entries = append(entries, domain.RevokedCertificateEntry{
			CertificateID: certificate.ID,
			SerialNumber:  certificate.SerialNumber,
			RevokedAt:     revocation.RevokedAt,
			Reason:        revocation.Reason,
		})
	}
	return entries
}

func listCRLPublicationsByIssuer(publications map[string]domain.CRLPublication, issuerID string) []domain.CRLPublication {
	result := make([]domain.CRLPublication, 0)
	for _, publication := range publications {
		if publication.IssuerID == issuerID {
			result = append(result, publication)
		}
	}
	return result
}

func ensureCRLPublicationNumberAvailable(publications map[string]domain.CRLPublication, candidate domain.CRLPublication) error {
	for _, publication := range publications {
		if publication.ID != candidate.ID &&
			publication.IssuerID == candidate.IssuerID &&
			publication.DistributionPoint == candidate.DistributionPoint &&
			publication.CRLNumber == candidate.CRLNumber {
			return domain.ErrInvalidTransition
		}
	}
	return nil
}

func listOCSPRespondersByIssuer(responders map[string]domain.OCSPResponder, issuerID string) []domain.OCSPResponder {
	result := make([]domain.OCSPResponder, 0)
	for _, responder := range responders {
		if responder.IssuerID == issuerID {
			result = append(result, responder)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func activeOCSPResponderByIssuer(responders map[string]domain.OCSPResponder, issuerID string) (domain.OCSPResponder, error) {
	var active domain.OCSPResponder
	found := false
	for _, responder := range responders {
		if responder.IssuerID != issuerID || responder.Status != domain.OCSPResponderActive {
			continue
		}
		if !found || responder.CreatedAt.After(active.CreatedAt) || (responder.CreatedAt.Equal(active.CreatedAt) && responder.ID > active.ID) {
			active = responder
			found = true
		}
	}
	if !found {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return active, nil
}

func listCertificatesForExpirationScan(certificates map[string]domain.Certificate, now time.Time, warningBefore time.Time, limit int) []domain.Certificate {
	if limit <= 0 {
		return nil
	}
	result := make([]domain.Certificate, 0)
	for _, certificate := range certificates {
		if certificateNeedsExpirationScan(certificate, now, warningBefore) {
			result = append(result, copyCertificate(certificate))
		}
	}
	sort.Slice(result, func(i int, j int) bool {
		if !result[i].NotAfter.Equal(result[j].NotAfter) {
			return result[i].NotAfter.Before(result[j].NotAfter)
		}
		return result[i].ID < result[j].ID
	})
	if len(result) > limit {
		return result[:limit]
	}
	return result
}

func listCertificatesExpiringWithin(certificates map[string]domain.Certificate, now time.Time, cutoff time.Time, limit int, offset int) []domain.Certificate {
	result := make([]domain.Certificate, 0)
	for _, certificate := range certificates {
		if certificate.Status == domain.CertificateValid &&
			certificate.NotAfter.After(now) &&
			!certificate.NotAfter.After(cutoff) {
			result = append(result, copyCertificate(certificate))
		}
	}
	sort.Slice(result, func(i int, j int) bool {
		if !result[i].NotAfter.Equal(result[j].NotAfter) {
			return result[i].NotAfter.Before(result[j].NotAfter)
		}
		return result[i].ID < result[j].ID
	})
	if offset >= len(result) {
		return []domain.Certificate{}
	}
	result = result[offset:]
	if limit > 0 && len(result) > limit {
		return result[:limit]
	}
	return result
}

func listCertificateInventory(certificates map[string]domain.Certificate, identities map[string]domain.Identity, issuers map[string]domain.Issuer, filter CertificateInventoryFilter) []CertificateInventoryRecord {
	result := make([]CertificateInventoryRecord, 0)
	for _, certificate := range certificates {
		identity := identities[certificate.IdentityID]
		issuer := issuers[certificate.IssuerID]
		if !certificateInventoryRecordMatches(certificate, identity, filter) {
			continue
		}
		result = append(result, CertificateInventoryRecord{
			Certificate: copyCertificate(certificate),
			Identity:    copyIdentity(identity),
			Issuer:      copyIssuer(issuer),
		})
	}
	sort.Slice(result, func(i int, j int) bool {
		if filter.Sort == "desc" {
			return result[i].Certificate.ID > result[j].Certificate.ID
		}
		return result[i].Certificate.ID < result[j].Certificate.ID
	})
	if filter.Offset >= len(result) {
		return []CertificateInventoryRecord{}
	}
	result = result[filter.Offset:]
	if filter.Limit > 0 && filter.Limit < len(result) {
		result = result[:filter.Limit]
	}
	return result
}

func certificateInventoryRecordMatches(certificate domain.Certificate, identity domain.Identity, filter CertificateInventoryFilter) bool {
	if filter.Owner != "" && identity.Owner != filter.Owner {
		return false
	}
	if filter.Team != "" && identity.Team != filter.Team {
		return false
	}
	if filter.Service != "" && identity.Service != filter.Service {
		return false
	}
	if filter.Environment != "" && identity.Environment != filter.Environment {
		return false
	}
	if filter.IssuerID != "" && certificate.IssuerID != filter.IssuerID {
		return false
	}
	if filter.ProfileID != "" && certificate.CertificateProfileID != filter.ProfileID {
		return false
	}
	if filter.RevocationState != "" && string(certificate.Status) != filter.RevocationState {
		return false
	}
	return true
}

func certificateNeedsExpirationScan(certificate domain.Certificate, now time.Time, warningBefore time.Time) bool {
	if (certificate.Status == domain.CertificateValid || certificate.Status == domain.CertificateSuspended) && !certificate.NotAfter.After(now) {
		return true
	}
	return certificate.Status == domain.CertificateValid &&
		certificate.NotAfter.After(now) &&
		!certificate.NotAfter.After(warningBefore) &&
		certificate.RenewalNotifiedAt.IsZero()
}

func latestCRLPublicationByIssuer(publications map[string]domain.CRLPublication, issuerID string) (domain.CRLPublication, error) {
	var latest domain.CRLPublication
	found := false
	for _, publication := range publications {
		if publication.IssuerID != issuerID {
			continue
		}
		if !found || publication.CRLNumber > latest.CRLNumber || publication.CreatedAt.After(latest.CreatedAt) {
			latest = publication
			found = true
		}
	}
	if !found {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return latest, nil
}

func cloneAuditEvents(src []domain.AuditEvent) []domain.AuditEvent {
	dst := make([]domain.AuditEvent, len(src))
	copy(dst, src)
	return dst
}

func listAuditEventsQuery(events []domain.AuditEvent, query AuditEventQuery) []domain.AuditEvent {
	result := make([]domain.AuditEvent, 0, len(events))
	for _, event := range events {
		if query.Actor != "" && event.Actor != query.Actor {
			continue
		}
		if query.Action != "" && event.Action != query.Action {
			continue
		}
		if query.ResourceType != "" && event.ResourceType != query.ResourceType {
			continue
		}
		if query.ResourceID != "" && event.ResourceID != query.ResourceID {
			continue
		}
		if !query.CreatedFrom.IsZero() && event.CreatedAt.Before(query.CreatedFrom) {
			continue
		}
		if !query.CreatedTo.IsZero() && event.CreatedAt.After(query.CreatedTo) {
			continue
		}
		result = append(result, event)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			if query.Sort == "desc" {
				return result[i].ID > result[j].ID
			}
			return result[i].ID < result[j].ID
		}
		if query.Sort == "desc" {
			return result[i].CreatedAt.After(result[j].CreatedAt)
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	if query.Offset > 0 {
		if query.Offset >= len(result) {
			return []domain.AuditEvent{}
		}
		result = result[query.Offset:]
	}
	if query.Limit > 0 && query.Limit < len(result) {
		result = result[:query.Limit]
	}
	return result
}

func cloneOutboxMessages(src map[string]domain.OutboxMessage) map[string]domain.OutboxMessage {
	dst := make(map[string]domain.OutboxMessage, len(src))
	for id, message := range src {
		dst[id] = message
	}
	return dst
}

func cloneJobAttempts(src map[string]domain.JobAttempt) map[string]domain.JobAttempt {
	dst := make(map[string]domain.JobAttempt, len(src))
	for id, attempt := range src {
		dst[id] = attempt
	}
	return dst
}

func getWebhookDelivery(deliveries map[string]domain.WebhookDelivery, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	delivery, ok := deliveries[webhookDeliveryKey(outboxMessageID, endpointID)]
	if !ok {
		return domain.WebhookDelivery{}, domain.ErrWebhookDeliveryNotFound
	}
	return delivery, nil
}

func webhookDeliveryKey(outboxMessageID string, endpointID string) string {
	return outboxMessageID + "\x00" + endpointID
}

func cloneWebhookDeliveries(src map[string]domain.WebhookDelivery) map[string]domain.WebhookDelivery {
	dst := make(map[string]domain.WebhookDelivery, len(src))
	for id, delivery := range src {
		dst[id] = delivery
	}
	return dst
}

func cloneAPIKeys(src map[string]domain.APIKey) map[string]domain.APIKey {
	dst := make(map[string]domain.APIKey, len(src))
	for id, key := range src {
		dst[id] = copyAPIKey(key)
	}
	return dst
}

func cloneACMEAccounts(src map[string]domain.ACMEAccount) map[string]domain.ACMEAccount {
	dst := make(map[string]domain.ACMEAccount, len(src))
	for id, account := range src {
		dst[id] = copyACMEAccount(account)
	}
	return dst
}

func ensureACMEAccountThumbprintAvailable(accounts map[string]domain.ACMEAccount, candidate domain.ACMEAccount) error {
	if candidate.KeyThumbprint == "" {
		return nil
	}
	for _, account := range accounts {
		if account.ID != candidate.ID && account.KeyThumbprint == candidate.KeyThumbprint {
			return domain.ErrInvalidTransition
		}
	}
	return nil
}

func cloneACMEOrders(src map[string]domain.ACMEOrder) map[string]domain.ACMEOrder {
	dst := make(map[string]domain.ACMEOrder, len(src))
	for id, order := range src {
		dst[id] = copyACMEOrder(order)
	}
	return dst
}

func cloneACMEAuthorizations(src map[string]domain.ACMEAuthorization) map[string]domain.ACMEAuthorization {
	dst := make(map[string]domain.ACMEAuthorization, len(src))
	for id, authorization := range src {
		dst[id] = authorization
	}
	return dst
}

func cloneACMEChallenges(src map[string]domain.ACMEChallenge) map[string]domain.ACMEChallenge {
	dst := make(map[string]domain.ACMEChallenge, len(src))
	for id, challenge := range src {
		dst[id] = challenge
	}
	return dst
}

func apiKeyByTokenHash(keys map[string]domain.APIKey, tokenHash string) (domain.APIKey, error) {
	for _, key := range keys {
		if key.TokenHash == tokenHash {
			return copyAPIKey(key), nil
		}
	}
	return domain.APIKey{}, domain.ErrAPIKeyNotFound
}

func appendMemoryAuditEvent(events *[]domain.AuditEvent, state *auditChainState, event domain.AuditEvent) error {
	report := verifyAuditState(*events, *state)
	if err := auditIntegrityError(report); err != nil {
		return err
	}
	prepared, err := withAuditEventHash(report.LastSequence+1, report.LastEventHash, event)
	if err != nil {
		return err
	}
	*events = append(*events, prepared)
	state.HashAlgorithm = AuditHashAlgorithmSHA256V1
	state.LatestSequence = prepared.Sequence
	state.LatestEventHash = prepared.EventHash
	state.UpdatedAt = prepared.CreatedAt
	if after := verifyAuditState(*events, *state); !after.Valid {
		return auditIntegrityError(after)
	}
	return nil
}

func pruneMemoryAuditEvents(events *[]domain.AuditEvent, state *auditChainState, before time.Time) (int, error) {
	report := verifyAuditState(*events, *state)
	if err := auditIntegrityError(report); err != nil {
		return 0, err
	}
	deleteCount := auditRetentionPrefixLength(*events, before)
	if deleteCount < 0 {
		return 0, fmt.Errorf("%w: retention_cutoff_non_prefix", domain.ErrAuditIntegrity)
	}
	if deleteCount == 0 {
		return 0, nil
	}
	lastDeleted := (*events)[deleteCount-1]
	state.HashAlgorithm = AuditHashAlgorithmSHA256V1
	state.CheckpointSequence = lastDeleted.Sequence
	state.CheckpointEventHash = lastDeleted.EventHash
	state.UpdatedAt = lastDeleted.CreatedAt
	kept := make([]domain.AuditEvent, len(*events)-deleteCount)
	copy(kept, (*events)[deleteCount:])
	*events = kept
	if after := verifyAuditState(*events, *state); !after.Valid {
		return 0, auditIntegrityError(after)
	}
	return deleteCount, nil
}

func auditRetentionPrefixLength(events []domain.AuditEvent, before time.Time) int {
	deleteCount := 0
	seenRetained := false
	for _, event := range events {
		if event.CreatedAt.Before(before) {
			if seenRetained {
				return -1
			}
			deleteCount++
			continue
		}
		seenRetained = true
	}
	return deleteCount
}
