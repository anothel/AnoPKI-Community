// SPDX-License-Identifier: MPL-2.0
package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

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
