// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/lifecycle"
)

type createIdentityRequest struct {
	Type               domain.IdentityType `json:"type"`
	Name               string              `json:"name"`
	ExternalID         string              `json:"external_id"`
	Owner              string              `json:"owner"`
	Team               string              `json:"team"`
	Service            string              `json:"service"`
	Environment        string              `json:"environment"`
	DeploymentTarget   string              `json:"deployment_target"`
	LastSeenAt         time.Time           `json:"last_seen_at"`
	MetadataJSON       string              `json:"metadata_json"`
	AllowedDNSNames    []string            `json:"allowed_dns_names"`
	AllowedIPAddresses []string            `json:"allowed_ip_addresses"`
}

type createIssuerRequest struct {
	Name                  string            `json:"name"`
	Kind                  domain.IssuerKind `json:"kind"`
	ParentIssuerID        string            `json:"parent_issuer_id"`
	CertificatePEM        string            `json:"certificate_pem"`
	KeyRef                string            `json:"key_ref"`
	AIAURL                string            `json:"aia_url"`
	CRLDistributionPoints []string          `json:"crl_distribution_points"`
	TrustAnchor           bool              `json:"trust_anchor"`
}

type createOCSPResponderRequest struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	KeyRef         string `json:"key_ref"`
}

type createNotificationEndpointRequest struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Secret     string   `json:"secret"`
	EventTypes []string `json:"event_types"`
}

type replayDeadLetterOutboxRequest struct {
	EventType   string    `json:"event_type"`
	CreatedFrom time.Time `json:"created_from"`
	CreatedTo   time.Time `json:"created_to"`
	Limit       int       `json:"limit"`
}

type pruneAuditEventsRequest struct {
	Before time.Time `json:"before"`
}

type createCertificateProfileRequest struct {
	Name                       string                           `json:"name"`
	Description                string                           `json:"description"`
	IssuerID                   string                           `json:"issuer_id"`
	ValidityPeriodSeconds      int64                            `json:"validity_period_seconds"`
	PublicTLS                  bool                             `json:"public_tls"`
	SubjectTemplate            string                           `json:"subject_template"`
	AllowedDNSPatterns         []string                         `json:"allowed_dns_patterns"`
	AllowedIPRanges            []string                         `json:"allowed_ip_ranges"`
	AllowedKeyAlgorithms       []string                         `json:"allowed_key_algorithms"`
	MinKeySizeBits             int                              `json:"min_key_size_bits"`
	AllowedSignatureAlgorithms []string                         `json:"allowed_signature_algorithms"`
	KeyUsage                   domain.StringListExtensionPolicy `json:"key_usage"`
	ExtendedKeyUsage           domain.StringListExtensionPolicy `json:"extended_key_usage"`
	BasicConstraints           domain.BasicConstraintsPolicy    `json:"basic_constraints"`
	SubjectKeyIdentifier       bool                             `json:"subject_key_identifier"`
	AuthorityKeyIdentifier     bool                             `json:"authority_key_identifier"`
}

type createEnrollmentRequest struct {
	IdentityID           string    `json:"identity_id"`
	IssuerID             string    `json:"issuer_id"`
	CertificateProfileID string    `json:"profile_id"`
	CSRPEM               string    `json:"csr_pem"`
	RequestedSubject     string    `json:"requested_subject"`
	RequestedDNSNames    []string  `json:"requested_dns_names"`
	RequestedIPAddresses []string  `json:"requested_ip_addresses"`
	RequestedNotAfter    time.Time `json:"requested_not_after"`
}

type approveEnrollmentRequest struct {
	Reason string `json:"reason"`
}

type issueCertificateRequest struct {
	EnrollmentID string `json:"enrollment_id"`
}

type revokeCertificateRequest struct {
	Reason domain.RevocationReason `json:"reason"`
	Force  bool                    `json:"force,omitempty"`
}

type renewCertificateRequest struct {
	CSRPEM            string    `json:"csr_pem"`
	RequestedNotAfter time.Time `json:"requested_not_after"`
}

type reissueCertificateRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type scanCertificateExpirationsRequest struct {
	WarningWindowSeconds int64 `json:"warning_window_seconds"`
	Limit                int   `json:"limit"`
}

type createAPIKeyRequest struct {
	Name      string               `json:"name"`
	Actor     string               `json:"actor"`
	Scopes    []domain.APIKeyScope `json:"scopes"`
	ExpiresAt time.Time            `json:"expires_at"`
}

type publishCRLRequest struct {
	IssuerID          string    `json:"issuer_id"`
	DistributionPoint string    `json:"distribution_point"`
	NextUpdate        time.Time `json:"next_update"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type identityResponse struct {
	ID                 string                `json:"id"`
	Type               domain.IdentityType   `json:"type"`
	Name               string                `json:"name"`
	ExternalID         string                `json:"external_id"`
	Owner              string                `json:"owner"`
	Team               string                `json:"team"`
	Service            string                `json:"service"`
	Environment        string                `json:"environment"`
	DeploymentTarget   string                `json:"deployment_target"`
	LastSeenAt         time.Time             `json:"last_seen_at"`
	MetadataJSON       string                `json:"metadata_json"`
	AllowedDNSNames    []string              `json:"allowed_dns_names"`
	AllowedIPAddresses []string              `json:"allowed_ip_addresses"`
	Status             domain.IdentityStatus `json:"status"`
	CreatedAt          time.Time             `json:"created_at"`
	UpdatedAt          time.Time             `json:"updated_at"`
}

type issuerResponse struct {
	ID                    string              `json:"id"`
	Name                  string              `json:"name"`
	Kind                  domain.IssuerKind   `json:"kind"`
	Status                domain.IssuerStatus `json:"status"`
	ParentIssuerID        string              `json:"parent_issuer_id"`
	CertificatePEM        string              `json:"certificate_pem"`
	KeyRef                string              `json:"key_ref"`
	AIAURL                string              `json:"aia_url"`
	CRLDistributionPoints []string            `json:"crl_distribution_points"`
	TrustAnchor           bool                `json:"trust_anchor"`
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`
}

type ocspResponderResponse struct {
	ID             string                     `json:"id"`
	IssuerID       string                     `json:"issuer_id"`
	Name           string                     `json:"name"`
	Status         domain.OCSPResponderStatus `json:"status"`
	CertificatePEM string                     `json:"certificate_pem"`
	KeyRef         string                     `json:"key_ref"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

type notificationEndpointResponse struct {
	ID         string                            `json:"id"`
	Name       string                            `json:"name"`
	Type       domain.NotificationEndpointType   `json:"type"`
	Status     domain.NotificationEndpointStatus `json:"status"`
	URL        string                            `json:"url"`
	EventTypes []string                          `json:"event_types"`
	CreatedAt  time.Time                         `json:"created_at"`
	UpdatedAt  time.Time                         `json:"updated_at"`
}

type outboxMessageResponse struct {
	ID           string                     `json:"id"`
	Type         string                     `json:"type"`
	PayloadJSON  string                     `json:"payload_json"`
	Status       domain.OutboxMessageStatus `json:"status"`
	AvailableAt  time.Time                  `json:"available_at"`
	AttemptCount int                        `json:"attempt_count"`
	MaxAttempts  int                        `json:"max_attempts"`
	LastError    string                     `json:"last_error"`
	CreatedAt    time.Time                  `json:"created_at"`
	UpdatedAt    time.Time                  `json:"updated_at"`
}

type replayDeadLetterOutboxResponse struct {
	ReplayedCount int      `json:"replayed_count"`
	MessageIDs    []string `json:"message_ids"`
}

type certificateInventoryEntryResponse struct {
	CertificateID        string    `json:"certificate_id"`
	Owner                string    `json:"owner"`
	Team                 string    `json:"team"`
	Service              string    `json:"service"`
	Environment          string    `json:"environment"`
	DeploymentTarget     string    `json:"deployment_target"`
	IssuerID             string    `json:"issuer_id"`
	ProfileID            string    `json:"profile_id"`
	IssuerKeyRef         string    `json:"issuer_key_ref"`
	RevocationState      string    `json:"revocation_state"`
	LastSeenAt           time.Time `json:"last_seen_at"`
	CompletenessWarnings []string  `json:"completeness_warnings"`
}

type expirySLOResponse struct {
	WindowDays     int      `json:"window_days"`
	UnhandledCount int      `json:"unhandled_count"`
	UnhandledIDs   []string `json:"unhandled_ids"`
	OK             bool     `json:"ok"`
}

type apiKeyResponse struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Actor            string               `json:"actor"`
	Status           domain.APIKeyStatus  `json:"status"`
	Scopes           []domain.APIKeyScope `json:"scopes"`
	ExpiresAt        time.Time            `json:"expires_at"`
	LastUsedAt       time.Time            `json:"last_used_at"`
	TokenFingerprint string               `json:"token_fingerprint,omitempty"`
	Token            string               `json:"token,omitempty"`
	TokenHash        string               `json:"token_hash,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

type acmeAccountResponse struct {
	ID                   string                   `json:"id"`
	Contacts             []string                 `json:"contacts"`
	Status               domain.ACMEAccountStatus `json:"status"`
	TermsOfServiceAgreed bool                     `json:"terms_of_service_agreed"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
}

type acmeOrderResponse struct {
	ID                   string                 `json:"id"`
	AccountID            string                 `json:"account_id"`
	IdentityID           string                 `json:"identity_id"`
	IssuerID             string                 `json:"issuer_id"`
	CertificateProfileID string                 `json:"profile_id"`
	Status               domain.ACMEOrderStatus `json:"status"`
	CSRPEM               string                 `json:"csr_pem"`
	RequestedSubject     string                 `json:"requested_subject"`
	RequestedDNSNames    []string               `json:"requested_dns_names"`
	RequestedIPAddresses []string               `json:"requested_ip_addresses"`
	RequestedNotAfter    time.Time              `json:"requested_not_after"`
	EnrollmentID         string                 `json:"enrollment_id"`
	CertificateID        string                 `json:"certificate_id"`
	ExpiresAt            time.Time              `json:"expires_at"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type acmeAuthorizationResponse struct {
	ID                       string                         `json:"id"`
	OrderID                  string                         `json:"order_id"`
	IdentifierType           string                         `json:"identifier_type"`
	IdentifierValue          string                         `json:"identifier_value"`
	Status                   domain.ACMEAuthorizationStatus `json:"status"`
	ExpiresAt                time.Time                      `json:"expires_at"`
	ValidationReuseExpiresAt time.Time                      `json:"validation_reuse_expires_at"`
	CreatedAt                time.Time                      `json:"created_at"`
	UpdatedAt                time.Time                      `json:"updated_at"`
}

type acmeChallengeResponse struct {
	ID              string                     `json:"id"`
	AuthorizationID string                     `json:"authorization_id"`
	Type            domain.ACMEChallengeType   `json:"type"`
	Token           string                     `json:"token"`
	Status          domain.ACMEChallengeStatus `json:"status"`
	ValidatedAt     time.Time                  `json:"validated_at"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

type acmeProtocolAccountResponse struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Contact  []string `json:"contact"`
	Location string   `json:"location"`
}

type acmeProtocolOrderResponse struct {
	ID             string                           `json:"id"`
	Status         string                           `json:"status"`
	URL            string                           `json:"url"`
	Identifiers    []acmeProtocolIdentifierResponse `json:"identifiers"`
	Authorizations []string                         `json:"authorizations"`
	Finalize       string                           `json:"finalize"`
	Certificate    string                           `json:"certificate,omitempty"`
	Expires        time.Time                        `json:"expires"`
}

type acmeProtocolAuthorizationResponse struct {
	ID         string                          `json:"id"`
	Status     string                          `json:"status"`
	Identifier acmeProtocolIdentifierResponse  `json:"identifier"`
	Challenges []acmeProtocolChallengeResponse `json:"challenges"`
	Expires    time.Time                       `json:"expires"`
}

type acmeProtocolIdentifierResponse struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeProtocolChallengeResponse struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

type certificateProfileResponse struct {
	ID                         string                           `json:"id"`
	Name                       string                           `json:"name"`
	Description                string                           `json:"description"`
	IssuerID                   string                           `json:"issuer_id"`
	ValidityPeriodSeconds      int64                            `json:"validity_period_seconds"`
	PublicTLS                  bool                             `json:"public_tls"`
	SubjectTemplate            string                           `json:"subject_template"`
	AllowedDNSPatterns         []string                         `json:"allowed_dns_patterns"`
	AllowedIPRanges            []string                         `json:"allowed_ip_ranges"`
	AllowedKeyAlgorithms       []string                         `json:"allowed_key_algorithms"`
	MinKeySizeBits             int                              `json:"min_key_size_bits"`
	AllowedSignatureAlgorithms []string                         `json:"allowed_signature_algorithms"`
	KeyUsage                   domain.StringListExtensionPolicy `json:"key_usage"`
	ExtendedKeyUsage           domain.StringListExtensionPolicy `json:"extended_key_usage"`
	BasicConstraints           domain.BasicConstraintsPolicy    `json:"basic_constraints"`
	SubjectKeyIdentifier       bool                             `json:"subject_key_identifier"`
	AuthorityKeyIdentifier     bool                             `json:"authority_key_identifier"`
	CreatedAt                  time.Time                        `json:"created_at"`
	UpdatedAt                  time.Time                        `json:"updated_at"`
}

type enrollmentResponse struct {
	ID                   string                  `json:"id"`
	IdentityID           string                  `json:"identity_id"`
	IssuerID             string                  `json:"issuer_id"`
	CertificateProfileID string                  `json:"profile_id"`
	SourceCertificateID  string                  `json:"source_certificate_id"`
	CSRPEM               string                  `json:"csr_pem"`
	Status               domain.EnrollmentStatus `json:"status"`
	RequestedSubject     string                  `json:"requested_subject"`
	RequestedDNSNames    []string                `json:"requested_dns_names"`
	RequestedIPAddresses []string                `json:"requested_ip_addresses"`
	CSRDNSNames          []string                `json:"csr_dns_names"`
	CSRIPAddresses       []string                `json:"csr_ip_addresses"`
	RequestedNotAfter    time.Time               `json:"requested_not_after"`
	ApprovedBy           string                  `json:"approved_by"`
	ApprovedAt           time.Time               `json:"approved_at"`
	CreatedAt            time.Time               `json:"created_at"`
	UpdatedAt            time.Time               `json:"updated_at"`
}

type certificateResponse struct {
	ID                   string                   `json:"id"`
	IdentityID           string                   `json:"identity_id"`
	IssuerID             string                   `json:"issuer_id"`
	EnrollmentID         string                   `json:"enrollment_id"`
	CertificateProfileID string                   `json:"profile_id"`
	SerialNumber         string                   `json:"serial_number"`
	Subject              string                   `json:"subject"`
	DNSNames             []string                 `json:"dns_names"`
	IPAddresses          []string                 `json:"ip_addresses"`
	NotBefore            time.Time                `json:"not_before"`
	NotAfter             time.Time                `json:"not_after"`
	Status               domain.CertificateStatus `json:"status"`
	CertificatePEM       string                   `json:"certificate_pem"`
	RenewalNotifiedAt    time.Time                `json:"renewal_notified_at"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
}

type certificateExpirationScanResponse struct {
	Expired            []certificateResponse `json:"expired"`
	ExpirationWarnings []certificateResponse `json:"expiration_warnings"`
}

type crlPublicationResponse struct {
	ID                string                      `json:"id"`
	IssuerID          string                      `json:"issuer_id"`
	DistributionPoint string                      `json:"distribution_point"`
	CRLNumber         int64                       `json:"crl_number"`
	ThisUpdate        time.Time                   `json:"this_update"`
	NextUpdate        time.Time                   `json:"next_update"`
	Status            domain.CRLPublicationStatus `json:"status"`
	CRLPEM            string                      `json:"crl_pem"`
	CreatedAt         time.Time                   `json:"created_at"`
	UpdatedAt         time.Time                   `json:"updated_at"`
}

type auditEventResponse struct {
	ID                string    `json:"id"`
	Sequence          int64     `json:"sequence"`
	Actor             string    `json:"actor"`
	Action            string    `json:"action"`
	ResourceType      string    `json:"resource_type"`
	ResourceID        string    `json:"resource_id"`
	MetadataJSON      string    `json:"metadata_json"`
	HashAlgorithm     string    `json:"hash_algorithm"`
	PreviousEventHash string    `json:"previous_event_hash"`
	EventHash         string    `json:"event_hash"`
	CreatedAt         time.Time `json:"created_at"`
}

type auditIntegrityResponse struct {
	Valid               bool   `json:"valid"`
	HashAlgorithm       string `json:"hash_algorithm"`
	EventCount          int    `json:"event_count"`
	FirstSequence       int64  `json:"first_sequence"`
	LastSequence        int64  `json:"last_sequence"`
	LastEventHash       string `json:"last_event_hash"`
	CheckpointSequence  int64  `json:"checkpoint_sequence"`
	CheckpointEventHash string `json:"checkpoint_event_hash"`
	FailureReason       string `json:"failure_reason,omitempty"`
}

type repairIssuanceAuditEventsResponse struct {
	RepairedCount int `json:"repaired_count"`
}

type pruneAuditEventsResponse struct {
	DeletedCount int `json:"deleted_count"`
}

func toIdentityResponse(identity domain.Identity) identityResponse {
	return identityResponse{
		ID:                 identity.ID,
		Type:               identity.Type,
		Name:               identity.Name,
		ExternalID:         identity.ExternalID,
		Owner:              identity.Owner,
		Team:               identity.Team,
		Service:            identity.Service,
		Environment:        identity.Environment,
		DeploymentTarget:   identity.DeploymentTarget,
		LastSeenAt:         identity.LastSeenAt,
		MetadataJSON:       identity.MetadataJSON,
		AllowedDNSNames:    identity.AllowedDNSNames,
		AllowedIPAddresses: identity.AllowedIPAddresses,
		Status:             identity.Status,
		CreatedAt:          identity.CreatedAt,
		UpdatedAt:          identity.UpdatedAt,
	}
}

func toIdentityResponses(identities []domain.Identity) []identityResponse {
	responses := make([]identityResponse, 0, len(identities))
	for _, identity := range identities {
		responses = append(responses, toIdentityResponse(identity))
	}
	return responses
}

func toIssuerResponse(issuer domain.Issuer) issuerResponse {
	return issuerResponse{
		ID:                    issuer.ID,
		Name:                  issuer.Name,
		Kind:                  issuer.Kind,
		Status:                issuer.Status,
		ParentIssuerID:        issuer.ParentIssuerID,
		CertificatePEM:        issuer.CertificatePEM,
		KeyRef:                issuer.KeyRef,
		AIAURL:                issuer.AIAURL,
		CRLDistributionPoints: issuer.CRLDistributionPoints,
		TrustAnchor:           issuer.TrustAnchor,
		CreatedAt:             issuer.CreatedAt,
		UpdatedAt:             issuer.UpdatedAt,
	}
}

func toIssuerResponses(issuers []domain.Issuer) []issuerResponse {
	responses := make([]issuerResponse, 0, len(issuers))
	for _, issuer := range issuers {
		responses = append(responses, toIssuerResponse(issuer))
	}
	return responses
}

func toOCSPResponderResponse(responder domain.OCSPResponder) ocspResponderResponse {
	return ocspResponderResponse{
		ID:             responder.ID,
		IssuerID:       responder.IssuerID,
		Name:           responder.Name,
		Status:         responder.Status,
		CertificatePEM: responder.CertificatePEM,
		KeyRef:         responder.KeyRef,
		CreatedAt:      responder.CreatedAt,
		UpdatedAt:      responder.UpdatedAt,
	}
}

func toOCSPResponderResponses(responders []domain.OCSPResponder) []ocspResponderResponse {
	responses := make([]ocspResponderResponse, 0, len(responders))
	for _, responder := range responders {
		responses = append(responses, toOCSPResponderResponse(responder))
	}
	return responses
}

func toNotificationEndpointResponse(endpoint domain.NotificationEndpoint) notificationEndpointResponse {
	return notificationEndpointResponse{
		ID:         endpoint.ID,
		Name:       endpoint.Name,
		Type:       endpoint.Type,
		Status:     endpoint.Status,
		URL:        endpoint.URL,
		EventTypes: endpoint.EventTypes,
		CreatedAt:  endpoint.CreatedAt,
		UpdatedAt:  endpoint.UpdatedAt,
	}
}

func toNotificationEndpointResponses(endpoints []domain.NotificationEndpoint) []notificationEndpointResponse {
	responses := make([]notificationEndpointResponse, 0, len(endpoints))
	for _, endpoint := range endpoints {
		responses = append(responses, toNotificationEndpointResponse(endpoint))
	}
	return responses
}

func toOutboxMessageResponse(message domain.OutboxMessage) outboxMessageResponse {
	return outboxMessageResponse{
		ID:           message.ID,
		Type:         message.Type,
		PayloadJSON:  message.PayloadJSON,
		Status:       message.Status,
		AvailableAt:  message.AvailableAt,
		AttemptCount: message.AttemptCount,
		MaxAttempts:  message.MaxAttempts,
		LastError:    message.LastError,
		CreatedAt:    message.CreatedAt,
		UpdatedAt:    message.UpdatedAt,
	}
}

func toOutboxMessageResponses(messages []domain.OutboxMessage) []outboxMessageResponse {
	responses := make([]outboxMessageResponse, 0, len(messages))
	for _, message := range messages {
		responses = append(responses, toOutboxMessageResponse(message))
	}
	return responses
}

func toReplayDeadLetterOutboxResponse(result lifecycle.ReplayDeadLetterOutboxResult) replayDeadLetterOutboxResponse {
	ids := make([]string, 0, len(result.ReplayedMessages))
	for _, message := range result.ReplayedMessages {
		ids = append(ids, message.ID)
	}
	return replayDeadLetterOutboxResponse{
		ReplayedCount: len(ids),
		MessageIDs:    ids,
	}
}

func toCertificateInventoryResponse(entry lifecycle.CertificateInventoryEntry) certificateInventoryEntryResponse {
	return certificateInventoryEntryResponse{
		CertificateID:        entry.CertificateID,
		Owner:                entry.Owner,
		Team:                 entry.Team,
		Service:              entry.Service,
		Environment:          entry.Environment,
		DeploymentTarget:     entry.DeploymentTarget,
		IssuerID:             entry.IssuerID,
		ProfileID:            entry.ProfileID,
		IssuerKeyRef:         entry.IssuerKeyRef,
		RevocationState:      entry.RevocationState,
		LastSeenAt:           entry.LastSeenAt,
		CompletenessWarnings: entry.CompletenessWarnings,
	}
}

func toCertificateInventoryResponses(entries []lifecycle.CertificateInventoryEntry) []certificateInventoryEntryResponse {
	responses := make([]certificateInventoryEntryResponse, 0, len(entries))
	for _, entry := range entries {
		responses = append(responses, toCertificateInventoryResponse(entry))
	}
	return responses
}

func toExpirySLOResponse(slo lifecycle.ExpirySLO) expirySLOResponse {
	return expirySLOResponse{
		WindowDays:     slo.WindowDays,
		UnhandledCount: slo.UnhandledCount,
		UnhandledIDs:   slo.UnhandledIDs,
		OK:             slo.OK,
	}
}

func toAPIKeyResponse(key domain.APIKey) apiKeyResponse {
	return apiKeyResponse{
		ID:               key.ID,
		Name:             key.Name,
		Actor:            key.Actor,
		Status:           key.Status,
		Scopes:           key.Scopes,
		ExpiresAt:        key.ExpiresAt,
		LastUsedAt:       key.LastUsedAt,
		TokenFingerprint: lifecycle.APIKeyTokenFingerprint(key.TokenHash),
		CreatedAt:        key.CreatedAt,
		UpdatedAt:        key.UpdatedAt,
	}
}

func toAPIKeyResponseWithToken(key domain.APIKey, token string) apiKeyResponse {
	response := toAPIKeyResponse(key)
	response.Token = token
	return response
}

func toAPIKeyResponses(keys []domain.APIKey) []apiKeyResponse {
	responses := make([]apiKeyResponse, 0, len(keys))
	for _, key := range keys {
		responses = append(responses, toAPIKeyResponse(key))
	}
	return responses
}

func toCertificateProfileResponse(profile domain.CertificateProfile) certificateProfileResponse {
	return certificateProfileResponse{
		ID:                         profile.ID,
		Name:                       profile.Name,
		Description:                profile.Description,
		IssuerID:                   profile.IssuerID,
		ValidityPeriodSeconds:      profile.ValidityPeriodSeconds,
		PublicTLS:                  profile.PublicTLS,
		SubjectTemplate:            profile.SubjectTemplate,
		AllowedDNSPatterns:         profile.AllowedDNSPatterns,
		AllowedIPRanges:            profile.AllowedIPRanges,
		AllowedKeyAlgorithms:       profile.AllowedKeyAlgorithms,
		MinKeySizeBits:             profile.MinKeySizeBits,
		AllowedSignatureAlgorithms: profile.AllowedSignatureAlgorithms,
		KeyUsage:                   profile.KeyUsage,
		ExtendedKeyUsage:           profile.ExtendedKeyUsage,
		BasicConstraints:           profile.BasicConstraints,
		SubjectKeyIdentifier:       profile.SubjectKeyIdentifier,
		AuthorityKeyIdentifier:     profile.AuthorityKeyIdentifier,
		CreatedAt:                  profile.CreatedAt,
		UpdatedAt:                  profile.UpdatedAt,
	}
}

func toCertificateProfileResponses(profiles []domain.CertificateProfile) []certificateProfileResponse {
	responses := make([]certificateProfileResponse, 0, len(profiles))
	for _, profile := range profiles {
		responses = append(responses, toCertificateProfileResponse(profile))
	}
	return responses
}

func toEnrollmentResponse(enrollment domain.Enrollment) enrollmentResponse {
	return enrollmentResponse{
		ID:                   enrollment.ID,
		IdentityID:           enrollment.IdentityID,
		IssuerID:             enrollment.IssuerID,
		CertificateProfileID: enrollment.CertificateProfileID,
		SourceCertificateID:  enrollment.SourceCertificateID,
		CSRPEM:               enrollment.CSRPEM,
		Status:               enrollment.Status,
		RequestedSubject:     enrollment.RequestedSubject,
		RequestedDNSNames:    enrollment.RequestedDNSNames,
		RequestedIPAddresses: enrollment.RequestedIPAddresses,
		CSRDNSNames:          enrollment.CSRDNSNames,
		CSRIPAddresses:       enrollment.CSRIPAddresses,
		RequestedNotAfter:    enrollment.RequestedNotAfter,
		ApprovedBy:           enrollment.ApprovedBy,
		ApprovedAt:           enrollment.ApprovedAt,
		CreatedAt:            enrollment.CreatedAt,
		UpdatedAt:            enrollment.UpdatedAt,
	}
}

func toEnrollmentResponses(enrollments []domain.Enrollment) []enrollmentResponse {
	responses := make([]enrollmentResponse, 0, len(enrollments))
	for _, enrollment := range enrollments {
		responses = append(responses, toEnrollmentResponse(enrollment))
	}
	return responses
}

func toCertificateResponse(certificate domain.Certificate) certificateResponse {
	return certificateResponse{
		ID:                   certificate.ID,
		IdentityID:           certificate.IdentityID,
		IssuerID:             certificate.IssuerID,
		EnrollmentID:         certificate.EnrollmentID,
		CertificateProfileID: certificate.CertificateProfileID,
		SerialNumber:         certificate.SerialNumber,
		Subject:              certificate.Subject,
		DNSNames:             certificate.DNSNames,
		IPAddresses:          certificate.IPAddresses,
		NotBefore:            certificate.NotBefore,
		NotAfter:             certificate.NotAfter,
		Status:               certificate.Status,
		CertificatePEM:       certificate.CertificatePEM,
		RenewalNotifiedAt:    certificate.RenewalNotifiedAt,
		CreatedAt:            certificate.CreatedAt,
		UpdatedAt:            certificate.UpdatedAt,
	}
}

func toCertificateResponses(certificates []domain.Certificate) []certificateResponse {
	responses := make([]certificateResponse, 0, len(certificates))
	for _, certificate := range certificates {
		responses = append(responses, toCertificateResponse(certificate))
	}
	return responses
}

func toCertificateExpirationScanResponse(result lifecycle.CertificateExpirationScanResult) certificateExpirationScanResponse {
	return certificateExpirationScanResponse{
		Expired:            toCertificateResponses(result.Expired),
		ExpirationWarnings: toCertificateResponses(result.ExpirationWarnings),
	}
}

func toCRLPublicationResponse(publication domain.CRLPublication) crlPublicationResponse {
	return crlPublicationResponse{
		ID:                publication.ID,
		IssuerID:          publication.IssuerID,
		DistributionPoint: publication.DistributionPoint,
		CRLNumber:         publication.CRLNumber,
		ThisUpdate:        publication.ThisUpdate,
		NextUpdate:        publication.NextUpdate,
		Status:            publication.Status,
		CRLPEM:            publication.CRLPEM,
		CreatedAt:         publication.CreatedAt,
		UpdatedAt:         publication.UpdatedAt,
	}
}

func toAuditEventResponse(event domain.AuditEvent) auditEventResponse {
	return auditEventResponse{
		ID:                event.ID,
		Sequence:          event.Sequence,
		Actor:             event.Actor,
		Action:            event.Action,
		ResourceType:      event.ResourceType,
		ResourceID:        event.ResourceID,
		MetadataJSON:      event.MetadataJSON,
		HashAlgorithm:     event.HashAlgorithm,
		PreviousEventHash: event.PreviousEventHash,
		EventHash:         event.EventHash,
		CreatedAt:         event.CreatedAt,
	}
}

func toAuditIntegrityResponse(report domain.AuditIntegrity) auditIntegrityResponse {
	return auditIntegrityResponse{
		Valid:               report.Valid,
		HashAlgorithm:       report.HashAlgorithm,
		EventCount:          report.EventCount,
		FirstSequence:       report.FirstSequence,
		LastSequence:        report.LastSequence,
		LastEventHash:       report.LastEventHash,
		CheckpointSequence:  report.CheckpointSequence,
		CheckpointEventHash: report.CheckpointEventHash,
		FailureReason:       report.FailureReason,
	}
}

func toAuditEventResponses(events []domain.AuditEvent) []auditEventResponse {
	responses := make([]auditEventResponse, 0, len(events))
	for _, event := range events {
		responses = append(responses, toAuditEventResponse(event))
	}
	return responses
}
