// SPDX-License-Identifier: MPL-2.0
package domain

import "time"

type IdentityType string

const (
	IdentityUser      IdentityType = "user"
	IdentityMachine   IdentityType = "machine"
	IdentityService   IdentityType = "service"
	IdentityIoTDevice IdentityType = "iot_device"
	IdentityWorkload  IdentityType = "workload"
)

type IdentityStatus string

const (
	IdentityActive   IdentityStatus = "active"
	IdentityDisabled IdentityStatus = "disabled"
)

type IssuerStatus string

const (
	IssuerActive   IssuerStatus = "active"
	IssuerDisabled IssuerStatus = "disabled"
)

type OCSPResponderStatus string

const (
	OCSPResponderActive   OCSPResponderStatus = "active"
	OCSPResponderDisabled OCSPResponderStatus = "disabled"
)

type NotificationEndpointType string

const (
	NotificationEndpointWebhook NotificationEndpointType = "webhook"
)

type NotificationEndpointStatus string

const (
	NotificationEndpointActive   NotificationEndpointStatus = "active"
	NotificationEndpointDisabled NotificationEndpointStatus = "disabled"
)

type EnrollmentStatus string

const (
	EnrollmentPending  EnrollmentStatus = "pending"
	EnrollmentApproved EnrollmentStatus = "approved"
	EnrollmentRejected EnrollmentStatus = "rejected"
	EnrollmentIssued   EnrollmentStatus = "issued"
	EnrollmentCanceled EnrollmentStatus = "canceled"
)

type IssuanceAttemptStatus string

const (
	IssuanceAttemptSigning   IssuanceAttemptStatus = "signing"
	IssuanceAttemptSigned    IssuanceAttemptStatus = "signed"
	IssuanceAttemptFinalized IssuanceAttemptStatus = "finalized"
	IssuanceAttemptFailed    IssuanceAttemptStatus = "failed"
)

type CertificateStatus string

const (
	CertificateValid     CertificateStatus = "valid"
	CertificateSuspended CertificateStatus = "suspended"
	CertificateRevoked   CertificateStatus = "revoked"
	CertificateExpired   CertificateStatus = "expired"
)

type CRLPublicationStatus string

const (
	CRLPublicationPublished CRLPublicationStatus = "published"
)

type OutboxMessageStatus string

const (
	OutboxPending    OutboxMessageStatus = "pending"
	OutboxProcessing OutboxMessageStatus = "processing"
	OutboxCompleted  OutboxMessageStatus = "completed"
	OutboxFailed     OutboxMessageStatus = "failed"
	OutboxDeadLetter OutboxMessageStatus = "dead_letter"
)

type JobAttemptStatus string

const (
	JobAttemptSucceeded JobAttemptStatus = "succeeded"
	JobAttemptFailed    JobAttemptStatus = "failed"
)

type APIKeyStatus string

const (
	APIKeyActive   APIKeyStatus = "active"
	APIKeyDisabled APIKeyStatus = "disabled"
)

type APIKeyScope string

const (
	APIKeyScopeRead     APIKeyScope = "read"
	APIKeyScopeWrite    APIKeyScope = "write"
	APIKeyScopeOperator APIKeyScope = "operator"
)

type ACMEAccountStatus string

const (
	ACMEAccountValid       ACMEAccountStatus = "valid"
	ACMEAccountDeactivated ACMEAccountStatus = "deactivated"
)

type ACMEOrderStatus string

const (
	ACMEOrderPending ACMEOrderStatus = "pending"
	ACMEOrderReady   ACMEOrderStatus = "ready"
	ACMEOrderValid   ACMEOrderStatus = "valid"
	ACMEOrderInvalid ACMEOrderStatus = "invalid"
)

type ACMEAuthorizationStatus string

const (
	ACMEAuthorizationPending ACMEAuthorizationStatus = "pending"
	ACMEAuthorizationValid   ACMEAuthorizationStatus = "valid"
	ACMEAuthorizationInvalid ACMEAuthorizationStatus = "invalid"
)

type ACMEChallengeType string

const (
	ACMEChallengeHTTP01 ACMEChallengeType = "http-01"
	ACMEChallengeDNS01  ACMEChallengeType = "dns-01"
)

type ACMEChallengeStatus string

const (
	ACMEChallengePending    ACMEChallengeStatus = "pending"
	ACMEChallengeProcessing ACMEChallengeStatus = "processing"
	ACMEChallengeValid      ACMEChallengeStatus = "valid"
	ACMEChallengeInvalid    ACMEChallengeStatus = "invalid"
)

type RevocationReason string

const (
	RevocationKeyCompromise        RevocationReason = "key_compromise"
	RevocationCACompromise         RevocationReason = "ca_compromise"
	RevocationAffiliationChanged   RevocationReason = "affiliation_changed"
	RevocationSuperseded           RevocationReason = "superseded"
	RevocationCessationOfOperation RevocationReason = "cessation_of_operation"
	RevocationPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
	RevocationUnspecified          RevocationReason = "unspecified"
)

type IssuerKind string

const (
	IssuerRootCA         IssuerKind = "root_ca"
	IssuerIntermediateCA IssuerKind = "intermediate_ca"
)

type Identity struct {
	ID                 string
	Type               IdentityType
	Name               string
	ExternalID         string
	Owner              string
	Team               string
	Service            string
	Environment        string
	DeploymentTarget   string
	LastSeenAt         time.Time
	MetadataJSON       string
	AllowedDNSNames    []string
	AllowedIPAddresses []string
	Status             IdentityStatus
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Issuer struct {
	ID                    string
	Name                  string
	Kind                  IssuerKind
	Status                IssuerStatus
	ParentIssuerID        string
	CertificatePEM        string
	KeyRef                string
	AIAURL                string
	CRLDistributionPoints []string
	TrustAnchor           bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type OCSPResponder struct {
	ID             string
	IssuerID       string
	Name           string
	Status         OCSPResponderStatus
	CertificatePEM string
	KeyRef         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type NotificationEndpoint struct {
	ID         string
	Name       string
	Type       NotificationEndpointType
	Status     NotificationEndpointStatus
	URL        string
	Secret     string
	EventTypes []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type StringListExtensionPolicy struct {
	Critical bool     `json:"critical"`
	Values   []string `json:"values"`
}

type BasicConstraintsPolicy struct {
	Critical   bool `json:"critical"`
	CA         bool `json:"ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

type CertificateProfile struct {
	ID                         string
	Name                       string
	Description                string
	IssuerID                   string
	ValidityPeriodSeconds      int64
	PublicTLS                  bool
	SubjectTemplate            string
	AllowedDNSPatterns         []string
	AllowedIPRanges            []string
	AllowedKeyAlgorithms       []string
	MinKeySizeBits             int
	AllowedSignatureAlgorithms []string
	KeyUsage                   StringListExtensionPolicy
	ExtendedKeyUsage           StringListExtensionPolicy
	BasicConstraints           BasicConstraintsPolicy
	SubjectKeyIdentifier       bool
	AuthorityKeyIdentifier     bool
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

type Enrollment struct {
	ID                   string
	IdentityID           string
	IssuerID             string
	CertificateProfileID string
	SourceCertificateID  string
	CSRPEM               string
	Status               EnrollmentStatus
	RequestedSubject     string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	CSRDNSNames          []string
	CSRIPAddresses       []string
	RequestedNotAfter    time.Time
	ApprovedBy           string
	ApprovedAt           time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type Certificate struct {
	ID                   string
	IdentityID           string
	IssuerID             string
	EnrollmentID         string
	CertificateProfileID string
	SerialNumber         string
	Subject              string
	DNSNames             []string
	IPAddresses          []string
	NotBefore            time.Time
	NotAfter             time.Time
	Status               CertificateStatus
	CertificatePEM       string
	RenewalNotifiedAt    time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type IssuanceAttempt struct {
	EnrollmentID     string
	Status           IssuanceAttemptStatus
	LeaseExpiresAt   time.Time
	CertificateID    string
	CertificatePEM   string
	SerialNumber     string
	Subject          string
	NotBefore        time.Time
	NotAfter         time.Time
	SigningStartedAt time.Time
	SignedAt         time.Time
	FinalizedAt      time.Time
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Revocation struct {
	ID            string
	CertificateID string
	Reason        RevocationReason
	RevokedBy     string
	RevokedAt     time.Time
	CreatedAt     time.Time
}

type RevokedCertificateEntry struct {
	CertificateID string
	SerialNumber  string
	RevokedAt     time.Time
	Reason        RevocationReason
}

type CRLPublication struct {
	ID                string
	IssuerID          string
	DistributionPoint string
	CRLNumber         int64
	ThisUpdate        time.Time
	NextUpdate        time.Time
	Status            CRLPublicationStatus
	CRLPEM            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type AuditEvent struct {
	ID                string
	Actor             string
	Action            string
	ResourceType      string
	ResourceID        string
	MetadataJSON      string
	PreviousEventHash string
	EventHash         string
	CreatedAt         time.Time
}

type OutboxMessage struct {
	ID                   string
	Type                 string
	PayloadJSON          string
	Status               OutboxMessageStatus
	AvailableAt          time.Time
	ProcessingDeadlineAt time.Time
	AttemptCount         int
	MaxAttempts          int
	LastError            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type JobAttempt struct {
	ID              string
	OutboxMessageID string
	Status          JobAttemptStatus
	Error           string
	StartedAt       time.Time
	FinishedAt      time.Time
	CreatedAt       time.Time
}

type WebhookDelivery struct {
	OutboxMessageID string
	EndpointID      string
	Status          JobAttemptStatus
	AttemptCount    int
	LastError       string
	LastAttemptedAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type APIKey struct {
	ID         string
	Name       string
	TokenHash  string
	Status     APIKeyStatus
	Actor      string
	Scopes     []APIKeyScope
	ExpiresAt  time.Time
	LastUsedAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type ACMEAccount struct {
	ID                   string
	Contacts             []string
	Status               ACMEAccountStatus
	TermsOfServiceAgreed bool
	KeyThumbprint        string
	KeyJWKJSON           string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type ACMEOrder struct {
	ID                   string
	AccountID            string
	IdentityID           string
	IssuerID             string
	CertificateProfileID string
	Status               ACMEOrderStatus
	CSRPEM               string
	RequestedSubject     string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	RequestedNotAfter    time.Time
	EnrollmentID         string
	CertificateID        string
	ExpiresAt            time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type ACMEAuthorization struct {
	ID                       string
	OrderID                  string
	IdentifierType           string
	IdentifierValue          string
	Status                   ACMEAuthorizationStatus
	ExpiresAt                time.Time
	ValidationReuseExpiresAt time.Time
	CreatedAt                time.Time
	UpdatedAt                time.Time
}

type ACMEChallenge struct {
	ID              string
	AuthorizationID string
	Type            ACMEChallengeType
	Token           string
	Status          ACMEChallengeStatus
	ValidatedAt     time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
