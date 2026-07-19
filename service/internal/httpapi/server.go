// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/lifecycle"
)

type Server struct {
	service *lifecycle.Service
	mux     *http.ServeMux
	auth    AuthConfig
	acme    ACMEConfig
	nonces  ACMENonceStore
	rateMu  sync.Mutex
	rates   map[string]acmeRateBucket
}

var errACMEBadNonce = errors.New("acme bad nonce")

const acmeRetryAfterSeconds = "5"

const (
	defaultJSONBodyLimit      = 1 << 20
	defaultOCSPBodyLimit      = 16 << 10
	defaultACMENonceTTL       = 10 * time.Minute
	defaultACMENonceCacheSize = 1024
	defaultACMERateLimit      = 120
	defaultACMERateWindow     = time.Minute
)

type AuthMode string

const (
	AuthModeDev    AuthMode = "dev"
	AuthModeAPIKey AuthMode = "api_key"
)

type AuthConfig struct {
	Mode           AuthMode
	TrustedProxies []netip.Prefix
}

type ACMEConfig struct {
	DefaultIdentityID           string
	DefaultIssuerID             string
	DefaultCertificateProfileID string
	DefaultValidityPeriod       time.Duration
	NonceStore                  ACMENonceStore
	RateLimit                   int
	RateLimitWindow             time.Duration
}

type ACMENonceStore interface {
	Issue(ctx context.Context, nonce string, issuedAt time.Time, expiresAt time.Time) error
	Consume(ctx context.Context, nonce string, now time.Time) (bool, error)
}

type acmeMemoryNonceStore struct {
	mu      sync.Mutex
	nonces  map[string]acmeStoredNonce
	maxSize int
}

type acmeStoredNonce struct {
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type acmeRateBucket struct {
	Count   int
	ResetAt time.Time
}

type requiredScope string

const (
	requiredScopeRead     requiredScope = "read"
	requiredScopeWrite    requiredScope = "write"
	requiredScopeOperator requiredScope = "operator"
)

type actorContextKey struct{}

func New(service *lifecycle.Service) *Server {
	return NewWithAuth(service, AuthConfig{Mode: AuthModeDev})
}

func NewWithAuth(service *lifecycle.Service, auth AuthConfig) *Server {
	return NewWithAuthAndACME(service, auth, ACMEConfig{})
}

func NewWithAuthAndACME(service *lifecycle.Service, auth AuthConfig, acme ACMEConfig) *Server {
	if auth.Mode == "" {
		auth.Mode = AuthModeDev
	}
	nonceStore := acme.NonceStore
	if nonceStore == nil {
		nonceStore = newACMEMemoryNonceStore(defaultACMENonceCacheSize)
	}
	if acme.RateLimit <= 0 {
		acme.RateLimit = defaultACMERateLimit
	}
	if acme.RateLimitWindow <= 0 {
		acme.RateLimitWindow = defaultACMERateWindow
	}
	s := &Server{
		service: service,
		mux:     http.NewServeMux(),
		auth:    auth,
		acme:    acme,
		nonces:  nonceStore,
		rates:   make(map[string]acmeRateBucket),
	}
	s.registerRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metricBoundary := requestMetricBoundary(r.URL.Path)
	rw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		recordRequestMetric(metricBoundary, rw.status)
	}()
	requestID := requestIDForRequest(r)
	rw.Header().Set("X-Request-ID", requestID)
	ctx := lifecycle.WithAuditRequestMetadata(r.Context(), lifecycle.AuditRequestMetadata{
		RequestID:   requestID,
		Traceparent: strings.TrimSpace(r.Header.Get("Traceparent")),
		ClientIP:    requestClientIP(r, s.auth.TrustedProxies),
		UserAgent:   strings.TrimSpace(r.UserAgent()),
		AuthMethod:  string(s.auth.Mode),
		StartedAt:   time.Now(),
	})
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(rw, r.Body, requestBodyLimit(r))
	authenticated, err := s.authenticateRequest(r)
	if err != nil {
		metricBoundary = "auth"
		recordEventMetric("auth:failure")
		r = r.WithContext(context.WithValue(r.Context(), actorContextKey{}, "anonymous"))
		s.writeError(rw, r, err)
		return
	}
	r = r.WithContext(authenticated)
	if err := s.checkACMERateLimit(r); err != nil {
		metricBoundary = "rate_limit"
		s.writeError(rw, r, err)
		return
	}
	s.mux.ServeHTTP(rw, r)
}

func requestBodyLimit(r *http.Request) int64 {
	if r.Method == http.MethodPost && r.URL.Path == "/ocsp" {
		return defaultOCSPBodyLimit
	}
	return defaultJSONBodyLimit
}

func requestIDForRequest(r *http.Request) string {
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID != "" {
		return requestID
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + base64.RawURLEncoding.EncodeToString(raw[:])
}

func (s *Server) registerRoutes() {
	s.mux.Handle("GET /debug/vars", expvar.Handler())

	s.mux.HandleFunc("POST /identities", s.createIdentity)
	s.mux.HandleFunc("GET /identities", s.listIdentities)
	s.mux.HandleFunc("GET /identities/{id}", s.getIdentity)

	s.mux.HandleFunc("POST /issuers", s.createIssuer)
	s.mux.HandleFunc("GET /issuers/{id}/chain", s.getIssuerChain)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders", s.createOCSPResponder)
	s.mux.HandleFunc("GET /issuers/{id}/ocsp-responders", s.listOCSPResponders)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders/rotate", s.rotateOCSPResponder)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders/{responderID}/disable", s.disableOCSPResponder)

	s.mux.HandleFunc("POST /notification-endpoints", s.createNotificationEndpoint)
	s.mux.HandleFunc("GET /notification-endpoints", s.listNotificationEndpoints)
	s.mux.HandleFunc("POST /notification-endpoints/{id}/disable", s.disableNotificationEndpoint)

	s.mux.HandleFunc("GET /outbox/messages", s.listOutboxMessages)
	s.mux.HandleFunc("POST /outbox/messages/dead-letter/replay", s.replayDeadLetterOutboxMessages)
	s.mux.HandleFunc("POST /outbox/messages/{id}/retry", s.retryOutboxMessage)

	s.mux.HandleFunc("GET /operator/certificate-inventory", s.listCertificateInventory)
	s.mux.HandleFunc("GET /operator/expiry-slo", s.getExpirySLO)

	s.mux.HandleFunc("POST /api-keys", s.createAPIKey)
	s.mux.HandleFunc("GET /api-keys", s.listAPIKeys)
	s.mux.HandleFunc("POST /api-keys/{id}/rotate", s.rotateAPIKey)
	s.mux.HandleFunc("POST /api-keys/{id}/disable", s.disableAPIKey)

	s.mux.HandleFunc("POST /acme/accounts", s.createACMEAccount)
	s.mux.HandleFunc("GET /acme/accounts", s.listACMEAccounts)
	s.mux.HandleFunc("POST /acme/orders", s.createACMEOrder)
	s.mux.HandleFunc("GET /acme/orders/{id}", s.getACMEOrder)
	s.mux.HandleFunc("GET /acme/orders/{id}/authorizations", s.listACMEAuthorizations)
	s.mux.HandleFunc("POST /acme/orders/{id}/finalize", s.finalizeACMEOrder)
	s.mux.HandleFunc("GET /acme/authorizations/{id}/challenges", s.listACMEChallenges)
	s.mux.HandleFunc("POST /acme/challenges/{id}/complete", s.completeACMEChallenge)

	s.mux.HandleFunc("GET /acme/directory", s.acmeDirectory)
	s.mux.HandleFunc("HEAD /acme/new-nonce", s.acmeNewNonce)
	s.mux.HandleFunc("GET /acme/new-nonce", s.acmeNewNonce)
	s.mux.HandleFunc("POST /acme/new-account", s.acmeNewAccount)
	s.mux.HandleFunc("POST /acme/account/{id}", s.acmeUpdateAccount)
	s.mux.HandleFunc("POST /acme/new-order", s.acmeNewOrder)
	s.mux.HandleFunc("POST /acme/key-change", s.acmeKeyChange)
	s.mux.HandleFunc("GET /acme/order/{id}", s.acmeGetOrder)
	s.mux.HandleFunc("POST /acme/order/{id}", s.acmePostAsGetOrder)
	s.mux.HandleFunc("GET /acme/authz/{id}", s.acmeGetAuthorization)
	s.mux.HandleFunc("POST /acme/authz/{id}", s.acmePostAsGetAuthorization)
	s.mux.HandleFunc("POST /acme/challenge/{id}", s.acmeCompleteChallenge)
	s.mux.HandleFunc("POST /acme/order/{id}/finalize", s.acmeFinalizeOrder)
	s.mux.HandleFunc("POST /acme/revoke-cert", s.acmeRevokeCertificate)
	s.mux.HandleFunc("GET /acme/cert/{id}", s.acmeGetCertificate)
	s.mux.HandleFunc("POST /acme/cert/{id}", s.acmePostAsGetCertificate)

	s.mux.HandleFunc("POST /certificate-profiles", s.createCertificateProfile)
	s.mux.HandleFunc("GET /certificate-profiles", s.listCertificateProfiles)
	s.mux.HandleFunc("GET /certificate-profiles/{id}", s.getCertificateProfile)

	s.mux.HandleFunc("POST /enrollments", s.createEnrollment)
	s.mux.HandleFunc("GET /enrollments", s.listEnrollments)
	s.mux.HandleFunc("GET /enrollments/{id}", s.getEnrollment)
	s.mux.HandleFunc("POST /enrollments/{id}/approve", s.approveEnrollment)
	s.mux.HandleFunc("POST /enrollments/{id}/reject", s.rejectEnrollment)

	s.mux.HandleFunc("POST /certificates", s.issueCertificate)
	s.mux.HandleFunc("GET /certificates", s.listCertificates)
	s.mux.HandleFunc("POST /certificates/expiration-scan", s.scanCertificateExpirations)
	s.mux.HandleFunc("GET /certificates/{id}", s.getCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/revoke", s.revokeCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/suspend", s.suspendCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/resume", s.resumeCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/renew", s.renewCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/reissue", s.reissueCertificate)

	s.mux.HandleFunc("POST /crls", s.publishCRL)
	s.mux.HandleFunc("GET /crls/{id}", s.getCRLPublication)
	s.mux.HandleFunc("GET /issuers/{id}/crl", s.getLatestIssuerCRL)

	s.mux.HandleFunc("POST /ocsp", s.respondOCSP)

	s.mux.HandleFunc("GET /audit-events", s.listAuditEvents)
	s.mux.HandleFunc("GET /audit-events/integrity", s.getAuditIntegrity)
	s.mux.HandleFunc("POST /audit-events/retention/prune", s.pruneAuditEvents)
	s.mux.HandleFunc("POST /audit-events/repair/issuance", s.repairIssuanceAuditEvents)
	s.mux.HandleFunc("GET /trust/anchors", s.listTrustAnchors)
}

func (s *Server) createIdentity(w http.ResponseWriter, r *http.Request) {
	var req createIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	identity, err := s.service.CreateIdentity(r.Context(), requestActor(r), lifecycle.CreateIdentityRequest{
		Type:               req.Type,
		Name:               req.Name,
		ExternalID:         req.ExternalID,
		Owner:              req.Owner,
		Team:               req.Team,
		Service:            req.Service,
		Environment:        req.Environment,
		DeploymentTarget:   req.DeploymentTarget,
		LastSeenAt:         req.LastSeenAt,
		MetadataJSON:       req.MetadataJSON,
		AllowedDNSNames:    req.AllowedDNSNames,
		AllowedIPAddresses: req.AllowedIPAddresses,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIdentityResponse(identity))
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) {
	opts, err := identityListOptionsFromQuery(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	identities, err := s.service.ListIdentitiesQuery(r.Context(), opts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponses(identities))
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request) {
	identity, err := s.service.GetIdentity(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponse(identity))
}

func (s *Server) createIssuer(w http.ResponseWriter, r *http.Request) {
	var req createIssuerRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	issuer, err := s.service.CreateIssuer(r.Context(), requestActor(r), lifecycle.CreateIssuerRequest{
		Name:                  req.Name,
		Kind:                  req.Kind,
		ParentIssuerID:        req.ParentIssuerID,
		CertificatePEM:        req.CertificatePEM,
		KeyRef:                req.KeyRef,
		AIAURL:                req.AIAURL,
		CRLDistributionPoints: req.CRLDistributionPoints,
		TrustAnchor:           req.TrustAnchor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIssuerResponse(issuer))
}

func (s *Server) getIssuerChain(w http.ResponseWriter, r *http.Request) {
	chain, err := s.service.GetIssuerChain(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIssuerResponses(chain))
}

func (s *Server) createOCSPResponder(w http.ResponseWriter, r *http.Request) {
	var req createOCSPResponderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	responder, err := s.service.CreateOCSPResponder(r.Context(), requestActor(r), lifecycle.CreateOCSPResponderRequest{
		IssuerID:       r.PathValue("id"),
		Name:           req.Name,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOCSPResponderResponse(responder))
}

func (s *Server) listOCSPResponders(w http.ResponseWriter, r *http.Request) {
	responders, err := s.service.ListOCSPRespondersByIssuer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOCSPResponderResponses(responders))
}

func (s *Server) disableOCSPResponder(w http.ResponseWriter, r *http.Request) {
	responder, err := s.service.DisableOCSPResponder(r.Context(), requestActor(r), r.PathValue("id"), r.PathValue("responderID"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOCSPResponderResponse(responder))
}

func (s *Server) rotateOCSPResponder(w http.ResponseWriter, r *http.Request) {
	var req createOCSPResponderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	responder, err := s.service.RotateOCSPResponder(r.Context(), requestActor(r), lifecycle.RotateOCSPResponderRequest{
		IssuerID:       r.PathValue("id"),
		Name:           req.Name,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOCSPResponderResponse(responder))
}

func (s *Server) createNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createNotificationEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	endpoint, err := s.service.CreateNotificationEndpoint(r.Context(), requestActor(r), lifecycle.CreateNotificationEndpointRequest{
		Name:       req.Name,
		URL:        req.URL,
		Secret:     req.Secret,
		EventTypes: req.EventTypes,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toNotificationEndpointResponse(endpoint))
}

func (s *Server) listNotificationEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.service.ListNotificationEndpoints(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNotificationEndpointResponses(endpoints))
}

func (s *Server) disableNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	endpoint, err := s.service.DisableNotificationEndpoint(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNotificationEndpointResponse(endpoint))
}

func (s *Server) listOutboxMessages(w http.ResponseWriter, r *http.Request) {
	opts, err := outboxMessageListOptionsFromQuery(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	messages, err := s.service.ListOutboxMessagesQuery(r.Context(), opts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOutboxMessageResponses(messages))
}

func (s *Server) retryOutboxMessage(w http.ResponseWriter, r *http.Request) {
	message, err := s.service.RetryOutboxMessage(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOutboxMessageResponse(message))
}

func (s *Server) replayDeadLetterOutboxMessages(w http.ResponseWriter, r *http.Request) {
	var req replayDeadLetterOutboxRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.service.ReplayDeadLetterOutboxMessages(r.Context(), requestActor(r), lifecycle.ReplayDeadLetterOutboxRequest{
		EventType:   req.EventType,
		CreatedFrom: req.CreatedFrom,
		CreatedTo:   req.CreatedTo,
		Limit:       req.Limit,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toReplayDeadLetterOutboxResponse(result))
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	result, err := s.service.CreateAPIKey(r.Context(), requestActor(r), lifecycle.CreateAPIKeyRequest{
		Name:      req.Name,
		Actor:     req.Actor,
		Scopes:    req.Scopes,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAPIKeyResponseWithToken(result.Key, result.Token))
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.service.ListAPIKeys(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPIKeyResponses(keys))
}

func (s *Server) disableAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.service.DisableAPIKey(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPIKeyResponse(key))
}

func (s *Server) rotateAPIKey(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.RotateAPIKey(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAPIKeyResponseWithToken(result.Key, result.Token))
}

func (s *Server) createCertificateProfile(w http.ResponseWriter, r *http.Request) {
	var req createCertificateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	profile, err := s.service.CreateCertificateProfile(r.Context(), requestActor(r), lifecycle.CreateCertificateProfileRequest{
		Name:                       req.Name,
		Description:                req.Description,
		IssuerID:                   req.IssuerID,
		ValidityPeriodSeconds:      req.ValidityPeriodSeconds,
		PublicTLS:                  req.PublicTLS,
		SubjectTemplate:            req.SubjectTemplate,
		AllowedDNSPatterns:         req.AllowedDNSPatterns,
		AllowedIPRanges:            req.AllowedIPRanges,
		AllowedKeyAlgorithms:       req.AllowedKeyAlgorithms,
		MinKeySizeBits:             req.MinKeySizeBits,
		AllowedSignatureAlgorithms: req.AllowedSignatureAlgorithms,
		KeyUsage:                   req.KeyUsage,
		ExtendedKeyUsage:           req.ExtendedKeyUsage,
		BasicConstraints:           req.BasicConstraints,
		SubjectKeyIdentifier:       req.SubjectKeyIdentifier,
		AuthorityKeyIdentifier:     req.AuthorityKeyIdentifier,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateProfileResponse(profile))
}

func (s *Server) listCertificateProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.service.ListCertificateProfiles(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponses(profiles))
}

func (s *Server) getCertificateProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := s.service.GetCertificateProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponse(profile))
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req createEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.CreateEnrollment(r.Context(), requestActor(r), lifecycle.CreateEnrollmentRequest{
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CertificateProfileID: req.CertificateProfileID,
		CSRPEM:               req.CSRPEM,
		RequestedSubject:     req.RequestedSubject,
		RequestedDNSNames:    req.RequestedDNSNames,
		RequestedIPAddresses: req.RequestedIPAddresses,
		RequestedNotAfter:    req.RequestedNotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	opts, err := enrollmentListOptionsFromQuery(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	enrollments, err := s.service.ListEnrollmentsQuery(r.Context(), opts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponses(enrollments))
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.GetEnrollment(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	var req approveEnrollmentRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	enrollment, err := s.service.ApproveEnrollmentWithReason(r.Context(), requestActor(r), r.PathValue("id"), req.Reason)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) rejectEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.RejectEnrollment(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	certificate, err := s.service.IssueCertificate(r.Context(), requestActor(r), req.EnrollmentID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateResponse(certificate))
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	opts, err := certificateListOptionsFromQuery(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	certificates, err := s.service.ListCertificatesQuery(r.Context(), opts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponses(certificates))
}

func identityListOptionsFromQuery(r *http.Request) (lifecycle.IdentityListOptions, error) {
	query := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.IdentityListOptions{}, err
	}
	return lifecycle.IdentityListOptions{
		Owner:       query.Get("owner"),
		Team:        query.Get("team"),
		Service:     query.Get("service"),
		Environment: query.Get("environment"),
		Sort:        sort,
		Limit:       limit,
		Offset:      offset,
	}, nil
}

func enrollmentListOptionsFromQuery(r *http.Request) (lifecycle.EnrollmentListOptions, error) {
	query := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.EnrollmentListOptions{}, err
	}
	return lifecycle.EnrollmentListOptions{
		IdentityID: query.Get("identity_id"),
		IssuerID:   query.Get("issuer_id"),
		ProfileID:  query.Get("profile_id"),
		Status:     domain.EnrollmentStatus(query.Get("status")),
		Sort:       sort,
		Limit:      limit,
		Offset:     offset,
	}, nil
}

func certificateListOptionsFromQuery(r *http.Request) (lifecycle.CertificateListOptions, error) {
	query := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.CertificateListOptions{}, err
	}
	opts := lifecycle.CertificateListOptions{
		Owner:           query.Get("owner"),
		Team:            query.Get("team"),
		Service:         query.Get("service"),
		Environment:     query.Get("environment"),
		IssuerID:        query.Get("issuer_id"),
		ProfileID:       query.Get("profile_id"),
		SAN:             query.Get("san"),
		RevocationState: query.Get("revocation_state"),
		RenewalState:    query.Get("renewal_state"),
		Sort:            sort,
		Limit:           limit,
		Offset:          offset,
	}
	if raw := query.Get("expires_within_days"); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 1 || !isAllowedExpiryWindowDays(days) {
			return lifecycle.CertificateListOptions{}, domain.ErrInvalidRequest
		}
		opts.ExpiresWithinDays = days
	}
	return opts, nil
}

func isAllowedExpiryWindowDays(days int) bool {
	switch days {
	case 30, 14, 7, 3, 1:
		return true
	default:
		return false
	}
}

func outboxMessageListOptionsFromQuery(r *http.Request) (lifecycle.OutboxMessageListOptions, error) {
	query := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.OutboxMessageListOptions{}, err
	}
	opts := lifecycle.OutboxMessageListOptions{
		Status: domain.OutboxMessageStatus(query.Get("status")),
		Type:   query.Get("type"),
		Sort:   sort,
		Limit:  limit,
		Offset: offset,
	}
	if raw := query.Get("from"); raw != "" {
		opts.CreatedFrom, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return lifecycle.OutboxMessageListOptions{}, domain.ErrInvalidRequest
		}
	}
	if raw := query.Get("to"); raw != "" {
		opts.CreatedTo, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return lifecycle.OutboxMessageListOptions{}, domain.ErrInvalidRequest
		}
	}
	return opts, nil
}

func (s *Server) listCertificateInventory(w http.ResponseWriter, r *http.Request) {
	opts, err := certificateInventoryOptionsFromQuery(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	entries, err := s.service.ListCertificateInventory(r.Context(), opts)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateInventoryResponses(entries))
}

func certificateInventoryOptionsFromQuery(r *http.Request) (lifecycle.CertificateInventoryOptions, error) {
	query := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.CertificateInventoryOptions{}, err
	}
	opts := lifecycle.CertificateInventoryOptions{
		Owner:           query.Get("owner"),
		Team:            query.Get("team"),
		Service:         query.Get("service"),
		Environment:     query.Get("environment"),
		IssuerID:        query.Get("issuer_id"),
		ProfileID:       query.Get("profile_id"),
		RevocationState: query.Get("revocation_state"),
		Sort:            sort,
	}
	opts.Limit = limit
	opts.Offset = offset
	return opts, nil
}

func paginationFromQuery(r *http.Request) (int, int, error) {
	query := r.URL.Query()
	limit := 0
	offset := 0
	if rawLimit := query.Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 {
			return 0, 0, domain.ErrInvalidRequest
		}
		limit = parsed
	}
	if rawOffset := query.Get("offset"); rawOffset != "" {
		if limit == 0 {
			return 0, 0, domain.ErrInvalidRequest
		}
		parsed, err := strconv.Atoi(rawOffset)
		if err != nil || parsed < 0 {
			return 0, 0, domain.ErrInvalidRequest
		}
		offset = parsed
	}
	return limit, offset, nil
}

func paginationAndSortFromQuery(r *http.Request) (string, int, int, error) {
	sort := r.URL.Query().Get("sort")
	if sort != "" && sort != "asc" && sort != "desc" {
		return "", 0, 0, domain.ErrInvalidRequest
	}
	limit, offset, err := paginationFromQuery(r)
	if err != nil {
		return "", 0, 0, err
	}
	return sort, limit, offset, nil
}

func (s *Server) getExpirySLO(w http.ResponseWriter, r *http.Request) {
	slo, err := s.service.ExpirySLO(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toExpirySLOResponse(slo))
}

func (s *Server) scanCertificateExpirations(w http.ResponseWriter, r *http.Request) {
	var req scanCertificateExpirationsRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	result, err := s.service.ScanCertificateExpirations(r.Context(), requestActor(r), lifecycle.ScanCertificateExpirationsRequest{
		WarningWindow: time.Duration(req.WarningWindowSeconds) * time.Second,
		Limit:         req.Limit,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateExpirationScanResponse(result))
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var req revokeCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	var certificate domain.Certificate
	var err error
	if req.Force {
		certificate, err = s.service.ForceRevokeCertificate(r.Context(), requestActor(r), r.PathValue("id"), req.Reason)
	} else {
		certificate, err = s.service.RevokeCertificate(r.Context(), requestActor(r), r.PathValue("id"), req.Reason)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) suspendCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.SuspendCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) resumeCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.ResumeCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) {
	var req renewCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.RenewCertificate(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.RenewCertificateRequest{
		CSRPEM:            req.CSRPEM,
		RequestedNotAfter: req.RequestedNotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) reissueCertificate(w http.ResponseWriter, r *http.Request) {
	var req reissueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.ReissueCertificate(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.ReissueCertificateRequest{
		CSRPEM: req.CSRPEM,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) publishCRL(w http.ResponseWriter, r *http.Request) {
	var req publishCRLRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	publication, err := s.service.PublishCRL(r.Context(), requestActor(r), lifecycle.PublishCRLRequest{
		IssuerID:          req.IssuerID,
		DistributionPoint: req.DistributionPoint,
		NextUpdate:        req.NextUpdate,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCRLPublicationResponse(publication))
}

func (s *Server) getCRLPublication(w http.ResponseWriter, r *http.Request) {
	publication, err := s.service.GetCRLPublication(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCRLPublicationResponse(publication))
}

func (s *Server) getLatestIssuerCRL(w http.ResponseWriter, r *http.Request) {
	distributionPoint := r.URL.Query().Get("distribution_point")
	var publication domain.CRLPublication
	var err error
	if distributionPoint == "" {
		publication, err = s.service.GetLatestCRLPublication(r.Context(), r.PathValue("id"))
	} else {
		publication, err = s.service.GetLatestCRLPublicationForDistributionPoint(r.Context(), r.PathValue("id"), distributionPoint)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(publication.CRLPEM))
}

func (s *Server) respondOCSP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		s.writeError(w, r, domain.ErrUnsupportedMediaType)
		return
	}
	requestDER, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	response, err := s.service.RespondOCSP(r.Context(), requestActor(r), requestDER)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.ResponseDER)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	query, err := auditEventQueryFromRequest(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	events, err := s.service.ListAuditEventsQuery(r.Context(), query)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuditEventResponses(events))
}

func (s *Server) getAuditIntegrity(w http.ResponseWriter, r *http.Request) {
	report, err := s.service.GetAuditIntegrity(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuditIntegrityResponse(report))
}

func auditEventQueryFromRequest(r *http.Request) (lifecycle.AuditEventQuery, error) {
	values := r.URL.Query()
	sort, limit, offset, err := paginationAndSortFromQuery(r)
	if err != nil {
		return lifecycle.AuditEventQuery{}, err
	}
	query := lifecycle.AuditEventQuery{
		Actor:        values.Get("actor"),
		Action:       values.Get("action"),
		ResourceType: values.Get("resource_type"),
		ResourceID:   values.Get("resource_id"),
		Sort:         sort,
		Limit:        limit,
		Offset:       offset,
	}
	if raw := values.Get("from"); raw != "" {
		query.CreatedFrom, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return lifecycle.AuditEventQuery{}, domain.ErrInvalidRequest
		}
	}
	if raw := values.Get("to"); raw != "" {
		query.CreatedTo, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return lifecycle.AuditEventQuery{}, domain.ErrInvalidRequest
		}
	}
	return query, nil
}

func (s *Server) pruneAuditEvents(w http.ResponseWriter, r *http.Request) {
	var req pruneAuditEventsRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	deleted, err := s.service.PruneAuditEventsBefore(r.Context(), requestActor(r), req.Before)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pruneAuditEventsResponse{DeletedCount: deleted})
}

func (s *Server) repairIssuanceAuditEvents(w http.ResponseWriter, r *http.Request) {
	repaired, err := s.service.RepairMissingIssuanceAuditEvents(r.Context(), requestActor(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, repairIssuanceAuditEventsResponse{RepairedCount: repaired})
}

func (s *Server) listTrustAnchors(w http.ResponseWriter, r *http.Request) {
	anchors, err := s.service.ListTrustAnchors(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIssuerResponses(anchors))
}

func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return domain.ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return domain.ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func requestActor(r *http.Request) string {
	if actor, ok := r.Context().Value(actorContextKey{}).(string); ok && actor != "" {
		return actor
	}
	actor := r.Header.Get("X-Actor")
	if actor == "" {
		return "anonymous"
	}
	return actor
}

func (s *Server) authenticateRequest(r *http.Request) (context.Context, error) {
	switch s.auth.Mode {
	case AuthModeDev, "":
		return context.WithValue(r.Context(), actorContextKey{}, requestActor(r)), nil
	case AuthModeAPIKey:
		if isPublicEndpoint(r.Method, r.URL.Path) {
			return context.WithValue(r.Context(), actorContextKey{}, "public"), nil
		}
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			return r.Context(), domain.ErrUnauthorized
		}
		key, err := s.service.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return r.Context(), err
		}
		if !apiKeyAllowsScope(key, requiredScopeForRequest(r.Method, r.URL.Path)) {
			ctx := context.WithValue(r.Context(), actorContextKey{}, key.Actor)
			ctx = lifecycle.WithAPIKeyAuditMetadata(ctx, lifecycle.APIKeyAuditMetadata{
				ID:          key.ID,
				Name:        key.Name,
				Actor:       key.Actor,
				Fingerprint: lifecycle.APIKeyTokenFingerprint(key.TokenHash),
				Scopes:      key.Scopes,
			})
			return ctx, domain.ErrForbidden
		}
		ctx := context.WithValue(r.Context(), actorContextKey{}, key.Actor)
		return lifecycle.WithAPIKeyAuditMetadata(ctx, lifecycle.APIKeyAuditMetadata{
			ID:          key.ID,
			Name:        key.Name,
			Actor:       key.Actor,
			Fingerprint: lifecycle.APIKeyTokenFingerprint(key.TokenHash),
			Scopes:      key.Scopes,
		}), nil
	default:
		return r.Context(), domain.ErrUnauthorized
	}
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func isPublicEndpoint(method string, path string) bool {
	if method == http.MethodPost && path == "/ocsp" {
		return true
	}
	if isPublicACMEProtocolEndpoint(method, path) {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/crls/") && len(strings.TrimPrefix(path, "/crls/")) > 0 {
		return true
	}
	if method != http.MethodGet || !strings.HasPrefix(path, "/issuers/") || !strings.HasSuffix(path, "/crl") {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && parts[0] == "issuers" && parts[1] != "" && parts[2] == "crl"
}

func isPublicACMEProtocolEndpoint(method string, path string) bool {
	if method == http.MethodGet && path == "/acme/directory" {
		return true
	}
	if (method == http.MethodHead || method == http.MethodGet) && path == "/acme/new-nonce" {
		return true
	}
	if method == http.MethodPost && (path == "/acme/new-account" || path == "/acme/new-order" || path == "/acme/key-change" || path == "/acme/revoke-cert") {
		return true
	}
	if method == http.MethodPost && strings.HasPrefix(path, "/acme/account/") {
		return true
	}
	if method == http.MethodGet && (strings.HasPrefix(path, "/acme/order/") || strings.HasPrefix(path, "/acme/authz/")) {
		return true
	}
	if method == http.MethodPost && (strings.HasPrefix(path, "/acme/order/") || strings.HasPrefix(path, "/acme/authz/") || strings.HasPrefix(path, "/acme/challenge/") || strings.HasPrefix(path, "/acme/cert/")) {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/acme/cert/") {
		return true
	}
	return false
}

func (s *Server) checkACMERateLimit(r *http.Request) error {
	if !isRateLimitedACMEProtocolEndpoint(r.Method, r.URL.Path) {
		return nil
	}
	now := time.Now()
	key := requestClientIP(r, s.auth.TrustedProxies) + " " + acmeRateLimitClass(r.URL.Path)
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	bucket := s.rates[key]
	if bucket.ResetAt.IsZero() || !bucket.ResetAt.After(now) {
		bucket = acmeRateBucket{ResetAt: now.Add(s.acme.RateLimitWindow)}
	}
	if bucket.Count >= s.acme.RateLimit {
		s.rates[key] = bucket
		recordEventMetric("rate_limit:acme_" + acmeRateLimitClass(r.URL.Path))
		return domain.ErrRateLimited
	}
	bucket.Count++
	s.rates[key] = bucket
	return nil
}

func isRateLimitedACMEProtocolEndpoint(method string, path string) bool {
	if method != http.MethodPost {
		return false
	}
	return path == "/acme/new-account" ||
		path == "/acme/new-order" ||
		path == "/acme/key-change" ||
		strings.HasPrefix(path, "/acme/challenge/") ||
		(strings.HasPrefix(path, "/acme/order/") && strings.HasSuffix(path, "/finalize"))
}

func acmeRateLimitClass(path string) string {
	switch {
	case path == "/acme/new-account":
		return "account"
	case path == "/acme/new-order":
		return "order"
	case path == "/acme/key-change":
		return "account"
	case strings.HasPrefix(path, "/acme/challenge/"):
		return "challenge"
	case strings.HasPrefix(path, "/acme/order/") && strings.HasSuffix(path, "/finalize"):
		return "finalize"
	default:
		return path
	}
}

func requiredScopeForRequest(method string, path string) requiredScope {
	if strings.HasPrefix(path, "/api-keys") || strings.HasPrefix(path, "/outbox/") || strings.HasPrefix(path, "/audit-events") || strings.HasPrefix(path, "/operator/") {
		return requiredScopeOperator
	}
	if method == http.MethodPost && path == "/certificates/expiration-scan" {
		return requiredScopeOperator
	}
	if method == http.MethodGet {
		return requiredScopeRead
	}
	return requiredScopeWrite
}

func apiKeyAllowsScope(key domain.APIKey, required requiredScope) bool {
	for _, scope := range key.Scopes {
		if scope == domain.APIKeyScopeOperator {
			return true
		}
		if required == requiredScopeRead && scope == domain.APIKeyScopeWrite {
			return true
		}
		if string(scope) == string(required) {
			return true
		}
	}
	return false
}

func requestClientIP(r *http.Request, trustedProxies []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if len(trustedProxies) > 0 && remoteAddrTrusted(host, trustedProxies) {
		if clientIP := forwardedClientIP(r.Header.Get("X-Forwarded-For")); clientIP != "" {
			return clientIP
		}
	}
	return host
}

func remoteAddrTrusted(host string, trustedProxies []netip.Prefix) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range trustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func forwardedClientIP(forwardedFor string) string {
	clientIP := strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
	if clientIP == "" {
		return ""
	}
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status := statusForError(err)
	auditErr := err
	if errors.Is(err, errACMEBadNonce) {
		auditErr = domain.ErrInvalidRequest
	}
	_ = s.service.RecordAPIFailure(r.Context(), requestActor(r), lifecycle.APIFailureAuditRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: status,
		Err:        auditErr,
	})
	if isPublicACMEProtocolEndpoint(r.Method, r.URL.Path) {
		s.writeACMEProblem(w, r, status, err)
		return
	}
	writeJSON(w, status, errorResponse{Error: publicErrorMessage(err)})
}

func (s *Server) writeACMEProblem(w http.ResponseWriter, r *http.Request, status int, err error) {
	nonce, nonceErr := s.issueACMENonce(r.Context())
	if nonceErr == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Link", acmeDirectoryLink(r))
	if errors.Is(err, domain.ErrRateLimited) {
		w.Header().Set("Retry-After", strconv.Itoa(int(s.acme.RateLimitWindow.Seconds())))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(acmeProblem{
		Type:   acmeProblemType(err),
		Title:  http.StatusText(status),
		Status: status,
		Detail: publicErrorMessage(err),
	})
}

func acmeProblemType(err error) string {
	switch {
	case errors.Is(err, errACMEBadNonce):
		return "urn:ietf:params:acme:error:badNonce"
	case errors.Is(err, domain.ErrRateLimited):
		return "urn:ietf:params:acme:error:rateLimited"
	case errors.Is(err, domain.ErrACMEAccountDeactivated):
		return "urn:ietf:params:acme:error:unauthorized"
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrForbidden):
		return "urn:ietf:params:acme:error:unauthorized"
	default:
		return "urn:ietf:params:acme:error:malformed"
	}
}

type acmeProblem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func publicErrorMessage(err error) string {
	switch {
	case errors.Is(err, errACMEBadNonce):
		return domain.ErrInvalidRequest.Error()
	case errors.Is(err, domain.ErrInvalidRequest):
		return domain.ErrInvalidRequest.Error()
	case errors.Is(err, domain.ErrUnsupportedMediaType):
		return domain.ErrUnsupportedMediaType.Error()
	case errors.Is(err, domain.ErrUnauthorized):
		return domain.ErrUnauthorized.Error()
	case errors.Is(err, domain.ErrForbidden):
		return domain.ErrForbidden.Error()
	case errors.Is(err, domain.ErrRateLimited):
		return domain.ErrRateLimited.Error()
	case errors.Is(err, domain.ErrInvalidTransition):
		return domain.ErrInvalidTransition.Error()
	case errors.Is(err, domain.ErrIdentityNotFound):
		return domain.ErrIdentityNotFound.Error()
	case errors.Is(err, domain.ErrIssuerNotFound):
		return domain.ErrIssuerNotFound.Error()
	case errors.Is(err, domain.ErrOCSPResponderNotFound):
		return domain.ErrOCSPResponderNotFound.Error()
	case errors.Is(err, domain.ErrNotificationEndpointNotFound):
		return domain.ErrNotificationEndpointNotFound.Error()
	case errors.Is(err, domain.ErrCertificateProfileNotFound):
		return domain.ErrCertificateProfileNotFound.Error()
	case errors.Is(err, domain.ErrEnrollmentNotFound):
		return domain.ErrEnrollmentNotFound.Error()
	case errors.Is(err, domain.ErrCertificateNotFound):
		return domain.ErrCertificateNotFound.Error()
	case errors.Is(err, domain.ErrCRLPublicationNotFound):
		return domain.ErrCRLPublicationNotFound.Error()
	case errors.Is(err, domain.ErrOutboxMessageNotFound):
		return domain.ErrOutboxMessageNotFound.Error()
	case errors.Is(err, domain.ErrAPIKeyNotFound):
		return domain.ErrAPIKeyNotFound.Error()
	case errors.Is(err, domain.ErrACMEAccountNotFound):
		return domain.ErrACMEAccountNotFound.Error()
	case errors.Is(err, domain.ErrACMEAccountDeactivated):
		return domain.ErrACMEAccountDeactivated.Error()
	case errors.Is(err, domain.ErrACMEOrderNotFound):
		return domain.ErrACMEOrderNotFound.Error()
	case errors.Is(err, domain.ErrACMEAuthorizationNotFound):
		return domain.ErrACMEAuthorizationNotFound.Error()
	case errors.Is(err, domain.ErrACMEChallengeNotFound):
		return domain.ErrACMEChallengeNotFound.Error()
	case errors.Is(err, domain.ErrCSRParseFailed):
		return domain.ErrCSRParseFailed.Error()
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return domain.ErrCertificateIssuanceFailed.Error()
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return domain.ErrCRLGenerationFailed.Error()
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return domain.ErrOCSPDecodeFailed.Error()
	case errors.Is(err, domain.ErrOCSPResponderValidationFailed):
		return domain.ErrOCSPResponderValidationFailed.Error()
	case errors.Is(err, domain.ErrOCSPResponseFailed):
		return domain.ErrOCSPResponseFailed.Error()
	case errors.Is(err, domain.ErrAuditIntegrity):
		return domain.ErrAuditIntegrity.Error()
	case errors.Is(err, domain.ErrStorageFailure):
		return domain.ErrStorageFailure.Error()
	default:
		return "internal server error"
	}
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, errACMEBadNonce):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, domain.ErrACMEAccountDeactivated):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrInvalidTransition):
		return http.StatusConflict
	case errors.Is(err, domain.ErrIdentityNotFound),
		errors.Is(err, domain.ErrIssuerNotFound),
		errors.Is(err, domain.ErrOCSPResponderNotFound),
		errors.Is(err, domain.ErrNotificationEndpointNotFound),
		errors.Is(err, domain.ErrCertificateProfileNotFound),
		errors.Is(err, domain.ErrEnrollmentNotFound),
		errors.Is(err, domain.ErrCertificateNotFound),
		errors.Is(err, domain.ErrCRLPublicationNotFound),
		errors.Is(err, domain.ErrOutboxMessageNotFound),
		errors.Is(err, domain.ErrAPIKeyNotFound),
		errors.Is(err, domain.ErrACMEAccountNotFound),
		errors.Is(err, domain.ErrACMEOrderNotFound),
		errors.Is(err, domain.ErrACMEAuthorizationNotFound),
		errors.Is(err, domain.ErrACMEChallengeNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrCSRParseFailed):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrOCSPResponderValidationFailed):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrOCSPResponseFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrAuditIntegrity):
		return http.StatusInternalServerError
	case errors.Is(err, domain.ErrStorageFailure):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

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
