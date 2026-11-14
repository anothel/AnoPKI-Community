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
	service    *lifecycle.Service
	mux        *http.ServeMux
	auth       AuthConfig
	acme       ACMEConfig
	authorizer RequestAuthorizer
	nonces     ACMENonceStore
	rateMu     sync.Mutex
	rates      map[string]acmeRateBucket
}

var errACMEBadNonce = errors.New("acme bad nonce")

const acmeRetryAfterSeconds = "5"

const (
	defaultJSONBodyLimit        = 1 << 20
	defaultOCSPBodyLimit        = 16 << 10
	defaultACMENonceTTL         = 10 * time.Minute
	defaultACMENonceCacheSize   = 1024
	defaultACMERateLimit        = 120
	defaultACMERateWindow       = time.Minute
	defaultAuthorizationTimeout = 2 * time.Second
)

type AuthMode string

const (
	AuthModeDev    AuthMode = "dev"
	AuthModeAPIKey AuthMode = "api_key"
)

type AuthConfig struct {
	Mode                 AuthMode
	TrustedProxies       []netip.Prefix
	AuthorizationTimeout time.Duration
}

type RequestAuthorizer interface {
	Authorize(context.Context, AuthorizationInput) (AuthorizationResult, error)
}

type AuthorizationInput struct {
	ActorID              string
	AuthenticationMethod string
	RequiredScope        string
	HTTPMethod           string
	RoutePattern         string
	RequestID            string
	Traceparent          string
	ClientIP             string
	UserAgent            string
}

type AuthorizationOutcome string

const (
	AuthorizationOutcomeAllow            AuthorizationOutcome = "allow"
	AuthorizationOutcomeDeny             AuthorizationOutcome = "deny"
	AuthorizationOutcomeApprovalRequired AuthorizationOutcome = "approval_required"
)

type AuthorizationResult struct {
	Outcome        AuthorizationOutcome
	DecisionID     string
	ReasonCode     string
	PolicyRevision string
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
	return NewWithAuthorizer(service, auth, acme, nil)
}

func NewWithAuthorizer(service *lifecycle.Service, auth AuthConfig, acme ACMEConfig, authorizer RequestAuthorizer) *Server {
	if auth.Mode == "" {
		auth.Mode = AuthModeDev
	}
	if auth.AuthorizationTimeout <= 0 || auth.AuthorizationTimeout > defaultAuthorizationTimeout {
		auth.AuthorizationTimeout = defaultAuthorizationTimeout
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
		service:    service,
		mux:        http.NewServeMux(),
		auth:       auth,
		acme:       acme,
		authorizer: authorizer,
		nonces:     nonceStore,
		rates:      make(map[string]acmeRateBucket),
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
	auditMetadata := lifecycle.AuditRequestMetadata{
		RequestID:   requestID,
		Traceparent: strings.TrimSpace(r.Header.Get("Traceparent")),
		ClientIP:    requestClientIP(r, s.auth.TrustedProxies),
		UserAgent:   strings.TrimSpace(r.UserAgent()),
		AuthMethod:  string(s.auth.Mode),
		StartedAt:   time.Now(),
	}
	ctx := lifecycle.WithAuditRequestMetadata(r.Context(), auditMetadata)
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
	if s.authorizer != nil && !isPublicEndpoint(r.Method, r.URL.Path) {
		_, routePattern := s.mux.Handler(r)
		if _, pathPattern, ok := strings.Cut(routePattern, " "); ok {
			routePattern = pathPattern
		}
		if routePattern != "" {
			authorizationContext, cancelAuthorization := context.WithTimeout(r.Context(), s.auth.AuthorizationTimeout)
			result, err := s.authorizer.Authorize(authorizationContext, AuthorizationInput{
				ActorID:              requestActor(r),
				AuthenticationMethod: string(s.auth.Mode),
				RequiredScope:        string(requiredScopeForRequest(r.Method, r.URL.Path)),
				HTTPMethod:           r.Method,
				RoutePattern:         routePattern,
				RequestID:            auditMetadata.RequestID,
				Traceparent:          auditMetadata.Traceparent,
				ClientIP:             auditMetadata.ClientIP,
				UserAgent:            auditMetadata.UserAgent,
			})
			authorizationContextErr := authorizationContext.Err()
			cancelAuthorization()
			r = r.WithContext(lifecycle.WithAuthorizationAuditMetadata(
				r.Context(),
				authorizationAuditMetadata(result, err, authorizationContextErr),
			))
			if err != nil || result.Outcome != AuthorizationOutcomeAllow {
				s.writeError(rw, r, domain.ErrForbidden)
				return
			}
		}
	}
	if err := s.checkACMERateLimit(r); err != nil {
		metricBoundary = "rate_limit"
		s.writeError(rw, r, err)
		return
	}
	s.mux.ServeHTTP(rw, r)
}

func authorizationAuditMetadata(result AuthorizationResult, err error, contextErr error) lifecycle.AuthorizationAuditMetadata {
	metadata := lifecycle.AuthorizationAuditMetadata{
		DecisionID:      result.DecisionID,
		ReasonCode:      result.ReasonCode,
		PolicyRevision:  result.PolicyRevision,
		EvaluatorStatus: "ok",
	}
	switch {
	case errors.Is(contextErr, context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		metadata.Outcome = "error"
		metadata.EvaluatorStatus = "timeout"
	case errors.Is(contextErr, context.Canceled), errors.Is(err, context.Canceled):
		metadata.Outcome = "error"
		metadata.EvaluatorStatus = "canceled"
	case err != nil:
		metadata.Outcome = "error"
		metadata.EvaluatorStatus = "error"
	default:
		switch result.Outcome {
		case AuthorizationOutcomeAllow, AuthorizationOutcomeDeny, AuthorizationOutcomeApprovalRequired:
			metadata.Outcome = string(result.Outcome)
		default:
			metadata.Outcome = "invalid"
			metadata.EvaluatorStatus = "invalid_result"
		}
	}
	return metadata
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
	if path == "/debug/vars" || strings.HasPrefix(path, "/api-keys") || strings.HasPrefix(path, "/outbox/") || strings.HasPrefix(path, "/audit-events") || strings.HasPrefix(path, "/operator/") {
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

