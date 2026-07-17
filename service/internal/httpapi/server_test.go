// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/lifecycle"
	"github.com/anothel/anopki/service/internal/observability"
	"github.com/anothel/anopki/service/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var testNow = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestCreateIdentity(t *testing.T) {
	api := newTestAPI(t)

	var created apiIdentity
	lastSeenAt := testNow.Add(-time.Hour)
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type":                 string(domain.IdentityMachine),
		"name":                 "edge-01",
		"external_id":          "asset-123",
		"owner":                "platform",
		"team":                 "edge-team",
		"service":              "edge-proxy",
		"environment":          "prod",
		"deployment_target":    "lb-1",
		"last_seen_at":         lastSeenAt,
		"metadata_json":        `{"rack":"r1"}`,
		"allowed_dns_names":    []string{"edge-01.example.test"},
		"allowed_ip_addresses": []string{},
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created identity ID is empty")
	}
	if created.Type != domain.IdentityMachine {
		t.Fatalf("created identity type = %q, want %q", created.Type, domain.IdentityMachine)
	}
	if created.Name != "edge-01" {
		t.Fatalf("created identity name = %q, want %q", created.Name, "edge-01")
	}
	if created.Status != domain.IdentityActive {
		t.Fatalf("created identity status = %q, want %q", created.Status, domain.IdentityActive)
	}
	if created.Owner != "platform" ||
		created.Team != "edge-team" ||
		created.Service != "edge-proxy" ||
		created.Environment != "prod" ||
		created.DeploymentTarget != "lb-1" ||
		!created.LastSeenAt.Equal(lastSeenAt) ||
		created.MetadataJSON != `{"rack":"r1"}` ||
		!reflect.DeepEqual(created.AllowedDNSNames, []string{"edge-01.example.test"}) ||
		!reflect.DeepEqual(created.AllowedIPAddresses, []string{}) {
		t.Fatalf("created identity machine policy = %#v", created)
	}

	var listed []apiIdentity
	status = api.doJSON(t, http.MethodGet, "/identities", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("identity count = %d, want 1", len(listed))
	}
	if listed[0].ID != created.ID {
		t.Fatalf("listed identity ID = %q, want %q", listed[0].ID, created.ID)
	}

	var got apiIdentity
	status = api.doJSON(t, http.MethodGet, "/identities/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got identity ID = %q, want %q", got.ID, created.ID)
	}
	if got.Owner != created.Owner ||
		got.Team != created.Team ||
		got.Service != created.Service ||
		got.Environment != created.Environment ||
		got.DeploymentTarget != created.DeploymentTarget ||
		!got.LastSeenAt.Equal(created.LastSeenAt) ||
		got.MetadataJSON != created.MetadataJSON ||
		!reflect.DeepEqual(got.AllowedDNSNames, created.AllowedDNSNames) ||
		!reflect.DeepEqual(got.AllowedIPAddresses, created.AllowedIPAddresses) {
		t.Fatalf("got identity machine policy = %#v, want %#v", got, created)
	}
}

func TestPublicErrorMessageAndStatusForErrorMapping(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantMessage string
		wantStatus  int
	}{
		{name: "bad nonce", err: errACMEBadNonce, wantMessage: domain.ErrInvalidRequest.Error(), wantStatus: http.StatusBadRequest},
		{name: "invalid request", err: domain.ErrInvalidRequest, wantMessage: domain.ErrInvalidRequest.Error(), wantStatus: http.StatusBadRequest},
		{name: "unsupported media type", err: domain.ErrUnsupportedMediaType, wantMessage: domain.ErrUnsupportedMediaType.Error(), wantStatus: http.StatusUnsupportedMediaType},
		{name: "unauthorized", err: domain.ErrUnauthorized, wantMessage: domain.ErrUnauthorized.Error(), wantStatus: http.StatusUnauthorized},
		{name: "forbidden", err: domain.ErrForbidden, wantMessage: domain.ErrForbidden.Error(), wantStatus: http.StatusForbidden},
		{name: "rate limited", err: domain.ErrRateLimited, wantMessage: domain.ErrRateLimited.Error(), wantStatus: http.StatusTooManyRequests},
		{name: "identity not found", err: domain.ErrIdentityNotFound, wantMessage: domain.ErrIdentityNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "issuer not found", err: domain.ErrIssuerNotFound, wantMessage: domain.ErrIssuerNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "ocsp responder not found", err: domain.ErrOCSPResponderNotFound, wantMessage: domain.ErrOCSPResponderNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "notification endpoint not found", err: domain.ErrNotificationEndpointNotFound, wantMessage: domain.ErrNotificationEndpointNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "certificate profile not found", err: domain.ErrCertificateProfileNotFound, wantMessage: domain.ErrCertificateProfileNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "enrollment not found", err: domain.ErrEnrollmentNotFound, wantMessage: domain.ErrEnrollmentNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "certificate not found", err: domain.ErrCertificateNotFound, wantMessage: domain.ErrCertificateNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "crl publication not found", err: domain.ErrCRLPublicationNotFound, wantMessage: domain.ErrCRLPublicationNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "outbox message not found", err: domain.ErrOutboxMessageNotFound, wantMessage: domain.ErrOutboxMessageNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "api key not found", err: domain.ErrAPIKeyNotFound, wantMessage: domain.ErrAPIKeyNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "acme account not found", err: domain.ErrACMEAccountNotFound, wantMessage: domain.ErrACMEAccountNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "acme account deactivated", err: domain.ErrACMEAccountDeactivated, wantMessage: domain.ErrACMEAccountDeactivated.Error(), wantStatus: http.StatusUnauthorized},
		{name: "acme account deactivated wrapped", err: fmt.Errorf("wrapped: %w", domain.ErrACMEAccountDeactivated), wantMessage: domain.ErrACMEAccountDeactivated.Error(), wantStatus: http.StatusUnauthorized},
		{name: "acme order not found", err: domain.ErrACMEOrderNotFound, wantMessage: domain.ErrACMEOrderNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "acme authorization not found", err: domain.ErrACMEAuthorizationNotFound, wantMessage: domain.ErrACMEAuthorizationNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "acme challenge not found", err: domain.ErrACMEChallengeNotFound, wantMessage: domain.ErrACMEChallengeNotFound.Error(), wantStatus: http.StatusNotFound},
		{name: "csr parse failed", err: domain.ErrCSRParseFailed, wantMessage: domain.ErrCSRParseFailed.Error(), wantStatus: http.StatusUnprocessableEntity},
		{name: "certificate issuance failed", err: domain.ErrCertificateIssuanceFailed, wantMessage: domain.ErrCertificateIssuanceFailed.Error(), wantStatus: http.StatusBadGateway},
		{name: "crl generation failed", err: domain.ErrCRLGenerationFailed, wantMessage: domain.ErrCRLGenerationFailed.Error(), wantStatus: http.StatusBadGateway},
		{name: "ocsp decode failed", err: domain.ErrOCSPDecodeFailed, wantMessage: domain.ErrOCSPDecodeFailed.Error(), wantStatus: http.StatusBadRequest},
		{name: "ocsp responder validation failed", err: domain.ErrOCSPResponderValidationFailed, wantMessage: domain.ErrOCSPResponderValidationFailed.Error(), wantStatus: http.StatusUnprocessableEntity},
		{name: "ocsp response failed", err: domain.ErrOCSPResponseFailed, wantMessage: domain.ErrOCSPResponseFailed.Error(), wantStatus: http.StatusBadGateway},
		{name: "storage failure", err: domain.ErrStorageFailure, wantMessage: domain.ErrStorageFailure.Error(), wantStatus: http.StatusInternalServerError},
		{name: "invalid transition", err: domain.ErrInvalidTransition, wantMessage: domain.ErrInvalidTransition.Error(), wantStatus: http.StatusConflict},
		{name: "issuance attempt not found internal only", err: domain.ErrIssuanceAttemptNotFound, wantMessage: "internal server error", wantStatus: http.StatusInternalServerError},
		{name: "webhook delivery not found internal only", err: domain.ErrWebhookDeliveryNotFound, wantMessage: "internal server error", wantStatus: http.StatusInternalServerError},
		{name: "unknown", err: errors.New("unexpected"), wantMessage: "internal server error", wantStatus: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publicErrorMessage(tt.err); got != tt.wantMessage {
				t.Fatalf("publicErrorMessage(%v) = %q, want %q", tt.err, got, tt.wantMessage)
			}
			if got := statusForError(tt.err); got != tt.wantStatus {
				t.Fatalf("statusForError(%v) = %d, want %d", tt.err, got, tt.wantStatus)
			}
		})
	}
}

func TestACMEProblemTypeMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "bad nonce", err: errACMEBadNonce, want: "urn:ietf:params:acme:error:badNonce"},
		{name: "bad nonce wrapped", err: fmt.Errorf("wrapped: %w", errACMEBadNonce), want: "urn:ietf:params:acme:error:badNonce"},
		{name: "rate limited", err: domain.ErrRateLimited, want: "urn:ietf:params:acme:error:rateLimited"},
		{name: "rate limited wrapped", err: fmt.Errorf("wrapped: %w", domain.ErrRateLimited), want: "urn:ietf:params:acme:error:rateLimited"},
		{name: "acme account deactivated", err: domain.ErrACMEAccountDeactivated, want: "urn:ietf:params:acme:error:unauthorized"},
		{name: "unauthorized", err: domain.ErrUnauthorized, want: "urn:ietf:params:acme:error:unauthorized"},
		{name: "forbidden", err: domain.ErrForbidden, want: "urn:ietf:params:acme:error:unauthorized"},
		{name: "forbidden wrapped", err: fmt.Errorf("wrapped: %w", domain.ErrForbidden), want: "urn:ietf:params:acme:error:unauthorized"},
		{name: "invalid request", err: domain.ErrInvalidRequest, want: "urn:ietf:params:acme:error:malformed"},
		{name: "not found", err: domain.ErrCertificateNotFound, want: "urn:ietf:params:acme:error:malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acmeProblemType(tt.err); got != tt.want {
				t.Fatalf("acmeProblemType(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestCreateIdentityRejectsMissingOwnerInProduction(t *testing.T) {
	api := newTestAPI(t)
	api.service.EnableProductionPolicy()

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestBodySizeLimitRejectsOversizedJSON(t *testing.T) {
	api := newTestAPI(t)

	status, _, _ := api.doBinary(t, http.MethodPost, "/identities", "admin", "application/json", bytes.Repeat([]byte(" "), defaultJSONBodyLimit+1))
	assertStatus(t, status, http.StatusBadRequest)
}

func TestBodySizeLimitRejectsOversizedOCSPRequest(t *testing.T) {
	api := newTestAPI(t)

	status, _, _ := api.doBinary(t, http.MethodPost, "/ocsp", "client", "application/ocsp-request", bytes.Repeat([]byte{0}, defaultOCSPBodyLimit+1))
	assertStatus(t, status, http.StatusBadRequest)
}

func TestCreateIssuer(t *testing.T) {
	api := newTestAPI(t)

	var created apiIssuer
	status := api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":            "intermediate-ca",
		"kind":            string(domain.IssuerIntermediateCA),
		"certificate_pem": "issuer-cert-pem",
		"key_ref":         "issuer-key-ref",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created issuer ID is empty")
	}
	if created.Name != "intermediate-ca" {
		t.Fatalf("created issuer name = %q, want %q", created.Name, "intermediate-ca")
	}
	if created.Kind != domain.IssuerIntermediateCA {
		t.Fatalf("created issuer kind = %q, want %q", created.Kind, domain.IssuerIntermediateCA)
	}
	if created.Status != domain.IssuerActive {
		t.Fatalf("created issuer status = %q, want %q", created.Status, domain.IssuerActive)
	}
}

func TestACMEOrderAPI(t *testing.T) {
	api := newTestAPI(t)

	var account apiACMEAccount
	status := api.doJSON(t, http.MethodPost, "/acme/accounts", "acme-client", map[string]any{
		"contacts":                []string{"mailto:ops@example.test"},
		"terms_of_service_agreed": true,
	}, &account)
	assertStatus(t, status, http.StatusCreated)
	if account.ID == "" || account.Status != domain.ACMEAccountValid {
		t.Fatalf("account = %#v", account)
	}

	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status = api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	var order apiACMEOrder
	status = api.doJSON(t, http.MethodPost, "/acme/orders", "acme-client", map[string]any{
		"account_id":             account.ID,
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"profile_id":             profile.ID,
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    testNow.Add(12 * time.Hour),
	}, &order)
	assertStatus(t, status, http.StatusCreated)
	if order.Status != domain.ACMEOrderPending {
		t.Fatalf("order = %#v", order)
	}

	var authzs []apiACMEAuthorization
	status = api.doJSON(t, http.MethodGet, "/acme/orders/"+order.ID+"/authorizations", "", nil, &authzs)
	assertStatus(t, status, http.StatusOK)
	if len(authzs) != 2 {
		t.Fatalf("authorizations = %#v", authzs)
	}
	for _, authz := range authzs {
		var challenges []apiACMEChallenge
		status = api.doJSON(t, http.MethodGet, "/acme/authorizations/"+authz.ID+"/challenges", "", nil, &challenges)
		assertStatus(t, status, http.StatusOK)
		if len(challenges) != 1 || challenges[0].Token == "" {
			t.Fatalf("challenges = %#v", challenges)
		}
		var completed apiACMEChallenge
		status = api.doJSON(t, http.MethodPost, "/acme/challenges/"+challenges[0].ID+"/complete", "validator", nil, &completed)
		assertStatus(t, status, http.StatusOK)
		if completed.Status != domain.ACMEChallengeValid {
			t.Fatalf("completed challenge = %#v", completed)
		}
	}

	var ready apiACMEOrder
	status = api.doJSON(t, http.MethodGet, "/acme/orders/"+order.ID, "", nil, &ready)
	assertStatus(t, status, http.StatusOK)
	if ready.Status != domain.ACMEOrderReady {
		t.Fatalf("ready order = %#v", ready)
	}

	var finalized apiACMEOrder
	status = api.doJSON(t, http.MethodPost, "/acme/orders/"+order.ID+"/finalize", "acme-client", map[string]any{
		"csr_pem":           "csr-pem",
		"requested_subject": "CN=edge-01",
	}, &finalized)
	assertStatus(t, status, http.StatusOK)
	if finalized.Status != domain.ACMEOrderValid || finalized.CertificateID == "" || finalized.EnrollmentID == "" {
		t.Fatalf("finalized order = %#v", finalized)
	}
}

func TestACMEProtocolDirectoryAndNonce(t *testing.T) {
	api := newTestAPI(t)

	var directory map[string]any
	status := api.doJSON(t, http.MethodGet, "/acme/directory", "", nil, &directory)
	assertStatus(t, status, http.StatusOK)
	for _, key := range []string{"newNonce", "newAccount", "newOrder", "keyChange", "revokeCert"} {
		value, ok := directory[key].(string)
		if !ok || value == "" {
			t.Fatalf("directory[%s] = %#v", key, directory[key])
		}
	}

	status, _, nonce := api.doACMENonce(t)
	assertStatus(t, status, http.StatusOK)
	if nonce == "" {
		t.Fatal("Replay-Nonce header is empty")
	}
}

func TestACMEProtocolRejectsReplayNonce(t *testing.T) {
	api := newTestAPI(t)
	_, _, nonce := api.doACMENonce(t)

	var account apiACMEProtocolAccount
	response := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, api.acmeKID, api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	status := response.StatusCode
	assertStatus(t, status, http.StatusCreated)
	if response.ReplayNonce == "" {
		t.Fatal("new-account Replay-Nonce header is empty")
	}
	if account.Status != string(domain.ACMEAccountValid) || account.Location == "" {
		t.Fatalf("account = %#v", account)
	}

	var body acmeProblemResponse
	response = api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, api.acmeKID, api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &body)
	status = response.StatusCode
	assertStatus(t, status, http.StatusBadRequest)
	if response.ContentType != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json", response.ContentType)
	}
	if response.ReplayNonce == "" {
		t.Fatal("error Replay-Nonce header is empty")
	}
	if body.Type != "urn:ietf:params:acme:error:badNonce" || body.Detail != domain.ErrInvalidRequest.Error() || body.Status != http.StatusBadRequest {
		t.Fatalf("problem body = %#v", body)
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	foundReplayNonce := false
	for _, event := range events {
		if event.Action != "api.request_failed" {
			continue
		}
		metadata := apiAuditMetadata(t, event)
		if metadata["http_status"] != float64(http.StatusBadRequest) ||
			metadata["http_path"] != "/acme/new-account" {
			continue
		}
		if metadata["error_code"] != "invalid_request" {
			t.Fatalf("bad nonce audit event has error_code = %q, want invalid_request: %#v", metadata["error_code"], metadata)
		}
		foundReplayNonce = true
		break
	}
	if !foundReplayNonce {
		t.Fatalf("missing bad nonce audit event with invalid_request code in %v", apiAuditEventIDs(events))
	}
}

func TestACMEProtocolRateLimitsAccountRequests(t *testing.T) {
	api := newTestAPIWithACMEConfig(t, ACMEConfig{RateLimit: 1, RateLimitWindow: time.Minute})

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	response := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, response.StatusCode, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var problem acmeProblemResponse
	response = api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &problem)
	assertStatus(t, response.StatusCode, http.StatusTooManyRequests)
	if problem.Type != "urn:ietf:params:acme:error:rateLimited" ||
		problem.Detail != domain.ErrRateLimited.Error() ||
		response.RetryAfter == "" {
		t.Fatalf("rate limit response = %#v problem = %#v", response, problem)
	}
}

func TestACMEProtocolMalformedJWSProblemResponses(t *testing.T) {
	api := newTestAPI(t)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)
	accountKID := account.Location

	payloadB64 := acmeRawPayloadB64(t, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	})
	validProtected := func(nonce string) map[string]any {
		return map[string]any{
			"alg":   api.acmeSigner.alg(),
			"nonce": nonce,
			"url":   api.url + "/acme/new-account",
			"jwk":   api.acmeSigner.jwk(),
		}
	}

	tests := []struct {
		name  string
		build func(t *testing.T, nonce string) map[string]string
	}{
		{
			name: "missing protected",
			build: func(t *testing.T, nonce string) map[string]string {
				body := api.makeRawACMEJWS(t, validProtected(nonce), payloadB64, api.acmeSigner)
				delete(body, "protected")
				return body
			},
		},
		{
			name: "missing signature",
			build: func(t *testing.T, nonce string) map[string]string {
				body := api.makeRawACMEJWS(t, validProtected(nonce), payloadB64, api.acmeSigner)
				delete(body, "signature")
				return body
			},
		},
		{
			name: "invalid protected base64",
			build: func(t *testing.T, nonce string) map[string]string {
				return map[string]string{
					"protected": "!",
					"payload":   payloadB64,
					"signature": "invalid",
				}
			},
		},
		{
			name: "invalid protected JSON",
			build: func(t *testing.T, nonce string) map[string]string {
				return map[string]string{
					"protected": base64.RawURLEncoding.EncodeToString([]byte("{")),
					"payload":   payloadB64,
					"signature": "invalid",
				}
			},
		},
		{
			name: "unsupported alg",
			build: func(t *testing.T, nonce string) map[string]string {
				protected := validProtected(nonce)
				protected["alg"] = "HS256"
				return api.makeRawACMEJWS(t, protected, payloadB64, api.acmeSigner)
			},
		},
		{
			name: "URL mismatch",
			build: func(t *testing.T, nonce string) map[string]string {
				protected := validProtected(nonce)
				protected["url"] = api.url + "/acme/new-order"
				return api.makeRawACMEJWS(t, protected, payloadB64, api.acmeSigner)
			},
		},
		{
			name: "invalid payload base64",
			build: func(t *testing.T, nonce string) map[string]string {
				return api.makeRawACMEJWS(t, validProtected(nonce), "!", api.acmeSigner)
			},
		},
		{
			name: "invalid signature",
			build: func(t *testing.T, nonce string) map[string]string {
				body := api.makeRawACMEJWS(t, validProtected(nonce), payloadB64, api.acmeSigner)
				body["signature"] = base64.RawURLEncoding.EncodeToString([]byte("invalid signature"))
				return body
			},
		},
		{
			name: "protected header without kid or jwk",
			build: func(t *testing.T, nonce string) map[string]string {
				protected := validProtected(nonce)
				delete(protected, "jwk")
				return api.makeRawACMEJWS(t, protected, payloadB64, api.acmeSigner)
			},
		},
		{
			name: "protected header with both kid and jwk",
			build: func(t *testing.T, nonce string) map[string]string {
				protected := validProtected(nonce)
				protected["kid"] = accountKID
				return api.makeRawACMEJWS(t, protected, payloadB64, api.acmeSigner)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, nonce := api.doACMENonce(t)
			var body acmeProblemResponse
			response := api.doRawACMEJWS(t, "/acme/new-account", tt.build(t, nonce), &body)
			assertACMEMalformedProblem(t, response, body, nonce)
		})
	}
}

func TestACMEProtocolBadNonceRetry(t *testing.T) {
	tests := []struct {
		name                string
		nonce               func(t *testing.T, api *testAPI) string
		wantRetryStatusCode int
	}{
		{
			name: "unknown nonce",
			nonce: func(t *testing.T, api *testAPI) string {
				return "unknown-nonce"
			},
			wantRetryStatusCode: http.StatusCreated,
		},
		{
			name: "replayed nonce",
			nonce: func(t *testing.T, api *testAPI) string {
				_, _, nonce := api.doACMENonce(t)
				var account apiACMEProtocolAccount
				response := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
					"contact":              []string{"mailto:ops@example.test"},
					"termsOfServiceAgreed": true,
				}, &account)
				assertStatus(t, response.StatusCode, http.StatusCreated)
				return nonce
			},
			wantRetryStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newTestAPI(t)
			payload := map[string]any{
				"contact":              []string{"mailto:ops@example.test"},
				"termsOfServiceAgreed": true,
			}
			nonce := tt.nonce(t, api)

			var problem acmeProblemResponse
			response := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, payload, &problem)
			assertStatus(t, response.StatusCode, http.StatusBadRequest)
			if response.ContentType != "application/problem+json" {
				t.Fatalf("content type = %q, want application/problem+json", response.ContentType)
			}
			if response.ReplayNonce == "" || response.ReplayNonce == nonce {
				t.Fatalf("badNonce Replay-Nonce = %q, request nonce = %q", response.ReplayNonce, nonce)
			}
			if problem.Type != "urn:ietf:params:acme:error:badNonce" ||
				problem.Detail != domain.ErrInvalidRequest.Error() ||
				problem.Status != http.StatusBadRequest {
				t.Fatalf("problem body = %#v", problem)
			}

			var account apiACMEProtocolAccount
			retry := api.doACMEJWSWithResponse(t, "/acme/new-account", response.ReplayNonce, "", api.acmeSigner, payload, &account)
			assertStatus(t, retry.StatusCode, tt.wantRetryStatusCode)
			if retry.ReplayNonce == "" {
				t.Fatal("retry Replay-Nonce header is empty")
			}
			if account.Status != string(domain.ACMEAccountValid) || account.Location == "" {
				t.Fatalf("retry account = %#v", account)
			}
		})
	}
}

func TestACMENonceExpiresAndIsRemoved(t *testing.T) {
	server := New(nil)
	store := server.nonces.(*acmeMemoryNonceStore)
	nonce := "expired"
	store.nonces[nonce] = acmeStoredNonce{
		IssuedAt:  time.Now().Add(-defaultACMENonceTTL - time.Second),
		ExpiresAt: time.Now().Add(-time.Second),
	}

	if server.consumeACMENonce(context.Background(), nonce) {
		t.Fatal("consumeACMENonce accepted expired nonce")
	}
	if _, ok := store.nonces[nonce]; ok {
		t.Fatal("expired nonce was not removed")
	}
}

func TestACMENonceIssueCleansExpiredEntries(t *testing.T) {
	server := New(nil)
	store := server.nonces.(*acmeMemoryNonceStore)
	expired := "expired"
	valid := "valid"
	store.nonces[expired] = acmeStoredNonce{IssuedAt: time.Now().Add(-defaultACMENonceTTL - time.Second), ExpiresAt: time.Now().Add(-time.Second)}
	store.nonces[valid] = acmeStoredNonce{IssuedAt: time.Now(), ExpiresAt: time.Now().Add(defaultACMENonceTTL)}

	issued, err := server.issueACMENonce(context.Background())
	if err != nil {
		t.Fatalf("issueACMENonce returned error: %v", err)
	}
	if _, ok := store.nonces[expired]; ok {
		t.Fatal("expired nonce was not removed")
	}
	if _, ok := store.nonces[valid]; !ok {
		t.Fatal("valid nonce was removed")
	}
	if _, ok := store.nonces[issued]; !ok {
		t.Fatal("issued nonce was not stored")
	}
}

func TestACMENonceIssueEnforcesCacheLimit(t *testing.T) {
	server := New(nil)
	store := server.nonces.(*acmeMemoryNonceStore)
	now := time.Now().Add(-time.Minute)
	for i := 0; i < defaultACMENonceCacheSize; i++ {
		issuedAt := now.Add(time.Duration(i) * time.Second)
		store.nonces[fmt.Sprintf("nonce-%04d", i)] = acmeStoredNonce{IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(defaultACMENonceTTL)}
	}

	issued, err := server.issueACMENonce(context.Background())
	if err != nil {
		t.Fatalf("issueACMENonce returned error: %v", err)
	}
	if len(store.nonces) != defaultACMENonceCacheSize {
		t.Fatalf("nonce cache size = %d, want %d", len(store.nonces), defaultACMENonceCacheSize)
	}
	if _, ok := store.nonces["nonce-0000"]; ok {
		t.Fatal("oldest nonce was not evicted")
	}
	if _, ok := store.nonces[fmt.Sprintf("nonce-%04d", defaultACMENonceCacheSize-1)]; !ok {
		t.Fatal("newest existing nonce was evicted")
	}
	if _, ok := store.nonces[issued]; !ok {
		t.Fatal("issued nonce was not retained")
	}
}

func TestACMENonceIssueKeepsReturnedNonceWhenExistingEntriesAreNewer(t *testing.T) {
	server := New(nil)
	store := server.nonces.(*acmeMemoryNonceStore)
	future := time.Now().Add(time.Hour)
	for i := 0; i < defaultACMENonceCacheSize; i++ {
		issuedAt := future.Add(time.Duration(i) * time.Second)
		store.nonces[fmt.Sprintf("nonce-%04d", i)] = acmeStoredNonce{IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(defaultACMENonceTTL)}
	}

	issued, err := server.issueACMENonce(context.Background())
	if err != nil {
		t.Fatalf("issueACMENonce returned error: %v", err)
	}
	if len(store.nonces) != defaultACMENonceCacheSize {
		t.Fatalf("nonce cache size = %d, want %d", len(store.nonces), defaultACMENonceCacheSize)
	}
	if _, ok := store.nonces[issued]; !ok {
		t.Fatal("issued nonce was evicted")
	}
}

func TestACMESQLNonceStoreRejectsCrossNodeReplay(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	nonceStore := NewSQLACMENonceStore(db, "sqlite")
	firstNode := NewWithAuthAndACME(nil, AuthConfig{Mode: AuthModeDev}, ACMEConfig{NonceStore: nonceStore})
	secondNode := NewWithAuthAndACME(nil, AuthConfig{Mode: AuthModeDev}, ACMEConfig{NonceStore: nonceStore})

	nonce, err := firstNode.issueACMENonce(ctx)
	if err != nil {
		t.Fatalf("issueACMENonce returned error: %v", err)
	}
	if !secondNode.consumeACMENonce(ctx, nonce) {
		t.Fatal("second node rejected first use of shared nonce")
	}
	if firstNode.consumeACMENonce(ctx, nonce) {
		t.Fatal("first node accepted replayed shared nonce")
	}
}

func TestACMESQLNonceStoreUsesPostgresPlaceholders(t *testing.T) {
	want := "DELETE FROM acme_nonces WHERE nonce = $1 AND expires_at > $2"
	if postgresConsumeNonceQuery != want {
		t.Fatalf("query = %q, want %q", postgresConsumeNonceQuery, want)
	}
}

func TestACMESQLNonceStorePostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ANOPKI_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("set ANOPKI_POSTGRES_TEST_DSN to run PostgreSQL ACME nonce integration test")
	}

	ctx := context.Background()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatalf("drop postgres test schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatalf("create postgres test schema: %v", err)
	}
	if err := store.ApplyInitialMigration(ctx, db, "pgx"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	nonceStore := NewSQLACMENonceStore(db, "pgx")
	firstNode := NewWithAuthAndACME(nil, AuthConfig{Mode: AuthModeDev}, ACMEConfig{NonceStore: nonceStore})
	secondNode := NewWithAuthAndACME(nil, AuthConfig{Mode: AuthModeDev}, ACMEConfig{NonceStore: nonceStore})

	nonce, err := firstNode.issueACMENonce(ctx)
	if err != nil {
		t.Fatalf("issueACMENonce returned error: %v", err)
	}
	if !secondNode.consumeACMENonce(ctx, nonce) {
		t.Fatal("second node rejected first use of shared postgres nonce")
	}
	if firstNode.consumeACMENonce(ctx, nonce) {
		t.Fatal("first node accepted replayed postgres nonce")
	}
}

func TestACMEProtocolCertbotCompatibilityFixture(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)
	if accountResponse.Location != account.Location || accountResponse.ReplayNonce == "" || !strings.Contains(accountResponse.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("new-account headers = %#v, account = %#v", accountResponse, account)
	}

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	orderResponse := api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
			{"type": "ip", "value": "127.0.0.1"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, orderResponse.StatusCode, http.StatusCreated)
	if orderResponse.Location != order.URL || orderResponse.ReplayNonce == "" || !strings.Contains(orderResponse.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("new-order headers = %#v, order = %#v", orderResponse, order)
	}

	var fetchedOrder apiACMEProtocolOrder
	orderPostAsGet := api.doACMEPostAsGET(t, api.pathFromURL(t, order.URL), account.Location, api.acmeSigner, &fetchedOrder)
	assertStatus(t, orderPostAsGet.StatusCode, http.StatusOK)
	if fetchedOrder.ID != order.ID || orderPostAsGet.ReplayNonce == "" || !strings.Contains(orderPostAsGet.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("POST-as-GET order response = %#v headers = %#v", fetchedOrder, orderPostAsGet)
	}

	var authz apiACMEProtocolAuthorization
	authzPostAsGet := api.doACMEPostAsGET(t, api.pathFromURL(t, order.Authorizations[0]), account.Location, api.acmeSigner, &authz)
	assertStatus(t, authzPostAsGet.StatusCode, http.StatusOK)
	if authz.ID == "" || len(authz.Challenges) != 1 || authzPostAsGet.ReplayNonce == "" || !strings.Contains(authzPostAsGet.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("POST-as-GET authz response = %#v headers = %#v", authz, authzPostAsGet)
	}

	for _, authzURL := range order.Authorizations {
		var currentAuthz apiACMEProtocolAuthorization
		currentAuthzResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, authzURL), account.Location, api.acmeSigner, &currentAuthz)
		assertStatus(t, currentAuthzResponse.StatusCode, http.StatusOK)
		if len(currentAuthz.Challenges) != 1 {
			t.Fatalf("authorization = %#v", currentAuthz)
		}
		_, _, nonce = api.doACMENonce(t)
		var challenge apiACMEProtocolChallenge
		challengeResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, currentAuthz.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, &challenge)
		assertStatus(t, challengeResponse.StatusCode, http.StatusOK)
		if challenge.Status != string(domain.ACMEChallengeValid) || challengeResponse.ReplayNonce == "" ||
			!strings.Contains(challengeResponse.Link, "<"+authzURL+">;rel=\"up\"") {
			t.Fatalf("challenge response = %#v headers = %#v", challenge, challengeResponse)
		}
	}

	_, _, nonce = api.doACMENonce(t)
	var finalized apiACMEProtocolOrder
	finalizeResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, order.Finalize), nonce, account.Location, api.acmeSigner, map[string]any{
		"csr_pem":           "csr-pem",
		"requested_subject": "CN=edge-01",
	}, &finalized)
	assertStatus(t, finalizeResponse.StatusCode, http.StatusOK)
	if finalized.Certificate == "" || finalizeResponse.ReplayNonce == "" {
		t.Fatalf("finalize response = %#v headers = %#v", finalized, finalizeResponse)
	}

	certResponse := api.doACMEPostAsGETRaw(t, api.pathFromURL(t, finalized.Certificate), account.Location, api.acmeSigner)
	assertStatus(t, certResponse.StatusCode, http.StatusOK)
	if certResponse.ContentType != "application/pem-certificate-chain" || certResponse.Body != "issued:csr-pem\nissuer-cert-pem\n" ||
		certResponse.ReplayNonce == "" || !strings.Contains(certResponse.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("POST-as-GET cert response = %#v", certResponse)
	}
}

func TestACMEProtocolFinalizeAcceptsRFC8555CSR(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	orderResponse := api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
			{"type": "ip", "value": "127.0.0.1"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, orderResponse.StatusCode, http.StatusCreated)

	for _, authzURL := range order.Authorizations {
		var authz apiACMEProtocolAuthorization
		authzResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, authzURL), account.Location, api.acmeSigner, &authz)
		assertStatus(t, authzResponse.StatusCode, http.StatusOK)
		if len(authz.Challenges) != 1 {
			t.Fatalf("authorization = %#v", authz)
		}
		_, _, nonce = api.doACMENonce(t)
		var challenge apiACMEProtocolChallenge
		challengeResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, &challenge)
		assertStatus(t, challengeResponse.StatusCode, http.StatusOK)
	}

	_, _, nonce = api.doACMENonce(t)
	var finalized apiACMEProtocolOrder
	finalizeResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, order.Finalize), nonce, account.Location, api.acmeSigner, map[string]any{
		"csr": testACMECSRBase64URL(t),
	}, &finalized)
	assertStatus(t, finalizeResponse.StatusCode, http.StatusOK)
	if finalized.Status != string(domain.ACMEOrderValid) || finalized.Certificate == "" {
		t.Fatalf("finalized order = %#v", finalized)
	}
	if len(api.issuer.requests) != 1 ||
		!strings.Contains(api.issuer.requests[0].CSRPEM, "BEGIN CERTIFICATE REQUEST") ||
		api.issuer.requests[0].Subject != "CN=edge-01.example.test" {
		t.Fatalf("issuer request = %#v", api.issuer.requests)
	}
}

func TestNormalizeACMEFinalizeRequestDefaultsSubjectFromCSRIdentifier(t *testing.T) {
	csrPEM, subject, err := normalizeACMEFinalizeRequest(finalizeACMEOrderRequest{
		CSR: testACMECSRBase64URLWithSubject(t, pkix.Name{}),
	})
	if err != nil {
		t.Fatalf("normalizeACMEFinalizeRequest returned error: %v", err)
	}
	if !strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST") || subject != "CN=edge-01.example.test" {
		t.Fatalf("CSR subject = %q, CSR PEM contains request = %t", subject, strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST"))
	}
}

func TestACMEProtocolNewOrderUsesConfiguredDefaults(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	server := httptest.NewServer(NewWithAuthAndACME(api.service, AuthConfig{Mode: AuthModeDev}, ACMEConfig{
		DefaultIdentityID:           identity.ID,
		DefaultIssuerID:             issuer.ID,
		DefaultCertificateProfileID: profile.ID,
		DefaultValidityPeriod:       12 * time.Hour,
	}))
	t.Cleanup(server.Close)
	api.client = server.Client()
	api.url = server.URL

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	orderResponse := api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
		},
	}, &order)
	assertStatus(t, orderResponse.StatusCode, http.StatusCreated)
	if len(order.Identifiers) != 1 ||
		order.Identifiers[0].Type != "dns" ||
		order.Identifiers[0].Value != "edge-01.example.test" {
		t.Fatalf("order identifiers = %#v, want edge-01.example.test", order.Identifiers)
	}
	storedOrder, err := api.repo.GetACMEOrder(api.ctx, order.ID)
	if err != nil {
		t.Fatalf("GetACMEOrder returned error: %v", err)
	}
	if storedOrder.IdentityID != identity.ID || storedOrder.IssuerID != issuer.ID || storedOrder.CertificateProfileID != profile.ID {
		t.Fatalf("stored order defaults = %#v, want identity=%s issuer=%s profile=%s", storedOrder, identity.ID, issuer.ID, profile.ID)
	}
	if order.Expires.IsZero() {
		t.Fatalf("order missing expires: %#v", order)
	}
}

func TestACMEProtocolChallengePollingRetriesProcessingChallenge(t *testing.T) {
	api := newTestAPI(t)
	api.acmeHTTP01.failuresRemaining = 1
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	status = api.doACMEJWS(t, "/acme/new-account", nonce, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	status = api.doACMEJWS(t, "/acme/new-order", nonce, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, status, http.StatusCreated)

	var authz apiACMEProtocolAuthorization
	authzResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, order.Authorizations[0]), account.Location, api.acmeSigner, &authz)
	assertStatus(t, authzResponse.StatusCode, http.StatusOK)
	if len(authz.Challenges) != 1 {
		t.Fatalf("authorization = %#v", authz)
	}

	_, _, nonce = api.doACMENonce(t)
	var challenge apiACMEProtocolChallenge
	challengeResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, &challenge)
	assertStatus(t, challengeResponse.StatusCode, http.StatusOK)
	if challenge.Status != string(domain.ACMEChallengeProcessing) || challengeResponse.RetryAfter == "" {
		t.Fatalf("challenge response = %#v headers = %#v", challenge, challengeResponse)
	}

	var polledAuthz apiACMEProtocolAuthorization
	pollResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, order.Authorizations[0]), account.Location, api.acmeSigner, &polledAuthz)
	assertStatus(t, pollResponse.StatusCode, http.StatusOK)
	if polledAuthz.Status != string(domain.ACMEAuthorizationValid) ||
		len(polledAuthz.Challenges) != 1 ||
		polledAuthz.Challenges[0].Status != string(domain.ACMEChallengeValid) {
		t.Fatalf("polled authorization = %#v headers = %#v", polledAuthz, pollResponse)
	}

	var ready apiACMEProtocolOrder
	readyResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, order.URL), account.Location, api.acmeSigner, &ready)
	assertStatus(t, readyResponse.StatusCode, http.StatusOK)
	if ready.Status != string(domain.ACMEOrderReady) {
		t.Fatalf("ready order = %#v headers = %#v", ready, readyResponse)
	}
	if len(api.acmeHTTP01.requests) != 2 {
		t.Fatalf("HTTP-01 verifier request count = %d, want 2", len(api.acmeHTTP01.requests))
	}
}

func TestACMEProtocolAccountManagementReusesUpdatesAndDeactivatesAccount(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var reused apiACMEProtocolAccount
	reuseResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &reused)
	assertStatus(t, reuseResponse.StatusCode, http.StatusOK)
	if reused.ID != account.ID || reuseResponse.Location != account.Location {
		t.Fatalf("reused account = %#v headers = %#v, want id %s location %s", reused, reuseResponse, account.ID, account.Location)
	}
	accounts, err := api.repo.ListACMEAccounts(api.ctx)
	if err != nil {
		t.Fatalf("ListACMEAccounts returned error: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("account count = %d, want 1", len(accounts))
	}

	var updated apiACMEProtocolAccount
	updateResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, account.Location), reuseResponse.ReplayNonce, account.Location, api.acmeSigner, map[string]any{
		"contact": []string{"mailto:pki-admin@example.test"},
	}, &updated)
	assertStatus(t, updateResponse.StatusCode, http.StatusOK)
	if len(updated.Contact) != 1 || updated.Contact[0] != "mailto:pki-admin@example.test" || updated.Status != string(domain.ACMEAccountValid) {
		t.Fatalf("updated account = %#v", updated)
	}

	_, _, nonce = api.doACMENonce(t)
	var deactivated apiACMEProtocolAccount
	deactivateResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, account.Location), nonce, account.Location, api.acmeSigner, map[string]any{
		"status": string(domain.ACMEAccountDeactivated),
	}, &deactivated)
	assertStatus(t, deactivateResponse.StatusCode, http.StatusOK)
	if deactivated.Status != string(domain.ACMEAccountDeactivated) {
		t.Fatalf("deactivated account = %#v", deactivated)
	}

	_, _, nonce = api.doACMENonce(t)
	var orderProblem acmeProblemResponse
	orderResponse := api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &orderProblem)
	assertStatus(t, orderResponse.StatusCode, http.StatusUnauthorized)
	if orderProblem.Type != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("order problem = %#v", orderProblem)
	}
}

func TestACMEProtocolAccountKeyRollover(t *testing.T) {
	api := newTestAPI(t)
	oldSigner := api.acmeSigner
	newSigner := newACMERSATestSigner(t)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", oldSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)

	innerPayload := acmeRawPayloadB64(t, map[string]any{
		"account": account.Location,
		"oldKey":  oldSigner.jwk(),
	})
	inner := api.makeRawACMEJWS(t, map[string]any{
		"alg": newSigner.alg(),
		"url": api.url + "/acme/key-change",
		"jwk": newSigner.jwk(),
	}, innerPayload, newSigner)

	_, _, nonce = api.doACMENonce(t)
	var changed apiACMEProtocolAccount
	changeResponse := api.doACMEJWSWithResponse(t, "/acme/key-change", nonce, account.Location, oldSigner, inner, &changed)
	assertStatus(t, changeResponse.StatusCode, http.StatusOK)
	if changed.ID != account.ID || changed.Status != string(domain.ACMEAccountValid) {
		t.Fatalf("changed account = %#v", changed)
	}
	stored, err := api.repo.GetACMEAccount(api.ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	if !strings.Contains(stored.KeyJWKJSON, `"kty":"RSA"`) || stored.KeyThumbprint == "" {
		t.Fatalf("stored account after rollover = %#v", stored)
	}

	_, _, nonce = api.doACMENonce(t)
	var updated apiACMEProtocolAccount
	updateResponse := api.doACMEJWSWithResponse(t, api.pathFromURL(t, account.Location), nonce, account.Location, newSigner, map[string]any{
		"contact": []string{"mailto:new-key@example.test"},
	}, &updated)
	assertStatus(t, updateResponse.StatusCode, http.StatusOK)
	if len(updated.Contact) != 1 || updated.Contact[0] != "mailto:new-key@example.test" {
		t.Fatalf("updated account after rollover = %#v", updated)
	}
}

func TestACMEProtocolRSAAccountKeyCreatesOrderAndFinalizes(t *testing.T) {
	api := newTestAPI(t)
	rsaSigner := newACMERSATestSigner(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", rsaSigner, map[string]any{
		"contact":              []string{"mailto:rsa-ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)
	if account.Status != string(domain.ACMEAccountValid) || account.Location == "" {
		t.Fatalf("RSA account = %#v headers = %#v", account, accountResponse)
	}
	storedAccount, err := api.repo.GetACMEAccount(api.ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	if !strings.Contains(storedAccount.KeyJWKJSON, `"kty":"RSA"`) || storedAccount.KeyThumbprint == "" {
		t.Fatalf("stored RSA account = %#v", storedAccount)
	}

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	status = api.doACMEJWSWithSigner(t, "/acme/new-order", nonce, account.Location, rsaSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
			{"type": "ip", "value": "127.0.0.1"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, status, http.StatusCreated)
	if order.Status != string(domain.ACMEOrderPending) || len(order.Authorizations) != 2 {
		t.Fatalf("RSA order = %#v", order)
	}

	for _, authzURL := range order.Authorizations {
		var authz apiACMEProtocolAuthorization
		authzResponse := api.doACMEPostAsGET(t, api.pathFromURL(t, authzURL), account.Location, rsaSigner, &authz)
		assertStatus(t, authzResponse.StatusCode, http.StatusOK)
		if len(authz.Challenges) != 1 {
			t.Fatalf("RSA authorization = %#v", authz)
		}

		_, _, nonce = api.doACMENonce(t)
		var challenge apiACMEProtocolChallenge
		status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, account.Location, rsaSigner, map[string]any{}, &challenge)
		assertStatus(t, status, http.StatusOK)
		if challenge.Status != string(domain.ACMEChallengeValid) {
			t.Fatalf("RSA challenge = %#v", challenge)
		}
	}

	_, _, nonce = api.doACMENonce(t)
	var finalized apiACMEProtocolOrder
	status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, order.Finalize), nonce, account.Location, rsaSigner, map[string]any{
		"csr_pem":           "csr-pem",
		"requested_subject": "CN=edge-01",
	}, &finalized)
	assertStatus(t, status, http.StatusOK)
	if finalized.Status != string(domain.ACMEOrderValid) || finalized.Certificate == "" {
		t.Fatalf("RSA finalized order = %#v", finalized)
	}
}

func TestACMEProtocolEd25519AccountKeyCreatesOrder(t *testing.T) {
	api := newTestAPI(t)
	edSigner := newACMEEd25519TestSigner(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	var profile apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	accountResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", edSigner, map[string]any{
		"contact":              []string{"mailto:ed25519-ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, accountResponse.StatusCode, http.StatusCreated)
	if account.Status != string(domain.ACMEAccountValid) || account.Location == "" {
		t.Fatalf("Ed25519 account = %#v headers = %#v", account, accountResponse)
	}
	storedAccount, err := api.repo.GetACMEAccount(api.ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	wantJWK := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, edSigner.jwk()["x"])
	if storedAccount.KeyJWKJSON != wantJWK || storedAccount.KeyThumbprint == "" {
		t.Fatalf("stored Ed25519 account = %#v", storedAccount)
	}

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	status = api.doACMEJWSWithSigner(t, "/acme/new-order", nonce, account.Location, edSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, status, http.StatusCreated)
	if order.Status != string(domain.ACMEOrderPending) || len(order.Authorizations) != 1 {
		t.Fatalf("Ed25519 order = %#v", order)
	}
}

func TestACMEOKPJWKRejectsMalformedKeys(t *testing.T) {
	validX := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for _, tt := range []struct {
		name string
		jwk  acmeJWK
	}{
		{
			name: "wrong curve",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed448", X: validX},
		},
		{
			name: "missing x",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed25519"},
		},
		{
			name: "invalid base64",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed25519", X: "not base64"},
		},
		{
			name: "wrong public key length",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed25519", X: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))},
		},
		{
			name: "extra y",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed25519", X: validX, Y: "extra"},
		},
		{
			name: "extra rsa fields",
			jwk:  acmeJWK{KTY: "OKP", CRV: "Ed25519", X: validX, N: "extra", E: "extra"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := canonicalACMEJWKJSON(tt.jwk); !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("canonicalACMEJWKJSON error = %v, want ErrInvalidRequest", err)
			}
			if _, err := acmeOKPJWKPublicKey(tt.jwk); !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("acmeOKPJWKPublicKey error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestACMEProtocolOrderChallengeAndFinalize(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	var root apiIssuer
	status := api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":            "root-ca",
		"kind":            string(domain.IssuerRootCA),
		"certificate_pem": "root-cert-pem",
		"key_ref":         "root-key-ref",
		"trust_anchor":    true,
	}, &root)
	assertStatus(t, status, http.StatusCreated)
	var issuer apiIssuer
	status = api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":             "intermediate-ca",
		"kind":             string(domain.IssuerIntermediateCA),
		"parent_issuer_id": root.ID,
		"certificate_pem":  "issuer-cert-pem",
		"key_ref":          "issuer-key-ref",
	}, &issuer)
	assertStatus(t, status, http.StatusCreated)
	var profile apiCertificateProfile
	status = api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":    []string{"*.example.test"},
		"allowed_ip_ranges":       []string{"127.0.0.0/8"},
	}, &profile)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	status = api.doACMEJWS(t, "/acme/new-account", nonce, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, status, http.StatusCreated)
	storedAccount, err := api.repo.GetACMEAccount(api.ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	if storedAccount.KeyThumbprint == "" || storedAccount.KeyJWKJSON == "" {
		t.Fatalf("stored account missing bound key: %#v", storedAccount)
	}
	accountSigner := api.acmeSigner
	accountKID := account.Location

	otherSigner := newACMETestSigner(t)
	_, _, nonce = api.doACMENonce(t)
	var otherAccount apiACMEProtocolAccount
	status = api.doACMEJWSWithSigner(t, "/acme/new-account", nonce, "", otherSigner, map[string]any{
		"contact":              []string{"mailto:other@example.test"},
		"termsOfServiceAgreed": true,
	}, &otherAccount)
	assertStatus(t, status, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var wrongBaseKIDBody acmeProblemResponse
	status = api.doACMEJWSWithSigner(t, "/acme/new-order", nonce, "https://evil.example/acme/account/"+account.ID, accountSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &wrongBaseKIDBody)
	assertStatus(t, status, http.StatusBadRequest)
	if wrongBaseKIDBody.Detail != domain.ErrInvalidRequest.Error() {
		t.Fatalf("wrong-base kid error detail = %q, want %q", wrongBaseKIDBody.Detail, domain.ErrInvalidRequest.Error())
	}

	_, _, nonce = api.doACMENonce(t)
	var invalidSignatureBody acmeProblemResponse
	status = api.doACMEJWSWithSigner(t, "/acme/new-order", nonce, accountKID, newACMETestSigner(t), map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
			{"type": "ip", "value": "127.0.0.1"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &invalidSignatureBody)
	assertStatus(t, status, http.StatusBadRequest)
	if invalidSignatureBody.Detail != domain.ErrInvalidRequest.Error() {
		t.Fatalf("invalid signature error detail = %q, want %q", invalidSignatureBody.Detail, domain.ErrInvalidRequest.Error())
	}

	_, _, nonce = api.doACMENonce(t)
	var order apiACMEProtocolOrder
	status = api.doACMEJWSWithSigner(t, "/acme/new-order", nonce, accountKID, accountSigner, map[string]any{
		"account_id":  account.ID,
		"identity_id": identity.ID,
		"issuer_id":   issuer.ID,
		"profile_id":  profile.ID,
		"identifiers": []map[string]any{
			{"type": "dns", "value": "edge-01.example.test"},
			{"type": "ip", "value": "127.0.0.1"},
		},
		"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order)
	assertStatus(t, status, http.StatusCreated)
	if order.Status != string(domain.ACMEOrderPending) || len(order.Authorizations) != 2 || order.Finalize == "" || order.Expires.IsZero() {
		t.Fatalf("order = %#v", order)
	}

	for _, authzURL := range order.Authorizations {
		var authz apiACMEProtocolAuthorization
		status = api.doJSON(t, http.MethodGet, api.pathFromURL(t, authzURL), "", nil, &authz)
		assertStatus(t, status, http.StatusOK)
		if len(authz.Challenges) != 1 || authz.Expires.IsZero() {
			t.Fatalf("authorization = %#v", authz)
		}

		_, _, nonce = api.doACMENonce(t)
		var wrongAccountChallenge acmeProblemResponse
		status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, otherAccount.Location, otherSigner, map[string]any{}, &wrongAccountChallenge)
		assertStatus(t, status, http.StatusBadRequest)
		if wrongAccountChallenge.Detail != domain.ErrInvalidRequest.Error() {
			t.Fatalf("wrong account challenge error detail = %q, want %q", wrongAccountChallenge.Detail, domain.ErrInvalidRequest.Error())
		}

		_, _, nonce = api.doACMENonce(t)
		var challenge apiACMEProtocolChallenge
		status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, accountKID, accountSigner, map[string]any{}, &challenge)
		assertStatus(t, status, http.StatusOK)
		if challenge.Status != string(domain.ACMEChallengeValid) {
			t.Fatalf("challenge = %#v", challenge)
		}
	}

	var ready apiACMEProtocolOrder
	status = api.doJSON(t, http.MethodGet, api.pathFromURL(t, order.URL), "", nil, &ready)
	assertStatus(t, status, http.StatusOK)
	if ready.Status != string(domain.ACMEOrderReady) {
		t.Fatalf("ready order = %#v", ready)
	}

	_, _, nonce = api.doACMENonce(t)
	var wrongAccountFinalize acmeProblemResponse
	status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, order.Finalize), nonce, otherAccount.Location, otherSigner, map[string]any{
		"csr_pem":           "csr-pem",
		"requested_subject": "CN=edge-01",
	}, &wrongAccountFinalize)
	assertStatus(t, status, http.StatusBadRequest)
	if wrongAccountFinalize.Detail != domain.ErrInvalidRequest.Error() {
		t.Fatalf("wrong account finalize error detail = %q, want %q", wrongAccountFinalize.Detail, domain.ErrInvalidRequest.Error())
	}

	_, _, nonce = api.doACMENonce(t)
	var finalized apiACMEProtocolOrder
	status = api.doACMEJWSWithSigner(t, api.pathFromURL(t, order.Finalize), nonce, accountKID, accountSigner, map[string]any{
		"csr_pem":           "csr-pem",
		"requested_subject": "CN=edge-01",
	}, &finalized)
	assertStatus(t, status, http.StatusOK)
	if finalized.Status != string(domain.ACMEOrderValid) || finalized.Certificate == "" {
		t.Fatalf("finalized order = %#v", finalized)
	}
	certificatePath := api.pathFromURL(t, finalized.Certificate)
	if !strings.HasPrefix(certificatePath, "/acme/cert/") {
		t.Fatalf("certificate URL path = %q, want /acme/cert/{id}", certificatePath)
	}
	status, certificatePEM, contentType := api.doRaw(t, http.MethodGet, certificatePath, "")
	assertStatus(t, status, http.StatusOK)
	if contentType != "application/pem-certificate-chain" {
		t.Fatalf("certificate content type = %q, want application/pem-certificate-chain", contentType)
	}
	if string(certificatePEM) != "issued:csr-pem\nissuer-cert-pem\nroot-cert-pem\n" {
		t.Fatalf("certificate PEM = %q, want leaf plus issuer chain", string(certificatePEM))
	}
	postAsGetCert := api.doACMEPostAsGETRaw(t, certificatePath, accountKID, accountSigner)
	assertStatus(t, postAsGetCert.StatusCode, http.StatusOK)
	if postAsGetCert.ContentType != "application/pem-certificate-chain" ||
		postAsGetCert.Body != "issued:csr-pem\nissuer-cert-pem\nroot-cert-pem\n" ||
		postAsGetCert.ReplayNonce == "" ||
		!strings.Contains(postAsGetCert.Link, "/acme/directory>;rel=\"index\"") {
		t.Fatalf("POST-as-GET cert response = %#v", postAsGetCert)
	}

	_, _, nonce = api.doACMENonce(t)
	revokeResponse := api.doACMEJWSWithResponse(t, "/acme/revoke-cert", nonce, accountKID, accountSigner, map[string]any{
		"certificate_id": strings.TrimPrefix(certificatePath, "/acme/cert/"),
		"reason":         string(domain.RevocationSuperseded),
	}, nil)
	assertStatus(t, revokeResponse.StatusCode, http.StatusOK)
	revoked, err := api.repo.GetCertificate(api.ctx, strings.TrimPrefix(certificatePath, "/acme/cert/"))
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}
	if len(api.acmeHTTP01.requests) != len(order.Authorizations) {
		t.Fatalf("HTTP-01 verifier request count = %d, want %d", len(api.acmeHTTP01.requests), len(order.Authorizations))
	}
}

func TestIssuerTrustDistributionAPI(t *testing.T) {
	api := newTestAPI(t)

	var root apiIssuer
	status := api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":            "root-ca",
		"kind":            string(domain.IssuerRootCA),
		"certificate_pem": "root-cert-pem",
		"key_ref":         "root-key-ref",
		"trust_anchor":    true,
	}, &root)
	assertStatus(t, status, http.StatusCreated)

	var intermediate apiIssuer
	status = api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":                    "intermediate-ca",
		"kind":                    string(domain.IssuerIntermediateCA),
		"parent_issuer_id":        root.ID,
		"certificate_pem":         "intermediate-cert-pem",
		"key_ref":                 "intermediate-key-ref",
		"aia_url":                 "https://pki.example.test/issuers/intermediate-ca.pem",
		"crl_distribution_points": []string{"https://pki.example.test/crl/intermediate-ca.pem"},
	}, &intermediate)
	assertStatus(t, status, http.StatusCreated)
	if intermediate.ParentIssuerID != root.ID || intermediate.AIAURL == "" ||
		!reflect.DeepEqual(intermediate.CRLDistributionPoints, []string{"https://pki.example.test/crl/intermediate-ca.pem"}) {
		t.Fatalf("intermediate issuer = %#v", intermediate)
	}

	var chain []apiIssuer
	status = api.doJSON(t, http.MethodGet, "/issuers/"+intermediate.ID+"/chain", "", nil, &chain)
	assertStatus(t, status, http.StatusOK)
	if len(chain) != 2 || chain[0].ID != intermediate.ID || chain[1].ID != root.ID {
		t.Fatalf("issuer chain = %#v", chain)
	}

	var anchors []apiIssuer
	status = api.doJSON(t, http.MethodGet, "/trust/anchors", "", nil, &anchors)
	assertStatus(t, status, http.StatusOK)
	if len(anchors) != 1 || anchors[0].ID != root.ID || !anchors[0].TrustAnchor {
		t.Fatalf("trust anchors = %#v", anchors)
	}
}

func TestCreateAndListOCSPResponders(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-pem",
		"key_ref":         "responder-key",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created OCSP responder ID is empty")
	}
	if created.IssuerID != issuer.ID {
		t.Fatalf("created OCSP responder issuer ID = %q, want %q", created.IssuerID, issuer.ID)
	}
	if created.Name != "issuer-a-ocsp" {
		t.Fatalf("created OCSP responder name = %q, want %q", created.Name, "issuer-a-ocsp")
	}
	if created.Status != domain.OCSPResponderActive {
		t.Fatalf("created OCSP responder status = %q, want %q", created.Status, domain.OCSPResponderActive)
	}
	if created.CertificatePEM != "responder-pem" {
		t.Fatalf("created OCSP responder certificate = %q, want %q", created.CertificatePEM, "responder-pem")
	}
	if created.KeyRef != "responder-key" {
		t.Fatalf("created OCSP responder key ref = %q, want %q", created.KeyRef, "responder-key")
	}
	if len(api.issuer.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(api.issuer.ocspResponderValidationRequests))
	}
	validationReq := api.issuer.ocspResponderValidationRequests[0]
	if validationReq.issuerCertificatePEM != issuer.CertificatePEM {
		t.Fatalf("ValidateOCSPResponder issuer certificate = %q, want %q", validationReq.issuerCertificatePEM, issuer.CertificatePEM)
	}
	if validationReq.responderCertificatePEM != "responder-pem" {
		t.Fatalf("ValidateOCSPResponder responder certificate = %q, want %q", validationReq.responderCertificatePEM, "responder-pem")
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("OCSP responder count = %d, want 1", len(listed))
	}
	if listed[0].ID != created.ID {
		t.Fatalf("listed OCSP responder ID = %q, want %q", listed[0].ID, created.ID)
	}
}

func TestCreateOCSPResponderRejectsInvalidJSON(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", "not-an-object", &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestCreateOCSPResponderRequiresDisableBeforeReplacement(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	var body errorResponse
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusConflict)
	if body.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidTransition.Error())
	}
	if len(api.issuer.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(api.issuer.ocspResponderValidationRequests))
	}
}

func TestDisableOCSPResponderAllowsReplacement(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)

	var disabled apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/"+first.ID+"/disable", "admin", nil, &disabled)
	assertStatus(t, status, http.StatusOK)
	if disabled.Status != domain.OCSPResponderDisabled {
		t.Fatalf("disabled responder status = %q, want %q", disabled.Status, domain.OCSPResponderDisabled)
	}

	var second apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &second)
	assertStatus(t, status, http.StatusCreated)
	if second.Status != domain.OCSPResponderActive {
		t.Fatalf("replacement responder status = %q, want %q", second.Status, domain.OCSPResponderActive)
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 2 {
		t.Fatalf("OCSP responder count = %d, want 2", len(listed))
	}
	if listed[0].Status != domain.OCSPResponderDisabled || listed[1].Status != domain.OCSPResponderActive {
		t.Fatalf("OCSP responder statuses = %#v", listed)
	}
}

func TestRotateOCSPResponder(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)

	var rotated apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &rotated)
	assertStatus(t, status, http.StatusCreated)
	if rotated.ID == "" || rotated.ID == first.ID {
		t.Fatalf("rotated responder ID = %q, first ID = %q", rotated.ID, first.ID)
	}
	if rotated.IssuerID != issuer.ID ||
		rotated.Name != "issuer-b-ocsp" ||
		rotated.Status != domain.OCSPResponderActive ||
		rotated.CertificatePEM != "responder-b-pem" ||
		rotated.KeyRef != "responder-b-key" {
		t.Fatalf("rotated responder = %#v", rotated)
	}
	if len(api.issuer.ocspResponderValidationRequests) != 2 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 2", len(api.issuer.ocspResponderValidationRequests))
	}
	if got := api.issuer.ocspResponderValidationRequests[1].responderCertificatePEM; got != "responder-b-pem" {
		t.Fatalf("rotation validation responder certificate = %q, want responder-b-pem", got)
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	statuses := map[string]domain.OCSPResponderStatus{}
	for _, responder := range listed {
		statuses[responder.ID] = responder.Status
	}
	if statuses[first.ID] != domain.OCSPResponderDisabled || statuses[rotated.ID] != domain.OCSPResponderActive {
		t.Fatalf("OCSP responder statuses = %#v", statuses)
	}
}

func TestRotateOCSPResponderRequiresActiveResponder(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusConflict)
	if body.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidTransition.Error())
	}
	if len(api.issuer.ocspResponderValidationRequests) != 0 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 0", len(api.issuer.ocspResponderValidationRequests))
	}
}

func TestRotateOCSPResponderRejectsInvalidResponderValidation(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)
	api.issuer.ocspResponderValidationConfigured = true
	api.issuer.ocspResponderValidationResult = corecli.ValidateOCSPResponderResult{Valid: false}

	var body errorResponse
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusUnprocessableEntity)
	if body.Error != domain.ErrOCSPResponderValidationFailed.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrOCSPResponderValidationFailed.Error())
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != first.ID || listed[0].Status != domain.OCSPResponderActive {
		t.Fatalf("OCSP responders after failed rotate = %#v", listed)
	}
}

func TestCreateListAndDisableNotificationEndpoints(t *testing.T) {
	api := newTestAPI(t)

	var created apiNotificationEndpoint
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":        "ops-webhook",
		"url":         "https://ops.example.test/hooks/pki",
		"secret":      "super-secret",
		"event_types": []string{"certificate.expiration_warning", "certificate.expired"},
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created notification endpoint ID is empty")
	}
	if created.Name != "ops-webhook" ||
		created.Type != domain.NotificationEndpointWebhook ||
		created.Status != domain.NotificationEndpointActive ||
		created.URL != "https://ops.example.test/hooks/pki" ||
		len(created.EventTypes) != 2 {
		t.Fatalf("created notification endpoint = %#v", created)
	}

	var listed []apiNotificationEndpoint
	status = api.doJSON(t, http.MethodGet, "/notification-endpoints", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed notification endpoints = %#v", listed)
	}

	var disabled apiNotificationEndpoint
	status = api.doJSON(t, http.MethodPost, "/notification-endpoints/"+created.ID+"/disable", "admin", nil, &disabled)
	assertStatus(t, status, http.StatusOK)
	if disabled.Status != domain.NotificationEndpointDisabled {
		t.Fatalf("disabled notification endpoint status = %q, want disabled", disabled.Status)
	}
}

func TestCreateNotificationEndpointRequiresSecret(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name": "ops-webhook",
		"url":  "https://ops.example.test/hooks/pki",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestCreateNotificationEndpointDoesNotExposeSecret(t *testing.T) {
	api := newTestAPI(t)

	var created map[string]any
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":   "ops-webhook",
		"url":    "https://ops.example.test/hooks/pki",
		"secret": "super-secret",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if _, ok := created["secret"]; ok {
		t.Fatalf("notification endpoint response exposed secret: %#v", created)
	}
}

func TestCreateNotificationEndpointRejectsInvalidURL(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":   "ops-webhook",
		"url":    "ftp://ops.example.test/hooks/pki",
		"secret": "super-secret",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestCreateNotificationEndpointRejectsUnsafeURL(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":   "ops-webhook",
		"url":    "http://127.0.0.1/hooks/pki",
		"secret": "super-secret",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestListOutboxMessagesByStatusAndRetry(t *testing.T) {
	api := newTestAPI(t)
	message := domain.OutboxMessage{
		ID:           "outbox-dead",
		Type:         "certificate.expiration_warning",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxDeadLetter,
		AvailableAt:  testNow.Add(time.Hour),
		AttemptCount: 5,
		MaxAttempts:  5,
		LastError:    "webhook failed",
		CreatedAt:    testNow,
		UpdatedAt:    testNow,
	}
	if err := api.repo.CreateOutboxMessage(api.ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	var listed []apiOutboxMessage
	status := api.doJSON(t, http.MethodGet, "/outbox/messages?status=dead_letter", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 ||
		listed[0].ID != message.ID ||
		listed[0].Status != domain.OutboxDeadLetter ||
		listed[0].AttemptCount != 5 ||
		listed[0].LastError != "webhook failed" {
		t.Fatalf("listed outbox messages = %#v", listed)
	}

	var retried apiOutboxMessage
	status = api.doJSON(t, http.MethodPost, "/outbox/messages/"+message.ID+"/retry", "operator", nil, &retried)
	assertStatus(t, status, http.StatusOK)
	if retried.Status != domain.OutboxPending ||
		retried.AttemptCount != 0 ||
		retried.LastError != "" ||
		!retried.AvailableAt.Equal(testNow) {
		t.Fatalf("retried outbox message = %#v", retried)
	}
}

func TestListOutboxMessagesFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	base := testNow.Add(-time.Hour)
	for _, message := range []domain.OutboxMessage{
		testOutboxMessage("message-1", "certificate.issued", domain.OutboxPending, base),
		testOutboxMessage("message-2", "certificate.revoked", domain.OutboxDeadLetter, base.Add(time.Minute)),
		testOutboxMessage("message-3", "certificate.revoked", domain.OutboxPending, base.Add(2*time.Minute)),
	} {
		if err := api.repo.CreateOutboxMessage(api.ctx, message); err != nil {
			t.Fatalf("CreateOutboxMessage(%s) returned error: %v", message.ID, err)
		}
	}

	var messages []apiOutboxMessage
	path := "/outbox/messages?type=certificate.revoked&status=pending&sort=desc&limit=1"
	status := api.doJSON(t, http.MethodGet, path, "", nil, &messages)
	assertStatus(t, status, http.StatusOK)
	if got := apiOutboxMessageIDs(messages); !reflect.DeepEqual(got, []string{"message-3"}) {
		t.Fatalf("filtered outbox IDs = %#v", got)
	}

	from := base.Format(time.RFC3339)
	to := base.Add(3 * time.Minute).Format(time.RFC3339)
	path = "/outbox/messages?from=" + url.QueryEscape(from) + "&to=" + url.QueryEscape(to) + "&sort=asc&limit=1&offset=1"
	status = api.doJSON(t, http.MethodGet, path, "", nil, &messages)
	assertStatus(t, status, http.StatusOK)
	if got := apiOutboxMessageIDs(messages); !reflect.DeepEqual(got, []string{"message-2"}) {
		t.Fatalf("paged outbox IDs = %#v", got)
	}
}

func TestListOutboxMessagesRejectsInvalidTimeRange(t *testing.T) {
	api := newTestAPI(t)
	from := testNow
	to := testNow.Add(-time.Minute)
	fromParam := url.QueryEscape(from.Format(time.RFC3339))
	toParam := url.QueryEscape(to.Format(time.RFC3339))

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/outbox/messages?from="+fromParam+"&to="+toParam, "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %#v", body)
	}
}

func TestReplayDeadLetterOutboxMessagesRequiresGuards(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/outbox/messages/dead-letter/replay", "operator", map[string]any{
		"event_type": "certificate.issued",
		"limit":      10,
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestReplayDeadLetterOutboxMessagesFiltersByEventTypeAndTimeWindow(t *testing.T) {
	api := newTestAPI(t)
	messages := []domain.OutboxMessage{
		testOutboxMessage("outbox-match-1", "certificate.issued", domain.OutboxDeadLetter, testNow.Add(-2*time.Hour)),
		testOutboxMessage("outbox-match-2", "certificate.issued", domain.OutboxDeadLetter, testNow.Add(-time.Hour)),
		testOutboxMessage("outbox-too-old", "certificate.issued", domain.OutboxDeadLetter, testNow.Add(-24*time.Hour)),
		testOutboxMessage("outbox-other-type", "certificate.revoked", domain.OutboxDeadLetter, testNow.Add(-time.Hour)),
		testOutboxMessage("outbox-failed", "certificate.issued", domain.OutboxFailed, testNow.Add(-time.Hour)),
	}
	originals := messagesByID(messages)
	for _, message := range messages {
		if err := api.repo.CreateOutboxMessage(api.ctx, message); err != nil {
			t.Fatalf("CreateOutboxMessage(%s) returned error: %v", message.ID, err)
		}
	}

	var replayed apiOutboxBulkReplay
	status := api.doJSON(t, http.MethodPost, "/outbox/messages/dead-letter/replay", "operator", map[string]any{
		"event_type":   "certificate.issued",
		"created_from": testNow.Add(-3 * time.Hour),
		"created_to":   testNow,
		"limit":        1,
	}, &replayed)
	assertStatus(t, status, http.StatusOK)
	if replayed.ReplayedCount != 1 || !reflect.DeepEqual(replayed.MessageIDs, []string{"outbox-match-1"}) {
		t.Fatalf("bulk replay response = %#v", replayed)
	}

	match, err := api.repo.GetOutboxMessage(api.ctx, "outbox-match-1")
	if err != nil {
		t.Fatalf("GetOutboxMessage match returned error: %v", err)
	}
	if match.Status != domain.OutboxPending || match.AttemptCount != 0 || match.LastError != "" || !match.AvailableAt.Equal(testNow) {
		t.Fatalf("replayed message = %#v", match)
	}
	for _, id := range []string{"outbox-match-2", "outbox-too-old", "outbox-other-type", "outbox-failed"} {
		message, err := api.repo.GetOutboxMessage(api.ctx, id)
		if err != nil {
			t.Fatalf("GetOutboxMessage(%s) returned error: %v", id, err)
		}
		if message.Status != originals[id].Status {
			t.Fatalf("message %s status = %q, want unchanged %q", id, message.Status, originals[id].Status)
		}
	}
}

func TestCreateCertificateProfile(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                         "machine-server",
		"description":                  "Machine TLS server profile",
		"issuer_id":                    issuer.ID,
		"validity_period_seconds":      int64((24 * time.Hour).Seconds()),
		"subject_template":             "CN={{identity.name}}",
		"allowed_dns_patterns":         []string{"*.example.test"},
		"allowed_key_algorithms":       []string{"rsa"},
		"min_key_size_bits":            2048,
		"allowed_signature_algorithms": []string{"sha256"},
		"key_usage": map[string]any{
			"critical": true,
			"values":   []string{"digital_signature", "key_encipherment"},
		},
		"extended_key_usage": map[string]any{
			"critical": false,
			"values":   []string{"server_auth"},
		},
		"basic_constraints": map[string]any{
			"critical": true,
			"ca":       false,
		},
		"subject_key_identifier":   true,
		"authority_key_identifier": true,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created profile ID is empty")
	}
	if created.IssuerID != issuer.ID {
		t.Fatalf("created profile issuer ID = %q, want %q", created.IssuerID, issuer.ID)
	}
	if !created.KeyUsage.Critical || len(created.KeyUsage.Values) != 2 {
		t.Fatalf("created profile key usage = %#v", created.KeyUsage)
	}
	if !reflect.DeepEqual(created.AllowedKeyAlgorithms, []string{"rsa"}) ||
		created.MinKeySizeBits != 2048 ||
		!reflect.DeepEqual(created.AllowedSignatureAlgorithms, []string{"sha256"}) {
		t.Fatalf("created profile algorithm policy = %#v", created)
	}
	if !created.SubjectKeyIdentifier || !created.AuthorityKeyIdentifier {
		t.Fatalf("created profile key identifiers = ski:%t aki:%t", created.SubjectKeyIdentifier, created.AuthorityKeyIdentifier)
	}

	var listed []apiCertificateProfile
	status = api.doJSON(t, http.MethodGet, "/certificate-profiles", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("profile count = %d, want 1", len(listed))
	}

	var got apiCertificateProfile
	status = api.doJSON(t, http.MethodGet, "/certificate-profiles/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got profile ID = %q, want %q", got.ID, created.ID)
	}
}

func TestCreateEnrollment(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	requestedNotAfter := testNow.Add(24 * time.Hour)

	var created apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/enrollments", "operator", map[string]any{
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"csr_pem":                "csr-pem",
		"requested_subject":      "CN=edge-01",
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    requestedNotAfter,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.Status != domain.EnrollmentPending {
		t.Fatalf("created enrollment status = %q, want %q", created.Status, domain.EnrollmentPending)
	}
	if created.IdentityID != identity.ID {
		t.Fatalf("created enrollment identity ID = %q, want %q", created.IdentityID, identity.ID)
	}
	if len(created.RequestedDNSNames) != 1 || created.RequestedDNSNames[0] != "edge-01.example.test" {
		t.Fatalf("created enrollment DNS names = %#v, want edge-01.example.test", created.RequestedDNSNames)
	}
	if len(created.CSRDNSNames) != 1 || created.CSRDNSNames[0] != "edge-01.example.test" {
		t.Fatalf("created enrollment CSR DNS names = %#v, want edge-01.example.test", created.CSRDNSNames)
	}

	var listed []apiEnrollment
	status = api.doJSON(t, http.MethodGet, "/enrollments", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("enrollment count = %d, want 1", len(listed))
	}

	var got apiEnrollment
	status = api.doJSON(t, http.MethodGet, "/enrollments/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got enrollment ID = %q, want %q", got.ID, created.ID)
	}
}

func TestCreateEnrollmentPolicyFailureRecordsReason(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)
	var identity apiIdentity
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type":              string(domain.IdentityMachine),
		"name":              "edge-01",
		"allowed_dns_names": []string{"allowed.example.test"},
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var errorBody errorResponse
	status = api.doJSON(t, http.MethodPost, "/enrollments", "operator", map[string]any{
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"csr_pem":                "csr-pem",
		"requested_subject":      "CN=edge-01",
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    testNow.Add(24 * time.Hour),
	}, &errorBody)
	assertStatus(t, status, http.StatusBadRequest)
	if errorBody.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrInvalidRequest.Error())
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events?action=api.request_failed", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("failure audit events = %#v", events)
	}
	metadata := apiAuditMetadata(t, events[0])
	if metadata["policy_decision"] != "reject" ||
		metadata["policy_decision_reason"] != "identity_dns_not_allowed" {
		t.Fatalf("failure audit metadata = %#v", metadata)
	}
}

func TestApproveEnrollment(t *testing.T) {
	api := newTestAPI(t)
	enrollment := api.createPendingEnrollment(t)

	var approved apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/approve", "approver", nil, &approved)
	assertStatus(t, status, http.StatusOK)
	if approved.Status != domain.EnrollmentApproved {
		t.Fatalf("approved enrollment status = %q, want %q", approved.Status, domain.EnrollmentApproved)
	}
	if approved.ApprovedBy != "approver" {
		t.Fatalf("approved enrollment ApprovedBy = %q, want %q", approved.ApprovedBy, "approver")
	}

	var errorBody errorResponse
	status = api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/approve", "approver", nil, &errorBody)
	assertStatus(t, status, http.StatusConflict)
	if errorBody.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrInvalidTransition.Error())
	}
}

func TestApproveEnrollmentRecordsReason(t *testing.T) {
	api := newTestAPI(t)
	enrollment := api.createPendingEnrollment(t)

	var approved apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/approve", "approver", map[string]string{
		"reason": "ticket-123 approved by security",
	}, &approved)
	assertStatus(t, status, http.StatusOK)

	events, err := api.repo.ListAuditEvents(api.ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	var metadata map[string]any
	for _, event := range events {
		if event.Action != "enrollment.approved" || event.ResourceID != enrollment.ID {
			continue
		}
		if err := json.Unmarshal([]byte(event.MetadataJSON), &metadata); err != nil {
			t.Fatalf("unmarshal audit metadata for %s: %v", event.Action, err)
		}
		break
	}
	if metadata == nil {
		t.Fatalf("missing enrollment.approved audit event for %q", enrollment.ID)
	}
	if metadata["approval_reason"] != "ticket-123 approved by security" {
		t.Fatalf("approval_reason = %#v, want request reason; metadata=%#v", metadata["approval_reason"], metadata)
	}
}

func TestIssueCertificate(t *testing.T) {
	api := newTestAPI(t)
	enrollment := api.createApprovedEnrollment(t)

	var issued apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates", "issuer", map[string]string{
		"enrollment_id": enrollment.ID,
	}, &issued)
	assertStatus(t, status, http.StatusCreated)
	if issued.Status != domain.CertificateValid {
		t.Fatalf("issued certificate status = %q, want %q", issued.Status, domain.CertificateValid)
	}
	if issued.Subject != "CN=edge-01" {
		t.Fatalf("issued certificate subject = %q, want %q", issued.Subject, "CN=edge-01")
	}
	if issued.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("issued certificate PEM = %q, want %q", issued.CertificatePEM, "issued:csr-pem")
	}
	if len(api.issuer.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(api.issuer.requests))
	}

	var listed []apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(listed))
	}

	var got apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates/"+issued.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != issued.ID {
		t.Fatalf("got certificate ID = %q, want %q", got.ID, issued.ID)
	}
}

func TestListCertificatesFiltersExpiryWindows(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var listed []apiCertificate
	status := api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=1", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != certificate.ID {
		t.Fatalf("listed certificates = %#v, want certificate %q", listed, certificate.ID)
	}

	var body errorResponse
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=2", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=-1", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=0", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=abc", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
}

func TestListCertificatesExpiryWindowPaginatesByExpiration(t *testing.T) {
	api := newTestAPI(t)
	for _, certificate := range []domain.Certificate{
		testCertificate("certificate-3", testNow.Add(72*time.Hour)),
		testCertificate("certificate-1", testNow.Add(24*time.Hour)),
		testCertificate("certificate-2", testNow.Add(48*time.Hour)),
		testCertificate("certificate-expired", testNow.Add(-time.Hour)),
		testCertificateWithStatus("certificate-revoked", testNow.Add(12*time.Hour), domain.CertificateRevoked),
	} {
		if err := api.repo.CreateCertificate(api.ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	var first []apiCertificate
	status := api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=7&limit=2&offset=0", "", nil, &first)
	assertStatus(t, status, http.StatusOK)
	if got := certificateIDs(first); !reflect.DeepEqual(got, []string{"certificate-1", "certificate-2"}) {
		t.Fatalf("first expiry page IDs = %#v", got)
	}

	var second []apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=7&limit=2&offset=2", "", nil, &second)
	assertStatus(t, status, http.StatusOK)
	if got := certificateIDs(second); !reflect.DeepEqual(got, []string{"certificate-3"}) {
		t.Fatalf("second expiry page IDs = %#v", got)
	}

	var body errorResponse
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=7&limit=0", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=7&offset=-1", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/certificates?expires_within_days=7&offset=1", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
}

func TestOperatorCertificateInventoryAndExpirySLO(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var inventory []apiCertificateInventoryEntry
	status := api.doJSON(t, http.MethodGet, "/operator/certificate-inventory", "", nil, &inventory)
	assertStatus(t, status, http.StatusOK)
	if len(inventory) != 1 || inventory[0].CertificateID != certificate.ID {
		t.Fatalf("inventory = %#v, want certificate %q", inventory, certificate.ID)
	}
	if inventory[0].IssuerKeyRef != "issuer-key-ref" || inventory[0].RevocationState != string(domain.CertificateValid) {
		t.Fatalf("inventory entry = %#v", inventory[0])
	}

	var slo apiExpirySLO
	status = api.doJSON(t, http.MethodGet, "/operator/expiry-slo", "", nil, &slo)
	assertStatus(t, status, http.StatusOK)
	if slo.WindowDays != 14 || slo.UnhandledCount != 1 || slo.OK {
		t.Fatalf("expiry SLO = %#v, want one unhandled certificate inside 14 days", slo)
	}
}

func TestOperatorCertificateInventoryFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	alpha := api.createCertificateForIdentity(t, "alpha", "platform", "payments", "pay-api", "prod", "k8s/pay-api")
	api.createCertificateForIdentity(t, "beta", "security", "identity", "id-api", "stage", "k8s/id-api")

	var inventory []apiCertificateInventoryEntry
	status := api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?owner=platform&service=pay-api&environment=prod&limit=1&offset=0", "", nil, &inventory)
	assertStatus(t, status, http.StatusOK)
	if len(inventory) != 1 || inventory[0].CertificateID != alpha.ID {
		t.Fatalf("filtered inventory = %#v, want alpha certificate %q", inventory, alpha.ID)
	}
	if inventory[0].Owner != "platform" || inventory[0].Team != "payments" || inventory[0].Service != "pay-api" ||
		inventory[0].Environment != "prod" || inventory[0].DeploymentTarget != "k8s/pay-api" {
		t.Fatalf("filtered inventory metadata = %#v", inventory[0])
	}

	var first []apiCertificateInventoryEntry
	status = api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?limit=1&offset=0", "", nil, &first)
	assertStatus(t, status, http.StatusOK)
	var second []apiCertificateInventoryEntry
	status = api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?limit=1&offset=1", "", nil, &second)
	assertStatus(t, status, http.StatusOK)
	if len(first) != 1 || len(second) != 1 || second[0].CertificateID == first[0].CertificateID {
		t.Fatalf("paginated inventory page0=%#v page1=%#v, want different certificates", first, second)
	}

	var sorted []apiCertificateInventoryEntry
	status = api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?sort=desc&limit=1", "", nil, &sorted)
	assertStatus(t, status, http.StatusOK)
	if len(sorted) != 1 || sorted[0].CertificateID != second[0].CertificateID || sorted[0].CertificateID == first[0].CertificateID {
		t.Fatalf("sorted inventory = %#v first page = %#v second page = %#v", sorted, first, second)
	}

	var body errorResponse
	status = api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?limit=0", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	status = api.doJSON(t, http.MethodGet, "/operator/certificate-inventory?sort=sideways", "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
}

func TestListEndpointsRejectInvalidQueryOptions(t *testing.T) {
	api := newTestAPI(t)
	paths := []string{
		"/identities?sort=sideways",
		"/identities?limit=0",
		"/identities?offset=1",
		"/enrollments?sort=sideways",
		"/enrollments?status=sideways",
		"/enrollments?limit=0",
		"/enrollments?offset=1",
		"/certificates?sort=sideways",
		"/certificates?revocation_state=sideways",
		"/certificates?renewal_state=bogus",
		"/certificates?expires_within_days=-1",
		"/certificates?expires_within_days=0",
		"/certificates?expires_within_days=abc",
		"/certificates?expires_within_days=2",
		"/certificates?limit=0",
		"/certificates?offset=1",
		"/operator/certificate-inventory?sort=sideways",
		"/operator/certificate-inventory?revocation_state=sideways",
		"/operator/certificate-inventory?limit=0",
		"/operator/certificate-inventory?offset=1",
		"/outbox/messages?sort=sideways",
		"/outbox/messages?status=sideways",
		"/outbox/messages?from=bad-date",
		"/outbox/messages?to=bad-date",
		"/outbox/messages?limit=0",
		"/outbox/messages?offset=1",
		"/audit-events?sort=sideways",
		"/audit-events?from=bad-date",
		"/audit-events?to=bad-date",
		"/audit-events?limit=0",
		"/audit-events?offset=1",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var body errorResponse
			status := api.doJSON(t, http.MethodGet, path, "", nil, &body)
			assertStatus(t, status, http.StatusBadRequest)
			if body.Error != domain.ErrInvalidRequest.Error() {
				t.Fatalf("error body = %#v", body)
			}
		})
	}
}

func TestListAuditEventsRejectsInvalidTimeRange(t *testing.T) {
	api := newTestAPI(t)
	from := testNow
	to := testNow.Add(-time.Minute)
	fromParam := url.QueryEscape(from.Format(time.RFC3339))
	toParam := url.QueryEscape(to.Format(time.RFC3339))

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/audit-events?from="+fromParam+"&to="+toParam, "", nil, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %#v", body)
	}
}

func TestListIdentitiesFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	for _, identity := range []domain.Identity{
		testHTTPIdentity("identity-1", "alpha", "platform", "payments", "pay-api", "prod"),
		testHTTPIdentity("identity-2", "beta", "platform", "payments", "pay-api", "stage"),
		testHTTPIdentity("identity-3", "gamma", "security", "identity", "id-api", "prod"),
	} {
		if err := api.repo.CreateIdentity(api.ctx, identity); err != nil {
			t.Fatalf("CreateIdentity(%s) returned error: %v", identity.ID, err)
		}
	}

	var identities []apiIdentity
	status := api.doJSON(t, http.MethodGet, "/identities?owner=platform&service=pay-api&environment=prod&sort=desc&limit=1", "", nil, &identities)
	assertStatus(t, status, http.StatusOK)
	if got := apiIdentityIDs(identities); !reflect.DeepEqual(got, []string{"identity-1"}) {
		t.Fatalf("filtered identity IDs = %#v", got)
	}

	status = api.doJSON(t, http.MethodGet, "/identities?sort=asc&limit=1&offset=1", "", nil, &identities)
	assertStatus(t, status, http.StatusOK)
	if got := apiIdentityIDs(identities); !reflect.DeepEqual(got, []string{"identity-2"}) {
		t.Fatalf("paged identity IDs = %#v", got)
	}
}

func TestListEnrollmentsFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	now := testNow
	for _, enrollment := range []domain.Enrollment{
		testHTTPEnrollment("enrollment-1", "identity-1", "issuer-1", "profile-1", domain.EnrollmentPending, now),
		testHTTPEnrollment("enrollment-2", "identity-2", "issuer-1", "profile-1", domain.EnrollmentRejected, now.Add(time.Minute)),
		testHTTPEnrollment("enrollment-3", "identity-1", "issuer-2", "profile-2", domain.EnrollmentPending, now.Add(2*time.Minute)),
	} {
		if err := api.repo.CreateEnrollment(api.ctx, enrollment); err != nil {
			t.Fatalf("CreateEnrollment(%s) returned error: %v", enrollment.ID, err)
		}
	}

	var enrollments []apiEnrollment
	status := api.doJSON(t, http.MethodGet, "/enrollments?identity_id=identity-1&status=pending&sort=desc&limit=1", "", nil, &enrollments)
	assertStatus(t, status, http.StatusOK)
	if got := apiEnrollmentIDs(enrollments); !reflect.DeepEqual(got, []string{"enrollment-3"}) {
		t.Fatalf("filtered enrollment IDs = %#v", got)
	}

	status = api.doJSON(t, http.MethodGet, "/enrollments?issuer_id=issuer-1&profile_id=profile-1&sort=asc&limit=1&offset=1", "", nil, &enrollments)
	assertStatus(t, status, http.StatusOK)
	if got := apiEnrollmentIDs(enrollments); !reflect.DeepEqual(got, []string{"enrollment-2"}) {
		t.Fatalf("paged enrollment IDs = %#v", got)
	}
}

func TestListCertificatesFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	now := testNow
	for _, identity := range []domain.Identity{
		testHTTPIdentity("identity-1", "alpha", "platform", "payments", "pay-api", "prod"),
		testHTTPIdentity("identity-2", "beta", "security", "identity", "id-api", "stage"),
	} {
		if err := api.repo.CreateIdentity(api.ctx, identity); err != nil {
			t.Fatalf("CreateIdentity(%s) returned error: %v", identity.ID, err)
		}
	}
	certificates := []domain.Certificate{
		testHTTPCertificate("certificate-1", "identity-1", "issuer-1", "profile-1", domain.CertificateValid, now.Add(24*time.Hour), []string{"alpha.example.test"}, nil),
		testHTTPCertificate("certificate-2", "identity-1", "issuer-1", "profile-1", domain.CertificateValid, now.Add(48*time.Hour), []string{"beta.example.test"}, nil),
		testHTTPCertificate("certificate-3", "identity-2", "issuer-2", "profile-2", domain.CertificateRevoked, now.Add(72*time.Hour), []string{"gamma.example.test"}, nil),
	}
	certificates[1].RenewalNotifiedAt = now
	for _, certificate := range certificates {
		if err := api.repo.CreateCertificate(api.ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	var listed []apiCertificate
	status := api.doJSON(t, http.MethodGet, "/certificates?owner=platform&service=pay-api&environment=prod&issuer_id=issuer-1&profile_id=profile-1&san=beta.example.test&renewal_state=notified&sort=desc&limit=1", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if got := certificateIDs(listed); !reflect.DeepEqual(got, []string{"certificate-2"}) {
		t.Fatalf("filtered certificate IDs = %#v", got)
	}

	status = api.doJSON(t, http.MethodGet, "/certificates?revocation_state=valid&expires_within_days=30&sort=asc&limit=1&offset=1", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if got := certificateIDs(listed); !reflect.DeepEqual(got, []string{"certificate-2"}) {
		t.Fatalf("paged certificate IDs = %#v", got)
	}
}

func TestScanCertificateExpirations(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var result apiExpirationScanResult
	status := api.doJSON(t, http.MethodPost, "/certificates/expiration-scan", "scanner", map[string]any{
		"warning_window_seconds": int64((48 * time.Hour).Seconds()),
		"limit":                  10,
	}, &result)
	assertStatus(t, status, http.StatusOK)
	if len(result.Expired) != 0 {
		t.Fatalf("expired certificates = %#v, want none", result.Expired)
	}
	if len(result.ExpirationWarnings) != 1 || result.ExpirationWarnings[0].ID != certificate.ID {
		t.Fatalf("expiration warnings = %#v, want certificate %q", result.ExpirationWarnings, certificate.ID)
	}
	if result.ExpirationWarnings[0].RenewalNotifiedAt.IsZero() {
		t.Fatalf("warning RenewalNotifiedAt is zero: %#v", result.ExpirationWarnings[0])
	}

	var listed []apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != certificate.ID || listed[0].RenewalNotifiedAt.IsZero() {
		t.Fatalf("listed certificate after expiration scan = %#v", listed)
	}
}

func TestIssueCertificateHidesIssuerErrorCause(t *testing.T) {
	api := newTestAPI(t)
	api.issuer.err = errors.New("fake issuer detail")
	enrollment := api.createApprovedEnrollment(t)

	var errorBody errorResponse
	status := api.doJSON(t, http.MethodPost, "/certificates", "issuer", map[string]string{
		"enrollment_id": enrollment.ID,
	}, &errorBody)
	assertStatus(t, status, http.StatusBadGateway)
	if errorBody.Error != domain.ErrCertificateIssuanceFailed.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrCertificateIssuanceFailed.Error())
	}
}

func TestRevokeCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}
}

func TestSuspendResumeAndForceRevokeCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var suspended apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)
	if suspended.Status != domain.CertificateSuspended {
		t.Fatalf("suspended certificate status = %q, want %q", suspended.Status, domain.CertificateSuspended)
	}

	var resumed apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/resume", "operator", nil, &resumed)
	assertStatus(t, status, http.StatusOK)
	if resumed.Status != domain.CertificateValid {
		t.Fatalf("resumed certificate status = %q, want %q", resumed.Status, domain.CertificateValid)
	}

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)
	var revoked apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]any{
		"reason": string(domain.RevocationSuperseded),
		"force":  true,
	}, &revoked)
	assertStatus(t, status, http.StatusOK)
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("force revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}
}

func TestRenewCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)
	requestedNotAfter := testNow.Add(90 * 24 * time.Hour)

	var renewal apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/renew", "operator", map[string]any{
		"csr_pem":             "renewal-csr-pem",
		"requested_not_after": requestedNotAfter,
	}, &renewal)
	assertStatus(t, status, http.StatusCreated)
	if renewal.Status != domain.EnrollmentPending {
		t.Fatalf("renewal status = %q, want %q", renewal.Status, domain.EnrollmentPending)
	}
	if renewal.IdentityID != certificate.IdentityID ||
		renewal.IssuerID != certificate.IssuerID ||
		renewal.CertificateProfileID != certificate.CertificateProfileID ||
		renewal.SourceCertificateID != certificate.ID ||
		renewal.RequestedSubject != certificate.Subject ||
		renewal.CSRPEM != "renewal-csr-pem" {
		t.Fatalf("renewal = %#v, certificate = %#v", renewal, certificate)
	}
}

func TestReissueCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var reissue apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/reissue", "operator", map[string]any{
		"csr_pem": "reissue-csr-pem",
	}, &reissue)
	assertStatus(t, status, http.StatusCreated)
	if reissue.Status != domain.EnrollmentPending {
		t.Fatalf("reissue status = %q, want %q", reissue.Status, domain.EnrollmentPending)
	}
	if reissue.IdentityID != certificate.IdentityID ||
		reissue.IssuerID != certificate.IssuerID ||
		reissue.CertificateProfileID != certificate.CertificateProfileID ||
		reissue.SourceCertificateID != certificate.ID ||
		reissue.RequestedSubject != certificate.Subject ||
		reissue.CSRPEM != "reissue-csr-pem" ||
		!reissue.RequestedNotAfter.Equal(certificate.NotAfter) {
		t.Fatalf("reissue = %#v, certificate = %#v", reissue, certificate)
	}
}

func TestCertificateLifecycleRejectsInvalidTransitions(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/resume", "operator", nil, &body)
	assertStatus(t, status, http.StatusConflict)

	var suspended apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &body)
	assertStatus(t, status, http.StatusConflict)

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationSuperseded),
	}, &body)
	assertStatus(t, status, http.StatusConflict)
}

func TestPublishCRL(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)

	var created apiCRLPublication
	nextUpdate := testNow.Add(24 * time.Hour)
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": "https://pki.example.test/intermediate.crl",
		"next_update":        nextUpdate,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.IssuerID != certificate.IssuerID || created.CRLNumber != 1 || created.CRLPEM != "crl-pem" {
		t.Fatalf("created CRL = %#v", created)
	}

	var got apiCRLPublication
	status = api.doJSON(t, http.MethodGet, "/crls/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got CRL ID = %q, want %q", got.ID, created.ID)
	}

	status, body, contentType := api.doRaw(t, http.MethodGet, "/issuers/"+certificate.IssuerID+"/crl", "")
	assertStatus(t, status, http.StatusOK)
	if string(body) != "crl-pem" {
		t.Fatalf("published CRL body = %q, want crl-pem", string(body))
	}
	if contentType != "application/x-pem-file" {
		t.Fatalf("published CRL content type = %q", contentType)
	}
}

func TestGetLatestIssuerCRLFiltersByDistributionPoint(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)

	dpA := "https://pki.example.test/a.crl"
	dpB := "https://pki.example.test/b.crl"
	nextUpdate := testNow.Add(24 * time.Hour)

	api.issuer.crlPEM = "crl-a"
	var crlA apiCRLPublication
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpA,
		"next_update":        nextUpdate,
	}, &crlA)
	assertStatus(t, status, http.StatusCreated)

	api.issuer.crlPEM = "crl-b"
	var crlB apiCRLPublication
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpB,
		"next_update":        nextUpdate,
	}, &crlB)
	assertStatus(t, status, http.StatusCreated)

	api.issuer.crlPEM = "crl-b-newer"
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpB,
		"next_update":        nextUpdate,
	}, &crlB)
	assertStatus(t, status, http.StatusCreated)

	status, body, _ := api.doRaw(t, http.MethodGet, "/issuers/"+certificate.IssuerID+"/crl?distribution_point="+url.QueryEscape(dpA), "")
	assertStatus(t, status, http.StatusOK)
	if string(body) != "crl-a" {
		t.Fatalf("published CRL body = %q, want crl-a", string(body))
	}
}

func TestRespondOCSP(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)
	api.issuer.ocspInfo = corecli.OCSPRequestInfo{
		Certificates: []corecli.OCSPCertificateID{
			{SerialNumber: certificate.SerialNumber, IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		},
	}
	api.issuer.ocspResponseDER = []byte("ocsp-response-der")

	status, body, contentType := api.doBinary(t, http.MethodPost, "/ocsp", "operator", "application/ocsp-request", []byte("ocsp-request-der"))
	assertStatus(t, status, http.StatusOK)
	if string(body) != "ocsp-response-der" {
		t.Fatalf("OCSP response body = %q", string(body))
	}
	if contentType != "application/ocsp-response" {
		t.Fatalf("OCSP content type = %q", contentType)
	}
}

func TestRespondOCSPRejectsWrongContentType(t *testing.T) {
	api := newTestAPI(t)

	status, _, _ := api.doBinary(t, http.MethodPost, "/ocsp", "operator", "application/octet-stream", []byte("ocsp-request-der"))
	assertStatus(t, status, http.StatusUnsupportedMediaType)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	metadata := apiAuditMetadata(t, events[0])
	if events[0].Action != "api.request_failed" ||
		metadata["error_code"] != "unsupported_media_type" ||
		metadata["http_status"] != float64(http.StatusUnsupportedMediaType) {
		t.Fatalf("unsupported media audit = event:%#v metadata:%#v", events[0], metadata)
	}
}

func TestListAuditEvents(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var identity apiIdentity
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var enrollment apiEnrollment
	status = api.doJSON(t, http.MethodPost, "/enrollments", "operator", map[string]any{
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"csr_pem":                "csr-pem",
		"requested_subject":      "CN=edge-01",
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    testNow.Add(24 * time.Hour),
	}, &enrollment)
	assertStatus(t, status, http.StatusCreated)

	var rejected apiEnrollment
	status = api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/reject", "reviewer", nil, &rejected)
	assertStatus(t, status, http.StatusOK)
	if rejected.Status != domain.EnrollmentRejected {
		t.Fatalf("rejected enrollment status = %q, want %q", rejected.Status, domain.EnrollmentRejected)
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)

	wantActions := []string{
		"issuer.created",
		"identity.created",
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
	if events[1].Actor != "admin" {
		t.Fatalf("identity actor = %q, want %q", events[1].Actor, "admin")
	}
	if events[2].Actor != "operator" {
		t.Fatalf("enrollment actor = %q, want %q", events[2].Actor, "operator")
	}
	if events[3].Actor != "reviewer" {
		t.Fatalf("reject actor = %q, want %q", events[3].Actor, "reviewer")
	}
}

func TestListAuditEventsFiltersSortsAndPaginates(t *testing.T) {
	api := newTestAPI(t)
	base := testNow.Add(-time.Hour)
	for _, event := range []domain.AuditEvent{
		testHTTPAuditEvent("audit-1", "alice", "identity.created", "identity", "identity-1", base),
		testHTTPAuditEvent("audit-2", "bob", "enrollment.created", "enrollment", "enrollment-1", base.Add(time.Minute)),
		testHTTPAuditEvent("audit-3", "alice", "enrollment.rejected", "enrollment", "enrollment-1", base.Add(2*time.Minute)),
		testHTTPAuditEvent("audit-4", "alice", "certificate.revoked", "certificate", "certificate-1", base.Add(3*time.Minute)),
	} {
		if err := api.repo.CreateAuditEvent(api.ctx, event); err != nil {
			t.Fatalf("CreateAuditEvent(%s) returned error: %v", event.ID, err)
		}
	}

	var events []apiAuditEvent
	status := api.doJSON(t, http.MethodGet, "/audit-events?actor=alice&resource_type=enrollment&sort=desc&limit=1", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if got := apiAuditEventIDs(events); !reflect.DeepEqual(got, []string{"audit-3"}) {
		t.Fatalf("filtered audit IDs = %#v", got)
	}

	status = api.doJSON(t, http.MethodGet, "/audit-events?limit=1&offset=1&sort=asc", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if got := apiAuditEventIDs(events); !reflect.DeepEqual(got, []string{"audit-2"}) {
		t.Fatalf("paged audit IDs = %#v", got)
	}
}

func TestPruneAuditEventsByRetentionCutoff(t *testing.T) {
	api := newTestAPI(t)
	base := testNow.Add(-72 * time.Hour)
	for _, event := range []domain.AuditEvent{
		testHTTPAuditEvent("audit-old-1", "alice", "identity.created", "identity", "identity-1", base),
		testHTTPAuditEvent("audit-old-2", "bob", "enrollment.created", "enrollment", "enrollment-1", base.Add(time.Hour)),
		testHTTPAuditEvent("audit-new", "alice", "certificate.revoked", "certificate", "certificate-1", testNow),
	} {
		if err := api.repo.CreateAuditEvent(api.ctx, event); err != nil {
			t.Fatalf("CreateAuditEvent(%s) returned error: %v", event.ID, err)
		}
	}

	var pruned pruneAuditEventsResponse
	status := api.doJSON(t, http.MethodPost, "/audit-events/retention/prune", "operator", map[string]any{
		"before": testNow.Add(-24 * time.Hour).Format(time.RFC3339),
	}, &pruned)
	assertStatus(t, status, http.StatusOK)
	if pruned.DeletedCount != 2 {
		t.Fatalf("deleted count = %d, want 2", pruned.DeletedCount)
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events?action=certificate.revoked", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if got := apiAuditEventIDs(events); !reflect.DeepEqual(got, []string{"audit-new"}) {
		t.Fatalf("remaining audit IDs = %#v", got)
	}
	status = api.doJSON(t, http.MethodGet, "/audit-events?action=audit.retention_pruned", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 || events[0].Actor != "operator" {
		t.Fatalf("retention audit events = %#v", events)
	}
}

func TestRepairMissingIssuanceAuditEvents(t *testing.T) {
	api := newTestAPI(t)
	certificate := domain.Certificate{
		ID:             "certificate-1",
		IdentityID:     "identity-1",
		IssuerID:       "issuer-1",
		EnrollmentID:   "enrollment-1",
		SerialNumber:   "serial-1",
		Subject:        "CN=edge-01",
		Status:         domain.CertificateValid,
		CertificatePEM: "cert-pem",
		CreatedAt:      testNow,
		UpdatedAt:      testNow,
	}
	if err := api.repo.CreateCertificate(api.ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	var repaired struct {
		RepairedCount int `json:"repaired_count"`
	}
	status := api.doJSON(t, http.MethodPost, "/audit-events/repair/issuance", "operator", nil, &repaired)
	assertStatus(t, status, http.StatusOK)
	if repaired.RepairedCount != 1 {
		t.Fatalf("repaired count = %d, want 1", repaired.RepairedCount)
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 || events[0].Action != "certificate.issued" || events[0].ResourceID != certificate.ID {
		t.Fatalf("audit events = %#v, want repaired certificate.issued", events)
	}
}

func TestAuditEventsIncludeRequestMetadata(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeDev, TrustedProxies: mustParseTrustedProxies(t, "127.0.0.0/8", "::1/128")})

	var identity apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, map[string]string{
		"X-Request-ID":    "req-123",
		"X-Forwarded-For": "203.0.113.10, 10.0.0.1",
		"Traceparent":     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"User-Agent":      "anopki-test/1.0",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	metadata := apiAuditMetadata(t, events[0])
	if metadata["request_id"] != "req-123" ||
		metadata["traceparent"] != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" ||
		metadata["client_ip"] != "203.0.113.10" ||
		metadata["user_agent"] != "anopki-test/1.0" ||
		metadata["auth_method"] != string(AuthModeDev) ||
		metadata["identity_id"] != identity.ID ||
		metadata["result_code"] != "ok" {
		t.Fatalf("audit metadata = %#v", metadata)
	}
}

func TestAuditEventsGenerateRequestIDWhenMissing(t *testing.T) {
	api := newTestAPI(t)

	var identity apiIdentity
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	metadata := apiAuditMetadata(t, events[0])
	requestID, ok := metadata["request_id"].(string)
	if !ok || requestID == "" {
		t.Fatalf("request_id = %#v, want generated string; metadata=%#v", metadata["request_id"], metadata)
	}
}

func TestAuditEventsIgnoreForwardedForWithoutTrustedProxy(t *testing.T) {
	api := newTestAPI(t)

	var identity apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, map[string]string{
		"X-Forwarded-For": "203.0.113.10",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	metadata := apiAuditMetadata(t, events[0])
	if metadata["client_ip"] == "203.0.113.10" {
		t.Fatalf("audit metadata trusted spoofed X-Forwarded-For: %#v", metadata)
	}
}

func TestFailedRequestsCreateAuditEvents(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeDev, TrustedProxies: mustParseTrustedProxies(t, "127.0.0.0/8", "::1/128")})

	var errorBody errorResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
	}, map[string]string{
		"X-Request-ID":    "req-failed",
		"X-Forwarded-For": "198.51.100.10",
	}, &errorBody)
	assertStatus(t, status, http.StatusBadRequest)
	if errorBody.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrInvalidRequest.Error())
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.Action != "api.request_failed" || event.Actor != "admin" || event.ResourceType != "api" {
		t.Fatalf("failure audit event = %#v", event)
	}
	metadata := apiAuditMetadata(t, event)
	if metadata["result_code"] != "error" ||
		metadata["error_code"] != "invalid_request" ||
		metadata["request_id"] != "req-failed" ||
		metadata["client_ip"] != "198.51.100.10" ||
		metadata["http_method"] != http.MethodPost ||
		metadata["http_path"] != "/identities" ||
		metadata["http_status"] != float64(http.StatusBadRequest) {
		t.Fatalf("failure audit metadata = %#v", metadata)
	}
}

func TestAPIKeyAuthRejectsMissingBearerToken(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	beforeAuthFailures := observability.EventMetricValue("auth:failure")
	beforeRequests := observability.HTTPRequestMetricValue("auth:401")

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/identities", "", nil, &body)
	assertStatus(t, status, http.StatusUnauthorized)
	if body.Error != domain.ErrUnauthorized.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrUnauthorized.Error())
	}
	if got := observability.EventMetricValue("auth:failure") - beforeAuthFailures; got != 1 {
		t.Fatalf("auth failure metric increment = %d, want 1", got)
	}
	if got := observability.HTTPRequestMetricValue("auth:401") - beforeRequests; got != 1 {
		t.Fatalf("auth request metric increment = %d, want 1", got)
	}
}

func TestAPIKeyAuthRejectsInvalidBearerToken(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createTestAPIKey(t, api.repo, "key-1", "admin-token", "api-admin", domain.APIKeyActive)

	var body errorResponse
	status := api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer wrong-token",
	}, &body)
	assertStatus(t, status, http.StatusUnauthorized)
	if body.Error != domain.ErrUnauthorized.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrUnauthorized.Error())
	}
}

func TestDebugVarsExposesAnoPKIMetrics(t *testing.T) {
	api := newTestAPI(t)

	var identity apiIdentity
	before := observability.HTTPRequestMetricValue("identity:201")
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)
	if got := observability.HTTPRequestMetricValue("identity:201") - before; got != 1 {
		t.Fatalf("identity request metric increment = %d, want 1", got)
	}

	req, err := http.NewRequest(http.MethodGet, api.url+"/debug/vars", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusOK)
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode debug vars: %v", err)
	}
	if _, ok := body["anopki_http_requests_total"]; !ok {
		t.Fatalf("debug vars missing anopki_http_requests_total: %#v", body)
	}
}

func TestACMERateLimitMetrics(t *testing.T) {
	api := newTestAPIWithACMEConfig(t, ACMEConfig{RateLimit: 1, RateLimitWindow: time.Minute})
	before := observability.EventMetricValue("rate_limit:acme_account")

	_, _, nonce := api.doACMENonce(t)
	var account apiACMEProtocolAccount
	firstResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &account)
	assertStatus(t, firstResponse.StatusCode, http.StatusCreated)

	_, _, nonce = api.doACMENonce(t)
	var problem acmeProblemResponse
	secondResponse := api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
		"contact":              []string{"mailto:ops@example.test"},
		"termsOfServiceAgreed": true,
	}, &problem)
	assertStatus(t, secondResponse.StatusCode, http.StatusTooManyRequests)

	if got := observability.EventMetricValue("rate_limit:acme_account") - before; got != 1 {
		t.Fatalf("rate limit metric increment = %d, want 1", got)
	}
}

func TestAPIKeyAuthUsesAPIKeyActorForMutations(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createTestAPIKey(t, api.repo, "key-1", "admin-token", "api-admin", domain.APIKeyActive)

	var created apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "ignored-header-actor", map[string]any{
		"type":        string(domain.IdentityMachine),
		"name":        "edge-01",
		"external_id": "asset-123",
	}, map[string]string{
		"Authorization": "Bearer admin-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	events, err := api.repo.ListAuditEvents(api.ctx)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	if events[0].Actor != "api-admin" {
		t.Fatalf("audit actor = %q, want api-admin", events[0].Actor)
	}
}

func TestAPIKeyAuthAllowsPublicCRLReads(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/crls/missing-crl", "", nil, &body)
	assertStatus(t, status, http.StatusNotFound)
	if body.Error != domain.ErrCRLPublicationNotFound.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrCRLPublicationNotFound.Error())
	}
}

func TestAPIKeyManagementCreatesKeyWithOneTimeToken(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKey(t, api.repo, "operator-key", "operator-token", "ops-admin", domain.APIKeyActive, domain.APIKeyScopeOperator)

	var created apiKeyResponse
	expiresAt := testNow.Add(24 * time.Hour)
	status := api.doJSONWithHeaders(t, http.MethodPost, "/api-keys", "", map[string]any{
		"name":       "reader",
		"actor":      "read-client",
		"scopes":     []string{string(domain.APIKeyScopeRead)},
		"expires_at": expiresAt.Format(time.RFC3339),
	}, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" || created.Token == "" {
		t.Fatalf("created api key missing id/token: %#v", created)
	}
	if created.Name != "reader" || created.Actor != "read-client" || created.Status != domain.APIKeyActive {
		t.Fatalf("created api key = %#v", created)
	}
	if len(created.Scopes) != 1 || created.Scopes[0] != domain.APIKeyScopeRead {
		t.Fatalf("created scopes = %#v, want [read]", created.Scopes)
	}
	if created.TokenHash != "" {
		t.Fatalf("created response exposed token hash: %#v", created)
	}
	if created.TokenFingerprint != lifecycle.APIKeyTokenFingerprint(lifecycle.HashAPIKeyToken(created.Token)) {
		t.Fatalf("created token fingerprint = %q, want derived fingerprint", created.TokenFingerprint)
	}
	if !created.ExpiresAt.Equal(expiresAt) || !created.LastUsedAt.IsZero() {
		t.Fatalf("created expiry/last_used_at = %s/%s, want %s/zero", created.ExpiresAt, created.LastUsedAt, expiresAt)
	}

	var identities []apiIdentity
	status = api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer " + created.Token,
	}, &identities)
	assertStatus(t, status, http.StatusOK)

	var listed []apiKeyResponse
	status = api.doJSONWithHeaders(t, http.MethodGet, "/api-keys", "", nil, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 2 {
		t.Fatalf("api key count = %d, want 2: %#v", len(listed), listed)
	}
	for _, key := range listed {
		if key.Token != "" || key.TokenHash != "" {
			t.Fatalf("list response exposed token material: %#v", key)
		}
		if key.TokenFingerprint == "" {
			t.Fatalf("list response missing token fingerprint: %#v", key)
		}
		if key.ID == created.ID && (!key.ExpiresAt.Equal(expiresAt) || key.LastUsedAt.IsZero()) {
			t.Fatalf("listed expiry/last_used_at = %s/%s, want %s/non-zero", key.ExpiresAt, key.LastUsedAt, expiresAt)
		}
	}
}

func TestAPIKeyAuthRejectsExpiredKey(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKeyWithExpiry(t, api.repo, "expired-key", "expired-token", "api-admin", domain.APIKeyActive, testNow.Add(-time.Second), domain.APIKeyScopeOperator)

	var body errorResponse
	status := api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer expired-token",
	}, &body)
	assertStatus(t, status, http.StatusUnauthorized)
	if body.Error != domain.ErrUnauthorized.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrUnauthorized.Error())
	}
}

func TestAPIKeyScopeRejectsReadKeyMutations(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKey(t, api.repo, "read-key", "read-token", "read-client", domain.APIKeyActive, domain.APIKeyScopeRead)

	var body errorResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, map[string]string{
		"Authorization": "Bearer read-token",
	}, &body)
	assertStatus(t, status, http.StatusForbidden)
	if body.Error != domain.ErrForbidden.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrForbidden.Error())
	}
}

func TestAPIKeyScopeAllowsWriteAndRejectsOperatorRoutes(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKey(t, api.repo, "write-key", "write-token", "writer", domain.APIKeyActive, domain.APIKeyScopeWrite)

	var created apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, map[string]string{
		"Authorization": "Bearer write-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	events, err := api.repo.ListAuditEvents(api.ctx)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(events[0].MetadataJSON), &metadata); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if metadata["api_key_id"] != "write-key" || metadata["api_key_name"] != "write-key" {
		t.Fatalf("audit metadata missing api key identity: %#v", metadata)
	}
	if metadata["api_key_actor"] != "writer" ||
		metadata["api_key_fingerprint"] != lifecycle.APIKeyTokenFingerprint(lifecycle.HashAPIKeyToken("write-token")) ||
		metadata["auth_method"] != string(AuthModeAPIKey) {
		t.Fatalf("audit metadata missing api key auth details: %#v", metadata)
	}
	scopes, ok := metadata["api_key_scopes"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != string(domain.APIKeyScopeWrite) {
		t.Fatalf("audit scopes = %#v, want [write]", metadata["api_key_scopes"])
	}

	var body errorResponse
	status = api.doJSONWithHeaders(t, http.MethodGet, "/outbox/messages", "", nil, map[string]string{
		"Authorization": "Bearer write-token",
	}, &body)
	assertStatus(t, status, http.StatusForbidden)
	if body.Error != domain.ErrForbidden.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrForbidden.Error())
	}
}

func TestAPIKeyManagementRotatesKeys(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKey(t, api.repo, "operator-key", "operator-token", "ops-admin", domain.APIKeyActive, domain.APIKeyScopeOperator)

	var created apiKeyResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/api-keys", "", map[string]any{
		"name":   "reader",
		"actor":  "read-client",
		"scopes": []string{string(domain.APIKeyScopeRead)},
	}, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	var rotated apiKeyResponse
	status = api.doJSONWithHeaders(t, http.MethodPost, "/api-keys/"+created.ID+"/rotate", "", nil, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &rotated)
	assertStatus(t, status, http.StatusCreated)
	if rotated.ID == "" || rotated.ID == created.ID || rotated.Token == "" || rotated.TokenHash != "" {
		t.Fatalf("rotated api key response = %#v", rotated)
	}
	if rotated.Name != created.Name || rotated.Actor != created.Actor || rotated.Status != domain.APIKeyActive ||
		len(rotated.Scopes) != 1 || rotated.Scopes[0] != domain.APIKeyScopeRead {
		t.Fatalf("rotated api key fields = %#v, created = %#v", rotated, created)
	}
	if rotated.TokenFingerprint != lifecycle.APIKeyTokenFingerprint(lifecycle.HashAPIKeyToken(rotated.Token)) {
		t.Fatalf("rotated token fingerprint = %q, want derived fingerprint", rotated.TokenFingerprint)
	}

	var body errorResponse
	status = api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer " + created.Token,
	}, &body)
	assertStatus(t, status, http.StatusUnauthorized)

	var identities []apiIdentity
	status = api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer " + rotated.Token,
	}, &identities)
	assertStatus(t, status, http.StatusOK)
}

func TestAPIKeyManagementUsesPepperedTokenFingerprint(t *testing.T) {
	pepper := "pepper-secret-0123456789abcdef"
	api := newTestAPIWithAuthAndAPIKeyPepper(t, AuthConfig{Mode: AuthModeAPIKey}, pepper)
	createScopedTestAPIKey(t, api.repo, "operator-key", "operator-token", "ops-admin", domain.APIKeyActive, domain.APIKeyScopeOperator)

	var created apiKeyResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/api-keys", "", map[string]any{
		"name":   "reader",
		"actor":  "read-client",
		"scopes": []string{string(domain.APIKeyScopeRead)},
	}, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.TokenHash != "" || created.TokenFingerprint == "" || !strings.HasPrefix(created.TokenFingerprint, "hmac-sha256:") {
		t.Fatalf("created token fields = %#v", created)
	}
	if created.TokenFingerprint != lifecycle.APIKeyTokenFingerprint(lifecycle.HashAPIKeyTokenWithPepper(created.Token, pepper)) {
		t.Fatalf("created token fingerprint = %q, want peppered fingerprint", created.TokenFingerprint)
	}

	var identities []apiIdentity
	status = api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer " + created.Token,
	}, &identities)
	assertStatus(t, status, http.StatusOK)
}

func TestAPIKeyManagementDisablesKeys(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createScopedTestAPIKey(t, api.repo, "operator-key", "operator-token", "ops-admin", domain.APIKeyActive, domain.APIKeyScopeOperator)

	var created apiKeyResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/api-keys", "", map[string]any{
		"name":   "reader",
		"actor":  "read-client",
		"scopes": []string{string(domain.APIKeyScopeRead)},
	}, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	var disabled apiKeyResponse
	status = api.doJSONWithHeaders(t, http.MethodPost, "/api-keys/"+created.ID+"/disable", "", nil, map[string]string{
		"Authorization": "Bearer operator-token",
	}, &disabled)
	assertStatus(t, status, http.StatusOK)
	if disabled.Status != domain.APIKeyDisabled || disabled.Token != "" || disabled.TokenHash != "" {
		t.Fatalf("disabled api key response = %#v", disabled)
	}

	var body errorResponse
	status = api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer " + created.Token,
	}, &body)
	assertStatus(t, status, http.StatusUnauthorized)
}

type testAPI struct {
	ctx        context.Context
	client     *http.Client
	url        string
	repo       store.Repository
	service    *lifecycle.Service
	issuer     *fakeIssuer
	acmeHTTP01 *fakeACMEHTTP01Verifier
	acmeSigner acmeTestSigner
	acmeKID    string
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	return newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeDev})
}

func newTestAPIWithAuth(t *testing.T, auth AuthConfig) *testAPI {
	t.Helper()
	return newTestAPIWithAuthAndAPIKeyPepper(t, auth, "")
}

func newTestAPIWithACMEConfig(t *testing.T, acme ACMEConfig) *testAPI {
	t.Helper()
	return newTestAPIWithAuthACMEAndAPIKeyPepper(t, AuthConfig{Mode: AuthModeDev}, acme, "")
}

func newTestAPIWithAuthAndAPIKeyPepper(t *testing.T, auth AuthConfig, pepper string) *testAPI {
	t.Helper()
	return newTestAPIWithAuthACMEAndAPIKeyPepper(t, auth, ACMEConfig{}, pepper)
}

func newTestAPIWithAuthACMEAndAPIKeyPepper(t *testing.T, auth AuthConfig, acme ACMEConfig, pepper string) *testAPI {
	t.Helper()
	issuer := &fakeIssuer{}
	acmeHTTP01 := &fakeACMEHTTP01Verifier{}
	repo := store.NewMemoryStore()
	service := lifecycle.NewWithACMEHTTP01VerifierAndAPIKeyPepper(
		repo,
		issuer,
		fixedClock{now: testNow},
		&fakeIDGenerator{},
		acmeHTTP01,
		pepper,
	)
	server := httptest.NewServer(NewWithAuthAndACME(service, auth, acme))
	t.Cleanup(server.Close)

	return &testAPI{
		ctx:        context.Background(),
		client:     server.Client(),
		url:        server.URL,
		repo:       repo,
		service:    service,
		issuer:     issuer,
		acmeHTTP01: acmeHTTP01,
		acmeSigner: newACMETestSigner(t),
	}
}

func mustParseTrustedProxies(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()

	proxies := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", value, err)
		}
		proxies = append(proxies, prefix)
	}
	return proxies
}

func createTestAPIKey(t *testing.T, repo store.Repository, id string, token string, actor string, status domain.APIKeyStatus) {
	t.Helper()
	createScopedTestAPIKey(t, repo, id, token, actor, status, domain.APIKeyScopeOperator)
}

func createScopedTestAPIKey(t *testing.T, repo store.Repository, id string, token string, actor string, status domain.APIKeyStatus, scopes ...domain.APIKeyScope) {
	t.Helper()
	createScopedTestAPIKeyWithExpiry(t, repo, id, token, actor, status, time.Time{}, scopes...)
}

func createScopedTestAPIKeyWithExpiry(t *testing.T, repo store.Repository, id string, token string, actor string, status domain.APIKeyStatus, expiresAt time.Time, scopes ...domain.APIKeyScope) {
	t.Helper()
	if err := repo.CreateAPIKey(context.Background(), domain.APIKey{
		ID:        id,
		Name:      id,
		TokenHash: lifecycle.HashAPIKeyToken(token),
		Status:    status,
		Actor:     actor,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: testNow,
		UpdatedAt: testNow,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}
}

func (api *testAPI) doJSON(t *testing.T, method string, path string, actor string, body any, into any) int {
	t.Helper()
	return api.doJSONWithHeaders(t, method, path, actor, body, nil, into)
}

func (api *testAPI) doJSONWithHeaders(t *testing.T, method string, path string, actor string, body any, headers map[string]string, into any) int {
	t.Helper()

	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		requestBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, api.url+path, requestBody)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()

	if into != nil {
		if err := json.NewDecoder(res.Body).Decode(into); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return res.StatusCode
}

func (api *testAPI) doACMENonce(t *testing.T) (int, []byte, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodHead, api.url+"/acme/new-nonce", nil)
	if err != nil {
		t.Fatalf("create nonce request: %v", err)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send nonce request: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read nonce body: %v", err)
	}
	return res.StatusCode, body, res.Header.Get("Replay-Nonce")
}

func (api *testAPI) doACMEJWS(t *testing.T, path string, nonce string, payload any, into any) int {
	t.Helper()
	return api.doACMEJWSWithSigner(t, path, nonce, api.acmeKID, api.acmeSigner, payload, into)
}

func (api *testAPI) doACMEJWSWithSigner(t *testing.T, path string, nonce string, kid string, signer acmeTestSigner, payload any, into any) int {
	t.Helper()
	return api.doACMEJWSWithResponse(t, path, nonce, kid, signer, payload, into).StatusCode
}

func (api *testAPI) doACMEJWSWithResponse(t *testing.T, path string, nonce string, kid string, signer acmeTestSigner, payload any, into any) acmeJWSHTTPResponse {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal ACME payload: %v", err)
	}
	protectedHeader := map[string]any{
		"alg":   signer.alg(),
		"nonce": nonce,
		"url":   api.url + path,
	}
	if kid != "" {
		protectedHeader["kid"] = kid
	} else {
		protectedHeader["jwk"] = signer.jwk()
	}
	protected, err := json.Marshal(protectedHeader)
	if err != nil {
		t.Fatalf("marshal ACME protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protected)
	payloadB64 := base64.RawURLEncoding.EncodeToString(data)
	signature := signer.sign(t, protectedB64+"."+payloadB64)
	body := map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signature,
	}
	requestBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal ACME JWS: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, api.url+path, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("create ACME request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send ACME request: %v", err)
	}
	defer res.Body.Close()
	if into != nil {
		if err := json.NewDecoder(res.Body).Decode(into); err != nil {
			t.Fatalf("decode ACME response: %v", err)
		}
	}
	if account, ok := into.(*apiACMEProtocolAccount); ok && account.Location != "" {
		api.acmeKID = account.Location
	}
	return acmeJWSHTTPResponse{
		StatusCode:  res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		ReplayNonce: res.Header.Get("Replay-Nonce"),
		Location:    res.Header.Get("Location"),
		Link:        strings.Join(res.Header.Values("Link"), ","),
		RetryAfter:  res.Header.Get("Retry-After"),
	}
}

func (api *testAPI) doACMEPostAsGET(t *testing.T, path string, kid string, signer acmeTestSigner, into any) acmeJWSHTTPResponse {
	t.Helper()
	_, _, nonce := api.doACMENonce(t)
	return api.doACMEJWSRawPayload(t, path, nonce, kid, signer, "", into)
}

func (api *testAPI) doACMEPostAsGETRaw(t *testing.T, path string, kid string, signer acmeTestSigner) acmeJWSHTTPResponse {
	t.Helper()
	_, _, nonce := api.doACMENonce(t)
	return api.doACMEJWSRawPayload(t, path, nonce, kid, signer, "", nil)
}

func (api *testAPI) doACMEJWSRawPayload(t *testing.T, path string, nonce string, kid string, signer acmeTestSigner, payloadB64 string, into any) acmeJWSHTTPResponse {
	t.Helper()
	protectedHeader := map[string]any{
		"alg":   signer.alg(),
		"nonce": nonce,
		"url":   api.url + path,
	}
	if kid != "" {
		protectedHeader["kid"] = kid
	} else {
		protectedHeader["jwk"] = signer.jwk()
	}
	protected, err := json.Marshal(protectedHeader)
	if err != nil {
		t.Fatalf("marshal ACME protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protected)
	signature := signer.sign(t, protectedB64+"."+payloadB64)
	body := map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signature,
	}
	requestBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal ACME JWS: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, api.url+path, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("create ACME request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send ACME request: %v", err)
	}
	defer res.Body.Close()
	if into != nil {
		if err := json.NewDecoder(res.Body).Decode(into); err != nil {
			t.Fatalf("decode ACME response: %v", err)
		}
	}
	var responseBody []byte
	if into == nil {
		responseBody, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("read ACME response: %v", err)
		}
	}
	return acmeJWSHTTPResponse{
		StatusCode:  res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		ReplayNonce: res.Header.Get("Replay-Nonce"),
		Location:    res.Header.Get("Location"),
		Link:        strings.Join(res.Header.Values("Link"), ","),
		RetryAfter:  res.Header.Get("Retry-After"),
		Body:        string(responseBody),
	}
}

func (api *testAPI) makeRawACMEJWS(t *testing.T, protectedHeader map[string]any, payloadB64 string, signer acmeTestSigner) map[string]string {
	t.Helper()

	protected, err := json.Marshal(protectedHeader)
	if err != nil {
		t.Fatalf("marshal raw ACME protected header: %v", err)
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protected)
	return map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": signer.sign(t, protectedB64+"."+payloadB64),
	}
}

func (api *testAPI) doRawACMEJWS(t *testing.T, path string, body map[string]string, into any) acmeJWSHTTPResponse {
	t.Helper()

	requestBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal raw ACME JWS: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, api.url+path, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("create raw ACME request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send raw ACME request: %v", err)
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read raw ACME response: %v", err)
	}
	if into != nil && res.StatusCode >= http.StatusBadRequest {
		if err := json.Unmarshal(responseBody, into); err != nil {
			t.Fatalf("decode raw ACME response: %v", err)
		}
	}
	return acmeJWSHTTPResponse{
		StatusCode:  res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		ReplayNonce: res.Header.Get("Replay-Nonce"),
		Location:    res.Header.Get("Location"),
		Link:        strings.Join(res.Header.Values("Link"), ","),
		RetryAfter:  res.Header.Get("Retry-After"),
		Body:        string(responseBody),
	}
}

func acmeRawPayloadB64(t *testing.T, payload any) string {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal raw ACME payload: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func assertACMEMalformedProblem(t *testing.T, response acmeJWSHTTPResponse, body acmeProblemResponse, requestNonce string) {
	t.Helper()

	assertStatus(t, response.StatusCode, http.StatusBadRequest)
	if response.ContentType != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json", response.ContentType)
	}
	if response.ReplayNonce == "" || response.ReplayNonce == requestNonce {
		t.Fatalf("Replay-Nonce = %q, request nonce = %q", response.ReplayNonce, requestNonce)
	}
	if body.Type != "urn:ietf:params:acme:error:malformed" ||
		body.Detail != domain.ErrInvalidRequest.Error() ||
		body.Status != http.StatusBadRequest {
		t.Fatalf("problem body = %#v", body)
	}
}

func (api *testAPI) pathFromURL(t *testing.T, raw string) string {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	path := parsed.Path
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

type acmeTestSigner interface {
	alg() string
	jwk() map[string]string
	sign(t *testing.T, input string) string
}

type acmeECTestSigner struct {
	key *ecdsa.PrivateKey
}

type acmeJWSHTTPResponse struct {
	StatusCode  int
	ContentType string
	ReplayNonce string
	Location    string
	Link        string
	RetryAfter  string
	Body        string
}

func newACMETestSigner(t *testing.T) acmeTestSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ACME test key: %v", err)
	}
	return &acmeECTestSigner{key: key}
}

func (s *acmeECTestSigner) alg() string {
	return "ES256"
}

func (s *acmeECTestSigner) jwk() map[string]string {
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(paddedBigInt(s.key.X, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(paddedBigInt(s.key.Y, 32)),
	}
}

func (s *acmeECTestSigner) sign(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	r, sigS, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		t.Fatalf("sign ACME test JWS: %v", err)
	}
	signature := append(paddedBigInt(r, 32), paddedBigInt(sigS, 32)...)
	return base64.RawURLEncoding.EncodeToString(signature)
}

type acmeRSATestSigner struct {
	key *rsa.PrivateKey
}

func newACMERSATestSigner(t *testing.T) acmeTestSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ACME RSA test key: %v", err)
	}
	return &acmeRSATestSigner{key: key}
}

func (s *acmeRSATestSigner) alg() string {
	return "RS256"
}

func (s *acmeRSATestSigner) jwk() map[string]string {
	return map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
	}
}

func (s *acmeRSATestSigner) sign(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign ACME RSA test JWS: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(signature)
}

type acmeEd25519TestSigner struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func newACMEEd25519TestSigner(t *testing.T) acmeTestSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ACME Ed25519 test key: %v", err)
	}
	return &acmeEd25519TestSigner{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

func (s *acmeEd25519TestSigner) alg() string {
	return "EdDSA"
}

func (s *acmeEd25519TestSigner) jwk() map[string]string {
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(s.publicKey),
	}
}

func (s *acmeEd25519TestSigner) sign(t *testing.T, input string) string {
	t.Helper()
	signature := ed25519.Sign(s.privateKey, []byte(input))
	return base64.RawURLEncoding.EncodeToString(signature)
}

func paddedBigInt(value *big.Int, size int) []byte {
	raw := value.Bytes()
	if len(raw) >= size {
		return raw
	}
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}

type fakeACMEHTTP01Verifier struct {
	err               error
	failuresRemaining int
	requests          []fakeACMEHTTP01Request
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
	if f.failuresRemaining > 0 {
		f.failuresRemaining--
		return errors.New("challenge token not ready")
	}
	return f.err
}

func (api *testAPI) doRaw(t *testing.T, method string, path string, actor string) (int, []byte, string) {
	t.Helper()

	req, err := http.NewRequest(method, api.url+path, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return res.StatusCode, body, res.Header.Get("Content-Type")
}

func (api *testAPI) doBinary(t *testing.T, method string, path string, actor string, contentType string, body []byte) (int, []byte, string) {
	t.Helper()

	req, err := http.NewRequest(method, api.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return res.StatusCode, responseBody, res.Header.Get("Content-Type")
}

func (api *testAPI) createIdentity(t *testing.T) domain.Identity {
	t.Helper()

	identity, err := api.service.CreateIdentity(api.ctx, "admin", lifecycle.CreateIdentityRequest{
		Type:       domain.IdentityMachine,
		Name:       "edge-01",
		ExternalID: "asset-123",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	return identity
}

func (api *testAPI) createIssuer(t *testing.T) domain.Issuer {
	t.Helper()

	issuer, err := api.service.CreateIssuer(api.ctx, "admin", lifecycle.CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	return issuer
}

func (api *testAPI) createPendingEnrollment(t *testing.T) domain.Enrollment {
	t.Helper()

	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	enrollment, err := api.service.CreateEnrollment(api.ctx, "operator", lifecycle.CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    testNow.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	return enrollment
}

func (api *testAPI) createApprovedEnrollment(t *testing.T) domain.Enrollment {
	t.Helper()

	enrollment := api.createPendingEnrollment(t)
	approved, err := api.service.ApproveEnrollment(api.ctx, "approver", enrollment.ID)
	if err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	return approved
}

func (api *testAPI) createCertificate(t *testing.T) domain.Certificate {
	t.Helper()

	enrollment := api.createApprovedEnrollment(t)
	certificate, err := api.service.IssueCertificate(api.ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	return certificate
}

func testCertificate(id string, notAfter time.Time) domain.Certificate {
	return testCertificateWithStatus(id, notAfter, domain.CertificateValid)
}

func testCertificateWithStatus(id string, notAfter time.Time, status domain.CertificateStatus) domain.Certificate {
	return domain.Certificate{
		ID:             id,
		IdentityID:     "identity-" + id,
		IssuerID:       "issuer-" + id,
		EnrollmentID:   "enrollment-" + id,
		SerialNumber:   "serial-" + id,
		Subject:        "CN=" + id,
		NotBefore:      testNow.Add(-time.Hour),
		NotAfter:       notAfter,
		Status:         status,
		CertificatePEM: "cert-pem",
		CreatedAt:      testNow,
		UpdatedAt:      testNow,
	}
}

func testOutboxMessage(id string, eventType string, status domain.OutboxMessageStatus, createdAt time.Time) domain.OutboxMessage {
	return domain.OutboxMessage{
		ID:           id,
		Type:         eventType,
		PayloadJSON:  `{"id":"` + id + `"}`,
		Status:       status,
		AvailableAt:  testNow.Add(time.Hour),
		AttemptCount: 5,
		MaxAttempts:  5,
		LastError:    "webhook failed",
		CreatedAt:    createdAt,
		UpdatedAt:    createdAt,
	}
}

func messagesByID(messages []domain.OutboxMessage) map[string]domain.OutboxMessage {
	byID := make(map[string]domain.OutboxMessage, len(messages))
	for _, message := range messages {
		byID[message.ID] = message
	}
	return byID
}

func certificateIDs(certificates []apiCertificate) []string {
	ids := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		ids = append(ids, certificate.ID)
	}
	return ids
}

func apiIdentityIDs(identities []apiIdentity) []string {
	ids := make([]string, 0, len(identities))
	for _, identity := range identities {
		ids = append(ids, identity.ID)
	}
	return ids
}

func apiEnrollmentIDs(enrollments []apiEnrollment) []string {
	ids := make([]string, 0, len(enrollments))
	for _, enrollment := range enrollments {
		ids = append(ids, enrollment.ID)
	}
	return ids
}

func apiOutboxMessageIDs(messages []apiOutboxMessage) []string {
	ids := make([]string, 0, len(messages))
	for _, message := range messages {
		ids = append(ids, message.ID)
	}
	return ids
}

func testHTTPIdentity(id string, name string, owner string, team string, serviceName string, environment string) domain.Identity {
	return domain.Identity{
		ID:          id,
		Type:        domain.IdentityMachine,
		Name:        name,
		Owner:       owner,
		Team:        team,
		Service:     serviceName,
		Environment: environment,
		Status:      domain.IdentityActive,
		CreatedAt:   testNow,
		UpdatedAt:   testNow,
	}
}

func testHTTPEnrollment(id string, identityID string, issuerID string, profileID string, status domain.EnrollmentStatus, createdAt time.Time) domain.Enrollment {
	return domain.Enrollment{
		ID:                   id,
		IdentityID:           identityID,
		IssuerID:             issuerID,
		CertificateProfileID: profileID,
		CSRPEM:               "csr-" + id,
		Status:               status,
		RequestedSubject:     "CN=" + id,
		RequestedNotAfter:    testNow.Add(24 * time.Hour),
		CreatedAt:            createdAt,
		UpdatedAt:            createdAt,
	}
}

func testHTTPCertificate(id string, identityID string, issuerID string, profileID string, status domain.CertificateStatus, notAfter time.Time, dnsNames []string, ipAddresses []string) domain.Certificate {
	return domain.Certificate{
		ID:                   id,
		IdentityID:           identityID,
		IssuerID:             issuerID,
		EnrollmentID:         "enrollment-" + id,
		CertificateProfileID: profileID,
		SerialNumber:         "serial-" + id,
		Subject:              "CN=" + id,
		DNSNames:             append([]string(nil), dnsNames...),
		IPAddresses:          append([]string(nil), ipAddresses...),
		NotBefore:            testNow.Add(-time.Hour),
		NotAfter:             notAfter,
		Status:               status,
		CertificatePEM:       "cert-pem",
		CreatedAt:            notAfter,
		UpdatedAt:            notAfter,
	}
}

func (api *testAPI) createCertificateForIdentity(t *testing.T, name string, owner string, team string, serviceName string, environment string, deploymentTarget string) domain.Certificate {
	t.Helper()

	identity, err := api.service.CreateIdentity(api.ctx, "admin", lifecycle.CreateIdentityRequest{
		Type:             domain.IdentityMachine,
		Name:             name,
		ExternalID:       "asset-" + name,
		Owner:            owner,
		Team:             team,
		Service:          serviceName,
		Environment:      environment,
		DeploymentTarget: deploymentTarget,
		LastSeenAt:       testNow,
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer := api.createIssuer(t)
	enrollment, err := api.service.CreateEnrollment(api.ctx, "operator", lifecycle.CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=" + name,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    testNow.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	approved, err := api.service.ApproveEnrollment(api.ctx, "approver", enrollment.ID)
	if err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := api.service.IssueCertificate(api.ctx, "issuer", approved.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	return certificate
}

func assertStatus(t *testing.T, got int, want int) {
	t.Helper()

	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func testACMECSRBase64URL(t *testing.T) string {
	t.Helper()

	return testACMECSRBase64URLWithSubject(t, pkix.Name{
		CommonName: "edge-01.example.test",
	})
}

func testACMECSRBase64URLWithSubject(t *testing.T, subject pkix.Name) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest returned error: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func fakeSigningEvidence(operation string, algorithm string) corecli.SigningEvidence {
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

type fakeIssuer struct {
	requests                          []corecli.IssueRequest
	crlRequests                       []corecli.GenerateCRLRequest
	err                               error
	crlPEM                            string
	ocspInfo                          corecli.OCSPRequestInfo
	ocspResponses                     []corecli.GenerateOCSPResponseRequest
	ocspResponseDER                   []byte
	ocspResponderValidationRequests   []ocspResponderValidationRequest
	ocspResponderValidationConfigured bool
	ocspResponderValidationResult     corecli.ValidateOCSPResponderResult
}

func (f *fakeIssuer) InspectCSR(ctx context.Context, csrPEM string) (corecli.CSRInfo, error) {
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
		SigningEvidence: fakeSigningEvidence("certificate_issue", req.SignatureAlgorithm),
	}, nil
}

func (f *fakeIssuer) GenerateCRL(ctx context.Context, req corecli.GenerateCRLRequest) (corecli.GenerateCRLResult, error) {
	f.crlRequests = append(f.crlRequests, req)
	if f.err != nil {
		return corecli.GenerateCRLResult{}, f.err
	}
	crlPEM := f.crlPEM
	if crlPEM == "" {
		crlPEM = "crl-pem"
	}
	return corecli.GenerateCRLResult{
		CRLPEM:          crlPEM,
		SigningEvidence: fakeSigningEvidence("crl_generate_sign", "sha256"),
	}, nil
}

func (f *fakeIssuer) InspectOCSPIssuer(ctx context.Context, issuerCertificatePEM string, hashAlgorithm string) (corecli.OCSPIssuerInfo, error) {
	if f.err != nil {
		return corecli.OCSPIssuerInfo{}, f.err
	}
	return corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash", HashAlgorithm: hashAlgorithm}, nil
}

func (f *fakeIssuer) ValidateOCSPResponder(ctx context.Context, issuerCertificatePEM string, responderCertificatePEM string) (corecli.ValidateOCSPResponderResult, error) {
	f.ocspResponderValidationRequests = append(f.ocspResponderValidationRequests, ocspResponderValidationRequest{
		issuerCertificatePEM:    issuerCertificatePEM,
		responderCertificatePEM: responderCertificatePEM,
	})
	if f.err != nil {
		return corecli.ValidateOCSPResponderResult{}, f.err
	}
	if !f.ocspResponderValidationConfigured {
		return corecli.ValidateOCSPResponderResult{Valid: true}, nil
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
	if f.err != nil {
		return corecli.GenerateOCSPResponseResult{}, f.err
	}
	return corecli.GenerateOCSPResponseResult{
		ResponseDER:     f.ocspResponseDER,
		SigningEvidence: fakeSigningEvidence("ocsp_response_sign", "sha256"),
	}, nil
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

type apiIdentity struct {
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

type apiIssuer struct {
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

type apiACMEAccount struct {
	ID                   string                   `json:"id"`
	Contacts             []string                 `json:"contacts"`
	Status               domain.ACMEAccountStatus `json:"status"`
	TermsOfServiceAgreed bool                     `json:"terms_of_service_agreed"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
}

type apiACMEOrder struct {
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
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type apiACMEAuthorization struct {
	ID                       string                         `json:"id"`
	OrderID                  string                         `json:"order_id"`
	IdentifierType           string                         `json:"identifier_type"`
	IdentifierValue          string                         `json:"identifier_value"`
	Status                   domain.ACMEAuthorizationStatus `json:"status"`
	ValidationReuseExpiresAt time.Time                      `json:"validation_reuse_expires_at"`
	CreatedAt                time.Time                      `json:"created_at"`
	UpdatedAt                time.Time                      `json:"updated_at"`
}

type apiACMEChallenge struct {
	ID              string                     `json:"id"`
	AuthorizationID string                     `json:"authorization_id"`
	Type            domain.ACMEChallengeType   `json:"type"`
	Token           string                     `json:"token"`
	Status          domain.ACMEChallengeStatus `json:"status"`
	ValidatedAt     time.Time                  `json:"validated_at"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

type apiACMEProtocolAccount struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Contact  []string `json:"contact"`
	Location string   `json:"location"`
}

type apiACMEProtocolOrder struct {
	ID             string                   `json:"id"`
	Status         string                   `json:"status"`
	URL            string                   `json:"url"`
	Identifiers    []acmeProtocolIdentifier `json:"identifiers"`
	Authorizations []string                 `json:"authorizations"`
	Finalize       string                   `json:"finalize"`
	Certificate    string                   `json:"certificate"`
	Expires        time.Time                `json:"expires"`
}

type apiACMEProtocolAuthorization struct {
	ID         string                     `json:"id"`
	Status     string                     `json:"status"`
	Identifier acmeProtocolIdentifier     `json:"identifier"`
	Challenges []apiACMEProtocolChallenge `json:"challenges"`
	Expires    time.Time                  `json:"expires"`
}

type apiACMEProtocolChallenge struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

type acmeProtocolIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeProblemResponse struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

type apiOCSPResponder struct {
	ID             string                     `json:"id"`
	IssuerID       string                     `json:"issuer_id"`
	Name           string                     `json:"name"`
	Status         domain.OCSPResponderStatus `json:"status"`
	CertificatePEM string                     `json:"certificate_pem"`
	KeyRef         string                     `json:"key_ref"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

type apiNotificationEndpoint struct {
	ID         string                            `json:"id"`
	Name       string                            `json:"name"`
	Type       domain.NotificationEndpointType   `json:"type"`
	Status     domain.NotificationEndpointStatus `json:"status"`
	URL        string                            `json:"url"`
	EventTypes []string                          `json:"event_types"`
	CreatedAt  time.Time                         `json:"created_at"`
	UpdatedAt  time.Time                         `json:"updated_at"`
}

type apiOutboxMessage struct {
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

type apiOutboxBulkReplay struct {
	ReplayedCount int      `json:"replayed_count"`
	MessageIDs    []string `json:"message_ids"`
}

type apiCertificateInventoryEntry struct {
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

type apiExpirySLO struct {
	WindowDays     int      `json:"window_days"`
	UnhandledCount int      `json:"unhandled_count"`
	UnhandledIDs   []string `json:"unhandled_ids"`
	OK             bool     `json:"ok"`
}

type apiCertificateProfile struct {
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

type apiEnrollment struct {
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

type apiCertificate struct {
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

type apiExpirationScanResult struct {
	Expired            []apiCertificate `json:"expired"`
	ExpirationWarnings []apiCertificate `json:"expiration_warnings"`
}

type apiCRLPublication struct {
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

type apiAuditEvent struct {
	ID           string    `json:"id"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	MetadataJSON string    `json:"metadata_json"`
	CreatedAt    time.Time `json:"created_at"`
}

type ocspResponderValidationRequest struct {
	issuerCertificatePEM    string
	responderCertificatePEM string
}

func apiAuditMetadata(t *testing.T, event apiAuditEvent) map[string]any {
	t.Helper()

	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.MetadataJSON), &metadata); err != nil {
		t.Fatalf("unmarshal audit metadata for %s: %v", event.Action, err)
	}
	return metadata
}

func testHTTPAuditEvent(id string, actor string, action string, resourceType string, resourceID string, createdAt time.Time) domain.AuditEvent {
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

func apiAuditEventIDs(events []apiAuditEvent) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	return ids
}
