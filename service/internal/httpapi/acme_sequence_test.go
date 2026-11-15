// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
	"github.com/anothel/anopki/service/internal/domain"
)

func TestACMEProtocolResponseNonceSequenceAndFinalizeReplay(t *testing.T) {
	for _, signingFailure := range []bool{false, true} {
		name := "successful finalize"
		if signingFailure {
			name = "signing failure then fresh nonce retry"
		}
		t.Run(name, func(t *testing.T) {
			api := newTestAPI(t)
			identity := api.createIdentity(t)
			issuer := api.createIssuer(t)
			var profile apiCertificateProfile
			status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
				"name":                         "nonce-sequence",
				"issuer_id":                    issuer.ID,
				"validity_period_seconds":      int64((24 * time.Hour).Seconds()),
				"allowed_dns_patterns":         []string{"*.example.test"},
				"allowed_ip_ranges":            []string{"127.0.0.0/8"},
				"allowed_signature_algorithms": []string{"rsa_with_sha256"},
			}, &profile)
			assertStatus(t, status, http.StatusCreated)

			// Like lego, obtain one initial nonce and then use response nonces
			// across account, order, authorization, challenge and finalize requests.
			_, _, nonce := api.doACMENonce(t)
			next := func(response acmeJWSHTTPResponse, want int) {
				t.Helper()
				assertStatus(t, response.StatusCode, want)
				if response.ReplayNonce == "" || response.ReplayNonce == nonce {
					t.Fatal("response must supply a fresh nonce")
				}
				nonce = response.ReplayNonce
			}
			var account apiACMEProtocolAccount
			next(api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner, map[string]any{
				"contact": []string{"mailto:ops@example.test"}, "termsOfServiceAgreed": true,
			}, &account), http.StatusCreated)
			var order apiACMEProtocolOrder
			next(api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
				"identity_id": identity.ID, "issuer_id": issuer.ID, "profile_id": profile.ID,
				"identifiers": []map[string]any{
					{"type": "dns", "value": "edge-01.example.test"},
					{"type": "ip", "value": "127.0.0.1"},
				},
				"notAfter": testNow.Add(12 * time.Hour).Format(time.RFC3339),
			}, &order), http.StatusCreated)
			for _, authzURL := range order.Authorizations {
				path := api.pathFromURL(t, authzURL)
				var authz apiACMEProtocolAuthorization
				next(api.doACMEJWSRawPayload(t, path, nonce, account.Location, api.acmeSigner, "", &authz), http.StatusOK)
				if len(authz.Challenges) != 1 {
					t.Fatal("expected one HTTP-01 challenge")
				}
				var challenge apiACMEProtocolChallenge
				next(api.doACMEJWSWithResponse(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, &challenge), http.StatusOK)
				next(api.doACMEJWSRawPayload(t, path, nonce, account.Location, api.acmeSigner, "", &authz), http.StatusOK)
				if authz.Status != string(domain.ACMEAuthorizationValid) {
					t.Fatalf("authorization status = %s", authz.Status)
				}
			}
			orderPath := strings.TrimSuffix(api.pathFromURL(t, order.Finalize), "/finalize")
			next(api.doACMEJWSRawPayload(t, orderPath, nonce, account.Location, api.acmeSigner, "", &order), http.StatusOK)
			if order.Status != string(domain.ACMEOrderReady) {
				t.Fatalf("order status = %s", order.Status)
			}

			path := api.pathFromURL(t, order.Finalize)
			payload := acmeRawPayloadB64(t, map[string]any{"csr": testACMECSRBase64URL(t)})
			body := api.makeRawACMEJWS(t, map[string]any{
				"alg": api.acmeSigner.alg(), "nonce": nonce, "url": api.url + path, "kid": account.Location,
			}, payload, api.acmeSigner)
			want := http.StatusOK
			if signingFailure {
				api.issuer.err = &corecli.CommandError{Code: "provider.algorithm_mismatch"}
				want = http.StatusBadGateway
			}
			response := api.doRawACMEJWS(t, path, body, nil)
			next(response, want)
			if len(api.issuer.requests) != 1 {
				t.Fatal("fresh finalize must reach signing once")
			}

			// lego's HTTP transport retries the identical JWS after a 502.
			// Reject it even when signing failed, and do not invoke signing again.
			var problem acmeProblemResponse
			next(api.doRawACMEJWS(t, path, body, &problem), http.StatusBadRequest)
			if problem.Type != "urn:ietf:params:acme:error:badNonce" || len(api.issuer.requests) != 1 {
				t.Fatal("replayed finalize must fail with badNonce before signing")
			}
			var finalized apiACMEProtocolOrder
			if signingFailure {
				api.issuer.err = nil
				next(api.doACMEJWSRawPayload(t, path, nonce, account.Location, api.acmeSigner, payload, &finalized), http.StatusOK)
			} else if err := json.Unmarshal([]byte(response.Body), &finalized); err != nil {
				t.Fatalf("decode finalized order: %v", err)
			}
			if finalized.Status != string(domain.ACMEOrderValid) || finalized.Certificate == "" {
				t.Fatal("fresh finalize must yield a valid order with a certificate URL")
			}
			certificate := api.doACMEJWSRawPayload(t, api.pathFromURL(t, finalized.Certificate), nonce, account.Location, api.acmeSigner, "", nil)
			next(certificate, http.StatusOK)
			if certificate.ContentType != "application/pem-certificate-chain" || certificate.Body == "" {
				t.Fatal("certificate POST-as-GET must return the chain")
			}
		})
	}
}
