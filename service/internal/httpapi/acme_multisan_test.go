// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestACMETwoDNSNamesRequireBothAuthorizations(t *testing.T) {
	api := newTestAPI(t)
	identity, issuer := api.createIdentity(t), api.createIssuer(t)
	var profile apiCertificateProfile
	assertStatus(t, api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name": "two-dns", "issuer_id": issuer.ID,
		"validity_period_seconds":      int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":         []string{"*.example.test"},
		"allowed_signature_algorithms": []string{"rsa_with_sha256"},
	}, &profile), http.StatusCreated)
	var account apiACMEProtocolAccount
	_, _, nonce := api.doACMENonce(t)
	assertStatus(t, api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner,
		map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:ops@example.test"}}, &account).StatusCode, http.StatusCreated)
	names := []string{"edge-01.example.test", "edge-02.example.test"}
	var order apiACMEProtocolOrder
	_, _, nonce = api.doACMENonce(t)
	assertStatus(t, api.doACMEJWSWithResponse(t, "/acme/new-order", nonce, account.Location, api.acmeSigner, map[string]any{
		"identity_id": identity.ID, "issuer_id": issuer.ID, "profile_id": profile.ID,
		"identifiers": []map[string]string{{"type": "dns", "value": names[0]}, {"type": "dns", "value": names[1]}},
		"notAfter":    testNow.Add(12 * time.Hour).Format(time.RFC3339),
	}, &order).StatusCode, http.StatusCreated)
	if len(order.Authorizations) != 2 {
		t.Fatal("expected two authorizations")
	}
	orderPath := strings.TrimSuffix(api.pathFromURL(t, order.Finalize), "/finalize")
	payload := map[string]any{"csr_pem": "csr-pem", "requested_subject": "CN=edge-01"}
	seen := map[string]bool{}
	for i, url := range order.Authorizations {
		// Signing must not run until both names validate.
		_, _, nonce = api.doACMENonce(t)
		response := api.doACMEJWSWithResponse(t, api.pathFromURL(t, order.Finalize), nonce, account.Location, api.acmeSigner, payload, nil)
		if response.StatusCode != http.StatusConflict || len(api.issuer.requests) != 0 {
			t.Fatal("premature finalize reached signing")
		}
		var authz apiACMEProtocolAuthorization
		assertStatus(t, api.doACMEPostAsGET(t, api.pathFromURL(t, url), account.Location, api.acmeSigner, &authz).StatusCode, http.StatusOK)
		if authz.Identifier.Type != "dns" || seen[authz.Identifier.Value] || len(authz.Challenges) != 1 {
			t.Fatal("incorrect authorization")
		}
		seen[authz.Identifier.Value] = true
		_, _, nonce = api.doACMENonce(t)
		var challenge apiACMEProtocolChallenge
		assertStatus(t, api.doACMEJWSWithResponse(t, api.pathFromURL(t, authz.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, &challenge).StatusCode, http.StatusOK)
		if challenge.Status != "valid" {
			t.Fatal("HTTP-01 challenge not valid")
		}
		var current apiACMEProtocolOrder
		assertStatus(t, api.doACMEPostAsGET(t, orderPath, account.Location, api.acmeSigner, &current).StatusCode, http.StatusOK)
		expected := "pending"
		if i == 1 {
			expected = "ready"
		}
		if current.Status != expected {
			t.Fatalf("after %d authorizations: %s", i+1, current.Status)
		}
	}
	for _, name := range names {
		if !seen[name] {
			t.Fatal("missing DNS authorization")
		}
	}
	if len(api.acmeHTTP01.requests) != 2 {
		t.Fatal("expected one verifier call per name")
	}
	tokens := map[string]bool{}
	for _, request := range api.acmeHTTP01.requests {
		if !seen[request.Identifier] || request.Token == "" || tokens[request.Token] || request.KeyAuthorization == "" {
			t.Fatal("incorrect per-name verifier request")
		}
		delete(seen, request.Identifier)
		tokens[request.Token] = true
	}
}
