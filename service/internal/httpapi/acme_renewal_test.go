// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
	"github.com/anothel/anopki/service/internal/lifecycle"
)

type renewalFixtureIssuer struct{ *fakeIssuer }

func (f renewalFixtureIssuer) InspectCSR(context.Context, string) (corecli.CSRInfo, error) {
	return corecli.CSRInfo{Subject: "CN=edge-01", DNSNames: []string{"edge-01.example.test"}}, nil
}

func (f renewalFixtureIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	result, err := f.fakeIssuer.Issue(ctx, req)
	result.SerialNumber = "renewal-" + strconv.Itoa(len(f.requests))
	return result, err
}

// A client renewal is another newOrder using the retained account, not another
// finalize of the old order. Fixtures test protocol guards; live Certbot tests
// the actual saved lineage, real signing and certificate/key relationships.
func TestACMERenewalNewOrderRequiresFreshNonceAndAuthorization(t *testing.T) {
	api := newTestAPI(t)
	// This fixture has one DNS SAN and a distinct signer serial per issuance.
	api.service = lifecycle.NewWithACMEHTTP01Verifier(api.repo, renewalFixtureIssuer{api.issuer},
		fixedClock{now: testNow}, &fakeIDGenerator{}, api.acmeHTTP01)
	server := httptest.NewServer(New(api.service))
	t.Cleanup(server.Close)
	api.url, api.client = server.URL, server.Client()
	identity, issuer := api.createIdentity(t), api.createIssuer(t)
	var profile apiCertificateProfile
	assertStatus(t, api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name": "renewal", "issuer_id": issuer.ID,
		"validity_period_seconds":      int64((24 * time.Hour).Seconds()),
		"allowed_dns_patterns":         []string{"*.example.test"},
		"allowed_signature_algorithms": []string{"rsa_with_sha256"},
	}, &profile), http.StatusCreated)
	_, _, nonce := api.doACMENonce(t)
	next := func(response acmeJWSHTTPResponse, want int) {
		t.Helper()
		assertStatus(t, response.StatusCode, want)
		if response.ReplayNonce == "" || response.ReplayNonce == nonce {
			t.Fatal("expected fresh response nonce")
		}
		nonce = response.ReplayNonce
	}
	var account apiACMEProtocolAccount
	next(api.doACMEJWSWithResponse(t, "/acme/new-account", nonce, "", api.acmeSigner,
		map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:ops@example.test"}}, &account), http.StatusCreated)
	orderPayload := acmeRawPayloadB64(t, map[string]any{
		"identity_id": identity.ID, "issuer_id": issuer.ID, "profile_id": profile.ID,
		"identifiers": []map[string]string{{"type": "dns", "value": "edge-01.example.test"}},
		"notAfter":    testNow.Add(12 * time.Hour).Format(time.RFC3339),
	})
	seenAuth, seenToken := map[string]bool{}, map[string]bool{}
	var previous apiACMEProtocolOrder
	var consumedNonce string
	for version := 0; version < 2; version++ {
		if version == 1 {
			// A newly signed renewal newOrder cannot use the first issuance's
			// consumed finalize nonce, even though the account is unchanged.
			var problem acmeProblemResponse
			next(api.doACMEJWSRawPayload(t, "/acme/new-order", consumedNonce, account.Location, api.acmeSigner, orderPayload, &problem), http.StatusBadRequest)
			if problem.Type != "urn:ietf:params:acme:error:badNonce" {
				t.Fatal("renewal accepted a consumed nonce")
			}
		}
		body := api.makeRawACMEJWS(t, map[string]any{
			"alg": api.acmeSigner.alg(), "nonce": nonce, "url": api.url + "/acme/new-order", "kid": account.Location,
		}, orderPayload, api.acmeSigner)
		response := api.doRawACMEJWS(t, "/acme/new-order", body, nil)
		next(response, http.StatusCreated)
		var order apiACMEProtocolOrder
		if err := json.Unmarshal([]byte(response.Body), &order); err != nil {
			t.Fatal(err)
		}
		if order.Status != "pending" || len(order.Authorizations) != 1 || order.Finalize == previous.Finalize {
			t.Fatal("renewal must create a distinct pending order")
		}
		var problem acmeProblemResponse
		next(api.doRawACMEJWS(t, "/acme/new-order", body, &problem), http.StatusBadRequest)
		if problem.Type != "urn:ietf:params:acme:error:badNonce" {
			t.Fatal("replayed newOrder not rejected")
		}
		finalizePath := api.pathFromURL(t, order.Finalize)
		finalizePayload := acmeRawPayloadB64(t, map[string]any{"csr_pem": "csr-pem", "requested_subject": "CN=edge-01"})
		next(api.doACMEJWSRawPayload(t, finalizePath, nonce, account.Location, api.acmeSigner, finalizePayload, nil), http.StatusConflict)
		if len(api.issuer.requests) != version {
			t.Fatal("unvalidated renewal reached signing")
		}
		var auth apiACMEProtocolAuthorization
		authPath := api.pathFromURL(t, order.Authorizations[0])
		next(api.doACMEJWSRawPayload(t, authPath, nonce, account.Location, api.acmeSigner, "", &auth), http.StatusOK)
		if seenAuth[authPath] || auth.Status != "pending" || len(auth.Challenges) != 1 ||
			auth.Identifier.Value != "edge-01.example.test" || auth.Challenges[0].Token == "" || seenToken[auth.Challenges[0].Token] {
			t.Fatal("renewal must require its own fresh DNS authorization and token")
		}
		seenAuth[authPath], seenToken[auth.Challenges[0].Token] = true, true
		next(api.doACMEJWSWithResponse(t, api.pathFromURL(t, auth.Challenges[0].URL), nonce, account.Location, api.acmeSigner, map[string]any{}, nil), http.StatusOK)
		next(api.doACMEJWSRawPayload(t, authPath, nonce, account.Location, api.acmeSigner, "", &auth), http.StatusOK)
		if auth.Status != "valid" {
			t.Fatal("renewal authorization not validated")
		}
		consumedNonce = nonce
		finalizeBody := api.makeRawACMEJWS(t, map[string]any{
			"alg": api.acmeSigner.alg(), "nonce": nonce, "url": api.url + finalizePath, "kid": account.Location,
		}, finalizePayload, api.acmeSigner)
		response = api.doRawACMEJWS(t, finalizePath, finalizeBody, nil)
		next(response, http.StatusOK)
		if err := json.Unmarshal([]byte(response.Body), &order); err != nil {
			t.Fatal(err)
		}
		if order.Status != "valid" || order.Certificate == "" || order.Certificate == previous.Certificate || len(api.issuer.requests) != version+1 {
			t.Fatal("renewal must produce a distinct valid order and certificate")
		}
		next(api.doRawACMEJWS(t, finalizePath, finalizeBody, &problem), http.StatusBadRequest)
		if problem.Type != "urn:ietf:params:acme:error:badNonce" || len(api.issuer.requests) != version+1 {
			t.Fatal("replayed finalize must not sign again")
		}
		certificate := api.doACMEJWSRawPayload(t, api.pathFromURL(t, order.Certificate), nonce, account.Location, api.acmeSigner, "", nil)
		next(certificate, http.StatusOK)
		if certificate.ContentType != "application/pem-certificate-chain" || certificate.Body == "" {
			t.Fatal("renewal certificate not downloadable")
		}
		previous = order
	}
	if len(api.acmeHTTP01.requests) != 2 {
		t.Fatal("expected fresh HTTP-01 verification on both orders")
	}
}
