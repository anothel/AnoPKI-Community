// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"github.com/anothel/anopki/service/internal/domain"
	"net/http"
	"testing"
)

// These pin the existing service extension, not RFC 8555 revocation support.
func TestACMERevocationContractAndSecurity(t *testing.T) {
	api := newTestAPI(t)
	cert := api.createCertificate(t)
	register := func(signer acmeTestSigner) apiACMEProtocolAccount {
		t.Helper()
		_, _, nonce := api.doACMENonce(t)
		var account apiACMEProtocolAccount
		assertStatus(t, api.doACMEJWSWithSigner(t, "/acme/new-account", nonce, "", signer,
			map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:ops@example.test"}}, &account), http.StatusCreated)
		return account
	}
	owner := register(api.acmeSigner)
	otherSigner := newACMETestSigner(t)
	other := register(otherSigner)
	// Repository fixture links a service-issued leaf to its owning ACME order.
	if err := api.repo.CreateACMEOrder(api.ctx, domain.ACMEOrder{
		ID: "revocation-order", AccountID: owner.ID, CertificateID: cert.ID,
		Status: domain.ACMEOrderValid, CreatedAt: testNow, UpdatedAt: testNow,
	}); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"certificate_id": cert.ID, "reason": "superseded"}
	unchanged := func() {
		t.Helper()
		got, err := api.repo.GetCertificate(api.ctx, cert.ID)
		if err != nil || got.Status != domain.CertificateValid {
			t.Fatal("rejected request changed certificate")
		}
		entries, err := api.repo.ListRevocationsByIssuer(api.ctx, cert.IssuerID)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected request created revocation")
		}
	}
	cases := []struct {
		name, kid string
		signer    acmeTestSigner
		payload   any
		want      int
	}{
		{"unrelated account", other.Location, otherSigner, payload, 403},
		{"forged owner signature", owner.Location, otherSigner, payload, 400},
		{"unregistered unrelated JWK", "", newACMETestSigner(t), payload, 400},
		{"owner JWK without account KID", "", api.acmeSigner, payload, 400},
		{"standard numeric reason", owner.Location, api.acmeSigner, map[string]any{"certificate": "MAA", "reason": 0}, 400},
		{"standard omitted reason", owner.Location, api.acmeSigner, map[string]any{"certificate": "MAA"}, 400},
		{"malformed certificate", owner.Location, api.acmeSigner, map[string]any{"certificate": "%%%", "reason": 1}, 400},
		{"numeric reason with legacy ID", owner.Location, api.acmeSigner, map[string]any{"certificate_id": cert.ID, "reason": 1}, 400},
		{"invalid legacy reason", owner.Location, api.acmeSigner, map[string]any{"certificate_id": cert.ID, "reason": "invalid"}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, nonce := api.doACMENonce(t)
			header := map[string]any{"alg": tc.signer.alg(), "nonce": nonce, "url": api.url + "/acme/revoke-cert"}
			if tc.kid == "" {
				header["jwk"] = tc.signer.jwk()
			} else {
				header["kid"] = tc.kid
			}
			body := api.makeRawACMEJWS(t, header, acmeRawPayloadB64(t, tc.payload), tc.signer)
			assertStatus(t, api.doRawACMEJWS(t, "/acme/revoke-cert", body, nil).StatusCode, tc.want)
			unchanged()
			var problem acmeProblemResponse
			assertStatus(t, api.doRawACMEJWS(t, "/acme/revoke-cert", body, &problem).StatusCode, 400)
			if problem.Type != "urn:ietf:params:acme:error:badNonce" {
				t.Fatal("rejected request nonce reusable")
			}
			unchanged()
		})
	}
	_, _, nonce := api.doACMENonce(t)
	body := api.makeRawACMEJWS(t, map[string]any{"alg": api.acmeSigner.alg(), "nonce": nonce, "url": api.url + "/acme/revoke-cert", "kid": owner.Location}, acmeRawPayloadB64(t, payload), api.acmeSigner)
	response := api.doRawACMEJWS(t, "/acme/revoke-cert", body, nil)
	assertStatus(t, response.StatusCode, 200)
	if response.ReplayNonce == "" || response.Body != "{}\n" {
		t.Fatal("legacy success response changed")
	}
	got, err := api.repo.GetCertificate(api.ctx, cert.ID)
	if err != nil || got.Status != domain.CertificateRevoked {
		t.Fatal("owner revocation failed")
	}
	entries, err := api.repo.ListRevocationsByIssuer(api.ctx, cert.IssuerID)
	if err != nil || len(entries) != 1 {
		t.Fatal("expected one revocation")
	}
	var problem acmeProblemResponse
	assertStatus(t, api.doRawACMEJWS(t, "/acme/revoke-cert", body, &problem).StatusCode, 400)
	if problem.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Fatal("successful revocation replay accepted")
	}
	_, _, nonce = api.doACMENonce(t)
	assertStatus(t, api.doACMEJWSWithSigner(t, "/acme/revoke-cert", nonce, owner.Location, api.acmeSigner, payload, nil), 409)
	entries, err = api.repo.ListRevocationsByIssuer(api.ctx, cert.IssuerID)
	if err != nil || len(entries) != 1 {
		t.Fatal("repeated revocation duplicated record")
	}
}
