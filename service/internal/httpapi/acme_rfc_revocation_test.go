// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestACMERFCRevocationAuthorizationAndReasons(t *testing.T) {
	for _, mode := range []string{"account", "certificate"} {
		for _, omitted := range []bool{true, false} {
			t.Run(mode+map[bool]string{true: " omitted", false: " zero"}[omitted], func(t *testing.T) {
				api := newTestAPI(t)
				cert := api.createCertificate(t)
				key := newACMETestSigner(t).(*acmeECTestSigner)
				template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"edge-01.example.test"}, NotBefore: testNow, NotAfter: cert.NotAfter}
				der, err := x509.CreateCertificate(rand.Reader, template, template, &key.key.PublicKey, key.key)
				if err != nil {
					t.Fatal(err)
				}
				cert.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
				cert.SerialNumber = "123"
				issuerID := "rfc-issuer"
				if err := api.repo.CreateIssuer(api.ctx, domain.Issuer{ID: issuerID, CertificatePEM: cert.CertificatePEM, Status: domain.IssuerActive, CreatedAt: testNow, UpdatedAt: testNow}); err != nil {
					t.Fatal(err)
				}
				cert.IssuerID = issuerID

				if err := api.repo.UpdateCertificate(api.ctx, cert); err != nil {
					t.Fatal(err)
				}
				register := func(signer acmeTestSigner) apiACMEProtocolAccount {
					_, _, nonce := api.doACMENonce(t)
					var a apiACMEProtocolAccount
					assertStatus(t, api.doACMEJWSWithSigner(t, "/acme/new-account", nonce, "", signer, map[string]any{"contact": []string{"mailto:test@example.test"}, "termsOfServiceAgreed": true}, &a), 201)
					return a
				}
				owner := register(api.acmeSigner)
				otherKey := newACMETestSigner(t)
				other := register(otherKey)
				// Even complete, currently valid identifier authorization does
				// not grant this other account revocation authority (#31).
				if err := api.repo.CreateACMEOrder(api.ctx, domain.ACMEOrder{ID: "other-order", AccountID: other.ID, Status: domain.ACMEOrderReady, RequestedDNSNames: []string{"edge-01.example.test"}, ExpiresAt: testNow.Add(time.Hour), CreatedAt: testNow, UpdatedAt: testNow}); err != nil {
					t.Fatal(err)
				}
				if err := api.repo.CreateACMEAuthorization(api.ctx, domain.ACMEAuthorization{ID: "other-auth", OrderID: "other-order", IdentifierType: "dns", IdentifierValue: "edge-01.example.test", Status: domain.ACMEAuthorizationValid, ExpiresAt: testNow.Add(time.Hour), CreatedAt: testNow, UpdatedAt: testNow}); err != nil {
					t.Fatal(err)
				}

				if err := api.repo.CreateACMEOrder(api.ctx, domain.ACMEOrder{ID: "order", AccountID: owner.ID, CertificateID: cert.ID, Status: domain.ACMEOrderValid, CreatedAt: testNow, UpdatedAt: testNow}); err != nil {
					t.Fatal(err)
				}
				differentDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.key.PublicKey, key.key)
				if err != nil {
					t.Fatal(err)
				}
				payload := map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(der)}
				if !omitted {
					payload["reason"] = 0
				}
				send := func(kid string, signer acmeTestSigner, payload any) (acmeJWSHTTPResponse, map[string]string) {
					_, _, nonce := api.doACMENonce(t)
					h := map[string]any{"alg": signer.alg(), "nonce": nonce, "url": api.url + "/acme/revoke-cert"}
					if kid != "" {
						h["kid"] = kid
					} else {
						h["jwk"] = signer.jwk()
					}
					body := api.makeRawACMEJWS(t, h, acmeRawPayloadB64(t, payload), signer)
					return api.doRawACMEJWS(t, "/acme/revoke-cert", body, nil), body
				}
				for _, bad := range []struct {
					kid     string
					key     acmeTestSigner
					payload any
					status  int
				}{
					{owner.Location, api.acmeSigner, map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(differentDER)}, 400},
					{other.Location, otherKey, payload, 403}, {"", otherKey, payload, 403},
					{owner.Location, otherKey, payload, 400},
					{owner.Location, api.acmeSigner, map[string]any{"certificate": payload["certificate"], "certificate_id": cert.ID, "reason": 0}, 400},
					{owner.Location, api.acmeSigner, map[string]any{"certificate": payload["certificate"], "reason": 6}, 400},
					{owner.Location, api.acmeSigner, map[string]any{"certificate": payload["certificate"], "reason": nil}, 400},
					{owner.Location, api.acmeSigner, map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(append(append([]byte{}, der...), 0)), "reason": 0}, 400},
				} {
					r, body := send(bad.kid, bad.key, bad.payload)
					assertStatus(t, r.StatusCode, bad.status)
					got, _ := api.repo.GetCertificate(api.ctx, cert.ID)
					if got.Status != domain.CertificateValid {
						t.Fatal("rejection changed state")
					}
					var problem acmeProblemResponse
					assertStatus(t, api.doRawACMEJWS(t, "/acme/revoke-cert", body, &problem).StatusCode, 400)
					if problem.Type != "urn:ietf:params:acme:error:badNonce" {
						t.Fatal("rejection nonce replay")
					}
				}
				inactive, _ := api.repo.GetACMEAccount(api.ctx, owner.ID)
				inactive.Status = domain.ACMEAccountDeactivated
				if err := api.repo.UpdateACMEAccountIfStatus(api.ctx, inactive, domain.ACMEAccountValid); err != nil {
					t.Fatal(err)
				}
				rejected, _ := send(owner.Location, api.acmeSigner, payload)
				assertStatus(t, rejected.StatusCode, 401)
				inactive.Status = domain.ACMEAccountValid
				if err := api.repo.UpdateACMEAccountIfStatus(api.ctx, inactive, domain.ACMEAccountDeactivated); err != nil {
					t.Fatal(err)
				}

				signer := api.acmeSigner
				kid := owner.Location
				if mode == "certificate" {
					signer = key
					kid = ""
				}
				response, body := send(kid, signer, payload)
				assertStatus(t, response.StatusCode, http.StatusOK)
				if response.Body != "" || response.ReplayNonce == "" {
					t.Fatal("RFC success must have empty body and fresh nonce")
				}
				entries, err := api.repo.ListRevocationsByIssuer(api.ctx, cert.IssuerID)
				want := domain.RevocationUnspecified
				if omitted {
					want = "not_provided"
				}
				if err != nil || len(entries) != 1 || entries[0].Reason != want {
					t.Fatal("RFC reason semantics lost")
				}
				var p acmeProblemResponse
				assertStatus(t, api.doRawACMEJWS(t, "/acme/revoke-cert", body, &p).StatusCode, 400)
				if p.Type != "urn:ietf:params:acme:error:badNonce" {
					t.Fatal("success replay accepted")
				}
				again, _ := send(kid, signer, payload)
				assertStatus(t, again.StatusCode, 400)
				if !strings.Contains(again.Body, "urn:ietf:params:acme:error:alreadyRevoked") {
					t.Fatal("missing alreadyRevoked")
				}
			})
		}
	}
}

func TestDecodeRFCRevocationRejectsAmbiguousPayloads(t *testing.T) {
	key := newACMETestSigner(t).(*acmeECTestSigner)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "parse"}, NotBefore: testNow, NotAfter: testNow.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.key.PublicKey, key.key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(der)
	for _, integer := range []string{"6", "9999999999999999999999999999999999999999999999999999999", "-9999999999999999999999999999999999999999999999999999999"} {
		_, _, err := decodeRFCRevocation([]byte(`{"certificate":"` + encoded + `","reason":` + integer + `}`))
		if err == nil || acmeProblemType(err) != "urn:ietf:params:acme:error:badRevocationReason" {
			t.Fatal("unsupported integer must return badRevocationReason")
		}
	}

	for _, payload := range []string{
		`{"certificate":"a","certificate":"b"}`, `{"certificate":"a","reason":0,"reason":1}`,
		`{"Certificate":"a"}`, `{"certificate":"a","certificate_id":null}`, `{"certificate":"a","unknown":true}`,
		`{"certificate":"MAA="}`, `{"certificate":"MAA","reason":null}`, `{"certificate":"MAA","reason":true}`,
		`{"certificate":"MAA","reason":1.5}`, `{"certificate":"MAA","reason":"0"}`, `{"certificate":"MAA"} {}`,
	} {
		payload = strings.ReplaceAll(payload, `"MAA="`, `"`+encoded+`="`)
		payload = strings.ReplaceAll(payload, `"MAA"`, `"`+encoded+`"`)
		payload = strings.ReplaceAll(payload, `"a"`, `"`+encoded+`"`)
		payload = strings.ReplaceAll(payload, `"b"`, `"`+encoded+`"`)
		if _, _, err := decodeRFCRevocation([]byte(payload)); err == nil {
			t.Fatal("accepted ambiguous RFC payload")
		}
	}
}

func TestACMERFCRevocationRateLimit(t *testing.T) {
	api := newTestAPIWithACMEConfig(t, ACMEConfig{RateLimit: 1, RateLimitWindow: time.Minute})
	for i := 0; i < 2; i++ {
		_, _, nonce := api.doACMENonce(t)
		var problem acmeProblemResponse
		response := api.doACMEJWSWithResponse(t, "/acme/revoke-cert", nonce, "", api.acmeSigner, map[string]any{"certificate": "MAA"}, &problem)
		if i == 0 {
			assertStatus(t, response.StatusCode, 400)
		} else {
			assertStatus(t, response.StatusCode, 429)
			if problem.Type != "urn:ietf:params:acme:error:rateLimited" {
				t.Fatal("missing rateLimited")
			}
		}
	}
}
