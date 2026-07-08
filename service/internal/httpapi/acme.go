// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/lifecycle"
)

func (s *Server) createACMEAccount(w http.ResponseWriter, r *http.Request) {
	var req createACMEAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	account, err := s.service.CreateACMEAccount(r.Context(), requestActor(r), lifecycle.CreateACMEAccountRequest{
		Contacts:             req.Contacts,
		TermsOfServiceAgreed: req.TermsOfServiceAgreed,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toACMEAccountResponse(account))
}

func (s *Server) listACMEAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.service.ListACMEAccounts(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEAccountResponses(accounts))
}

func (s *Server) createACMEOrder(w http.ResponseWriter, r *http.Request) {
	var req createACMEOrderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	order, err := s.service.CreateACMEOrder(r.Context(), requestActor(r), lifecycle.CreateACMEOrderRequest{
		AccountID:            req.AccountID,
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CertificateProfileID: req.CertificateProfileID,
		RequestedDNSNames:    req.RequestedDNSNames,
		RequestedIPAddresses: req.RequestedIPAddresses,
		RequestedNotAfter:    req.RequestedNotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toACMEOrderResponse(order))
}

func (s *Server) getACMEOrder(w http.ResponseWriter, r *http.Request) {
	order, err := s.service.GetACMEOrder(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEOrderResponse(order))
}

func (s *Server) listACMEAuthorizations(w http.ResponseWriter, r *http.Request) {
	authorizations, err := s.service.ListACMEAuthorizations(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEAuthorizationResponses(authorizations))
}

func (s *Server) listACMEChallenges(w http.ResponseWriter, r *http.Request) {
	challenges, err := s.service.ListACMEChallenges(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEChallengeResponses(challenges))
}

func (s *Server) completeACMEChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := s.service.CompleteACMEChallenge(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEChallengeResponse(challenge))
}

func (s *Server) finalizeACMEOrder(w http.ResponseWriter, r *http.Request) {
	var req finalizeACMEOrderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	order, err := s.service.FinalizeACMEOrder(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.FinalizeACMEOrderRequest{
		CSRPEM:           req.CSRPEM,
		RequestedSubject: req.RequestedSubject,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toACMEOrderResponse(order))
}

func (s *Server) acmeDirectory(w http.ResponseWriter, r *http.Request) {
	baseURL := requestBaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   baseURL + "/acme/new-nonce",
		"newAccount": baseURL + "/acme/new-account",
		"newOrder":   baseURL + "/acme/new-order",
		"keyChange":  baseURL + "/acme/key-change",
		"revokeCert": baseURL + "/acme/revoke-cert",
		"meta": map[string]any{
			"externalAccountRequired": false,
		},
	})
}

func (s *Server) acmeNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := s.issueACMENonce(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", acmeDirectoryLink(r))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) acmeNewAccount(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var req acmeNewAccountRequest
	if err := json.Unmarshal(jws.Payload, &req); err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	result, err := s.service.CreateOrGetACMEAccount(r.Context(), requestActor(r), lifecycle.CreateACMEAccountRequest{
		Contacts:             req.Contact,
		TermsOfServiceAgreed: req.TermsOfServiceAgreed,
		KeyThumbprint:        jws.KeyThumbprint,
		KeyJWKJSON:           jws.KeyJWKJSON,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response := s.toACMEProtocolAccount(r, result.Account)
	w.Header().Set("Location", response.Location)
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	s.writeACMEJSON(w, r, status, response)
}

func (s *Server) acmeUpdateAccount(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	accountID := r.PathValue("id")
	if jws.AccountID == "" || jws.AccountID != accountID {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	var req acmeUpdateAccountRequest
	if err := json.Unmarshal(jws.Payload, &req); err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	update := lifecycle.UpdateACMEAccountRequest{}
	if req.Contact != nil {
		update.Contacts = append([]string(nil), (*req.Contact)...)
		update.UpdateContacts = true
	}
	if req.Status != "" {
		if req.Status != string(domain.ACMEAccountDeactivated) {
			s.writeError(w, r, domain.ErrInvalidRequest)
			return
		}
		update.Deactivate = true
	}
	account, err := s.service.UpdateACMEAccount(r.Context(), requestActor(r), accountID, update)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeACMEJSON(w, r, http.StatusOK, s.toACMEProtocolAccount(r, account))
}

func (s *Server) acmeKeyChange(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if jws.AccountID == "" {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	account, err := s.service.GetACMEAccount(r.Context(), jws.AccountID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if account.KeyJWKJSON == "" {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	inner, err := s.decodeACMEKeyChangeJWS(r, jws.Payload)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if inner.Account != requestBaseURL(r)+"/acme/account/"+account.ID {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	oldKeyJSON, err := canonicalACMEJWKJSON(inner.OldKey)
	if err != nil || oldKeyJSON != account.KeyJWKJSON {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	updated, err := s.service.UpdateACMEAccountKey(r.Context(), requestActor(r), account.ID, lifecycle.UpdateACMEAccountKeyRequest{
		KeyThumbprint: inner.NewKeyThumbprint,
		KeyJWKJSON:    inner.NewKeyJWKJSON,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeACMEJSON(w, r, http.StatusOK, s.toACMEProtocolAccount(r, updated))
}

func (s *Server) acmeNewOrder(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var req acmeNewOrderRequest
	if err := json.Unmarshal(jws.Payload, &req); err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if jws.AccountID == "" {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if req.AccountID == "" {
		req.AccountID = jws.AccountID
	}
	if req.IdentityID == "" {
		req.IdentityID = s.acme.DefaultIdentityID
	}
	if req.IssuerID == "" {
		req.IssuerID = s.acme.DefaultIssuerID
	}
	if req.CertificateProfileID == "" {
		req.CertificateProfileID = s.acme.DefaultCertificateProfileID
	}
	if req.NotAfter.IsZero() && s.acme.DefaultValidityPeriod > 0 {
		req.NotAfter = time.Now().UTC().Add(s.acme.DefaultValidityPeriod)
	}
	if req.AccountID != jws.AccountID {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	dnsNames, ipAddresses, err := acmeOrderIdentifiers(req.Identifiers)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	order, err := s.service.CreateACMEOrder(r.Context(), requestActor(r), lifecycle.CreateACMEOrderRequest{
		AccountID:            req.AccountID,
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CertificateProfileID: req.CertificateProfileID,
		RequestedDNSNames:    dnsNames,
		RequestedIPAddresses: ipAddresses,
		RequestedNotAfter:    req.NotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolOrder(r, order)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", response.URL)
	s.writeACMEJSON(w, r, http.StatusCreated, response)
}

func (s *Server) acmeGetOrder(w http.ResponseWriter, r *http.Request) {
	order, err := s.service.GetACMEOrder(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolOrder(r, order)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) acmePostAsGetOrder(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if len(jws.Payload) != 0 {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if err := s.requireACMEOrderAccount(r.Context(), r.PathValue("id"), jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	order, err := s.service.GetACMEOrder(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolOrder(r, order)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeACMEJSON(w, r, http.StatusOK, response)
}

func (s *Server) acmeGetAuthorization(w http.ResponseWriter, r *http.Request) {
	authorization, err := s.service.PollACMEAuthorization(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolAuthorization(r, authorization)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if acmeAuthorizationHasProcessingChallenge(response) {
		w.Header().Set("Retry-After", acmeRetryAfterSeconds)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) acmePostAsGetAuthorization(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if len(jws.Payload) != 0 {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if err := s.requireACMEAuthorizationAccount(r.Context(), r.PathValue("id"), jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	authorization, err := s.service.PollACMEAuthorization(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolAuthorization(r, authorization)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if acmeAuthorizationHasProcessingChallenge(response) {
		w.Header().Set("Retry-After", acmeRetryAfterSeconds)
	}
	s.writeACMEJSON(w, r, http.StatusOK, response)
}

func (s *Server) acmeCompleteChallenge(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.requireACMEChallengeAccount(r.Context(), r.PathValue("id"), jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	challenge, err := s.service.ValidateACMEHTTP01Challenge(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if challenge.Status == domain.ACMEChallengeProcessing {
		w.Header().Set("Retry-After", acmeRetryAfterSeconds)
	}
	w.Header().Add("Link", acmeAuthorizationLink(r, challenge.AuthorizationID))
	s.writeACMEJSON(w, r, http.StatusOK, s.toACMEProtocolChallenge(r, challenge))
}

func (s *Server) acmeFinalizeOrder(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var req finalizeACMEOrderRequest
	if err := json.Unmarshal(jws.Payload, &req); err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if err := s.requireACMEOrderAccount(r.Context(), r.PathValue("id"), jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	csrPEM, requestedSubject, err := normalizeACMEFinalizeRequest(req)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	order, err := s.service.FinalizeACMEOrder(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.FinalizeACMEOrderRequest{
		CSRPEM:           csrPEM,
		RequestedSubject: requestedSubject,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	response, err := s.toACMEProtocolOrder(r, order)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeACMEJSON(w, r, http.StatusOK, response)
}

func (s *Server) acmeRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var req acmeRevokeCertificateRequest
	if err := json.Unmarshal(jws.Payload, &req); err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if req.CertificateID == "" || req.Reason == "" {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if err := s.requireACMECertificateAccount(r.Context(), req.CertificateID, jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	if _, err := s.service.RevokeCertificate(r.Context(), requestActor(r), req.CertificateID, req.Reason); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeACMEJSON(w, r, http.StatusOK, map[string]any{})
}

func (s *Server) acmeGetCertificate(w http.ResponseWriter, r *http.Request) {
	chainPEM, err := s.acmeCertificateChainPEM(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, chainPEM) // #nosec G705 -- ACME certificate chain is PEM, not HTML.
}

func normalizeACMEFinalizeRequest(req finalizeACMEOrderRequest) (string, string, error) {
	if strings.TrimSpace(req.CSRPEM) != "" {
		return req.CSRPEM, req.RequestedSubject, nil
	}
	if strings.TrimSpace(req.CSR) == "" {
		return "", "", domain.ErrInvalidRequest
	}
	der, err := decodeACMECSR(req.CSR)
	if err != nil {
		return "", "", domain.ErrInvalidRequest
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", "", domain.ErrInvalidRequest
	}
	subject := req.RequestedSubject
	if strings.TrimSpace(subject) == "" {
		subject = csr.Subject.String()
	}
	if strings.TrimSpace(subject) == "" {
		subject = acmeDefaultSubjectFromCSR(csr)
	}
	if strings.TrimSpace(subject) == "" {
		return "", "", domain.ErrInvalidRequest
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}))
	return csrPEM, subject, nil
}

func acmeDefaultSubjectFromCSR(csr *x509.CertificateRequest) string {
	for _, name := range csr.DNSNames {
		if strings.TrimSpace(name) != "" {
			return pkix.Name{CommonName: name}.String()
		}
	}
	for _, ip := range csr.IPAddresses {
		if ip != nil {
			return pkix.Name{CommonName: ip.String()}.String()
		}
	}
	return ""
}

func decodeACMECSR(encoded string) ([]byte, error) {
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err == nil {
		return der, nil
	}
	return base64.URLEncoding.DecodeString(encoded)
}

func (s *Server) acmePostAsGetCertificate(w http.ResponseWriter, r *http.Request) {
	jws, err := s.decodeACMEJWS(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if len(jws.Payload) != 0 {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if err := s.requireACMECertificateAccount(r.Context(), r.PathValue("id"), jws.AccountID); err != nil {
		s.writeError(w, r, err)
		return
	}
	chainPEM, err := s.acmeCertificateChainPEM(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	nonce, err := s.issueACMENonce(r.Context())
	if err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Set("Link", acmeDirectoryLink(r))
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, chainPEM) // #nosec G705 -- ACME certificate chain is PEM, not HTML.
}

func (s *Server) acmeCertificateChainPEM(ctx context.Context, certificateID string) (string, error) {
	certificate, err := s.service.GetCertificate(ctx, certificateID)
	if err != nil {
		return "", err
	}
	chain, err := s.service.GetIssuerChain(ctx, certificate.IssuerID)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	acmeAppendCertificateChainBlock(&builder, certificate.CertificatePEM)
	for _, issuer := range chain {
		acmeAppendCertificateChainBlock(&builder, issuer.CertificatePEM)
	}
	if builder.Len() > 0 {
		builder.WriteByte('\n')
	}
	return builder.String(), nil
}

func acmeAppendCertificateChainBlock(builder *strings.Builder, block string) {
	normalized := strings.TrimRight(block, "\r\n")
	if normalized == "" {
		return
	}
	if builder.Len() > 0 {
		builder.WriteByte('\n')
	}
	builder.WriteString(normalized)
}

func (s *Server) decodeACMEJWS(r *http.Request) (acmeJWSResult, error) {
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(contentType, "application/jose+json") {
		return acmeJWSResult{}, domain.ErrUnsupportedMediaType
	}
	var req acmeJWSRequest
	if err := decodeJSON(r, &req); err != nil {
		return acmeJWSResult{}, err
	}
	if req.Protected == "" || req.Signature == "" {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(req.Protected)
	if err != nil {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	var protected acmeProtectedHeader
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	if !isSupportedACMEJWSAlg(protected.Alg) || protected.Nonce == "" || protected.URL == "" || protected.URL != requestAbsoluteURL(r) {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	if (protected.KID == "") == (protected.JWK == nil) {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	if !s.consumeACMENonce(r.Context(), protected.Nonce) {
		return acmeJWSResult{}, errACMEBadNonce
	}
	payload, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	result := acmeJWSResult{Payload: payload}
	var jwk acmeJWK
	if protected.KID != "" {
		if !strings.HasPrefix(protected.KID, requestBaseURL(r)+"/acme/account/") {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		accountID, err := acmeAccountIDFromKID(protected.KID)
		if err != nil {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		account, err := s.service.GetACMEAccount(r.Context(), accountID)
		if err != nil {
			return acmeJWSResult{}, err
		}
		if account.KeyJWKJSON == "" || account.KeyThumbprint == "" {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		if err := json.Unmarshal([]byte(account.KeyJWKJSON), &jwk); err != nil {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		result.AccountID = account.ID
		result.KeyThumbprint = account.KeyThumbprint
		result.KeyJWKJSON = account.KeyJWKJSON
	} else {
		parsedJWK, err := acmeJWKFromProtected(protected.JWK)
		if err != nil {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		jwk = parsedJWK
		keyJSON, err := canonicalACMEJWKJSON(jwk)
		if err != nil {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		thumbprint, err := acmeJWKThumbprint(jwk)
		if err != nil {
			return acmeJWSResult{}, domain.ErrInvalidRequest
		}
		result.KeyJWKJSON = keyJSON
		result.KeyThumbprint = thumbprint
	}
	if err := verifyACMEJWS(protected.Alg, jwk, req.Protected+"."+req.Payload, req.Signature); err != nil {
		return acmeJWSResult{}, domain.ErrInvalidRequest
	}
	return result, nil
}

func (s *Server) decodeACMEKeyChangeJWS(r *http.Request, payload []byte) (acmeKeyChangeJWSResult, error) {
	var req acmeJWSRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	if req.Protected == "" || req.Payload == "" || req.Signature == "" {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	protectedBytes, err := base64.RawURLEncoding.DecodeString(req.Protected)
	if err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	var protected acmeProtectedHeader
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	if !isSupportedACMEJWSAlg(protected.Alg) || protected.URL != requestBaseURL(r)+"/acme/key-change" || protected.KID != "" || protected.JWK == nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	jwk, err := acmeJWKFromProtected(protected.JWK)
	if err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	if err := verifyACMEJWS(protected.Alg, jwk, req.Protected+"."+req.Payload, req.Signature); err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	innerPayload, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	var change acmeKeyChangeRequest
	if err := json.Unmarshal(innerPayload, &change); err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	if change.Account == "" {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	keyJSON, err := canonicalACMEJWKJSON(jwk)
	if err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	thumbprint, err := acmeJWKThumbprint(jwk)
	if err != nil {
		return acmeKeyChangeJWSResult{}, domain.ErrInvalidRequest
	}
	return acmeKeyChangeJWSResult{
		Account:          change.Account,
		OldKey:           change.OldKey,
		NewKeyThumbprint: thumbprint,
		NewKeyJWKJSON:    keyJSON,
	}, nil
}

func isSupportedACMEJWSAlg(alg string) bool {
	return alg == "ES256" || alg == "RS256" || alg == "EdDSA"
}

func (s *Server) issueACMENonce(ctx context.Context) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now()
	if err := s.nonces.Issue(ctx, nonce, now, now.Add(defaultACMENonceTTL)); err != nil {
		return "", err
	}
	return nonce, nil
}

func (s *Server) consumeACMENonce(ctx context.Context, nonce string) bool {
	ok, err := s.nonces.Consume(ctx, nonce, time.Now())
	return err == nil && ok
}

func newACMEMemoryNonceStore(maxSize int) *acmeMemoryNonceStore {
	return &acmeMemoryNonceStore{
		nonces:  make(map[string]acmeStoredNonce),
		maxSize: maxSize,
	}
}

func (s *acmeMemoryNonceStore) Issue(ctx context.Context, nonce string, issuedAt time.Time, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(issuedAt)
	s.evictOldestLocked(s.maxSize - 1)
	s.nonces[nonce] = acmeStoredNonce{IssuedAt: issuedAt, ExpiresAt: expiresAt}
	return nil
}

func (s *acmeMemoryNonceStore) Consume(ctx context.Context, nonce string, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpiredLocked(now)
	if _, ok := s.nonces[nonce]; !ok {
		return false, nil
	}
	delete(s.nonces, nonce)
	return true, nil
}

func (s *acmeMemoryNonceStore) removeExpiredLocked(now time.Time) {
	for nonce, stored := range s.nonces {
		if !stored.ExpiresAt.After(now) {
			delete(s.nonces, nonce)
		}
	}
}

func (s *acmeMemoryNonceStore) evictOldestLocked(maxSize int) {
	for len(s.nonces) > maxSize {
		var oldestNonce string
		var oldestIssuedAt time.Time
		for nonce, issuedAt := range s.nonces {
			if oldestNonce == "" || issuedAt.IssuedAt.Before(oldestIssuedAt) {
				oldestNonce = nonce
				oldestIssuedAt = issuedAt.IssuedAt
			}
		}
		delete(s.nonces, oldestNonce)
	}
}

func (s *Server) writeACMEJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	nonce, err := s.issueACMENonce(r.Context())
	if err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
	w.Header().Add("Link", acmeDirectoryLink(r))
	writeJSON(w, status, value)
}

func acmeDirectoryLink(r *http.Request) string {
	return "<" + requestBaseURL(r) + "/acme/directory>;rel=\"index\""
}

func acmeAuthorizationLink(r *http.Request, authorizationID string) string {
	return "<" + requestBaseURL(r) + "/acme/authz/" + authorizationID + ">;rel=\"up\""
}

func requestBaseURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func requestAbsoluteURL(r *http.Request) string {
	return requestBaseURL(r) + r.URL.RequestURI()
}

func acmeOrderIdentifiers(identifiers []acmeIdentifierRequest) ([]string, []string, error) {
	dnsNames := make([]string, 0)
	ipAddresses := make([]string, 0)
	for _, identifier := range identifiers {
		if strings.TrimSpace(identifier.Value) == "" {
			return nil, nil, domain.ErrInvalidRequest
		}
		switch identifier.Type {
		case "dns":
			dnsNames = append(dnsNames, identifier.Value)
		case "ip":
			ipAddresses = append(ipAddresses, identifier.Value)
		default:
			return nil, nil, domain.ErrInvalidRequest
		}
	}
	return dnsNames, ipAddresses, nil
}

func (s *Server) requireACMEChallengeAccount(ctx context.Context, challengeID string, accountID string) error {
	if accountID == "" {
		return domain.ErrInvalidRequest
	}
	challenge, err := s.service.GetACMEChallenge(ctx, challengeID)
	if err != nil {
		return err
	}
	authorization, err := s.service.GetACMEAuthorization(ctx, challenge.AuthorizationID)
	if err != nil {
		return err
	}
	return s.requireACMEOrderAccount(ctx, authorization.OrderID, accountID)
}

func (s *Server) requireACMEAuthorizationAccount(ctx context.Context, authorizationID string, accountID string) error {
	if accountID == "" {
		return domain.ErrInvalidRequest
	}
	authorization, err := s.service.GetACMEAuthorization(ctx, authorizationID)
	if err != nil {
		return err
	}
	return s.requireACMEOrderAccount(ctx, authorization.OrderID, accountID)
}

func (s *Server) requireACMECertificateAccount(ctx context.Context, certificateID string, accountID string) error {
	if certificateID == "" || accountID == "" {
		return domain.ErrInvalidRequest
	}
	orders, err := s.service.ListACMEOrdersByAccount(ctx, accountID)
	if err != nil {
		return err
	}
	for _, order := range orders {
		if order.CertificateID == certificateID {
			return nil
		}
	}
	return domain.ErrForbidden
}

func (s *Server) requireACMEOrderAccount(ctx context.Context, orderID string, accountID string) error {
	if accountID == "" {
		return domain.ErrInvalidRequest
	}
	account, err := s.service.GetACMEAccount(ctx, accountID)
	if err != nil {
		return err
	}
	if account.Status == domain.ACMEAccountDeactivated {
		return domain.ErrACMEAccountDeactivated
	}
	if account.Status != domain.ACMEAccountValid {
		return domain.ErrInvalidRequest
	}
	order, err := s.service.GetACMEOrder(ctx, orderID)
	if err != nil {
		return err
	}
	if order.AccountID != accountID {
		return domain.ErrInvalidRequest
	}
	return nil
}

func acmeJWKFromProtected(value any) (acmeJWK, error) {
	if value == nil {
		return acmeJWK{}, domain.ErrInvalidRequest
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return acmeJWK{}, err
	}
	var jwk acmeJWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return acmeJWK{}, err
	}
	if isValidACMEECJWK(jwk) || isValidACMERSAJWK(jwk) || isValidACMEOKPJWK(jwk) {
		return jwk, nil
	}
	return acmeJWK{}, domain.ErrInvalidRequest
}

func acmeAccountIDFromKID(kid string) (string, error) {
	parsed, err := url.Parse(kid)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "acme" || parts[1] != "account" || parts[2] == "" {
		return "", domain.ErrInvalidRequest
	}
	return parts[2], nil
}

func verifyACMEJWS(alg string, jwk acmeJWK, signingInput string, signatureB64 string) error {
	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return domain.ErrInvalidRequest
	}
	sum := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "ES256":
		publicKey, err := acmeECJWKPublicKey(jwk)
		if err != nil {
			return err
		}
		if len(signature) != 64 {
			return domain.ErrInvalidRequest
		}
		r := new(big.Int).SetBytes(signature[:32])
		sigS := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(publicKey, sum[:], r, sigS) {
			return domain.ErrInvalidRequest
		}
		return nil
	case "RS256":
		publicKey, err := acmeRSAJWKPublicKey(jwk)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature); err != nil {
			return domain.ErrInvalidRequest
		}
		return nil
	case "EdDSA":
		publicKey, err := acmeOKPJWKPublicKey(jwk)
		if err != nil {
			return err
		}
		if !ed25519.Verify(publicKey, []byte(signingInput), signature) {
			return domain.ErrInvalidRequest
		}
		return nil
	default:
		return domain.ErrInvalidRequest
	}
}

func isValidACMEECJWK(jwk acmeJWK) bool {
	return jwk.KTY == "EC" && jwk.CRV == "P-256" && jwk.X != "" && jwk.Y != "" && jwk.N == "" && jwk.E == ""
}

func isValidACMERSAJWK(jwk acmeJWK) bool {
	return jwk.KTY == "RSA" && jwk.N != "" && jwk.E != "" && jwk.CRV == "" && jwk.X == "" && jwk.Y == ""
}

func isValidACMEOKPJWK(jwk acmeJWK) bool {
	return jwk.KTY == "OKP" && jwk.CRV == "Ed25519" && jwk.X != "" && jwk.Y == "" && jwk.N == "" && jwk.E == ""
}

func acmeECJWKPublicKey(jwk acmeJWK) (*ecdsa.PublicKey, error) {
	if !isValidACMEECJWK(jwk) {
		return nil, domain.ErrInvalidRequest
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, domain.ErrInvalidRequest
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, domain.ErrInvalidRequest
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, domain.ErrInvalidRequest
	}
	encoded := make([]byte, 1+len(xBytes)+len(yBytes))
	encoded[0] = 4
	copy(encoded[1:], xBytes)
	copy(encoded[1+len(xBytes):], yBytes)
	if _, err := ecdh.P256().NewPublicKey(encoded); err != nil {
		return nil, domain.ErrInvalidRequest
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func acmeRSAJWKPublicKey(jwk acmeJWK) (*rsa.PublicKey, error) {
	if !isValidACMERSAJWK(jwk) {
		return nil, domain.ErrInvalidRequest
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, domain.ErrInvalidRequest
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, domain.ErrInvalidRequest
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.Sign() <= 0 || !e.IsInt64() || e.Int64() <= 1 {
		return nil, domain.ErrInvalidRequest
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func acmeOKPJWKPublicKey(jwk acmeJWK) (ed25519.PublicKey, error) {
	if !isValidACMEOKPJWK(jwk) {
		return nil, domain.ErrInvalidRequest
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(xBytes) != ed25519.PublicKeySize {
		return nil, domain.ErrInvalidRequest
	}
	return ed25519.PublicKey(xBytes), nil
}

func canonicalACMEJWKJSON(jwk acmeJWK) (string, error) {
	switch jwk.KTY {
	case "EC":
		if _, err := acmeECJWKPublicKey(jwk); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.CRV, jwk.KTY, jwk.X, jwk.Y), nil
	case "RSA":
		if _, err := acmeRSAJWKPublicKey(jwk); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"e":"%s","kty":"%s","n":"%s"}`, jwk.E, jwk.KTY, jwk.N), nil
	case "OKP":
		if _, err := acmeOKPJWKPublicKey(jwk); err != nil {
			return "", err
		}
		return fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s"}`, jwk.CRV, jwk.KTY, jwk.X), nil
	default:
		return "", domain.ErrInvalidRequest
	}
}

func acmeJWKThumbprint(jwk acmeJWK) (string, error) {
	canonical, err := canonicalACMEJWKJSON(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

type createACMEAccountRequest struct {
	Contacts             []string `json:"contacts"`
	TermsOfServiceAgreed bool     `json:"terms_of_service_agreed"`
}

type createACMEOrderRequest struct {
	AccountID            string    `json:"account_id"`
	IdentityID           string    `json:"identity_id"`
	IssuerID             string    `json:"issuer_id"`
	CertificateProfileID string    `json:"profile_id"`
	RequestedDNSNames    []string  `json:"requested_dns_names"`
	RequestedIPAddresses []string  `json:"requested_ip_addresses"`
	RequestedNotAfter    time.Time `json:"requested_not_after"`
}

type finalizeACMEOrderRequest struct {
	CSRPEM           string `json:"csr_pem"`
	CSR              string `json:"csr"`
	RequestedSubject string `json:"requested_subject"`
}

type acmeRevokeCertificateRequest struct {
	CertificateID string                  `json:"certificate_id"`
	Reason        domain.RevocationReason `json:"reason"`
}

type acmeJWSRequest struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type acmeJWSResult struct {
	Payload       []byte
	AccountID     string
	KeyThumbprint string
	KeyJWKJSON    string
}

type acmeKeyChangeJWSResult struct {
	Account          string
	OldKey           acmeJWK
	NewKeyThumbprint string
	NewKeyJWKJSON    string
}

type acmeProtectedHeader struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	KID   string `json:"kid,omitempty"`
	JWK   any    `json:"jwk,omitempty"`
}

type acmeJWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type acmeNewAccountRequest struct {
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

type acmeUpdateAccountRequest struct {
	Contact *[]string `json:"contact,omitempty"`
	Status  string    `json:"status,omitempty"`
}

type acmeKeyChangeRequest struct {
	Account string  `json:"account"`
	OldKey  acmeJWK `json:"oldKey"`
}

type acmeNewOrderRequest struct {
	AccountID            string                  `json:"account_id"`
	IdentityID           string                  `json:"identity_id"`
	IssuerID             string                  `json:"issuer_id"`
	CertificateProfileID string                  `json:"profile_id"`
	Identifiers          []acmeIdentifierRequest `json:"identifiers"`
	NotAfter             time.Time               `json:"notAfter"`
}

type acmeIdentifierRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func toACMEAccountResponse(account domain.ACMEAccount) acmeAccountResponse {
	return acmeAccountResponse{
		ID:                   account.ID,
		Contacts:             account.Contacts,
		Status:               account.Status,
		TermsOfServiceAgreed: account.TermsOfServiceAgreed,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	}
}

func toACMEAccountResponses(accounts []domain.ACMEAccount) []acmeAccountResponse {
	responses := make([]acmeAccountResponse, 0, len(accounts))
	for _, account := range accounts {
		responses = append(responses, toACMEAccountResponse(account))
	}
	return responses
}

func toACMEOrderResponse(order domain.ACMEOrder) acmeOrderResponse {
	return acmeOrderResponse{
		ID:                   order.ID,
		AccountID:            order.AccountID,
		IdentityID:           order.IdentityID,
		IssuerID:             order.IssuerID,
		CertificateProfileID: order.CertificateProfileID,
		Status:               order.Status,
		CSRPEM:               order.CSRPEM,
		RequestedSubject:     order.RequestedSubject,
		RequestedDNSNames:    order.RequestedDNSNames,
		RequestedIPAddresses: order.RequestedIPAddresses,
		RequestedNotAfter:    order.RequestedNotAfter,
		EnrollmentID:         order.EnrollmentID,
		CertificateID:        order.CertificateID,
		ExpiresAt:            order.ExpiresAt,
		CreatedAt:            order.CreatedAt,
		UpdatedAt:            order.UpdatedAt,
	}
}

func toACMEAuthorizationResponse(authorization domain.ACMEAuthorization) acmeAuthorizationResponse {
	return acmeAuthorizationResponse{
		ID:                       authorization.ID,
		OrderID:                  authorization.OrderID,
		IdentifierType:           authorization.IdentifierType,
		IdentifierValue:          authorization.IdentifierValue,
		Status:                   authorization.Status,
		ExpiresAt:                authorization.ExpiresAt,
		ValidationReuseExpiresAt: authorization.ValidationReuseExpiresAt,
		CreatedAt:                authorization.CreatedAt,
		UpdatedAt:                authorization.UpdatedAt,
	}
}

func toACMEAuthorizationResponses(authorizations []domain.ACMEAuthorization) []acmeAuthorizationResponse {
	responses := make([]acmeAuthorizationResponse, 0, len(authorizations))
	for _, authorization := range authorizations {
		responses = append(responses, toACMEAuthorizationResponse(authorization))
	}
	return responses
}

func toACMEChallengeResponse(challenge domain.ACMEChallenge) acmeChallengeResponse {
	return acmeChallengeResponse{
		ID:              challenge.ID,
		AuthorizationID: challenge.AuthorizationID,
		Type:            challenge.Type,
		Token:           challenge.Token,
		Status:          challenge.Status,
		ValidatedAt:     challenge.ValidatedAt,
		CreatedAt:       challenge.CreatedAt,
		UpdatedAt:       challenge.UpdatedAt,
	}
}

func toACMEChallengeResponses(challenges []domain.ACMEChallenge) []acmeChallengeResponse {
	responses := make([]acmeChallengeResponse, 0, len(challenges))
	for _, challenge := range challenges {
		responses = append(responses, toACMEChallengeResponse(challenge))
	}
	return responses
}

func (s *Server) toACMEProtocolAccount(r *http.Request, account domain.ACMEAccount) acmeProtocolAccountResponse {
	return acmeProtocolAccountResponse{
		ID:       account.ID,
		Status:   string(account.Status),
		Contact:  account.Contacts,
		Location: requestBaseURL(r) + "/acme/account/" + account.ID,
	}
}

func (s *Server) toACMEProtocolOrder(r *http.Request, order domain.ACMEOrder) (acmeProtocolOrderResponse, error) {
	authorizations, err := s.service.ListACMEAuthorizations(r.Context(), order.ID)
	if err != nil {
		return acmeProtocolOrderResponse{}, err
	}
	baseURL := requestBaseURL(r)
	authzURLs := make([]string, 0, len(authorizations))
	for _, authorization := range authorizations {
		authzURLs = append(authzURLs, baseURL+"/acme/authz/"+authorization.ID)
	}
	response := acmeProtocolOrderResponse{
		ID:             order.ID,
		Status:         string(order.Status),
		URL:            baseURL + "/acme/order/" + order.ID,
		Identifiers:    acmeProtocolOrderIdentifiers(order),
		Authorizations: authzURLs,
		Finalize:       baseURL + "/acme/order/" + order.ID + "/finalize",
		Expires:        order.ExpiresAt,
	}
	if order.CertificateID != "" {
		response.Certificate = baseURL + "/acme/cert/" + order.CertificateID
	}
	return response, nil
}

func acmeProtocolOrderIdentifiers(order domain.ACMEOrder) []acmeProtocolIdentifierResponse {
	identifiers := make([]acmeProtocolIdentifierResponse, 0, len(order.RequestedDNSNames)+len(order.RequestedIPAddresses))
	for _, name := range order.RequestedDNSNames {
		identifiers = append(identifiers, acmeProtocolIdentifierResponse{
			Type:  "dns",
			Value: name,
		})
	}
	for _, address := range order.RequestedIPAddresses {
		identifiers = append(identifiers, acmeProtocolIdentifierResponse{
			Type:  "ip",
			Value: address,
		})
	}
	return identifiers
}

func (s *Server) toACMEProtocolAuthorization(r *http.Request, authorization domain.ACMEAuthorization) (acmeProtocolAuthorizationResponse, error) {
	challenges, err := s.service.ListACMEChallenges(r.Context(), authorization.ID)
	if err != nil {
		return acmeProtocolAuthorizationResponse{}, err
	}
	response := acmeProtocolAuthorizationResponse{
		ID:     authorization.ID,
		Status: string(authorization.Status),
		Identifier: acmeProtocolIdentifierResponse{
			Type:  authorization.IdentifierType,
			Value: authorization.IdentifierValue,
		},
		Challenges: make([]acmeProtocolChallengeResponse, 0, len(challenges)),
		Expires:    authorization.ExpiresAt,
	}
	for _, challenge := range challenges {
		response.Challenges = append(response.Challenges, s.toACMEProtocolChallenge(r, challenge))
	}
	return response, nil
}

func (s *Server) toACMEProtocolChallenge(r *http.Request, challenge domain.ACMEChallenge) acmeProtocolChallengeResponse {
	return acmeProtocolChallengeResponse{
		ID:     challenge.ID,
		Type:   string(challenge.Type),
		URL:    requestBaseURL(r) + "/acme/challenge/" + challenge.ID,
		Token:  challenge.Token,
		Status: string(challenge.Status),
	}
}

func acmeAuthorizationHasProcessingChallenge(authorization acmeProtocolAuthorizationResponse) bool {
	for _, challenge := range authorization.Challenges {
		if challenge.Status == string(domain.ACMEChallengeProcessing) {
			return true
		}
	}
	return false
}
