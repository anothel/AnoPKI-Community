// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/anothel/anopki/service/internal/domain"
)

// This error is used only by RFC revocation, preserving legacy error contracts.
type acmeRevocationError struct {
	cause  error
	kind   string
	status int
}

func (e *acmeRevocationError) Error() string { return e.cause.Error() }
func (e *acmeRevocationError) Unwrap() error { return e.cause }
func rfcRevocationError(cause error, kind string, status int) error {
	return &acmeRevocationError{cause, "urn:ietf:params:acme:error:" + kind, status}
}

func hasRFCCertificate(payload []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return false
	}
	for key := range fields {
		if strings.EqualFold(key, "certificate") {
			return true
		}
	}
	return false
}

// Reject duplicate/unknown fields and mixed formats before selecting authority.
func decodeRFCRevocation(payload []byte) (*x509.Certificate, domain.RevocationReason, error) {
	invalid := domain.ErrInvalidRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, "", invalid
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, "", invalid
		}
		key, ok := token.(string)
		if !ok {
			return nil, "", invalid
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, "", invalid
		}
		if key != "certificate" && key != "reason" {
			return nil, "", invalid
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, "", invalid
		}
		fields[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, "", invalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, "", invalid
	}
	var encoded string
	if json.Unmarshal(fields["certificate"], &encoded) != nil || encoded == "" {
		return nil, "", invalid
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != encoded {
		return nil, "", invalid
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(certificate.Raw, der) {
		return nil, "", invalid
	}
	reason := domain.RevocationNotProvided
	if raw, present := fields["reason"]; present {
		numeric, integer := new(big.Int).SetString(string(bytes.TrimSpace(raw)), 10)
		if !integer {
			return nil, "", invalid
		}
		if !numeric.IsInt64() {
			return nil, "", rfcRevocationError(invalid, "badRevocationReason", 400)
		}
		reasons := map[int64]domain.RevocationReason{0: domain.RevocationUnspecified, 1: domain.RevocationKeyCompromise, 2: domain.RevocationCACompromise, 3: domain.RevocationAffiliationChanged, 4: domain.RevocationSuperseded, 5: domain.RevocationCessationOfOperation, 9: domain.RevocationPrivilegeWithdrawn}
		var ok bool
		reason, ok = reasons[numeric.Int64()]
		if !ok {
			return nil, "", rfcRevocationError(invalid, "badRevocationReason", 400)
		}
	}
	return certificate, reason, nil
}

func (s *Server) acmeRevokeRFCCertificate(w http.ResponseWriter, r *http.Request, jws acmeJWSResult) {
	if err := s.checkACMERateLimitClass(r, "revocation"); err != nil {
		s.writeError(w, r, err)
		return
	}
	certificate, reason, err := decodeRFCRevocation(jws.Payload)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// Resolve the issuer before the indexed issuer/serial lookup. Never load the
	// certificate inventory for a request authenticated only by an untrusted JWK.
	issuers, err := s.service.ListIssuers(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var target *domain.Certificate
	for _, issuer := range issuers {
		issuerBlock, _ := pem.Decode([]byte(issuer.CertificatePEM))
		if issuerBlock == nil {
			continue
		}
		parsedIssuer, parseErr := x509.ParseCertificate(issuerBlock.Bytes)
		if parseErr != nil || !bytes.Equal(parsedIssuer.RawSubject, certificate.RawIssuer) {
			continue
		}
		candidate, lookupErr := s.service.GetCertificateByIssuerSerial(r.Context(), issuer.ID, certificate.SerialNumber.String())
		if errors.Is(lookupErr, domain.ErrCertificateNotFound) {
			continue
		}
		if lookupErr != nil {
			s.writeError(w, r, lookupErr)
			return
		}
		block, rest := pem.Decode([]byte(candidate.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			continue
		}
		if bytes.Equal(block.Bytes, certificate.Raw) {
			if target != nil {
				s.writeError(w, r, domain.ErrInvalidRequest)
				return
			}
			target = &candidate
		}
	}
	if target == nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	if jws.AccountID != "" {
		// Other accounts' identifier authorizations are deliberately not consulted (#31).
		account, accountErr := s.service.GetACMEAccount(r.Context(), jws.AccountID)
		if accountErr != nil {
			s.writeError(w, r, accountErr)
			return
		}
		if account.Status != domain.ACMEAccountValid {
			s.writeError(w, r, domain.ErrACMEAccountDeactivated)
			return
		}
		err = s.requireACMECertificateAccount(r.Context(), target.ID, jws.AccountID)
	} else {
		var jwk acmeJWK
		if json.Unmarshal([]byte(jws.KeyJWKJSON), &jwk) != nil {
			err = domain.ErrForbidden
		} else {
			var key any
			switch jwk.KTY {
			case "EC":
				key, err = acmeECJWKPublicKey(jwk)
			case "RSA":
				key, err = acmeRSAJWKPublicKey(jwk)
			case "OKP":
				key, err = acmeOKPJWKPublicKey(jwk)
			default:
				err = domain.ErrForbidden
			}
			if err == nil {
				var spki []byte
				spki, err = x509.MarshalPKIXPublicKey(key)
				if err == nil && !bytes.Equal(spki, certificate.RawSubjectPublicKeyInfo) {
					err = domain.ErrForbidden
				}
			}
		}
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if target.Status == domain.CertificateRevoked {
		s.writeError(w, r, rfcRevocationError(domain.ErrInvalidTransition, "alreadyRevoked", 400))
		return
	}
	if reason == domain.RevocationNotProvided {
		_, err = s.service.RevokeCertificateWithoutReason(r.Context(), requestActor(r), target.ID)
	} else {
		_, err = s.service.RevokeCertificate(r.Context(), requestActor(r), target.ID, reason)
	}
	if err != nil {
		// A competing transaction may have revoked after the read above.
		if errors.Is(err, domain.ErrInvalidTransition) {
			current, getErr := s.service.GetCertificate(r.Context(), target.ID)
			if getErr == nil && current.Status == domain.CertificateRevoked {
				err = rfcRevocationError(err, "alreadyRevoked", 400)
			}
		}
		s.writeError(w, r, err)
		return
	}
	nonce, err := s.issueACMENonce(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", acmeDirectoryLink(r))
	w.WriteHeader(http.StatusOK)
}
