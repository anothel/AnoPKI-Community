// SPDX-License-Identifier: MPL-2.0
package corecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type IssueRequest struct {
	CSRPEM                     string    `json:"csr_pem"`
	IssuerCertificatePEM       string    `json:"issuer_certificate_pem"`
	IssuerKeyRef               string    `json:"issuer_key_ref"`
	AIAURL                     string    `json:"aia_url,omitempty"`
	CRLDistributionPoints      []string  `json:"crl_distribution_points,omitempty"`
	Subject                    string    `json:"subject"`
	DNSNames                   []string  `json:"dns_names"`
	IPAddresses                []string  `json:"ip_addresses"`
	NotBefore                  time.Time `json:"not_before"`
	NotAfter                   time.Time `json:"not_after"`
	SignatureAlgorithm         string    `json:"signature_algorithm"`
	ProfileID                  string    `json:"profile_id,omitempty"`
	BasicConstraintsCritical   bool      `json:"basic_constraints_critical,omitempty"`
	BasicConstraintsCA         bool      `json:"basic_constraints_ca,omitempty"`
	BasicConstraintsMaxPathLen *int      `json:"basic_constraints_max_path_len,omitempty"`
	KeyUsageCritical           bool      `json:"key_usage_critical,omitempty"`
	KeyUsage                   []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsageCritical   bool      `json:"extended_key_usage_critical,omitempty"`
	ExtendedKeyUsage           []string  `json:"extended_key_usage,omitempty"`
	SubjectKeyIdentifier       bool      `json:"subject_key_identifier,omitempty"`
	AuthorityKeyIdentifier     bool      `json:"authority_key_identifier,omitempty"`
}

type SigningEvidence struct {
	SchemaVersion               int    `json:"schema_version"`
	EvidenceSource              string `json:"evidence_source"`
	Operation                   string `json:"operation"`
	ProviderID                  string `json:"provider_id"`
	ProviderClass               string `json:"provider_class"`
	ProviderReadiness           string `json:"provider_readiness"`
	ProviderExportability       string `json:"provider_exportability"`
	ReferenceClass              string `json:"reference_class"`
	KeyAlgorithm                string `json:"key_algorithm"`
	RequestedSignatureAlgorithm string `json:"requested_signature_algorithm"`
	IssuerBindingVerified       bool   `json:"issuer_binding_verified"`
	FallbackUsed                bool   `json:"fallback_used"`
	ResultCode                  string `json:"result_code"`
}

type IssueResult struct {
	CertificatePEM  string          `json:"certificate_pem"`
	SerialNumber    string          `json:"serial_number"`
	Subject         string          `json:"subject"`
	NotBefore       time.Time       `json:"not_before"`
	NotAfter        time.Time       `json:"not_after"`
	SigningEvidence SigningEvidence `json:"-"`
}

type CSRInfo struct {
	Subject            string   `json:"subject"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	PublicKeySizeBits  int      `json:"public_key_size_bits"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	ExtensionOIDs      []string `json:"extension_oids"`
}

type RevokedCertificate struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

type GenerateCRLRequest struct {
	IssuerCertificatePEM string
	IssuerKeyRef         string
	CRLNumber            int64
	ThisUpdate           time.Time
	NextUpdate           time.Time
	RevokedCertificates  []RevokedCertificate
}

type GenerateCRLResult struct {
	CRLPEM          string          `json:"crl_pem"`
	SigningEvidence SigningEvidence `json:"-"`
}

type OCSPCertificateID struct {
	SerialNumber   string `json:"serial_number"`
	IssuerNameHash string `json:"issuer_name_hash"`
	IssuerKeyHash  string `json:"issuer_key_hash"`
	HashAlgorithm  string `json:"hash_algorithm"`
}

type OCSPRequestInfo struct {
	Certificates []OCSPCertificateID `json:"certificates"`
	HasNonce     bool                `json:"has_nonce"`
	NonceHex     string              `json:"nonce_hex"`
}

type OCSPIssuerInfo struct {
	IssuerNameHash string `json:"issuer_name_hash"`
	IssuerKeyHash  string `json:"issuer_key_hash"`
	HashAlgorithm  string `json:"hash_algorithm"`
}

type ValidateOCSPResponderResult struct {
	Valid bool `json:"valid"`
}

type OCSPCertificateStatus struct {
	SerialNumber     string
	Status           string
	RevokedAt        time.Time
	RevocationReason string
	HashAlgorithm    string
	IssuerNameHash   string
	IssuerKeyHash    string
}

type GenerateOCSPResponseRequest struct {
	RequestDER           []byte
	IssuerCertificatePEM string
	IssuerKeyRef         string
	ThisUpdate           time.Time
	NextUpdate           time.Time
	Certificates         []OCSPCertificateStatus
}

type GenerateOCSPResponseResult struct {
	ResponseDER     []byte
	SigningEvidence SigningEvidence `json:"-"`
}

type Runner struct {
	Bin string
}

type CommandError struct {
	Code          string
	Message       string
	OpenSSLErrors []string
	Err           error
}

func (e *CommandError) Error() string {
	const prefix = "anopki-core command failed"
	detail := e.Code
	if e.Message != "" {
		if detail != "" {
			detail += ": "
		}
		detail += e.Message
	}
	if detail == "" {
		if e.Err == nil {
			return prefix
		}
		return fmt.Sprintf("%s: %v", prefix, e.Err)
	}
	if len(e.OpenSSLErrors) != 0 {
		detail += ": " + strings.Join(e.OpenSSLErrors, "; ")
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", prefix, detail)
	}
	return fmt.Sprintf("%s: %s: %v", prefix, detail, e.Err)
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

func closeWithError(err error, file *os.File) error {
	return errors.Join(err, file.Close())
}

func coreCommand(ctx context.Context, bin string, args ...string) *exec.Cmd {
	if bin == "" {
		bin = "anopki-core"
	}
	return exec.CommandContext(ctx, bin, args...) // #nosec G204 -- no shell; core CLI path is explicit config.
}

func openCoreResult(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- path comes from os.CreateTemp in the caller.
}

func readCoreResult(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- path comes from os.CreateTemp in the caller.
}

const signingEvidenceEnvironment = "ANOPKI_CORE_SIGNING_EVIDENCE_FILE"

func createSigningEvidenceFile() (string, error) {
	file, err := os.CreateTemp("", "anopki-core-signing-evidence-*.json")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", errors.Join(err, os.Remove(path))
	}
	return path, nil
}

func withSigningEvidenceEnvironment(cmd *exec.Cmd, path string) {
	prefix := signingEvidenceEnvironment + "="
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, signingEvidenceEnvironment) {
			continue
		}
		environment = append(environment, entry)
	}
	cmd.Env = append(environment, prefix+path)
}

func readSigningEvidence(path string, expectedOperation string, expectedAlgorithm string) (SigningEvidence, error) {
	file, err := openCoreResult(path)
	if err != nil {
		return SigningEvidence{}, fmt.Errorf("open signing evidence: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var evidence SigningEvidence
	if err := decoder.Decode(&evidence); err != nil {
		return SigningEvidence{}, fmt.Errorf("decode signing evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return SigningEvidence{}, fmt.Errorf("decode signing evidence: trailing JSON value")
		}
		return SigningEvidence{}, fmt.Errorf("decode signing evidence: %w", err)
	}
	if err := ValidateSigningEvidence(evidence, expectedOperation, expectedAlgorithm); err != nil {
		return SigningEvidence{}, err
	}
	return evidence, nil
}

// ValidateSigningEvidence verifies that evidence came from the completed core
// signing operation rather than from provider readiness or key-ref classification.
func ValidateSigningEvidence(evidence SigningEvidence, expectedOperation string, expectedAlgorithm string) error {
	if evidence.SchemaVersion != 1 ||
		evidence.EvidenceSource != "core_signing" ||
		evidence.Operation != expectedOperation ||
		strings.TrimSpace(evidence.ProviderID) == "" ||
		strings.TrimSpace(evidence.ProviderClass) == "" ||
		evidence.ProviderReadiness != "ready" ||
		(evidence.ProviderExportability != "exportable" && evidence.ProviderExportability != "non_exportable") ||
		strings.TrimSpace(evidence.ReferenceClass) == "" ||
		strings.TrimSpace(evidence.KeyAlgorithm) == "" ||
		evidence.RequestedSignatureAlgorithm != expectedAlgorithm ||
		!evidence.IssuerBindingVerified ||
		evidence.FallbackUsed ||
		evidence.ResultCode != "ok" {
		return fmt.Errorf("validate signing evidence: inconsistent core signing result")
	}
	return nil
}

func (r Runner) InspectCSR(ctx context.Context, csrPEM string) (CSRInfo, error) {
	csrFile, err := os.CreateTemp("", "anopki-core-csr-*.pem")
	if err != nil {
		return CSRInfo{}, fmt.Errorf("create csr temp file: %w", err)
	}
	csrPath := csrFile.Name()
	defer os.Remove(csrPath)

	if _, err := csrFile.WriteString(csrPEM); err != nil {
		return CSRInfo{}, fmt.Errorf("write csr temp file: %w", closeWithError(err, csrFile))
	}
	if err := csrFile.Close(); err != nil {
		return CSRInfo{}, fmt.Errorf("close csr temp file: %w", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "csr", "inspect", "--in", csrPath, "--out", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return CSRInfo{}, commandError(err, stderr.String())
	}

	var info CSRInfo
	if err := json.NewDecoder(&stdout).Decode(&info); err != nil {
		return CSRInfo{}, fmt.Errorf("decode csr info: %w", err)
	}
	return info, nil
}

func (r Runner) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	requestFile, err := os.CreateTemp("", "anopki-core-issue-request-*.json")
	if err != nil {
		return IssueResult{}, fmt.Errorf("create issue request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	if err := json.NewEncoder(requestFile).Encode(req); err != nil {
		return IssueResult{}, fmt.Errorf("write issue request: %w", closeWithError(err, requestFile))
	}
	if err := requestFile.Close(); err != nil {
		return IssueResult{}, fmt.Errorf("close issue request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "anopki-core-issue-result-*.json")
	if err != nil {
		return IssueResult{}, fmt.Errorf("create issue result temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)

	if err := resultFile.Close(); err != nil {
		return IssueResult{}, fmt.Errorf("close issue result temp file: %w", err)
	}

	evidencePath, err := createSigningEvidenceFile()
	if err != nil {
		return IssueResult{}, fmt.Errorf("create issue signing evidence temp file: %w", err)
	}
	defer os.Remove(evidencePath)

	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "cert", "issue", "--request", requestPath, "--out", resultPath)
	withSigningEvidenceEnvironment(cmd, evidencePath)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return IssueResult{}, commandError(err, stderr.String())
	}

	resultFile, err = openCoreResult(resultPath)
	if err != nil {
		return IssueResult{}, fmt.Errorf("open issue result: %w", err)
	}
	defer resultFile.Close()

	var result IssueResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return IssueResult{}, fmt.Errorf("decode issue result: %w", err)
	}
	evidence, err := readSigningEvidence(evidencePath, "certificate_issue", req.SignatureAlgorithm)
	if err != nil {
		return IssueResult{}, err
	}
	result.SigningEvidence = evidence
	return result, nil
}

func (r Runner) GenerateCRL(ctx context.Context, req GenerateCRLRequest) (GenerateCRLResult, error) {
	requestFile, err := os.CreateTemp("", "anopki-core-crl-request-*.json")
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("create crl request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	fileReq := crlFileRequest{
		IssuerCertificatePEM: req.IssuerCertificatePEM,
		IssuerKeyRef:         req.IssuerKeyRef,
		CRLNumber:            req.CRLNumber,
		ThisUpdate:           coreTime(req.ThisUpdate),
		NextUpdate:           coreTime(req.NextUpdate),
		RevokedSerialNumbers: make([]string, 0, len(req.RevokedCertificates)),
		RevokedAtTimes:       make([]string, 0, len(req.RevokedCertificates)),
		RevocationReasons:    make([]string, 0, len(req.RevokedCertificates)),
	}
	for _, revoked := range req.RevokedCertificates {
		fileReq.RevokedSerialNumbers = append(fileReq.RevokedSerialNumbers, revoked.SerialNumber)
		fileReq.RevokedAtTimes = append(fileReq.RevokedAtTimes, coreTime(revoked.RevokedAt))
		fileReq.RevocationReasons = append(fileReq.RevocationReasons, revoked.Reason)
	}
	if err := json.NewEncoder(requestFile).Encode(fileReq); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("write crl request: %w", closeWithError(err, requestFile))
	}
	if err := requestFile.Close(); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("close crl request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "anopki-core-crl-result-*.json")
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("create crl result temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)

	if err := resultFile.Close(); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("close crl result temp file: %w", err)
	}

	evidencePath, err := createSigningEvidenceFile()
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("create crl signing evidence temp file: %w", err)
	}
	defer os.Remove(evidencePath)

	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "crl", "generate", "--request", requestPath, "--out", resultPath)
	withSigningEvidenceEnvironment(cmd, evidencePath)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return GenerateCRLResult{}, commandError(err, stderr.String())
	}

	resultFile, err = openCoreResult(resultPath)
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("open crl result: %w", err)
	}
	defer resultFile.Close()

	var result GenerateCRLResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("decode crl result: %w", err)
	}
	evidence, err := readSigningEvidence(evidencePath, "crl_generate_sign", "sha256")
	if err != nil {
		return GenerateCRLResult{}, err
	}
	result.SigningEvidence = evidence
	return result, nil
}

func (r Runner) InspectOCSP(ctx context.Context, requestDER []byte) (OCSPRequestInfo, error) {
	requestFile, err := os.CreateTemp("", "anopki-core-ocsp-request-*.der")
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("create ocsp request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	if _, err := requestFile.Write(requestDER); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("write ocsp request: %w", closeWithError(err, requestFile))
	}
	if err := requestFile.Close(); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("close ocsp request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "anopki-core-ocsp-info-*.json")
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("create ocsp info temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("close ocsp info temp file: %w", err)
	}

	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "ocsp", "inspect", "--in", requestPath, "--out", resultPath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return OCSPRequestInfo{}, commandError(err, stderr.String())
	}

	resultFile, err = openCoreResult(resultPath)
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("open ocsp info: %w", err)
	}
	defer resultFile.Close()

	var result OCSPRequestInfo
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("decode ocsp info: %w", err)
	}
	return result, nil
}

func (r Runner) InspectOCSPIssuer(ctx context.Context, issuerCertificatePEM string, hashAlgorithm string) (OCSPIssuerInfo, error) {
	issuerFile, err := os.CreateTemp("", "anopki-core-ocsp-issuer-*.pem")
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("create ocsp issuer temp file: %w", err)
	}
	issuerPath := issuerFile.Name()
	defer os.Remove(issuerPath)

	if _, err := issuerFile.WriteString(issuerCertificatePEM); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("write ocsp issuer: %w", closeWithError(err, issuerFile))
	}
	if err := issuerFile.Close(); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("close ocsp issuer: %w", err)
	}

	resultFile, err := os.CreateTemp("", "anopki-core-ocsp-issuer-info-*.json")
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("create ocsp issuer info temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("close ocsp issuer info temp file: %w", err)
	}

	var stderr bytes.Buffer
	if hashAlgorithm == "" {
		hashAlgorithm = "sha1"
	}
	cmd := coreCommand(ctx, r.Bin, "ocsp", "inspect-issuer", "--issuer", issuerPath, "--out", resultPath, "--hash", hashAlgorithm)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return OCSPIssuerInfo{}, commandError(err, stderr.String())
	}

	resultFile, err = openCoreResult(resultPath)
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("open ocsp issuer info: %w", err)
	}
	defer resultFile.Close()

	var result OCSPIssuerInfo
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("decode ocsp issuer info: %w", err)
	}
	return result, nil
}

func (r Runner) ValidateOCSPResponder(ctx context.Context, issuerCertificatePEM string, responderCertificatePEM string) (ValidateOCSPResponderResult, error) {
	issuerFile, err := os.CreateTemp("", "anopki-core-ocsp-issuer-*.pem")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp issuer temp file: %w", err)
	}
	issuerPath := issuerFile.Name()
	defer os.Remove(issuerPath)
	if _, err := issuerFile.WriteString(issuerCertificatePEM); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("write ocsp issuer: %w", closeWithError(err, issuerFile))
	}
	if err := issuerFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp issuer: %w", err)
	}

	responderFile, err := os.CreateTemp("", "anopki-core-ocsp-responder-*.pem")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp responder temp file: %w", err)
	}
	responderPath := responderFile.Name()
	defer os.Remove(responderPath)
	if _, err := responderFile.WriteString(responderCertificatePEM); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("write ocsp responder: %w", closeWithError(err, responderFile))
	}
	if err := responderFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp responder: %w", err)
	}

	resultFile, err := os.CreateTemp("", "anopki-core-ocsp-responder-validation-*.json")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp responder validation temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp responder validation temp file: %w", err)
	}

	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "ocsp", "validate-responder", "--issuer", issuerPath, "--responder", responderPath, "--out", resultPath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return ValidateOCSPResponderResult{}, commandError(err, stderr.String())
	}

	resultFile, err = openCoreResult(resultPath)
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("open ocsp responder validation: %w", err)
	}
	defer resultFile.Close()

	var result ValidateOCSPResponderResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("decode ocsp responder validation: %w", err)
	}
	return result, nil
}

func (r Runner) GenerateOCSPResponse(ctx context.Context, req GenerateOCSPResponseRequest) (GenerateOCSPResponseResult, error) {
	requestDERFile, err := os.CreateTemp("", "anopki-core-ocsp-request-*.der")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp request temp file: %w", err)
	}
	requestDERPath := requestDERFile.Name()
	defer os.Remove(requestDERPath)
	if _, err := requestDERFile.Write(req.RequestDER); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("write ocsp request der: %w", closeWithError(err, requestDERFile))
	}
	if err := requestDERFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp request der: %w", err)
	}

	requestFile, err := os.CreateTemp("", "anopki-core-ocsp-response-request-*.json")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp response request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	fileReq := ocspResponseFileRequest{
		IssuerCertificatePEM: req.IssuerCertificatePEM,
		IssuerKeyRef:         req.IssuerKeyRef,
		ThisUpdate:           coreTime(req.ThisUpdate),
		NextUpdate:           coreTime(req.NextUpdate),
		SerialNumbers:        make([]string, 0, len(req.Certificates)),
		HashAlgorithms:       make([]string, 0, len(req.Certificates)),
		IssuerNameHashes:     make([]string, 0, len(req.Certificates)),
		IssuerKeyHashes:      make([]string, 0, len(req.Certificates)),
		Statuses:             make([]string, 0, len(req.Certificates)),
		RevokedAtTimes:       make([]string, 0, len(req.Certificates)),
		RevocationReasons:    make([]string, 0, len(req.Certificates)),
	}
	for _, certificate := range req.Certificates {
		fileReq.SerialNumbers = append(fileReq.SerialNumbers, certificate.SerialNumber)
		fileReq.HashAlgorithms = append(fileReq.HashAlgorithms, certificate.HashAlgorithm)
		fileReq.IssuerNameHashes = append(fileReq.IssuerNameHashes, certificate.IssuerNameHash)
		fileReq.IssuerKeyHashes = append(fileReq.IssuerKeyHashes, certificate.IssuerKeyHash)
		fileReq.Statuses = append(fileReq.Statuses, certificate.Status)
		fileReq.RevokedAtTimes = append(fileReq.RevokedAtTimes, coreTime(certificate.RevokedAt))
		fileReq.RevocationReasons = append(fileReq.RevocationReasons, certificate.RevocationReason)
	}
	if err := json.NewEncoder(requestFile).Encode(fileReq); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("write ocsp response request: %w", closeWithError(err, requestFile))
	}
	if err := requestFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp response request: %w", err)
	}

	responseFile, err := os.CreateTemp("", "anopki-core-ocsp-response-*.der")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp response temp file: %w", err)
	}
	responsePath := responseFile.Name()
	defer os.Remove(responsePath)
	if err := responseFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp response temp file: %w", err)
	}

	evidencePath, err := createSigningEvidenceFile()
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp signing evidence temp file: %w", err)
	}
	defer os.Remove(evidencePath)

	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "ocsp", "respond", "--in", requestDERPath, "--request", requestPath, "--out", responsePath)
	withSigningEvidenceEnvironment(cmd, evidencePath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return GenerateOCSPResponseResult{}, commandError(err, stderr.String())
	}

	responseDER, err := readCoreResult(responsePath)
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("read ocsp response: %w", err)
	}
	evidence, err := readSigningEvidence(evidencePath, "ocsp_response_sign", "sha256")
	if err != nil {
		return GenerateOCSPResponseResult{}, err
	}
	return GenerateOCSPResponseResult{ResponseDER: responseDER, SigningEvidence: evidence}, nil
}

type crlFileRequest struct {
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
	IssuerKeyRef         string   `json:"issuer_key_ref"`
	CRLNumber            int64    `json:"crl_number"`
	ThisUpdate           string   `json:"this_update"`
	NextUpdate           string   `json:"next_update"`
	RevokedSerialNumbers []string `json:"revoked_serial_numbers"`
	RevokedAtTimes       []string `json:"revoked_at_times"`
	RevocationReasons    []string `json:"revocation_reasons"`
}

type ocspResponseFileRequest struct {
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
	IssuerKeyRef         string   `json:"issuer_key_ref"`
	ThisUpdate           string   `json:"this_update"`
	NextUpdate           string   `json:"next_update"`
	SerialNumbers        []string `json:"serial_numbers"`
	HashAlgorithms       []string `json:"hash_algorithms"`
	IssuerNameHashes     []string `json:"issuer_name_hashes"`
	IssuerKeyHashes      []string `json:"issuer_key_hashes"`
	Statuses             []string `json:"statuses"`
	RevokedAtTimes       []string `json:"revoked_at_times"`
	RevocationReasons    []string `json:"revocation_reasons"`
}

func coreTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

type commandErrorPayload struct {
	Code          string   `json:"code"`
	Message       string   `json:"message"`
	OpenSSLErrors []string `json:"openssl_errors"`
}

func commandError(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return &CommandError{Err: err}
	}

	var payload commandErrorPayload
	if json.Unmarshal([]byte(stderr), &payload) == nil && (payload.Code != "" || payload.Message != "") {
		return &CommandError{Code: payload.Code, Message: payload.Message, OpenSSLErrors: payload.OpenSSLErrors, Err: err}
	}

	return &CommandError{Message: stderr, Err: err}
}
