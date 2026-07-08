// SPDX-License-Identifier: MPL-2.0
package corecli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunnerMapsIssueResultJSON(t *testing.T) {
	bin := writeFakeIssueCommand(t, true)

	result, err := (Runner{Bin: bin}).Issue(context.Background(), IssueRequest{
		CSRPEM:               "csr-pem",
		IssuerCertificatePEM: "issuer-pem",
		IssuerKeyRef:         "issuer-key-ref",
		Subject:              "CN=leaf",
		DNSNames:             []string{"leaf.example.test"},
		IPAddresses:          []string{"127.0.0.1"},
		NotBefore:            time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:             time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC),
		SignatureAlgorithm:   "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if result.CertificatePEM != "cert-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", result.CertificatePEM, "cert-pem")
	}
	if result.SerialNumber != "12345" {
		t.Fatalf("SerialNumber = %q, want %q", result.SerialNumber, "12345")
	}
	if result.Subject != "CN=leaf" {
		t.Fatalf("Subject = %q, want %q", result.Subject, "CN=leaf")
	}
	if !result.NotBefore.Equal(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("NotBefore = %s", result.NotBefore.Format(time.RFC3339))
	}
	if !result.NotAfter.Equal(time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)) {
		t.Fatalf("NotAfter = %s", result.NotAfter.Format(time.RFC3339))
	}
}

func TestRunnerIssueWritesIssuerDistributionMetadata(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "issue-request.json")
	bin := writeFakeIssueCommandWithCapture(t, capturePath)

	_, err := (Runner{Bin: bin}).Issue(context.Background(), IssueRequest{
		CSRPEM:                "csr-pem",
		IssuerCertificatePEM:  "issuer-pem",
		IssuerKeyRef:          "issuer-key-ref",
		AIAURL:                "https://pki.example.test/issuers/intermediate.pem",
		CRLDistributionPoints: []string{"https://pki.example.test/crl/intermediate.crl"},
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	payload, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	body := string(payload)
	for _, want := range []string{
		`"aia_url":"https://pki.example.test/issuers/intermediate.pem"`,
		`"crl_distribution_points":["https://pki.example.test/crl/intermediate.crl"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured request = %s, want it to contain %s", body, want)
		}
	}
}

func TestRunnerMapsCommandFailure(t *testing.T) {
	bin := writeFakeIssueCommand(t, false)

	_, err := (Runner{Bin: bin}).Issue(context.Background(), IssueRequest{
		CSRPEM: "csr-pem",
	})
	if err == nil {
		t.Fatal("Issue returned nil error")
	}

	for _, want := range []string{"CORE_ISSUE_FAILED", "bad csr"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

func TestRunnerMapsCSRInfoJSON(t *testing.T) {
	bin := writeFakeInspectCommand(t, true)

	info, err := (Runner{Bin: bin}).InspectCSR(context.Background(), "csr-pem")
	if err != nil {
		t.Fatalf("InspectCSR returned error: %v", err)
	}

	if info.Subject != "CN=leaf" {
		t.Fatalf("Subject = %q, want CN=leaf", info.Subject)
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != "leaf.example.test" || info.DNSNames[1] != "alt.example.test" {
		t.Fatalf("DNSNames = %#v", info.DNSNames)
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "127.0.0.1" {
		t.Fatalf("IPAddresses = %#v", info.IPAddresses)
	}
	if info.PublicKeyAlgorithm != "rsa" || info.PublicKeySizeBits != 2048 || info.SignatureAlgorithm != "sha256" {
		t.Fatalf("CSR key metadata = algorithm:%q size:%d signature:%q", info.PublicKeyAlgorithm, info.PublicKeySizeBits, info.SignatureAlgorithm)
	}
	if len(info.ExtensionOIDs) != 2 || info.ExtensionOIDs[0] != "2.5.29.17" || info.ExtensionOIDs[1] != "2.5.29.15" {
		t.Fatalf("ExtensionOIDs = %#v", info.ExtensionOIDs)
	}
}

func TestRunnerMapsCSRInspectFailure(t *testing.T) {
	bin := writeFakeInspectCommand(t, false)

	_, err := (Runner{Bin: bin}).InspectCSR(context.Background(), "bad-csr")
	if err == nil {
		t.Fatal("InspectCSR returned nil error")
	}

	for _, want := range []string{"csr.pem_read_failed", "bad csr"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

func TestRunnerRejectsMalformedCSRInfoJSON(t *testing.T) {
	bin := writeFakeMalformedInspectCommand(t)

	_, err := (Runner{Bin: bin}).InspectCSR(context.Background(), "csr-pem")
	if err == nil {
		t.Fatal("InspectCSR returned nil error")
	}
	if !strings.Contains(err.Error(), "decode csr info") {
		t.Fatalf("error = %q, want decode csr info", err.Error())
	}
}

func TestRunnerPreservesContextDeadline(t *testing.T) {
	bin := writeFakeInspectCommand(t, true)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err := (Runner{Bin: bin}).InspectCSR(ctx, "csr-pem")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("InspectCSR error = %v, want context deadline exceeded", err)
	}
}

func TestRunnerGenerateCRLNormalizesTimes(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "crl-request.json")
	bin := writeFakeCRLCommand(t, true, capturePath)

	result, err := (Runner{Bin: bin}).GenerateCRL(context.Background(), GenerateCRLRequest{
		IssuerCertificatePEM: "issuer-pem",
		IssuerKeyRef:         "issuer-key-ref",
		CRLNumber:            7,
		ThisUpdate:           time.Date(2026, time.January, 2, 3, 4, 5, 123456789, time.FixedZone("KST", 9*60*60)),
		NextUpdate:           time.Date(2026, time.January, 3, 4, 5, 6, 987654321, time.UTC),
		RevokedCertificates: []RevokedCertificate{{
			SerialNumber: "12345",
			RevokedAt:    time.Date(2026, time.January, 2, 4, 4, 5, 999999999, time.FixedZone("KST", 9*60*60)),
			Reason:       "key_compromise",
		}},
	})
	if err != nil {
		t.Fatalf("GenerateCRL returned error: %v", err)
	}
	if result.CRLPEM != "crl-pem" {
		t.Fatalf("CRLPEM = %q, want crl-pem", result.CRLPEM)
	}

	payload, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	body := string(payload)
	for _, want := range []string{
		`"this_update":"2026-01-01T18:04:05Z"`,
		`"next_update":"2026-01-03T04:05:06Z"`,
		`"revoked_at_times":["2026-01-01T19:04:05Z"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured request = %s, want it to contain %s", body, want)
		}
	}
	if strings.Contains(body, ".123") || strings.Contains(body, ".987") || strings.Contains(body, ".999") {
		t.Fatalf("captured request contains fractional seconds: %s", body)
	}
}

func TestRunnerMapsOCSPIssuerInfoJSON(t *testing.T) {
	bin := writeFakeOCSPIssuerInspectCommand(t, true)

	info, err := (Runner{Bin: bin}).InspectOCSPIssuer(context.Background(), "issuer-pem", "sha256")
	if err != nil {
		t.Fatalf("InspectOCSPIssuer returned error: %v", err)
	}

	if info.IssuerNameHash != "name-hash" {
		t.Fatalf("IssuerNameHash = %q, want name-hash", info.IssuerNameHash)
	}
	if info.IssuerKeyHash != "key-hash" {
		t.Fatalf("IssuerKeyHash = %q, want key-hash", info.IssuerKeyHash)
	}
	if info.HashAlgorithm != "sha256" {
		t.Fatalf("HashAlgorithm = %q, want sha256", info.HashAlgorithm)
	}
}

func TestRunnerValidateOCSPResponderMapsJSONAndWritesFiles(t *testing.T) {
	issuerCapturePath := filepath.Join(t.TempDir(), "issuer.pem")
	responderCapturePath := filepath.Join(t.TempDir(), "responder.pem")
	argsCapturePath := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeOCSPValidateResponderCommand(t, true, issuerCapturePath, responderCapturePath, argsCapturePath)

	result, err := (Runner{Bin: bin}).ValidateOCSPResponder(context.Background(), "issuer-pem", "responder-pem")
	if err != nil {
		t.Fatalf("ValidateOCSPResponder returned error: %v", err)
	}
	if !result.Valid {
		t.Fatal("Valid = false, want true")
	}

	if got, err := os.ReadFile(issuerCapturePath); err != nil {
		t.Fatalf("read captured issuer: %v", err)
	} else if string(got) != "issuer-pem" {
		t.Fatalf("issuer capture = %q, want issuer-pem", string(got))
	}
	if got, err := os.ReadFile(responderCapturePath); err != nil {
		t.Fatalf("read captured responder: %v", err)
	} else if string(got) != "responder-pem" {
		t.Fatalf("responder capture = %q, want responder-pem", string(got))
	}

	args, err := os.ReadFile(argsCapturePath)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	tokens := strings.Split(strings.TrimSpace(string(args)), ";")
	if len(tokens) != 9 {
		t.Fatalf("captured args = %q, want 9 tokens", string(args))
	}
	for index, want := range map[int]string{
		1: "ocsp",
		2: "validate-responder",
		3: "--issuer",
		5: "--responder",
		7: "--out",
	} {
		if tokens[index] != want {
			t.Fatalf("captured args token %d = %q, want %q", index, tokens[index], want)
		}
	}
	for _, index := range []int{4, 6, 8} {
		if tokens[index] == "" {
			t.Fatalf("captured args token %d is empty", index)
		}
	}
}

func TestRunnerValidateOCSPResponderMapsCommandFailure(t *testing.T) {
	bin := writeFakeOCSPValidateResponderCommand(t, false, "", "", "")

	_, err := (Runner{Bin: bin}).ValidateOCSPResponder(context.Background(), "issuer-pem", "responder-pem")
	if err == nil {
		t.Fatal("ValidateOCSPResponder returned nil error")
	}

	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error type = %T, want *CommandError", err)
	}
	if commandErr.Code != "ocsp.responder_invalid" {
		t.Fatalf("command error code = %q, want ocsp.responder_invalid", commandErr.Code)
	}
	if commandErr.Message != "bad responder" {
		t.Fatalf("command error message = %q, want bad responder", commandErr.Message)
	}
}

func TestRunnerInspectOCSPPreservesDERAndMapsJSON(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "ocsp-request.der")
	bin := writeFakeOCSPInspectCommand(t, true, capturePath)
	requestDER := []byte{0x30, 0x03, 0x00, 0xff}

	info, err := (Runner{Bin: bin}).InspectOCSP(context.Background(), requestDER)
	if err != nil {
		t.Fatalf("InspectOCSP returned error: %v", err)
	}

	if len(info.Certificates) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(info.Certificates))
	}
	certificate := info.Certificates[0]
	if certificate.SerialNumber != "1001" {
		t.Fatalf("SerialNumber = %q, want 1001", certificate.SerialNumber)
	}
	if certificate.IssuerNameHash != "name-hash" {
		t.Fatalf("IssuerNameHash = %q, want name-hash", certificate.IssuerNameHash)
	}
	if certificate.IssuerKeyHash != "key-hash" {
		t.Fatalf("IssuerKeyHash = %q, want key-hash", certificate.IssuerKeyHash)
	}
	if certificate.HashAlgorithm != "sha256" {
		t.Fatalf("HashAlgorithm = %q, want sha256", certificate.HashAlgorithm)
	}
	if !info.HasNonce {
		t.Fatal("HasNonce = false, want true")
	}
	if info.NonceHex != "01020304a5" {
		t.Fatalf("NonceHex = %q, want 01020304a5", info.NonceHex)
	}

	capturedDER, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured DER: %v", err)
	}
	if !bytes.Equal(capturedDER, requestDER) {
		t.Fatalf("captured DER = %#v, want %#v", capturedDER, requestDER)
	}
}

func TestRunnerGenerateOCSPResponseWritesHashAwareStatusRequest(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "ocsp-response-request.json")
	bin := writeFakeOCSPResponseCommand(t, true, capturePath)

	result, err := (Runner{Bin: bin}).GenerateOCSPResponse(context.Background(), GenerateOCSPResponseRequest{
		RequestDER:           []byte("ocsp-request-der"),
		IssuerCertificatePEM: "issuer-pem",
		IssuerKeyRef:         "issuer-key-ref",
		ThisUpdate:           time.Date(2026, time.January, 2, 3, 4, 5, 123456789, time.FixedZone("KST", 9*60*60)),
		NextUpdate:           time.Date(2026, time.January, 3, 4, 5, 6, 987654321, time.UTC),
		Certificates: []OCSPCertificateStatus{{
			SerialNumber:     "1001",
			HashAlgorithm:    "sha256",
			IssuerNameHash:   "name-hash",
			IssuerKeyHash:    "key-hash",
			Status:           "revoked",
			RevokedAt:        time.Date(2026, time.January, 2, 4, 4, 5, 999999999, time.FixedZone("KST", 9*60*60)),
			RevocationReason: "key_compromise",
		}},
	})
	if err != nil {
		t.Fatalf("GenerateOCSPResponse returned error: %v", err)
	}
	if string(result.ResponseDER) != "ocsp-response-der" {
		t.Fatalf("ResponseDER = %q, want ocsp-response-der", string(result.ResponseDER))
	}

	payload, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	body := string(payload)
	for _, want := range []string{
		`"this_update":"2026-01-01T18:04:05Z"`,
		`"next_update":"2026-01-03T04:05:06Z"`,
		`"serial_numbers":["1001"]`,
		`"hash_algorithms":["sha256"]`,
		`"issuer_name_hashes":["name-hash"]`,
		`"issuer_key_hashes":["key-hash"]`,
		`"revoked_at_times":["2026-01-01T19:04:05Z"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured request = %s, want it to contain %s", body, want)
		}
	}
}

func TestCommandErrorPreservesPayloadCode(t *testing.T) {
	err := commandError(errors.New("exit status 1"), `{"code":"issue.csr_parse_failed","message":"bad csr"}`)

	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error type = %T, want *CommandError", err)
	}
	if commandErr.Code != "issue.csr_parse_failed" {
		t.Fatalf("command error code = %q, want issue.csr_parse_failed", commandErr.Code)
	}
	if commandErr.Message != "bad csr" {
		t.Fatalf("command error message = %q, want bad csr", commandErr.Message)
	}
}

func TestCommandErrorPreservesOpenSSLErrors(t *testing.T) {
	err := commandError(errors.New("exit status 1"), `{"code":"csr.parse_failed","message":"csr.parse_failed","openssl_errors":["error:0480006C:PEM routines::no start line"]}`)

	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error type = %T, want *CommandError", err)
	}
	if len(commandErr.OpenSSLErrors) != 1 || commandErr.OpenSSLErrors[0] != "error:0480006C:PEM routines::no start line" {
		t.Fatalf("OpenSSLErrors = %#v", commandErr.OpenSSLErrors)
	}
	if !strings.Contains(commandErr.Error(), "error:0480006C") {
		t.Fatalf("error string = %q, want OpenSSL detail", commandErr.Error())
	}
}

func writeFakeInspectCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsInspectScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixInspectScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeMalformedInspectCommand(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsMalformedInspectScript()), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixMalformedInspectScript()), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeIssueCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsIssueScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixIssueScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeIssueCommandWithCapture(t *testing.T, capturePath string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsIssueCaptureScript(capturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixIssueCaptureScript(capturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeCRLCommand(t *testing.T, success bool, capturePath string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsCRLScript(success, capturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixCRLScript(success, capturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeOCSPIssuerInspectCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsOCSPIssuerInspectScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixOCSPIssuerInspectScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeOCSPValidateResponderCommand(
	t *testing.T,
	success bool,
	issuerCapturePath,
	responderCapturePath,
	argsCapturePath string,
) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsOCSPValidateResponderScript(success, issuerCapturePath, responderCapturePath, argsCapturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixOCSPValidateResponderScript(success, issuerCapturePath, responderCapturePath, argsCapturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeOCSPInspectCommand(t *testing.T, success bool, capturePath string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsOCSPInspectScript(success, capturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixOCSPInspectScript(success, capturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeOCSPResponseCommand(t *testing.T, success bool, capturePath string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		if err := os.WriteFile(path, []byte(windowsOCSPResponseScript(success, capturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "anopki-core")
	if err := os.WriteFile(path, []byte(unixOCSPResponseScript(success, capturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func windowsIssueScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"CORE_ISSUE_FAILED^\",^\"message^\":^\"bad csr^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%OUT%\"==\"\" exit /b 2",
		"> \"%OUT%\" echo {^\"certificate_pem^\":^\"cert-pem^\",^\"serial_number^\":^\"12345^\",^\"subject^\":^\"CN=leaf^\",^\"not_before^\":^\"2026-01-02T03:04:05Z^\",^\"not_after^\":^\"2026-01-03T04:05:06Z^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsIssueCaptureScript(capturePath string) string {
	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"REQ=\"",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--request\" (",
		"  set \"REQ=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%REQ%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%REQ%\" \"" + capturePath + "\" >NUL",
		"> \"%OUT%\" echo {^\"certificate_pem^\":^\"cert-pem^\",^\"serial_number^\":^\"12345^\",^\"subject^\":^\"CN=leaf^\",^\"not_before^\":^\"2026-01-02T03:04:05Z^\",^\"not_after^\":^\"2026-01-03T04:05:06Z^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsCRLScript(success bool, capturePath string) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"crl.create_failed^\",^\"message^\":^\"bad crl request^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"REQ=\"",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--request\" (",
		"  set \"REQ=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%REQ%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%REQ%\" \"" + capturePath + "\" >NUL",
		"> \"%OUT%\" echo {^\"crl_pem^\":^\"crl-pem^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsOCSPIssuerInspectScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"ocsp.issuer_parse_failed^\",^\"message^\":^\"bad issuer^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"if not \"%~1\"==\"ocsp\" exit /b 3",
		"if not \"%~2\"==\"inspect-issuer\" exit /b 3",
		"if not \"%~7\"==\"--hash\" exit /b 3",
		"if not \"%~8\"==\"sha256\" exit /b 3",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%OUT%\"==\"\" exit /b 2",
		"> \"%OUT%\" echo {^\"issuer_name_hash^\":^\"name-hash^\",^\"issuer_key_hash^\":^\"key-hash^\",^\"hash_algorithm^\":^\"sha256^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsOCSPInspectScript(success bool, capturePath string) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"ocsp.parse_failed^\",^\"message^\":^\"bad request^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"if not \"%~1\"==\"ocsp\" exit /b 3",
		"if not \"%~2\"==\"inspect\" exit /b 3",
		"set \"IN=\"",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--in\" (",
		"  set \"IN=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%IN%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%IN%\" \"" + capturePath + "\" >NUL",
		"> \"%OUT%\" echo {^\"certificates^\": [{^\"serial_number^\":^\"1001^\",^\"issuer_name_hash^\":^\"name-hash^\",^\"issuer_key_hash^\":^\"key-hash^\",^\"hash_algorithm^\":^\"sha256^\"}],^\"has_nonce^\":true,^\"nonce_hex^\":^\"01020304a5^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsOCSPResponseScript(success bool, capturePath string) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"ocsp.create_failed^\",^\"message^\":^\"bad response^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"REQ=\"",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--request\" (",
		"  set \"REQ=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%REQ%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%REQ%\" \"" + capturePath + "\" >NUL",
		"<nul set /p \"=ocsp-response-der\" > \"%OUT%\"",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsOCSPValidateResponderScript(success bool, issuerCapturePath, responderCapturePath, argsCapturePath string) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"ocsp.responder_invalid^\",^\"message^\":^\"bad responder^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"ISSUER=\"",
		"set \"RESPONDER=\"",
		"set \"OUT=\"",
		"set \"ARGS=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"set \"ARGS=%ARGS%;%~1\"",
		"if \"%~1\"==\"--issuer\" (",
		"  set \"ARGS=%ARGS%;%~2\"",
		"  set \"ISSUER=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--responder\" (",
		"  set \"ARGS=%ARGS%;%~2\"",
		"  set \"RESPONDER=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"ARGS=%ARGS%;%~2\"",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%ISSUER%\"==\"\" exit /b 2",
		"if \"%RESPONDER%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%ISSUER%\" \"" + issuerCapturePath + "\" >NUL",
		"copy /Y \"%RESPONDER%\" \"" + responderCapturePath + "\" >NUL",
		"> \"" + argsCapturePath + "\" echo %ARGS%",
		"> \"%OUT%\" echo {^\"valid^\":true}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsInspectScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"csr.pem_read_failed^\",^\"message^\":^\"bad csr^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"echo {^\"subject^\":^\"CN=leaf^\",^\"dns_names^\": [^\"leaf.example.test^\", ^\"alt.example.test^\"],^\"ip_addresses^\": [^\"127.0.0.1^\"],^\"public_key_algorithm^\":^\"rsa^\",^\"public_key_size_bits^\":2048,^\"signature_algorithm^\":^\"sha256^\",^\"extension_oids^\": [^\"2.5.29.17^\", ^\"2.5.29.15^\"]}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsMalformedInspectScript() string {
	return strings.Join([]string{
		"@echo off",
		"echo not-json",
		"exit /b 0",
		"",
	}, "\r\n")
}

func unixIssueScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"CORE_ISSUE_FAILED","message":"bad csr"}' >&2
exit 7
`
	}

	return `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$out" ]; then
	exit 2
fi
cat > "$out" <<'JSON'
{"certificate_pem":"cert-pem","serial_number":"12345","subject":"CN=leaf","not_before":"2026-01-02T03:04:05Z","not_after":"2026-01-03T04:05:06Z"}
JSON
exit 0
`
}

func unixIssueCaptureScript(capturePath string) string {
	escapedCapturePath := strings.ReplaceAll(capturePath, "'", "'\"'\"'")
	return `#!/bin/sh
req=""
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--request" ]; then
		req="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$req" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$req" '` + escapedCapturePath + `'
cat > "$out" <<'JSON'
{"certificate_pem":"cert-pem","serial_number":"12345","subject":"CN=leaf","not_before":"2026-01-02T03:04:05Z","not_after":"2026-01-03T04:05:06Z"}
JSON
exit 0
`
}

func unixCRLScript(success bool, capturePath string) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"crl.create_failed","message":"bad crl request"}' >&2
exit 7
`
	}

	escapedCapturePath := strings.ReplaceAll(capturePath, "'", "'\"'\"'")
	return `#!/bin/sh
req=""
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--request" ]; then
		req="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$req" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$req" '` + escapedCapturePath + `'
cat > "$out" <<'JSON'
{"crl_pem":"crl-pem"}
JSON
exit 0
`
}

func unixOCSPIssuerInspectScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"ocsp.issuer_parse_failed","message":"bad issuer"}' >&2
exit 7
`
	}

	return `#!/bin/sh
if [ "$1" != "ocsp" ] || [ "$2" != "inspect-issuer" ] || [ "$7" != "--hash" ] || [ "$8" != "sha256" ]; then
	exit 3
fi
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$out" ]; then
	exit 2
fi
cat > "$out" <<'JSON'
{"issuer_name_hash":"name-hash","issuer_key_hash":"key-hash","hash_algorithm":"sha256"}
JSON
exit 0
`
}

func unixOCSPInspectScript(success bool, capturePath string) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"ocsp.parse_failed","message":"bad request"}' >&2
exit 7
`
	}

	escapedCapturePath := strings.ReplaceAll(capturePath, "'", "'\"'\"'")
	return `#!/bin/sh
if [ "$1" != "ocsp" ] || [ "$2" != "inspect" ]; then
	exit 3
fi
input=""
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--in" ]; then
		input="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$input" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$input" '` + escapedCapturePath + `'
cat > "$out" <<'JSON'
{"certificates":[{"serial_number":"1001","issuer_name_hash":"name-hash","issuer_key_hash":"key-hash","hash_algorithm":"sha256"}],"has_nonce":true,"nonce_hex":"01020304a5"}
JSON
exit 0
`
}

func unixOCSPResponseScript(success bool, capturePath string) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"ocsp.create_failed","message":"bad response"}' >&2
exit 7
`
	}

	escapedCapturePath := strings.ReplaceAll(capturePath, "'", "'\"'\"'")
	return `#!/bin/sh
request=""
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--request" ]; then
		request="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$request" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$request" '` + escapedCapturePath + `'
printf '%s' 'ocsp-response-der' > "$out"
exit 0
`
}

func unixOCSPValidateResponderScript(success bool, issuerCapturePath, responderCapturePath, argsCapturePath string) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"ocsp.responder_invalid","message":"bad responder"}' >&2
exit 7
`
	}

	escapedIssuerCapturePath := strings.ReplaceAll(issuerCapturePath, "'", "'\"'\"'")
	escapedResponderCapturePath := strings.ReplaceAll(responderCapturePath, "'", "'\"'\"'")
	escapedArgsCapturePath := strings.ReplaceAll(argsCapturePath, "'", "'\"'\"'")
	return `#!/bin/sh
issuer=""
responder=""
out=""
	args=""
while [ "$#" -gt 0 ]; do
	args="$args;$1"
	if [ "$1" = "--issuer" ]; then
		args="$args;$2"
		issuer="$2"
		shift 2
	elif [ "$1" = "--responder" ]; then
		args="$args;$2"
		responder="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		args="$args;$2"
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$issuer" ] || [ -z "$responder" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$issuer" '` + escapedIssuerCapturePath + `'
cp "$responder" '` + escapedResponderCapturePath + `'
printf '%s' "$args" > '` + escapedArgsCapturePath + `'
cat > "$out" <<'JSON'
{"valid":true}
JSON
exit 0
`
}

func unixInspectScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"csr.pem_read_failed","message":"bad csr"}' >&2
exit 7
`
	}

	return `#!/bin/sh
printf '%s\n' '{"subject":"CN=leaf","dns_names":["leaf.example.test","alt.example.test"],"ip_addresses":["127.0.0.1"],"public_key_algorithm":"rsa","public_key_size_bits":2048,"signature_algorithm":"sha256","extension_oids":["2.5.29.17","2.5.29.15"]}'
exit 0
`
}

func unixMalformedInspectScript() string {
	return `#!/bin/sh
printf '%s\n' 'not-json'
exit 0
`
}
