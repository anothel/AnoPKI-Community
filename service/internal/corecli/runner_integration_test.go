// SPDX-License-Identifier: MPL-2.0
package corecli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreCLIIntegrationSuccessPaths(t *testing.T) {
	runner := coreCLIIntegrationRunner(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	issuerCertPEM, issuerKeyPEM := testCA(t)
	issuerKeyPath := filepath.Join(t.TempDir(), "issuer.key")
	if err := os.WriteFile(issuerKeyPath, []byte(issuerKeyPEM), 0600); err != nil {
		t.Fatalf("write issuer key: %v", err)
	}
	csrPEM := testCSR(t)

	info, err := runner.InspectCSR(ctx, csrPEM)
	if err != nil {
		t.Fatalf("InspectCSR returned error: %v", err)
	}
	if info.Subject != "/CN=leaf.example.test" {
		t.Fatalf("CSR subject = %q", info.Subject)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "leaf.example.test" {
		t.Fatalf("CSR DNSNames = %#v", info.DNSNames)
	}

	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	issued, err := runner.Issue(ctx, IssueRequest{
		CSRPEM:               csrPEM,
		IssuerCertificatePEM: issuerCertPEM,
		IssuerKeyRef:         issuerKeyPath,
		Subject:              "CN=leaf.example.test",
		DNSNames:             []string{"leaf.example.test"},
		NotBefore:            now,
		NotAfter:             now.Add(24 * time.Hour),
		SignatureAlgorithm:   "sha256",
		KeyUsage:             []string{"digital_signature"},
		ExtendedKeyUsage:     []string{"server_auth"},
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !strings.Contains(issued.CertificatePEM, "BEGIN CERTIFICATE") || issued.SerialNumber == "" {
		t.Fatalf("Issue result = %#v", issued)
	}

	crl, err := runner.GenerateCRL(ctx, GenerateCRLRequest{
		IssuerCertificatePEM: issuerCertPEM,
		IssuerKeyRef:         issuerKeyPath,
		CRLNumber:            9,
		ThisUpdate:           now,
		NextUpdate:           now.Add(24 * time.Hour),
		RevokedCertificates: []RevokedCertificate{{
			SerialNumber: issued.SerialNumber,
			RevokedAt:    now.Add(time.Hour),
			Reason:       "key_compromise",
		}},
	})
	if err != nil {
		t.Fatalf("GenerateCRL returned error: %v", err)
	}
	if !strings.Contains(crl.CRLPEM, "BEGIN X509 CRL") {
		t.Fatalf("CRLPEM = %q", crl.CRLPEM)
	}
}

func TestCoreCLIIntegrationCommandErrors(t *testing.T) {
	runner := coreCLIIntegrationRunner(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name string
		run  func() error
		code string
	}{
		{
			name: "csr inspect",
			run: func() error {
				_, err := runner.InspectCSR(ctx, "not a csr")
				return err
			},
			code: "csr.parse_failed",
		},
		{
			name: "ocsp inspect",
			run: func() error {
				_, err := runner.InspectOCSP(ctx, []byte("not an ocsp request"))
				return err
			},
			code: "ocsp.parse_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("command returned nil error")
			}
			var commandErr *CommandError
			if !errors.As(err, &commandErr) {
				t.Fatalf("error type = %T, want *CommandError", err)
			}
			if commandErr.Code != tt.code {
				t.Fatalf("command error code = %q, want %q", commandErr.Code, tt.code)
			}
			if commandErr.Message == "" {
				t.Fatal("command error message is empty")
			}
		})
	}
}

func coreCLIIntegrationRunner(t *testing.T) Runner {
	t.Helper()
	bin := strings.TrimSpace(os.Getenv("ANOPKI_CORE_BIN"))
	if bin == "" {
		t.Skip("set ANOPKI_CORE_BIN to run core CLI boundary integration tests")
	}
	return Runner{Bin: bin}
}

func testCA(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func testCSR(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "leaf.example.test"},
		DNSNames: []string{"leaf.example.test"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
