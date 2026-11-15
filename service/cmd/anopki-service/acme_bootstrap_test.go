// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/lifecycle"
	"github.com/anothel/anopki/service/internal/store"
)

func TestACMEBootstrapProfileMatchesIssuerSigningKey(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	svc := lifecycle.New(repo, nil, lifecycle.RealClock{}, lifecycle.UUIDGenerator{})
	cfg, err := bootstrapACMEDefaults(ctx, svc, 24*time.Hour, filepath.Join(t.TempDir(), "issuer.key"))
	if err != nil {
		t.Fatalf("bootstrap ACME defaults: %v", err)
	}
	issuer, err := repo.GetIssuer(ctx, cfg.DefaultIssuerID)
	if err != nil {
		t.Fatalf("get issuer: %v", err)
	}
	block, _ := pem.Decode([]byte(issuer.CertificatePEM))
	if block == nil {
		t.Fatal("missing issuer certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issuer certificate: %v", err)
	}
	profile, err := repo.GetCertificateProfile(ctx, cfg.DefaultCertificateProfileID)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	// An unset algorithm selects the service's ECDSA default, which the
	// provider must reject for this RSA issuer even with an EC leaf CSR.
	if cert.PublicKeyAlgorithm != x509.RSA || len(profile.AllowedSignatureAlgorithms) != 1 || profile.AllowedSignatureAlgorithms[0] != "rsa_with_sha256" {
		t.Fatalf("bootstrap signing mismatch: issuer=%s profile algorithms=%v", cert.PublicKeyAlgorithm, profile.AllowedSignatureAlgorithms)
	}
}
