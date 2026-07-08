// SPDX-License-Identifier: MPL-2.0
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	target := flag.String("target", "http://127.0.0.1:8080", "HTTP target base URL")
	flag.Parse()

	targetURL, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("parse target: %v", err)
	}
	cert, err := selfSignedCertificate()
	if err != nil {
		log.Fatalf("create certificate: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	server := &http.Server{
		Addr:      *listen,
		Handler:   proxy,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	log.Printf("AnoPKI ACME HTTPS proxy listening on https://%s -> %s", *listen, targetURL.String())
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("serve HTTPS proxy: %v", err)
	}
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "AnoPKI local ACME smoke proxy",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
