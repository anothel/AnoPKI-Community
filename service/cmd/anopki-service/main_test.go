// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/httpapi"
	"github.com/anothel/anopki/service/internal/observability"
	"github.com/anothel/anopki/service/internal/store"
)

func TestLoadOutboxConfigDefaults(t *testing.T) {
	t.Setenv("ANOPKI_OUTBOX_ENABLED", "")
	t.Setenv("ANOPKI_OUTBOX_INTERVAL", "")
	t.Setenv("ANOPKI_OUTBOX_BATCH_SIZE", "")

	cfg, err := loadOutboxConfig()
	if err != nil {
		t.Fatalf("loadOutboxConfig returned error: %v", err)
	}
	if !cfg.Enabled || cfg.Interval != 5*time.Second || cfg.BatchSize != 10 {
		t.Fatalf("config = %#v, want enabled 5s batch 10", cfg)
	}
}

func TestLoadPublicTLSConfig(t *testing.T) {
	t.Setenv("ANOPKI_PUBLIC_TLS_MAX_VALIDITY", "")
	cfg, err := loadPublicTLSConfig()
	if err != nil {
		t.Fatalf("loadPublicTLSConfig default returned error: %v", err)
	}
	if cfg.MaxValidity != 0 {
		t.Fatalf("default public TLS max validity = %s, want zero override", cfg.MaxValidity)
	}

	t.Setenv("ANOPKI_PUBLIC_TLS_MAX_VALIDITY", "720h")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN", "ca.example")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_ACCOUNT_URI", "https://ca.example/acct/1")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_VALIDATION_METHOD", "http-01")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_RESOLVER", "127.0.0.1:53")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_LOOKUP_TIMEOUT", "2s")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE", "true")
	cfg, err = loadPublicTLSConfig()
	if err != nil {
		t.Fatalf("loadPublicTLSConfig override returned error: %v", err)
	}
	if cfg.MaxValidity != 720*time.Hour {
		t.Fatalf("public TLS max validity = %s, want 720h", cfg.MaxValidity)
	}
	if cfg.CAAIssuerDomain != "ca.example" ||
		cfg.CAAAccountURI != "https://ca.example/acct/1" ||
		cfg.CAAValidationMethod != "http-01" ||
		cfg.CAAResolver != "127.0.0.1:53" ||
		cfg.CAALookupTimeout != 2*time.Second ||
		!cfg.AllowDNSSECIndeterminate {
		t.Fatalf("public TLS CAA config = %#v", cfg)
	}
}

func TestLoadPublicTLSConfigRejectsInvalidMaxValidity(t *testing.T) {
	for _, value := range []string{"0s", "-1h", "soon"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ANOPKI_PUBLIC_TLS_MAX_VALIDITY", value)
			_, err := loadPublicTLSConfig()
			if err == nil || !strings.Contains(err.Error(), "ANOPKI_PUBLIC_TLS_MAX_VALIDITY") {
				t.Fatalf("loadPublicTLSConfig error = %v, want env name", err)
			}
		})
	}
}

func TestLoadPublicTLSConfigRequiresCAAResolverWhenIssuerIsSet(t *testing.T) {
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN", "ca.example")
	t.Setenv("ANOPKI_PUBLIC_TLS_CAA_RESOLVER", "")

	_, err := loadPublicTLSConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_PUBLIC_TLS_CAA_RESOLVER") {
		t.Fatalf("loadPublicTLSConfig error = %v, want resolver env name", err)
	}
}

func TestNewHTTPServerAppliesOperationalTimeouts(t *testing.T) {
	srv := newHTTPServer(":8080", http.NewServeMux())

	if srv.Addr != ":8080" ||
		srv.ReadHeaderTimeout != 5*time.Second ||
		srv.ReadTimeout != 15*time.Second ||
		srv.WriteTimeout != 30*time.Second ||
		srv.IdleTimeout != 60*time.Second ||
		srv.MaxHeaderBytes != 1<<20 {
		t.Fatalf("server config = %#v", srv)
	}
}

func TestRunServerUntilShutdownStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	serveStarted := make(chan struct{})
	serveDone := make(chan struct{})
	shutdownCalled := make(chan struct{}, 1)

	serve := func() error {
		close(serveStarted)
		<-serveDone
		return http.ErrServerClosed
	}
	shutdown := func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("shutdown context has no deadline")
		}
		shutdownCalled <- struct{}{}
		close(serveDone)
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServerUntilShutdown(ctx, serve, shutdown, time.Second, nil)
	}()
	<-serveStarted
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServerUntilShutdown returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}
	select {
	case <-shutdownCalled:
	default:
		t.Fatal("shutdown was not called")
	}
}

func TestRunServerUntilShutdownReturnsServeError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantErr := errors.New("listen failed")

	err := runServerUntilShutdown(ctx, func() error {
		return wantErr
	}, func(context.Context) error {
		t.Fatal("shutdown should not run after serve failure")
		return nil
	}, time.Second, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("runServerUntilShutdown error = %v, want %v", err, wantErr)
	}
}

func TestHTTPServerShutdownWaitsForInFlightRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})

	server := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusNoContent)
	}))
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	responseDone := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			responseDone <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			responseDone <- fmt.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			return
		}
		responseDone <- nil
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for in-flight request")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- server.Shutdown(shutdownCtx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before in-flight request completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseRequest)
	select {
	case err := <-responseDone:
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for request")
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Serve")
	}
}

func TestLoadOutboxConfigCustomValues(t *testing.T) {
	t.Setenv("ANOPKI_OUTBOX_ENABLED", "false")
	t.Setenv("ANOPKI_OUTBOX_INTERVAL", "30s")
	t.Setenv("ANOPKI_OUTBOX_BATCH_SIZE", "25")

	cfg, err := loadOutboxConfig()
	if err != nil {
		t.Fatalf("loadOutboxConfig returned error: %v", err)
	}
	if cfg.Enabled || cfg.Interval != 30*time.Second || cfg.BatchSize != 25 {
		t.Fatalf("config = %#v, want disabled 30s batch 25", cfg)
	}
}

func TestLoadOutboxConfigRejectsInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		envName   string
		envValue  string
		wantError string
	}{
		{name: "enabled", envName: "ANOPKI_OUTBOX_ENABLED", envValue: "sometimes", wantError: "ANOPKI_OUTBOX_ENABLED"},
		{name: "interval", envName: "ANOPKI_OUTBOX_INTERVAL", envValue: "0s", wantError: "ANOPKI_OUTBOX_INTERVAL"},
		{name: "batch", envName: "ANOPKI_OUTBOX_BATCH_SIZE", envValue: "0", wantError: "ANOPKI_OUTBOX_BATCH_SIZE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ANOPKI_OUTBOX_ENABLED", "")
			t.Setenv("ANOPKI_OUTBOX_INTERVAL", "")
			t.Setenv("ANOPKI_OUTBOX_BATCH_SIZE", "")
			t.Setenv(tt.envName, tt.envValue)

			_, err := loadOutboxConfig()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("loadOutboxConfig error = %v, want mention %s", err, tt.wantError)
			}
		})
	}
}

func TestLoadAuthConfigDefaults(t *testing.T) {
	clearAuthEnv(t)

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if cfg.HTTP.Mode != httpapi.AuthModeDev || cfg.BootstrapAPIKey != "" {
		t.Fatalf("auth config = %#v, want dev mode without bootstrap key", cfg)
	}
}

func TestLoadAuthConfigAPIKeyMode(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_AUTH_MODE", "api_key")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY", "bootstrap-token")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY_NAME", "bootstrap-admin")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY_ACTOR", "ops-admin")
	t.Setenv("ANOPKI_API_KEY_PEPPER", "pepper-secret-0123456789abcdef-extra")

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if cfg.HTTP.Mode != httpapi.AuthModeAPIKey ||
		cfg.BootstrapAPIKey != "bootstrap-token" ||
		cfg.BootstrapAPIKeyName != "bootstrap-admin" ||
		cfg.BootstrapAPIKeyActor != "ops-admin" ||
		cfg.APIKeyPepper != "pepper-secret-0123456789abcdef-extra" {
		t.Fatalf("auth config = %#v", cfg)
	}
}

func TestLoadAuthConfigTrustedProxies(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_TRUSTED_PROXIES", "10.0.0.0/8, 127.0.0.1")

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if len(cfg.HTTP.TrustedProxies) != 2 ||
		cfg.HTTP.TrustedProxies[0].String() != "10.0.0.0/8" ||
		cfg.HTTP.TrustedProxies[1].String() != "127.0.0.1/32" {
		t.Fatalf("trusted proxies = %#v", cfg.HTTP.TrustedProxies)
	}
}

func TestLoadAuthConfigRejectsInvalidTrustedProxy(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_TRUSTED_PROXIES", "not-a-cidr")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_TRUSTED_PROXIES") {
		t.Fatalf("loadAuthConfig error = %v, want trusted proxy error", err)
	}
}

func TestLoadAuthConfigRejectsInvalidMode(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_AUTH_MODE", "mtls")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_AUTH_MODE") {
		t.Fatalf("loadAuthConfig error = %v, want ANOPKI_AUTH_MODE", err)
	}
}

func TestLoadAuthConfigRejectsDevAuthInProduction(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_ENV", "production")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_ENV") || !strings.Contains(err.Error(), "ANOPKI_AUTH_MODE") {
		t.Fatalf("loadAuthConfig error = %v, want production auth mode error", err)
	}
}

func TestLoadAuthConfigRejectsProductionAPIKeyWithoutPepper(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_AUTH_MODE", "api_key")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_API_KEY_PEPPER") {
		t.Fatalf("loadAuthConfig error = %v, want API key pepper error", err)
	}
}

func TestLoadAuthConfigRejectsWeakProductionAPIKeyPepper(t *testing.T) {
	for _, pepper := range []string{"short", strings.Repeat("p", 32), "change-me"} {
		t.Run(pepper, func(t *testing.T) {
			clearAuthEnv(t)
			t.Setenv("ANOPKI_ENV", "production")
			t.Setenv("ANOPKI_AUTH_MODE", "api_key")
			t.Setenv("ANOPKI_API_KEY_PEPPER", pepper)

			_, err := loadAuthConfig()
			if err == nil || !strings.Contains(err.Error(), "ANOPKI_API_KEY_PEPPER") {
				t.Fatalf("loadAuthConfig error = %v, want API key pepper error", err)
			}
		})
	}
}

func TestLoadAuthConfigRejectsWeakProductionBootstrapKey(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_AUTH_MODE", "api_key")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY", "change-me")
	t.Setenv("ANOPKI_API_KEY_PEPPER", "pepper-secret-0123456789abcdef-extra")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_BOOTSTRAP_API_KEY") {
		t.Fatalf("loadAuthConfig error = %v, want bootstrap key error", err)
	}
}

func TestLoadAuthConfigRejectsRepeatedProductionBootstrapKey(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_AUTH_MODE", "api_key")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY", strings.Repeat("a", 32))
	t.Setenv("ANOPKI_API_KEY_PEPPER", "pepper-secret-0123456789abcdef-extra")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_BOOTSTRAP_API_KEY") {
		t.Fatalf("loadAuthConfig error = %v, want bootstrap key error", err)
	}
}

func TestLoadAuthConfigAllowsStrongProductionBootstrapKey(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_AUTH_MODE", "api_key")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY", "prod-bootstrap-key-0123456789abcdef")
	t.Setenv("ANOPKI_API_KEY_PEPPER", "pepper-secret-0123456789abcdef-extra")

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if cfg.BootstrapAPIKey != "prod-bootstrap-key-0123456789abcdef" ||
		cfg.APIKeyPepper != "pepper-secret-0123456789abcdef-extra" {
		t.Fatalf("auth config = %#v", cfg)
	}
}

func TestOperationalHandlerExposesHealthReadyAndVersion(t *testing.T) {
	handler := newOperationalHandler(http.NotFoundHandler(), operationalConfig{
		Version:   "test-version",
		Ready:     func(context.Context) error { return nil },
		StartedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	})

	for _, path := range []string{"/healthz", "/readyz", "/version"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 body=%s", path, rec.Code, rec.Body.String())
		}
	}
	if body := httptestResponseBody(t, handler, "/version"); !strings.Contains(body, "test-version") {
		t.Fatalf("/version response = %s, want version", body)
	}
}

func TestOperationalHandlerReadinessFailureReturnsServiceUnavailable(t *testing.T) {
	handler := newOperationalHandler(http.NotFoundHandler(), operationalConfig{
		Version:   "test-version",
		Ready:     func(context.Context) error { return errors.New("db unavailable: secret-key-ref") },
		StartedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503 body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "db unavailable") || strings.Contains(rec.Body.String(), "secret-key-ref") {
		t.Fatalf("/readyz leaked readiness error detail: %s", rec.Body.String())
	}
}

func TestServiceReadinessCheckRejectsMissingCoreCLI(t *testing.T) {
	ctx := context.Background()
	db, repo := newMigratedTestStore(t)

	err := newServiceReadinessCheck(db, "sqlite", repo, filepath.Join(t.TempDir(), "missing-core"))(ctx)
	if err == nil || !strings.Contains(err.Error(), "core CLI") {
		t.Fatalf("readiness error = %v, want core CLI error", err)
	}
}

func TestServiceReadinessCheckRejectsMissingActiveKeyRef(t *testing.T) {
	ctx := context.Background()
	db, repo := newMigratedTestStore(t)
	coreBin := writeFakeCoreBinary(t)
	missingKeyRef := filepath.Join(t.TempDir(), "missing-issuer.key")

	if err := repo.CreateIssuer(ctx, domain.Issuer{
		ID:             "issuer-1",
		Name:           "issuer",
		Kind:           domain.IssuerRootCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         missingKeyRef,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	err := newServiceReadinessCheck(db, "sqlite", repo, coreBin)(ctx)
	if err == nil || !strings.Contains(err.Error(), "issuer key ref") {
		t.Fatalf("readiness error = %v, want issuer key ref error", err)
	}
}

func TestServiceReadinessCheckRejectsLocalFileKeyRefInProduction(t *testing.T) {
	t.Setenv("ANOPKI_ENV", "production")
	ctx := context.Background()
	db, repo := newMigratedTestStore(t)
	coreBin := writeFakeCoreBinary(t)
	keyRef := writeReadableKeyRef(t, "issuer.key")

	if err := repo.CreateIssuer(ctx, domain.Issuer{
		ID:             "issuer-1",
		Name:           "issuer",
		Kind:           domain.IssuerRootCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         keyRef,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	err := newServiceReadinessCheck(db, "sqlite", repo, coreBin)(ctx)
	if err == nil || !strings.Contains(err.Error(), "file key provider") {
		t.Fatalf("readiness error = %v, want production file provider error", err)
	}
}

func TestServiceReadinessCheckAcceptsActiveIssuerAndResponderKeyRefs(t *testing.T) {
	ctx := context.Background()
	db, repo := newMigratedTestStore(t)
	coreBin := writeFakeCoreBinary(t)
	now := time.Now()
	issuerKeyRef := writeReadableKeyRef(t, "issuer.key")
	responderKeyRef := writeReadableKeyRef(t, "responder.key")

	if err := repo.CreateIssuer(ctx, domain.Issuer{
		ID:             "issuer-1",
		Name:           "issuer",
		Kind:           domain.IssuerRootCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         issuerKeyRef,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if err := repo.CreateOCSPResponder(ctx, domain.OCSPResponder{
		ID:             "responder-1",
		IssuerID:       "issuer-1",
		Name:           "responder",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "responder-cert-pem",
		KeyRef:         responderKeyRef,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("CreateOCSPResponder returned error: %v", err)
	}

	if err := newServiceReadinessCheck(db, "sqlite", repo, coreBin)(ctx); err != nil {
		t.Fatalf("readiness returned error: %v", err)
	}
}

func TestDatabaseReadinessCheckRecordsMetrics(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := store.ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	before := observability.OperationMetricValue("db:readiness:success")
	if err := newDatabaseReadinessCheck(db, "sqlite")(ctx); err != nil {
		t.Fatalf("readiness returned error: %v", err)
	}
	if got := observability.OperationMetricValue("db:readiness:success") - before; got != 1 {
		t.Fatalf("db readiness metric increment = %d, want 1", got)
	}
}

func TestCoreCLIReadinessRecordsMetrics(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable returned error: %v", err)
	}
	before := observability.OperationMetricValue("core_cli:readiness:success")
	if err := checkCoreCLI(exe); err != nil {
		t.Fatalf("checkCoreCLI returned error: %v", err)
	}
	if got := observability.OperationMetricValue("core_cli:readiness:success") - before; got != 1 {
		t.Fatalf("core cli readiness metric increment = %d, want 1", got)
	}
}

func TestDatabaseReadinessCheckRejectsDirtyMigration(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if err := store.ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_migrations SET dirty = 1 WHERE version = 1"); err != nil {
		t.Fatalf("dirty schema_migrations row: %v", err)
	}

	err = newDatabaseReadinessCheck(db, "sqlite")(ctx)
	if err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("readiness error = %v, want dirty migration", err)
	}
}

func newMigratedTestStore(t *testing.T) (*sql.DB, store.Repository) {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyInitialMigration(context.Background(), db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	return db, store.NewSQLStore(db)
}

func writeFakeCoreBinary(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "anopki-core")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatalf("write fake core binary: %v", err)
	}
	return path
}

func writeReadableKeyRef(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("key"), 0600); err != nil {
		t.Fatalf("write key ref: %v", err)
	}
	return path
}

func httptestResponseBody(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Body.String()
}

func TestLoadExpirationScanConfigDefaults(t *testing.T) {
	clearExpirationScanEnv(t)

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if cfg.Enabled || cfg.Interval != time.Hour || cfg.WarningWindow != 30*24*time.Hour || cfg.BatchSize != 100 {
		t.Fatalf("config = %#v, want disabled 1h warning 720h batch 100", cfg)
	}
}

func TestLoadExpirationScanConfigCustomValues(t *testing.T) {
	clearExpirationScanEnv(t)
	t.Setenv("ANOPKI_EXPIRATION_SCAN_ENABLED", "true")
	t.Setenv("ANOPKI_EXPIRATION_SCAN_INTERVAL", "15m")
	t.Setenv("ANOPKI_EXPIRATION_WARNING_WINDOW", "168h")
	t.Setenv("ANOPKI_EXPIRATION_SCAN_BATCH_SIZE", "50")

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if !cfg.Enabled || cfg.Interval != 15*time.Minute || cfg.WarningWindow != 168*time.Hour || cfg.BatchSize != 50 {
		t.Fatalf("config = %#v, want enabled 15m warning 168h batch 50", cfg)
	}
}

func TestLoadExpirationScanConfigAllowsZeroWarningWindow(t *testing.T) {
	clearExpirationScanEnv(t)
	t.Setenv("ANOPKI_EXPIRATION_WARNING_WINDOW", "0s")

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if cfg.WarningWindow != 0 {
		t.Fatalf("warning window = %s, want 0", cfg.WarningWindow)
	}
}

func TestLoadExpirationScanConfigRejectsInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		envName   string
		envValue  string
		wantError string
	}{
		{name: "enabled", envName: "ANOPKI_EXPIRATION_SCAN_ENABLED", envValue: "sometimes", wantError: "ANOPKI_EXPIRATION_SCAN_ENABLED"},
		{name: "interval", envName: "ANOPKI_EXPIRATION_SCAN_INTERVAL", envValue: "0s", wantError: "ANOPKI_EXPIRATION_SCAN_INTERVAL"},
		{name: "warning window", envName: "ANOPKI_EXPIRATION_WARNING_WINDOW", envValue: "-1h", wantError: "ANOPKI_EXPIRATION_WARNING_WINDOW"},
		{name: "batch", envName: "ANOPKI_EXPIRATION_SCAN_BATCH_SIZE", envValue: "0", wantError: "ANOPKI_EXPIRATION_SCAN_BATCH_SIZE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearExpirationScanEnv(t)
			t.Setenv(tt.envName, tt.envValue)

			_, err := loadExpirationScanConfig()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("loadExpirationScanConfig error = %v, want mention %s", err, tt.wantError)
			}
		})
	}
}

func TestLoadACMEHTTP01VerifierConfigDefaults(t *testing.T) {
	t.Setenv("ANOPKI_ACME_HTTP01_BASE_URL", "")

	cfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		t.Fatalf("loadACMEHTTP01VerifierConfig returned error: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Fatalf("base URL = %q, want empty", cfg.BaseURL)
	}
}

func TestLoadACMEHTTP01VerifierConfigCustomBaseURL(t *testing.T) {
	t.Setenv("ANOPKI_ACME_HTTP01_BASE_URL", "http://127.0.0.1:5002")

	cfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		t.Fatalf("loadACMEHTTP01VerifierConfig returned error: %v", err)
	}
	if cfg.BaseURL != "http://127.0.0.1:5002" {
		t.Fatalf("base URL = %q", cfg.BaseURL)
	}
}

func TestLoadACMEHTTP01VerifierConfigRejectsInvalidBaseURL(t *testing.T) {
	t.Setenv("ANOPKI_ACME_HTTP01_BASE_URL", "://bad-url")

	_, err := loadACMEHTTP01VerifierConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_ACME_HTTP01_BASE_URL") {
		t.Fatalf("loadACMEHTTP01VerifierConfig error = %v, want ANOPKI_ACME_HTTP01_BASE_URL", err)
	}
}

func TestLoadACMEDefaultsConfigIncludesIssuerKeyRef(t *testing.T) {
	t.Setenv("ANOPKI_ACME_BOOTSTRAP_DEFAULTS", "true")
	t.Setenv("ANOPKI_ACME_DEFAULT_VALIDITY", "12h")
	t.Setenv("ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF", "issuer.key")

	cfg, err := loadACMEDefaultsConfig()
	if err != nil {
		t.Fatalf("loadACMEDefaultsConfig returned error: %v", err)
	}
	if !cfg.BootstrapDefaults || cfg.ValidityPeriod != 12*time.Hour || cfg.IssuerKeyRef != "issuer.key" {
		t.Fatalf("ACME defaults config = %#v", cfg)
	}
}

func TestLoadACMENonceConfigDefaultsToMemory(t *testing.T) {
	t.Setenv("ANOPKI_ENV", "")
	t.Setenv("ANOPKI_ACME_NONCE_STORE", "")

	cfg, err := loadACMENonceConfig()
	if err != nil {
		t.Fatalf("loadACMENonceConfig returned error: %v", err)
	}
	if cfg.Store != "memory" {
		t.Fatalf("nonce store = %q, want memory", cfg.Store)
	}
}

func TestLoadACMENonceConfigAllowsSQL(t *testing.T) {
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_ACME_NONCE_STORE", "sql")

	cfg, err := loadACMENonceConfig()
	if err != nil {
		t.Fatalf("loadACMENonceConfig returned error: %v", err)
	}
	if cfg.Store != "sql" {
		t.Fatalf("nonce store = %q, want sql", cfg.Store)
	}
}

func TestLoadACMENonceConfigRejectsInvalidStore(t *testing.T) {
	t.Setenv("ANOPKI_ENV", "")
	t.Setenv("ANOPKI_ACME_NONCE_STORE", "redis")

	_, err := loadACMENonceConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_ACME_NONCE_STORE") {
		t.Fatalf("loadACMENonceConfig error = %v, want nonce store error", err)
	}
}

func TestLoadACMENonceConfigRejectsMemoryInProduction(t *testing.T) {
	t.Setenv("ANOPKI_ENV", "production")
	t.Setenv("ANOPKI_ACME_NONCE_STORE", "")

	_, err := loadACMENonceConfig()
	if err == nil || !strings.Contains(err.Error(), "ANOPKI_ACME_NONCE_STORE") {
		t.Fatalf("loadACMENonceConfig error = %v, want production nonce store error", err)
	}
}

func TestEnsureACMESmokeIssuerMaterialWritesCAKey(t *testing.T) {
	keyRef := filepath.Join(t.TempDir(), "issuer.key")

	certPEM, gotKeyRef, err := ensureACMESmokeIssuerMaterial(keyRef)
	if err != nil {
		t.Fatalf("ensureACMESmokeIssuerMaterial returned error: %v", err)
	}
	if gotKeyRef != keyRef {
		t.Fatalf("key ref = %q, want %q", gotKeyRef, keyRef)
	}
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("certificate PEM block = %#v", certBlock)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("certificate is not CA-capable: %#v", cert)
	}
	keyPEM, err := os.ReadFile(keyRef)
	if err != nil {
		t.Fatalf("ReadFile key returned error: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM block = %#v", keyBlock)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("ParsePKCS8PrivateKey returned error: %v", err)
	}
}

func TestStructuredLogRedactsSecrets(t *testing.T) {
	var lines []string
	logStructured(func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}, "bootstrap.ready", map[string]any{
		"api_key_pepper": "pepper-secret",
		"token":          "api-token",
		"name":           "bootstrap",
	})
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(lines))
	}
	if strings.Contains(lines[0], "pepper-secret") || strings.Contains(lines[0], "api-token") {
		t.Fatalf("structured log leaked secret values: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"api_key_pepper":"[redacted]"`) ||
		!strings.Contains(lines[0], `"token":"[redacted]"`) ||
		!strings.Contains(lines[0], `"name":"bootstrap"`) {
		t.Fatalf("structured log = %s", lines[0])
	}
}

func clearExpirationScanEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ANOPKI_EXPIRATION_SCAN_ENABLED", "")
	t.Setenv("ANOPKI_EXPIRATION_SCAN_INTERVAL", "")
	t.Setenv("ANOPKI_EXPIRATION_WARNING_WINDOW", "")
	t.Setenv("ANOPKI_EXPIRATION_SCAN_BATCH_SIZE", "")
}

func clearAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ANOPKI_ENV", "")
	t.Setenv("ANOPKI_AUTH_MODE", "")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY", "")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY_NAME", "")
	t.Setenv("ANOPKI_BOOTSTRAP_API_KEY_ACTOR", "")
	t.Setenv("ANOPKI_API_KEY_PEPPER", "")
}
