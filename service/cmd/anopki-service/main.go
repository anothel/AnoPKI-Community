// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/anothel/anopki/service/internal/corecli"
	"github.com/anothel/anopki/service/internal/domain"
	"github.com/anothel/anopki/service/internal/httpapi"
	"github.com/anothel/anopki/service/internal/lifecycle"
	"github.com/anothel/anopki/service/internal/observability"
	"github.com/anothel/anopki/service/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	defaultAddr     = ":8080"
	defaultDBDriver = "sqlite"
	defaultDBDSN    = "anopki.db"
	defaultCoreBin  = "anopki-core"

	defaultOutboxEnabled   = true
	defaultOutboxInterval  = 5 * time.Second
	defaultOutboxBatchSize = 10

	defaultExpirationScanEnabled       = false
	defaultExpirationScanInterval      = time.Hour
	defaultExpirationScanWarningWindow = 30 * 24 * time.Hour
	defaultExpirationScanBatchSize     = 100

	defaultBootstrapAPIKeyName  = "bootstrap"
	defaultBootstrapAPIKeyActor = "bootstrap"

	defaultACMESmokeValidity     = 24 * time.Hour
	defaultACMESmokeIssuerKeyRef = ".tmp/acme-smoke/acme-smoke-issuer.key"

	productionEnv                   = "production"
	minProductionBootstrapKeyLength = 32
	defaultServiceVersion           = "dev"
	defaultServiceCommit            = "unknown"
	defaultServiceBuildTime         = "unknown"
	defaultShutdownTimeout          = 10 * time.Second
	defaultCoreMetadataTimeout      = 5 * time.Second
)

var (
	serviceVersion   = defaultServiceVersion
	serviceCommit    = defaultServiceCommit
	serviceBuildTime = defaultServiceBuildTime
)

type outboxConfig struct {
	Enabled   bool
	Interval  time.Duration
	BatchSize int
}

type expirationScanConfig struct {
	Enabled       bool
	Interval      time.Duration
	WarningWindow time.Duration
	BatchSize     int
}

type acmeHTTP01VerifierConfig struct {
	BaseURL string
}

type acmeDefaultsConfig struct {
	BootstrapDefaults bool
	ValidityPeriod    time.Duration
	IssuerKeyRef      string
}

type acmeNonceConfig struct {
	Store string
}

type publicTLSConfig struct {
	MaxValidity              time.Duration
	CAAIssuerDomain          string
	CAAAccountURI            string
	CAAValidationMethod      string
	CAAResolver              string
	CAALookupTimeout         time.Duration
	AllowDNSSECIndeterminate bool
}

type authConfig struct {
	HTTP                 httpapi.AuthConfig
	BootstrapAPIKey      string
	BootstrapAPIKeyName  string
	BootstrapAPIKeyActor string
	APIKeyPepper         string
}

type operationalConfig struct {
	Version           string
	Commit            string
	BuildTime         string
	StartedAt         time.Time
	Ready             func(context.Context) error
	Backend           corecli.BackendInfo
	KeyProviderPolicy keyProviderPolicyMetadata
}

func main() {
	startedAt := time.Now().UTC()
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	addr := envOrDefault("ANOPKI_ADDR", defaultAddr)
	dbDriver := envOrDefault("ANOPKI_DB_DRIVER", defaultDBDriver)
	dbDSN := envOrDefault("ANOPKI_DB_DSN", defaultDBDSN)
	coreBin := envOrDefault("ANOPKI_CORE_BIN", defaultCoreBin)
	authCfg, err := loadAuthConfig()
	if err != nil {
		log.Fatalf("load auth config: %v", err)
	}
	outboxCfg, err := loadOutboxConfig()
	if err != nil {
		log.Fatalf("load outbox config: %v", err)
	}
	expirationScanCfg, err := loadExpirationScanConfig()
	if err != nil {
		log.Fatalf("load expiration scan config: %v", err)
	}
	acmeHTTP01VerifierCfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		log.Fatalf("load ACME HTTP-01 verifier config: %v", err)
	}
	acmeDefaultsCfg, err := loadACMEDefaultsConfig()
	if err != nil {
		log.Fatalf("load ACME defaults config: %v", err)
	}
	acmeNonceCfg, err := loadACMENonceConfig()
	if err != nil {
		log.Fatalf("load ACME nonce config: %v", err)
	}
	publicTLSCfg, err := loadPublicTLSConfig()
	if err != nil {
		log.Fatalf("load public TLS config: %v", err)
	}

	coreRunner := corecli.Runner{Bin: coreBin}
	metadataCtx, cancelMetadata := context.WithTimeout(rootCtx, defaultCoreMetadataTimeout)
	backendInfo, err := coreRunner.BackendInfo(metadataCtx)
	cancelMetadata()
	if err != nil {
		log.Fatalf("load core backend metadata: %v", err)
	}

	db, err := sql.Open(dbDriver, dbDSN)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := observeOperation("db", "migration", func() error {
		return store.ApplyInitialMigration(rootCtx, db, dbDriver)
	}); err != nil {
		log.Fatalf("apply database migration: %v", err)
	}

	repo := store.NewSQLStore(db)
	acmeHTTP01Verifier, err := lifecycle.NewACMEHTTP01Verifier(acmeHTTP01VerifierCfg.BaseURL)
	if err != nil {
		log.Fatalf("create ACME HTTP-01 verifier: %v", err)
	}
	svc := lifecycle.NewWithACMEHTTP01VerifierAndAPIKeyPepper(repo, coreRunner, lifecycle.RealClock{}, lifecycle.UUIDGenerator{}, acmeHTTP01Verifier, authCfg.APIKeyPepper)
	if isProductionEnv(os.Getenv("ANOPKI_ENV")) {
		svc.EnableProductionPolicy()
	}
	if publicTLSCfg.MaxValidity > 0 {
		if err := svc.SetPublicTLSMaxValidity(publicTLSCfg.MaxValidity); err != nil {
			log.Fatalf("set public TLS max validity: %v", err)
		}
	}
	if publicTLSCfg.CAAIssuerDomain != "" {
		lookup, err := lifecycle.NewDNSCAALookup(publicTLSCfg.CAAResolver, publicTLSCfg.CAALookupTimeout)
		if err != nil {
			log.Fatalf("create public TLS CAA lookup: %v", err)
		}
		if err := svc.SetPublicTLSCAAPolicy(lifecycle.PublicTLSCAAPolicy{
			IssuerDomain:             publicTLSCfg.CAAIssuerDomain,
			AccountURI:               publicTLSCfg.CAAAccountURI,
			ValidationMethod:         publicTLSCfg.CAAValidationMethod,
			AllowDNSSECIndeterminate: publicTLSCfg.AllowDNSSECIndeterminate,
			Lookup:                   lookup,
		}); err != nil {
			log.Fatalf("set public TLS CAA policy: %v", err)
		}
	}
	if acmeHTTP01VerifierCfg.BaseURL != "" {
		logStructured(log.Printf, "acme_http01_override.enabled", map[string]any{"base_url": acmeHTTP01VerifierCfg.BaseURL})
	}
	if authCfg.BootstrapAPIKey != "" {
		key, err := svc.EnsureAPIKey(rootCtx, "system", lifecycle.EnsureAPIKeyRequest{
			Name:  authCfg.BootstrapAPIKeyName,
			Token: authCfg.BootstrapAPIKey,
			Actor: authCfg.BootstrapAPIKeyActor,
		})
		if err != nil {
			log.Fatalf("bootstrap api key: %v", err)
		}
		logStructured(log.Printf, "bootstrap_api_key.ready", map[string]any{"id": key.ID, "name": key.Name, "actor": key.Actor})
	}
	acmeHTTPConfig := httpapi.ACMEConfig{}
	if acmeDefaultsCfg.BootstrapDefaults {
		acmeHTTPConfig, err = bootstrapACMEDefaults(rootCtx, svc, acmeDefaultsCfg.ValidityPeriod, acmeDefaultsCfg.IssuerKeyRef)
		if err != nil {
			log.Fatalf("bootstrap ACME defaults: %v", err)
		}
		logStructured(log.Printf, "acme_defaults.ready", map[string]any{
			"identity_id": acmeHTTPConfig.DefaultIdentityID,
			"issuer_id":   acmeHTTPConfig.DefaultIssuerID,
			"profile_id":  acmeHTTPConfig.DefaultCertificateProfileID,
			"validity":    acmeHTTPConfig.DefaultValidityPeriod.String(),
		})
	}
	if acmeNonceCfg.Store == "sql" {
		acmeHTTPConfig.NonceStore = httpapi.NewSQLACMENonceStore(db, dbDriver)
		logStructured(log.Printf, "acme_nonce_store.enabled", map[string]any{"store": "sql"})
	}
	server := httpapi.NewWithAuthAndACME(svc, authCfg.HTTP, acmeHTTPConfig)
	if outboxCfg.Enabled {
		webhookHandler := lifecycle.NewWebhookOutboxHandler(repo, nil)
		dispatcher := lifecycle.NewOutboxDispatcher(repo, lifecycle.NewLifecycleOutboxHandlerWithWebhook(webhookHandler), lifecycle.RealClock{}, lifecycle.UUIDGenerator{})
		worker := lifecycle.NewOutboxWorker(dispatcher, outboxCfg.Interval, outboxCfg.BatchSize, log.Printf)
		go worker.Run(rootCtx)
		logStructured(log.Printf, "outbox_worker.enabled", map[string]any{"interval": outboxCfg.Interval.String(), "batch": outboxCfg.BatchSize})
	}
	if expirationScanCfg.Enabled {
		worker := lifecycle.NewExpirationScanWorker(svc, expirationScanCfg.Interval, expirationScanCfg.WarningWindow, expirationScanCfg.BatchSize, log.Printf)
		go worker.Run(rootCtx)
		logStructured(log.Printf, "expiration_scan_worker.enabled", map[string]any{
			"interval":       expirationScanCfg.Interval.String(),
			"warning_window": expirationScanCfg.WarningWindow.String(),
			"batch":          expirationScanCfg.BatchSize,
		})
	}
	handler := newOperationalHandler(server, operationalConfig{
		Version:           serviceVersion,
		Commit:            serviceCommit,
		BuildTime:         serviceBuildTime,
		StartedAt:         startedAt,
		Ready:             newServiceReadinessCheck(db, dbDriver, repo, coreBin),
		Backend:           backendInfo,
		KeyProviderPolicy: communityKeyProviderPolicyMetadata(),
	})

	logStructured(log.Printf, "service.listening", map[string]any{"addr": addr})
	httpServer := newHTTPServer(addr, handler)
	if err := runServerUntilShutdown(rootCtx, httpServer.ListenAndServe, httpServer.Shutdown, defaultShutdownTimeout, log.Printf); err != nil {
		log.Fatalf("serve HTTP: %v", err)
	}
}

func logStructured(logf func(string, ...any), event string, fields map[string]any) {
	record := make(map[string]any, len(fields)+1)
	record["event"] = event
	for key, value := range fields {
		if isSecretLogField(key) {
			record[key] = "[redacted]"
			continue
		}
		record[key] = value
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		logf(`{"event":"log_encode_failed"}`)
		return
	}
	logf("%s", encoded)
}

func isSecretLogField(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "secret") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "pepper") ||
		strings.Contains(key, "private_key")
}

func newServiceReadinessCheck(db *sql.DB, driver string, repo store.Repository, coreBin string) func(context.Context) error {
	keyPolicy := keyRefReadinessPolicy{Production: isProductionEnv(os.Getenv("ANOPKI_ENV"))}
	return func(ctx context.Context) error {
		if err := newDatabaseReadinessCheck(db, driver)(ctx); err != nil {
			return err
		}
		if err := checkCoreCLI(coreBin); err != nil {
			return err
		}
		return checkActiveKeyRefs(ctx, repo, keyPolicy)
	}
}

func newDatabaseReadinessCheck(db *sql.DB, driver string) func(context.Context) error {
	return func(ctx context.Context) error {
		return observeOperation("db", "readiness", func() error {
			readyCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := db.PingContext(readyCtx); err != nil {
				return err
			}
			return store.CheckInitialMigration(readyCtx, db, driver)
		})
	}
}

func checkCoreCLI(bin string) error {
	return observeOperation("core_cli", "readiness", func() error {
		return checkCoreCLIAvailable(bin)
	})
}

func observeOperation(boundary string, operation string, fn func() error) error {
	start := time.Now()
	err := fn()
	observability.ObserveOperation(boundary, operation, start, err)
	return err
}

func checkCoreCLIAvailable(bin string) error {
	if strings.TrimSpace(bin) == "" {
		bin = defaultCoreBin
	}
	if strings.ContainsAny(bin, `/\`) || filepath.IsAbs(bin) {
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("core CLI unavailable: %w", err)
		}
		return nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("core CLI unavailable: %w", err)
	}
	return nil
}

func checkActiveKeyRefs(ctx context.Context, repo store.Repository, keyPolicy keyRefReadinessPolicy) error {
	issuers, err := repo.ListIssuers(ctx)
	if err != nil {
		return err
	}
	for _, issuer := range issuers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if issuer.Status != domain.IssuerActive {
			continue
		}
		if err := checkReadableKeyRef(issuer.KeyRef, keyPolicy); err != nil {
			return fmt.Errorf("issuer key ref unavailable: %w", err)
		}
		responders, err := repo.ListOCSPRespondersByIssuer(ctx, issuer.ID)
		if err != nil {
			return err
		}
		for _, responder := range responders {
			if responder.Status != domain.OCSPResponderActive {
				continue
			}
			if err := checkReadableKeyRef(responder.KeyRef, keyPolicy); err != nil {
				return fmt.Errorf("ocsp responder key ref unavailable: %w", err)
			}
		}
	}
	return nil
}

func runServerUntilShutdown(ctx context.Context, serve func() error, shutdown func(context.Context) error, timeout time.Duration, logf func(string, ...any)) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		if logf != nil {
			logf("AnoPKI service shutting down")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			return err
		}
		select {
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-shutdownCtx.Done():
			return shutdownCtx.Err()
		}
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func newOperationalHandler(next http.Handler, cfg operationalConfig) http.Handler {
	if cfg.Version == "" {
		cfg.Version = defaultServiceVersion
	}
	if cfg.Commit == "" {
		cfg.Commit = defaultServiceCommit
	}
	if cfg.BuildTime == "" {
		cfg.BuildTime = defaultServiceBuildTime
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = time.Now().UTC()
	}
	if cfg.Ready == nil {
		cfg.Ready = func(context.Context) error { return nil }
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"status":     "ok",
			"started_at": cfg.StartedAt.Format(time.RFC3339Nano),
		})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Ready(r.Context()) != nil {
			writeOperationalJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not_ready",
				"error":  "readiness check failed",
			})
			return
		}
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
		})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"service":             "anopki-service",
			"version":             cfg.Version,
			"commit":              cfg.Commit,
			"build_time":          cfg.BuildTime,
			"backend":             cfg.Backend,
			"key_provider_policy": cfg.KeyProviderPolicy,
		})
	})
	mux.Handle("/", next)
	return mux
}

func writeOperationalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func loadAuthConfig() (authConfig, error) {
	modeValue := strings.TrimSpace(envOrDefault("ANOPKI_AUTH_MODE", string(httpapi.AuthModeDev)))
	mode := httpapi.AuthMode(modeValue)
	switch mode {
	case httpapi.AuthModeDev, httpapi.AuthModeAPIKey:
	default:
		return authConfig{}, fmt.Errorf("ANOPKI_AUTH_MODE must be %q or %q", httpapi.AuthModeDev, httpapi.AuthModeAPIKey)
	}

	bootstrapAPIKey := os.Getenv("ANOPKI_BOOTSTRAP_API_KEY")
	apiKeyPepper := os.Getenv("ANOPKI_API_KEY_PEPPER")
	trustedProxies, err := parseTrustedProxiesEnv("ANOPKI_TRUSTED_PROXIES")
	if err != nil {
		return authConfig{}, err
	}
	if err := validateProductionAuthConfig(os.Getenv("ANOPKI_ENV"), mode, bootstrapAPIKey, apiKeyPepper); err != nil {
		return authConfig{}, err
	}

	return authConfig{
		HTTP: httpapi.AuthConfig{
			Mode:           mode,
			TrustedProxies: trustedProxies,
		},
		BootstrapAPIKey:      bootstrapAPIKey,
		BootstrapAPIKeyName:  envOrDefault("ANOPKI_BOOTSTRAP_API_KEY_NAME", defaultBootstrapAPIKeyName),
		BootstrapAPIKeyActor: envOrDefault("ANOPKI_BOOTSTRAP_API_KEY_ACTOR", defaultBootstrapAPIKeyActor),
		APIKeyPepper:         strings.TrimSpace(apiKeyPepper),
	}, nil
}

func parseTrustedProxiesEnv(name string) ([]netip.Prefix, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	values := strings.Split(raw, ",")
	proxies := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := parseTrustedProxy(value)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid proxy %q: %w", name, value, err)
		}
		proxies = append(proxies, prefix)
	}
	return proxies, nil
}

func parseTrustedProxy(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func validateProductionAuthConfig(env string, mode httpapi.AuthMode, bootstrapAPIKey string, apiKeyPepper string) error {
	if !isProductionEnv(env) {
		return nil
	}
	if mode == httpapi.AuthModeDev {
		return fmt.Errorf("ANOPKI_ENV=%s requires ANOPKI_AUTH_MODE=%q", productionEnv, httpapi.AuthModeAPIKey)
	}
	if isWeakProductionSecret(apiKeyPepper) {
		return fmt.Errorf("ANOPKI_API_KEY_PEPPER must be at least %d characters and not a common default in production", minProductionBootstrapKeyLength)
	}
	if bootstrapAPIKey != "" && isWeakProductionBootstrapAPIKey(bootstrapAPIKey) {
		return fmt.Errorf("ANOPKI_BOOTSTRAP_API_KEY must be at least %d characters and not a common default in production", minProductionBootstrapKeyLength)
	}
	return nil
}

func isProductionEnv(env string) bool {
	return strings.EqualFold(strings.TrimSpace(env), productionEnv)
}

func isWeakProductionBootstrapAPIKey(token string) bool {
	return isWeakProductionSecret(token)
}

func isWeakProductionSecret(token string) bool {
	trimmed := strings.TrimSpace(token)
	if len(trimmed) < minProductionBootstrapKeyLength {
		return true
	}
	if isSingleRepeatedRune(trimmed) {
		return true
	}
	switch strings.ToLower(trimmed) {
	case "change-me", "changeme", "bootstrap", "bootstrap-token", "password", "secret", "admin", "anopki", "anopki-bootstrap":
		return true
	default:
		return false
	}
}

func isSingleRepeatedRune(value string) bool {
	var first rune
	for idx, current := range value {
		if idx == 0 {
			first = current
			continue
		}
		if current != first {
			return false
		}
	}
	return value != ""
}

func loadOutboxConfig() (outboxConfig, error) {
	enabled, err := parseBoolEnv("ANOPKI_OUTBOX_ENABLED", defaultOutboxEnabled)
	if err != nil {
		return outboxConfig{}, err
	}
	interval, err := parseDurationEnv("ANOPKI_OUTBOX_INTERVAL", defaultOutboxInterval)
	if err != nil {
		return outboxConfig{}, err
	}
	batchSize, err := parsePositiveIntEnv("ANOPKI_OUTBOX_BATCH_SIZE", defaultOutboxBatchSize)
	if err != nil {
		return outboxConfig{}, err
	}
	return outboxConfig{
		Enabled:   enabled,
		Interval:  interval,
		BatchSize: batchSize,
	}, nil
}

func loadExpirationScanConfig() (expirationScanConfig, error) {
	enabled, err := parseBoolEnv("ANOPKI_EXPIRATION_SCAN_ENABLED", defaultExpirationScanEnabled)
	if err != nil {
		return expirationScanConfig{}, err
	}
	interval, err := parseDurationEnv("ANOPKI_EXPIRATION_SCAN_INTERVAL", defaultExpirationScanInterval)
	if err != nil {
		return expirationScanConfig{}, err
	}
	warningWindow, err := parseNonNegativeDurationEnv("ANOPKI_EXPIRATION_WARNING_WINDOW", defaultExpirationScanWarningWindow)
	if err != nil {
		return expirationScanConfig{}, err
	}
	batchSize, err := parsePositiveIntEnv("ANOPKI_EXPIRATION_SCAN_BATCH_SIZE", defaultExpirationScanBatchSize)
	if err != nil {
		return expirationScanConfig{}, err
	}
	return expirationScanConfig{
		Enabled:       enabled,
		Interval:      interval,
		WarningWindow: warningWindow,
		BatchSize:     batchSize,
	}, nil
}

func loadPublicTLSConfig() (publicTLSConfig, error) {
	cfg := publicTLSConfig{
		CAAIssuerDomain:     strings.TrimSpace(os.Getenv("ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN")),
		CAAAccountURI:       strings.TrimSpace(os.Getenv("ANOPKI_PUBLIC_TLS_CAA_ACCOUNT_URI")),
		CAAValidationMethod: strings.TrimSpace(envOrDefault("ANOPKI_PUBLIC_TLS_CAA_VALIDATION_METHOD", string(domain.ACMEChallengeHTTP01))),
		CAAResolver:         strings.TrimSpace(os.Getenv("ANOPKI_PUBLIC_TLS_CAA_RESOLVER")),
		CAALookupTimeout:    5 * time.Second,
	}
	value := strings.TrimSpace(os.Getenv("ANOPKI_PUBLIC_TLS_MAX_VALIDITY"))
	if value != "" {
		maxValidity, err := time.ParseDuration(value)
		if err != nil {
			return publicTLSConfig{}, fmt.Errorf("ANOPKI_PUBLIC_TLS_MAX_VALIDITY: %w", err)
		}
		if maxValidity <= 0 {
			return publicTLSConfig{}, fmt.Errorf("ANOPKI_PUBLIC_TLS_MAX_VALIDITY must be positive")
		}
		cfg.MaxValidity = maxValidity
	}
	timeoutValue := strings.TrimSpace(os.Getenv("ANOPKI_PUBLIC_TLS_CAA_LOOKUP_TIMEOUT"))
	if timeoutValue != "" {
		timeout, err := time.ParseDuration(timeoutValue)
		if err != nil {
			return publicTLSConfig{}, fmt.Errorf("ANOPKI_PUBLIC_TLS_CAA_LOOKUP_TIMEOUT: %w", err)
		}
		if timeout <= 0 {
			return publicTLSConfig{}, fmt.Errorf("ANOPKI_PUBLIC_TLS_CAA_LOOKUP_TIMEOUT must be positive")
		}
		cfg.CAALookupTimeout = timeout
	}
	allowIndeterminate, err := parseBoolEnv("ANOPKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE", false)
	if err != nil {
		return publicTLSConfig{}, err
	}
	cfg.AllowDNSSECIndeterminate = allowIndeterminate
	if cfg.CAAIssuerDomain != "" && (cfg.CAAResolver == "" || cfg.CAAValidationMethod == "") {
		return publicTLSConfig{}, fmt.Errorf("ANOPKI_PUBLIC_TLS_CAA_RESOLVER and ANOPKI_PUBLIC_TLS_CAA_VALIDATION_METHOD are required when ANOPKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN is set")
	}
	return cfg, nil
}

func loadACMEHTTP01VerifierConfig() (acmeHTTP01VerifierConfig, error) {
	baseURL := strings.TrimSpace(os.Getenv("ANOPKI_ACME_HTTP01_BASE_URL"))
	if baseURL != "" {
		if _, err := lifecycle.NewACMEHTTP01Verifier(baseURL); err != nil {
			return acmeHTTP01VerifierConfig{}, fmt.Errorf("ANOPKI_ACME_HTTP01_BASE_URL: %w", err)
		}
	}
	return acmeHTTP01VerifierConfig{BaseURL: baseURL}, nil
}

func loadACMEDefaultsConfig() (acmeDefaultsConfig, error) {
	bootstrap, err := parseBoolEnv("ANOPKI_ACME_BOOTSTRAP_DEFAULTS", false)
	if err != nil {
		return acmeDefaultsConfig{}, err
	}
	validity, err := parseDurationEnv("ANOPKI_ACME_DEFAULT_VALIDITY", defaultACMESmokeValidity)
	if err != nil {
		return acmeDefaultsConfig{}, err
	}
	return acmeDefaultsConfig{
		BootstrapDefaults: bootstrap,
		ValidityPeriod:    validity,
		IssuerKeyRef:      envOrDefault("ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF", defaultACMESmokeIssuerKeyRef),
	}, nil
}

func loadACMENonceConfig() (acmeNonceConfig, error) {
	store := strings.TrimSpace(envOrDefault("ANOPKI_ACME_NONCE_STORE", "memory"))
	switch store {
	case "memory", "sql":
	default:
		return acmeNonceConfig{}, fmt.Errorf("ANOPKI_ACME_NONCE_STORE must be memory or sql")
	}
	if isProductionEnv(os.Getenv("ANOPKI_ENV")) && store != "sql" {
		return acmeNonceConfig{}, fmt.Errorf("ANOPKI_ACME_NONCE_STORE must be sql when ANOPKI_ENV=production")
	}
	return acmeNonceConfig{Store: store}, nil
}

func bootstrapACMEDefaults(ctx context.Context, svc *lifecycle.Service, validity time.Duration, issuerKeyRef string) (httpapi.ACMEConfig, error) {
	issuerCertificatePEM, issuerKeyRef, err := ensureACMESmokeIssuerMaterial(issuerKeyRef)
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	identity, err := svc.CreateIdentity(ctx, "system", lifecycle.CreateIdentityRequest{
		Type:         "machine",
		Name:         "acme-smoke-edge-01",
		ExternalID:   "acme-smoke-edge-01",
		Owner:        "platform",
		MetadataJSON: `{"team":"platform","service":"acme-smoke","environment":"local","deployment_target":"local"}`,
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	issuer, err := svc.CreateIssuer(ctx, "system", lifecycle.CreateIssuerRequest{
		Name:           "acme-smoke-issuer",
		Kind:           "intermediate_ca",
		CertificatePEM: issuerCertificatePEM,
		KeyRef:         issuerKeyRef,
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	profile, err := svc.CreateCertificateProfile(ctx, "system", lifecycle.CreateCertificateProfileRequest{
		IssuerID:              issuer.ID,
		Name:                  "acme-smoke-profile",
		ValidityPeriodSeconds: int64(validity.Seconds()),
		AllowedDNSPatterns:    []string{"*.example.test"},
		AllowedIPRanges:       []string{"127.0.0.0/8"},
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	return httpapi.ACMEConfig{
		DefaultIdentityID:           identity.ID,
		DefaultIssuerID:             issuer.ID,
		DefaultCertificateProfileID: profile.ID,
		DefaultValidityPeriod:       validity,
	}, nil
}

func ensureACMESmokeIssuerMaterial(issuerKeyRef string) (string, string, error) {
	if strings.TrimSpace(issuerKeyRef) == "" {
		return "", "", fmt.Errorf("ANOPKI_ACME_BOOTSTRAP_ISSUER_KEY_REF must not be empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate ACME smoke issuer key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("generate ACME smoke issuer serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AnoPKI ACME Smoke CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create ACME smoke issuer certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal ACME smoke issuer key: %w", err)
	}
	keyDir := filepath.Dir(issuerKeyRef)
	if keyDir != "." {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return "", "", fmt.Errorf("create ACME smoke issuer key dir: %w", err)
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(issuerKeyRef, keyPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write ACME smoke issuer key: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, issuerKeyRef, nil
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func parseNonNegativeDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be non-negative", name)
	}
	return parsed, nil
}

func parsePositiveIntEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}
