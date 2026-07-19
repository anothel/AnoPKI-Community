// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

type hardeningAuthorizerFunc func(context.Context, AuthorizationInput) (AuthorizationResult, error)

func (f hardeningAuthorizerFunc) Authorize(ctx context.Context, input AuthorizationInput) (AuthorizationResult, error) {
	return f(ctx, input)
}

func newHardeningServer(t *testing.T, auth AuthConfig, authorizer RequestAuthorizer) (*testAPI, *httptest.Server) {
	t.Helper()
	api := newTestAPI(t)
	server := httptest.NewServer(NewWithAuthorizer(api.service, auth, ACMEConfig{}, authorizer))
	t.Cleanup(server.Close)
	return api, server
}

func hardeningJSONRequest(t *testing.T, client *http.Client, baseURL string, method string, path string, actor string, token string, body any) (*http.Response, errorResponse) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	var response errorResponse
	if res.StatusCode >= 400 {
		_ = json.NewDecoder(res.Body).Decode(&response)
	}
	return res, response
}

func TestRequestAuthorizerDefaultTimeout(t *testing.T) {
	server := NewWithAuthorizer(nil, AuthConfig{Mode: AuthModeDev}, ACMEConfig{}, hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		return AuthorizationResult{Outcome: AuthorizationOutcomeAllow}, nil
	}))
	if server.auth.AuthorizationTimeout != defaultAuthorizationTimeout {
		t.Fatalf("authorization timeout = %s, want %s", server.auth.AuthorizationTimeout, defaultAuthorizationTimeout)
	}
}

func TestRequestAuthorizerTimeoutIsCapped(t *testing.T) {
	server := NewWithAuthorizer(nil, AuthConfig{Mode: AuthModeDev, AuthorizationTimeout: 30 * time.Second}, ACMEConfig{}, hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		return AuthorizationResult{Outcome: AuthorizationOutcomeAllow}, nil
	}))
	if server.auth.AuthorizationTimeout != defaultAuthorizationTimeout {
		t.Fatalf("authorization timeout = %s, want capped %s", server.auth.AuthorizationTimeout, defaultAuthorizationTimeout)
	}
}

func TestRequestAuthorizerTimeoutFailsClosed(t *testing.T) {
	var sawDeadline atomic.Bool
	authorizer := hardeningAuthorizerFunc(func(ctx context.Context, _ AuthorizationInput) (AuthorizationResult, error) {
		<-ctx.Done()
		sawDeadline.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
		return AuthorizationResult{}, ctx.Err()
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev, AuthorizationTimeout: 20 * time.Millisecond}, authorizer)

	res, body := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "actor", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "timeout-blocked",
	})
	defer res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusForbidden)
	if body.Error != domain.ErrForbidden.Error() {
		t.Fatalf("error = %q, want %q", body.Error, domain.ErrForbidden.Error())
	}
	if !sawDeadline.Load() {
		t.Fatal("authorizer did not observe the configured deadline")
	}
	identities, err := api.repo.ListIdentities(context.Background())
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("identity count = %d, want 0", len(identities))
	}
}

func TestRequestAuthorizerRunsAfterLegacyScopeAndSkipsPublicRoutes(t *testing.T) {
	var calls atomic.Int32
	authorizer := hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		calls.Add(1)
		return AuthorizationResult{Outcome: AuthorizationOutcomeAllow}, nil
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeAPIKey}, authorizer)
	createScopedTestAPIKey(t, api.repo, "read-key", "read-token", "reader", domain.APIKeyActive, domain.APIKeyScopeRead)

	res, _ := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "", "read-token", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "scope-blocked",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusForbidden)

	res, _ = hardeningJSONRequest(t, server.Client(), server.URL, http.MethodGet, "/crls/missing", "", "", nil)
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusNotFound)

	if got := calls.Load(); got != 0 {
		t.Fatalf("authorizer calls = %d, want 0", got)
	}
}

func TestRequestAuthorizerInputExcludesRequestSecrets(t *testing.T) {
	inputCh := make(chan AuthorizationInput, 1)
	authorizer := hardeningAuthorizerFunc(func(_ context.Context, input AuthorizationInput) (AuthorizationResult, error) {
		inputCh <- input
		return AuthorizationResult{Outcome: AuthorizationOutcomeAllow}, nil
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeAPIKey}, authorizer)
	createScopedTestAPIKey(t, api.repo, "write-key", "raw-token-secret", "writer", domain.APIKeyActive, domain.APIKeyScopeWrite)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/identities?customer=query-secret", strings.NewReader(`{"type":"machine","name":"body-secret"}`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer raw-token-secret")
	req.Header.Set("Cookie", "session=cookie-secret")
	req.Header.Set("X-Request-ID", "req-authz-hardening")
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set("User-Agent", "authz-hardening/1.0")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusCreated)

	input := <-inputCh
	if input.ActorID != "writer" || input.RequiredScope != string(requiredScopeWrite) || input.RoutePattern != "/identities" || input.RequestID != "req-authz-hardening" {
		t.Fatalf("authorization input = %#v", input)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	for _, secret := range []string{"raw-token-secret", "Bearer ", "cookie-secret", "body-secret", "query-secret"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("authorization input exposed %q: %s", secret, encoded)
		}
	}
}

func TestDebugVarsRequiresOperatorScope(t *testing.T) {
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeAPIKey}, nil)
	createScopedTestAPIKey(t, api.repo, "read-key", "read-token", "reader", domain.APIKeyActive, domain.APIKeyScopeRead)
	createScopedTestAPIKey(t, api.repo, "operator-key", "operator-token", "operator", domain.APIKeyActive, domain.APIKeyScopeOperator)

	res, body := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodGet, "/debug/vars", "", "read-token", nil)
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusForbidden)
	if body.Error != domain.ErrForbidden.Error() {
		t.Fatalf("read-scope error = %q", body.Error)
	}

	res, _ = hardeningJSONRequest(t, server.Client(), server.URL, http.MethodGet, "/debug/vars", "", "operator-token", nil)
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusOK)
}

func TestRequiredScopeHardeningFixture(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   requiredScope
	}{
		{http.MethodGet, "/debug/vars", requiredScopeOperator},
		{http.MethodGet, "/identities", requiredScopeRead},
		{http.MethodPost, "/identities", requiredScopeWrite},
		{http.MethodGet, "/audit-events/integrity", requiredScopeOperator},
		{http.MethodPost, "/certificates/expiration-scan", requiredScopeOperator},
	}
	for _, tt := range tests {
		if got := requiredScopeForRequest(tt.method, tt.path); got != tt.want {
			t.Errorf("requiredScopeForRequest(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}
