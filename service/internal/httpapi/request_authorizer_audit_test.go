// SPDX-License-Identifier: MPL-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anothel/anopki/service/internal/domain"
)

func TestAuthorizationAuditMetadataClassification(t *testing.T) {
	tests := []struct {
		name          string
		result        AuthorizationResult
		err           error
		contextErr    error
		wantOutcome   string
		wantEvaluator string
	}{
		{name: "allow", result: AuthorizationResult{Outcome: AuthorizationOutcomeAllow}, wantOutcome: "allow", wantEvaluator: "ok"},
		{name: "deny", result: AuthorizationResult{Outcome: AuthorizationOutcomeDeny}, wantOutcome: "deny", wantEvaluator: "ok"},
		{name: "approval required", result: AuthorizationResult{Outcome: AuthorizationOutcomeApprovalRequired}, wantOutcome: "approval_required", wantEvaluator: "ok"},
		{name: "invalid", result: AuthorizationResult{Outcome: AuthorizationOutcome("unknown")}, wantOutcome: "invalid", wantEvaluator: "invalid_result"},
		{name: "error", err: errors.New("policy failed"), wantOutcome: "error", wantEvaluator: "error"},
		{name: "canceled", err: context.Canceled, wantOutcome: "error", wantEvaluator: "canceled"},
		{name: "timeout", err: errors.New("wrapped"), contextErr: context.DeadlineExceeded, wantOutcome: "error", wantEvaluator: "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := authorizationAuditMetadata(tt.result, tt.err, tt.contextErr)
			if metadata.Outcome != tt.wantOutcome || metadata.EvaluatorStatus != tt.wantEvaluator {
				t.Fatalf("metadata = %#v, want outcome=%q evaluator=%q", metadata, tt.wantOutcome, tt.wantEvaluator)
			}
		})
	}
}

func TestRequestAuthorizerAllowDecisionCorrelatesLifecycleAudit(t *testing.T) {
	authorizer := hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		return AuthorizationResult{
			Outcome:        AuthorizationOutcomeAllow,
			DecisionID:     "decision-allow-001",
			ReasonCode:     "identity.create.allowed",
			PolicyRevision: "policy-sha256:0123456789abcdef",
		}, nil
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev}, authorizer)

	res, _ := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "operator", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "audit-allowed",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusCreated)

	metadata := latestAuthorizationAuditMetadata(t, api, "identity.created")
	assertAuthorizationAuditMetadata(t, metadata, map[string]any{
		"authorization_outcome":          "allow",
		"authorization_decision_id":      "decision-allow-001",
		"authorization_reason_code":      "identity.create.allowed",
		"authorization_policy_revision":  "policy-sha256:0123456789abcdef",
		"authorization_evaluator_status": "ok",
	})
}

func TestRequestAuthorizerDenyDecisionCorrelatesFailureAudit(t *testing.T) {
	authorizer := hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		return AuthorizationResult{
			Outcome:        AuthorizationOutcomeDeny,
			DecisionID:     "decision-deny-001",
			ReasonCode:     "identity.create.denied",
			PolicyRevision: "policy-v7",
		}, nil
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev}, authorizer)

	res, body := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "operator", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "audit-denied",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusForbidden)
	if body.Error != domain.ErrForbidden.Error() {
		t.Fatalf("error = %q, want %q", body.Error, domain.ErrForbidden.Error())
	}

	metadata := latestAuthorizationAuditMetadata(t, api, "api.request_failed")
	assertAuthorizationAuditMetadata(t, metadata, map[string]any{
		"authorization_outcome":          "deny",
		"authorization_decision_id":      "decision-deny-001",
		"authorization_reason_code":      "identity.create.denied",
		"authorization_policy_revision":  "policy-v7",
		"authorization_evaluator_status": "ok",
		"error_code":                     "forbidden",
	})
}

func TestRequestAuthorizerTimeoutAuditDoesNotExposeEvaluatorError(t *testing.T) {
	const rawError = "remote-policy-token-secret"
	authorizer := hardeningAuthorizerFunc(func(ctx context.Context, _ AuthorizationInput) (AuthorizationResult, error) {
		<-ctx.Done()
		return AuthorizationResult{
			DecisionID:     "decision-timeout-001",
			PolicyRevision: "policy-v8",
		}, errors.New(rawError + ": " + ctx.Err().Error())
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev, AuthorizationTimeout: 20 * time.Millisecond}, authorizer)

	res, _ := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "operator", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "audit-timeout",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusForbidden)

	metadata := latestAuthorizationAuditMetadata(t, api, "api.request_failed")
	assertAuthorizationAuditMetadata(t, metadata, map[string]any{
		"authorization_outcome":          "error",
		"authorization_decision_id":      "decision-timeout-001",
		"authorization_policy_revision":  "policy-v8",
		"authorization_evaluator_status": "timeout",
	})
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	if strings.Contains(string(encoded), rawError) {
		t.Fatalf("authorization audit exposed evaluator error: %s", encoded)
	}
}

func TestRequestAuthorizerInvalidReferencesAreOmitted(t *testing.T) {
	authorizer := hardeningAuthorizerFunc(func(context.Context, AuthorizationInput) (AuthorizationResult, error) {
		return AuthorizationResult{
			Outcome:        AuthorizationOutcomeAllow,
			DecisionID:     "decision with spaces",
			ReasonCode:     strings.Repeat("x", 129),
			PolicyRevision: "policy\nrevision",
		}, nil
	})
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev}, authorizer)

	res, _ := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "operator", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "audit-invalid-reference",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusCreated)

	metadata := latestAuthorizationAuditMetadata(t, api, "identity.created")
	if metadata["authorization_outcome"] != "allow" || metadata["authorization_evaluator_status"] != "ok" {
		t.Fatalf("authorization metadata = %#v", metadata)
	}
	for _, key := range []string{"authorization_decision_id", "authorization_reason_code", "authorization_policy_revision"} {
		if _, ok := metadata[key]; ok {
			t.Fatalf("invalid %s unexpectedly retained: %#v", key, metadata)
		}
	}
}

func TestRequestsWithoutAuthorizerDoNotClaimAuthorizationEvidence(t *testing.T) {
	api, server := newHardeningServer(t, AuthConfig{Mode: AuthModeDev}, nil)
	res, _ := hardeningJSONRequest(t, server.Client(), server.URL, http.MethodPost, "/identities", "operator", "", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "no-authorizer",
	})
	res.Body.Close()
	assertStatus(t, res.StatusCode, http.StatusCreated)

	metadata := latestAuthorizationAuditMetadata(t, api, "identity.created")
	for key := range metadata {
		if strings.HasPrefix(key, "authorization_") {
			t.Fatalf("default Community path claimed authorization evidence: %#v", metadata)
		}
	}
}

func latestAuthorizationAuditMetadata(t *testing.T, api *testAPI, action string) map[string]any {
	t.Helper()
	events, err := api.repo.ListAuditEvents(context.Background())
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action != action {
			continue
		}
		var metadata map[string]any
		if err := json.Unmarshal([]byte(events[i].MetadataJSON), &metadata); err != nil {
			t.Fatalf("decode %s audit metadata: %v", action, err)
		}
		return metadata
	}
	t.Fatalf("missing %s audit event", action)
	return nil
}

func assertAuthorizationAuditMetadata(t *testing.T, metadata map[string]any, want map[string]any) {
	t.Helper()
	for key, value := range want {
		if metadata[key] != value {
			t.Errorf("%s = %#v, want %#v; metadata=%#v", key, metadata[key], value, metadata)
		}
	}
}
