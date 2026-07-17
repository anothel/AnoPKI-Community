// SPDX-License-Identifier: MPL-2.0
package corecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// BackendInfo mirrors the stable `anopki-core backend info` JSON contract.
// It is operational/release metadata and is not part of certificate lifecycle
// request or response payloads.
type BackendInfo struct {
	ProductProfile          string   `json:"product_profile"`
	Edition                 string   `json:"edition"`
	SelectedBackend         string   `json:"selected_backend"`
	FallbackEnabled         bool     `json:"fallback_enabled"`
	BackendID               string   `json:"backend_id"`
	BackendDependency       string   `json:"backend_dependency"`
	BackendVersion          string   `json:"backend_version"`
	BackendReadiness        string   `json:"backend_readiness"`
	BackendCapabilities     []string `json:"backend_capabilities"`
	BackendABIVersion       uint32   `json:"backend_abi_version"`
	BackendBuildFingerprint string   `json:"backend_build_fingerprint"`
}

// ValidateBackendInfo rejects malformed, fallback-enabled, or internally
// inconsistent control metadata before it reaches service/version or release
// evidence.
func ValidateBackendInfo(info BackendInfo) error {
	for name, value := range map[string]string{
		"product_profile":           info.ProductProfile,
		"edition":                   info.Edition,
		"selected_backend":          info.SelectedBackend,
		"backend_id":                info.BackendID,
		"backend_dependency":        info.BackendDependency,
		"backend_version":           info.BackendVersion,
		"backend_readiness":         info.BackendReadiness,
		"backend_build_fingerprint": info.BackendBuildFingerprint,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("validate backend info: %s is empty", name)
		}
	}
	if info.FallbackEnabled {
		return fmt.Errorf("validate backend info: fallback must be disabled")
	}
	if info.SelectedBackend != info.BackendID {
		return fmt.Errorf("validate backend info: selected backend does not match backend id")
	}
	if info.BackendReadiness != "ready" {
		return fmt.Errorf("validate backend info: backend is not ready")
	}
	if info.BackendABIVersion == 0 {
		return fmt.Errorf("validate backend info: backend ABI version is zero")
	}
	seen := make(map[string]struct{}, len(info.BackendCapabilities))
	for _, capability := range info.BackendCapabilities {
		capability = strings.TrimSpace(capability)
		if capability == "" {
			return fmt.Errorf("validate backend info: blank capability")
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("validate backend info: duplicate capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func decodeBackendInfo(payload []byte) (BackendInfo, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var info BackendInfo
	if err := decoder.Decode(&info); err != nil {
		return BackendInfo{}, fmt.Errorf("decode backend info: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return BackendInfo{}, fmt.Errorf("decode backend info: trailing JSON value")
		}
		return BackendInfo{}, fmt.Errorf("decode backend info: %w", err)
	}
	if err := ValidateBackendInfo(info); err != nil {
		return BackendInfo{}, err
	}
	return info, nil
}

// BackendInfo executes the immutable build-selected backend control command.
func (r Runner) BackendInfo(ctx context.Context) (BackendInfo, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := coreCommand(ctx, r.Bin, "backend", "info")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return BackendInfo{}, commandError(err, stderr.String())
	}
	return decodeBackendInfo(stdout.Bytes())
}
