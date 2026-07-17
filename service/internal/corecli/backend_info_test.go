// SPDX-License-Identifier: MPL-2.0
package corecli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const validBackendInfoJSON = `{"product_profile":"community-openssl","edition":"community","selected_backend":"openssl","fallback_enabled":false,"backend_id":"openssl","backend_dependency":"OpenSSL","backend_version":"3.5.5","backend_readiness":"ready","backend_capabilities":["csr_inspect","certificate_issue","crl_generate","crl_inspect","ocsp_request_inspect","ocsp_issuer_inspect","ocsp_response_generate","ocsp_responder_validate"],"backend_abi_version":1,"backend_build_fingerprint":"test-build"}`

func TestRunnerBackendInfoMapsStrictMetadata(t *testing.T) {
	bin := writeFakeBackendInfoCommand(t, validBackendInfoJSON, true)
	info, err := (Runner{Bin: bin}).BackendInfo(context.Background())
	if err != nil {
		t.Fatalf("BackendInfo returned error: %v", err)
	}
	if info.ProductProfile != "community-openssl" || info.Edition != "community" || info.SelectedBackend != "openssl" {
		t.Fatalf("BackendInfo = %#v", info)
	}
	if info.FallbackEnabled || info.BackendReadiness != "ready" || info.BackendABIVersion != 1 {
		t.Fatalf("BackendInfo control metadata = %#v", info)
	}
	if len(info.BackendCapabilities) != 8 {
		t.Fatalf("BackendCapabilities = %#v", info.BackendCapabilities)
	}
}

func TestRunnerBackendInfoRejectsUnknownField(t *testing.T) {
	payload := strings.TrimSuffix(validBackendInfoJSON, "}") + `,"key_ref":"secret-path"}`
	bin := writeFakeBackendInfoCommand(t, payload, true)
	_, err := (Runner{Bin: bin}).BackendInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "decode backend info") {
		t.Fatalf("BackendInfo error = %v, want strict decode failure", err)
	}
}

func TestRunnerBackendInfoRejectsFallbackEnabled(t *testing.T) {
	payload := strings.Replace(validBackendInfoJSON, `"fallback_enabled":false`, `"fallback_enabled":true`, 1)
	bin := writeFakeBackendInfoCommand(t, payload, true)
	_, err := (Runner{Bin: bin}).BackendInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fallback must be disabled") {
		t.Fatalf("BackendInfo error = %v, want fallback rejection", err)
	}
}

func TestRunnerBackendInfoRejectsBackendIdentityMismatch(t *testing.T) {
	payload := strings.Replace(validBackendInfoJSON, `"backend_id":"openssl"`, `"backend_id":"other"`, 1)
	bin := writeFakeBackendInfoCommand(t, payload, true)
	_, err := (Runner{Bin: bin}).BackendInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("BackendInfo error = %v, want identity mismatch", err)
	}
}

func TestRunnerBackendInfoMapsCommandFailure(t *testing.T) {
	bin := writeFakeBackendInfoCommand(t, `{"code":"backend.module_not_operational","message":"not ready"}`, false)
	_, err := (Runner{Bin: bin}).BackendInfo(context.Background())
	if err == nil || !strings.Contains(err.Error(), "backend.module_not_operational") {
		t.Fatalf("BackendInfo error = %v, want command error", err)
	}
}

func writeFakeBackendInfoCommand(t *testing.T, payload string, success bool) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "anopki-core.bat")
		escaped := strings.ReplaceAll(payload, `"`, `^"`)
		stream := ""
		code := "0"
		if !success {
			stream = " 1>&2"
			code = "7"
		}
		script := strings.Join([]string{
			"@echo off",
			`if not "%~1"=="backend" exit /b 3`,
			`if not "%~2"=="info" exit /b 3`,
			"echo " + escaped + stream,
			"exit /b " + code,
			"",
		}, "\r\n")
		if err := os.WriteFile(path, []byte(script), 0644); err != nil {
			t.Fatalf("write fake backend command: %v", err)
		}
		return path
	}
	path := filepath.Join(dir, "anopki-core")
	escaped := strings.ReplaceAll(payload, `'`, `'"'"'`)
	stream := ""
	code := "0"
	if !success {
		stream = " >&2"
		code = "7"
	}
	script := "#!/bin/sh\n" +
		`if [ "$1" != "backend" ] || [ "$2" != "info" ]; then exit 3; fi` + "\n" +
		"printf '%s\\n' '" + escaped + "'" + stream + "\n" +
		"exit " + code + "\n"
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write fake backend command: %v", err)
	}
	return path
}
