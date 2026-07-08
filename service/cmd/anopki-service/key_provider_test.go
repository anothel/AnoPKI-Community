// SPDX-License-Identifier: MPL-2.0
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyRefReadinessRejectsLocalFileInProduction(t *testing.T) {
	keyRef := writeReadableKeyRef(t, "issuer.key")

	err := checkReadableKeyRef(keyRef, keyRefReadinessPolicy{Production: true})

	if err == nil || !strings.Contains(err.Error(), "file key provider") {
		t.Fatalf("checkReadableKeyRef error = %v, want file provider production error", err)
	}
}

func TestKeyRefReadinessAcceptsFileSchemeInDevelopment(t *testing.T) {
	keyRef := "file:" + writeReadableKeyRef(t, "issuer.key")

	if err := checkReadableKeyRef(keyRef, keyRefReadinessPolicy{}); err != nil {
		t.Fatalf("checkReadableKeyRef returned error: %v", err)
	}
}

func TestKeyRefReadinessRejectsUnsupportedProvider(t *testing.T) {
	err := checkReadableKeyRef("pkcs11:token=ca;object=issuer-a", keyRefReadinessPolicy{})

	if err == nil || !strings.Contains(err.Error(), "unsupported key provider") {
		t.Fatalf("checkReadableKeyRef error = %v, want unsupported provider", err)
	}
}

func TestKeyRefProviderTreatsWindowsAbsolutePathAsFile(t *testing.T) {
	keyRef := filepath.Join(`C:\keys`, "issuer.key")

	if got := keyRefProvider(keyRef); got != keyProviderFile {
		t.Fatalf("keyRefProvider = %q, want %q", got, keyProviderFile)
	}
}
