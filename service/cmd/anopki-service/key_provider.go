// SPDX-License-Identifier: MPL-2.0
package main

import (
	"fmt"
	"os"

	"github.com/anothel/anopki/service/internal/keyref"
)

type keyProviderClass string

const keyProviderFile keyProviderClass = keyProviderClass(keyref.ClassFile)

type keyRefReadinessPolicy struct {
	Production bool
}

func checkReadableKeyRef(keyRef string, policy keyRefReadinessPolicy) error {
	switch provider := keyRefProvider(keyRef); provider {
	case keyProviderFile:
		if policy.Production {
			return fmt.Errorf("file key provider is not allowed in production")
		}
		file, err := os.Open(fileKeyRefPath(keyRef)) // #nosec G304 -- operator-managed local/dev key_ref.
		if err != nil {
			return err
		}
		return file.Close()
	default:
		return fmt.Errorf("unsupported key provider %q", provider)
	}
}

func keyRefProvider(keyRef string) keyProviderClass {
	return keyProviderClass(keyref.Class(keyRef))
}

func fileKeyRefPath(keyRef string) string {
	return keyref.FilePath(keyRef)
}

type keyProviderPolicyMetadata struct {
	SupportedClasses              []string `json:"supported_classes"`
	FileProviderExportability     string   `json:"file_provider_exportability"`
	FileProviderAllowedProduction bool     `json:"file_provider_allowed_in_production"`
	CoreSigningEvidenceRequired   bool     `json:"core_signing_evidence_required"`
	AutomaticProviderFallback     bool     `json:"automatic_provider_fallback"`
}

func communityKeyProviderPolicyMetadata() keyProviderPolicyMetadata {
	return keyProviderPolicyMetadata{
		SupportedClasses:              []string{string(keyProviderFile)},
		FileProviderExportability:     string(keyref.ExportabilityExportable),
		FileProviderAllowedProduction: false,
		CoreSigningEvidenceRequired:   true,
		AutomaticProviderFallback:     false,
	}
}
