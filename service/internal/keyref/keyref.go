// SPDX-License-Identifier: MPL-2.0
package keyref

import (
	"strings"
	"unicode"
)

const (
	ClassFile = "file"

	ExportabilityExportable            = "exportable"
	ExportabilityNonExportableExpected = "non_exportable_expected"
	ExportabilityUnknown               = "unknown"
)

func Class(ref string) string {
	trimmed := strings.TrimSpace(ref)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "file:") || looksLikeWindowsAbs(trimmed) {
		return ClassFile
	}
	if idx := strings.Index(trimmed, ":"); idx > 0 {
		return strings.ToLower(trimmed[:idx])
	}
	return ClassFile
}

func FilePath(ref string) string {
	trimmed := strings.TrimSpace(ref)
	if strings.HasPrefix(strings.ToLower(trimmed), "file:") {
		return strings.TrimSpace(trimmed[len("file:"):])
	}
	return trimmed
}

func Exportability(ref string) string {
	switch Class(ref) {
	case ClassFile:
		return ExportabilityExportable
	case "kms", "pkcs11":
		return ExportabilityNonExportableExpected
	default:
		return ExportabilityUnknown
	}
}

func looksLikeWindowsAbs(ref string) bool {
	return len(ref) >= 3 &&
		unicode.IsLetter(rune(ref[0])) &&
		ref[1] == ':' &&
		(ref[2] == '\\' || ref[2] == '/')
}
