// SPDX-License-Identifier: MPL-2.0
package keyref

import "testing"

func TestClassAndExportability(t *testing.T) {
	for _, tt := range []struct {
		name       string
		ref        string
		wantClass  string
		wantPath   string
		wantExport string
	}{
		{name: "bare file", ref: "/var/lib/issuer.key", wantClass: ClassFile, wantPath: "/var/lib/issuer.key", wantExport: ExportabilityExportable},
		{name: "file scheme", ref: "file:/var/lib/issuer.key", wantClass: ClassFile, wantPath: "/var/lib/issuer.key", wantExport: ExportabilityExportable},
		{name: "windows path", ref: `C:\keys\issuer.key`, wantClass: ClassFile, wantPath: `C:\keys\issuer.key`, wantExport: ExportabilityExportable},
		{name: "pkcs11", ref: "pkcs11:token=ca;object=issuer-a", wantClass: "pkcs11", wantPath: "pkcs11:token=ca;object=issuer-a", wantExport: ExportabilityNonExportableExpected},
		{name: "kms", ref: "kms:provider/key/version", wantClass: "kms", wantPath: "kms:provider/key/version", wantExport: ExportabilityNonExportableExpected},
		{name: "unknown", ref: "vault:path/to/key", wantClass: "vault", wantPath: "vault:path/to/key", wantExport: ExportabilityUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Class(tt.ref); got != tt.wantClass {
				t.Fatalf("Class(%q) = %q, want %q", tt.ref, got, tt.wantClass)
			}
			if got := FilePath(tt.ref); got != tt.wantPath {
				t.Fatalf("FilePath(%q) = %q, want %q", tt.ref, got, tt.wantPath)
			}
			if got := Exportability(tt.ref); got != tt.wantExport {
				t.Fatalf("Exportability(%q) = %q, want %q", tt.ref, got, tt.wantExport)
			}
		})
	}
}
