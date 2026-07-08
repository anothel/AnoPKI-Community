// SPDX-License-Identifier: MPL-2.0
package keyref

import (
	"context"
	"testing"
)

func TestFileProviderReadinessClassifiesKey(t *testing.T) {
	var provider Provider = FileProvider{}

	info, err := provider.CheckReady(context.Background(), "file:/tmp/issuer.key")
	if err != nil {
		t.Fatalf("CheckReady returned error: %v", err)
	}
	if info.Class != ClassFile || info.Exportability != ExportabilityExportable {
		t.Fatalf("provider info = %#v", info)
	}
}
