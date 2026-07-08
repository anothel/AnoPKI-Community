// SPDX-License-Identifier: MPL-2.0
package keyref

import "context"

type ProviderInfo struct {
	Class         string
	Exportability string
}

type Provider interface {
	CheckReady(context.Context, string) (ProviderInfo, error)
}

type FileProvider struct{}

func (FileProvider) CheckReady(_ context.Context, ref string) (ProviderInfo, error) {
	return ProviderInfo{
		Class:         Class(ref),
		Exportability: Exportability(ref),
	}, nil
}
