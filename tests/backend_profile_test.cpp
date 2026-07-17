// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/runtime.hpp"

#include <cassert>
#include <string>

int main()
{
    const anopki::crypto::ProductProfileInfo &profile = anopki::crypto::selected_product_profile();
    const anopki::crypto::Backend &backend = anopki::crypto::selected_backend();

    assert(!profile.id.empty());
    assert(!profile.edition.empty());
    assert(profile.selected_backend == backend.info().id);
    assert(!profile.fallback_enabled);
    assert(backend.info().readiness == anopki::crypto::BackendReadiness::ready);
    assert(backend.info().abi_version == 1);
    assert(backend.info().build_fingerprint.starts_with("sha256:"));
    assert(backend.info().build_fingerprint.size() == std::string{"sha256:"}.size() + 64U);
    for (const anopki::crypto::BackendCapability capability : profile.required_capabilities)
    {
        assert(anopki::crypto::has_capability(backend.info(), capability));
    }
    return 0;
}
