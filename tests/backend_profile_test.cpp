// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/runtime.hpp"

#include <cassert>

int main()
{
    const anopki::crypto::ProductProfileInfo &profile = anopki::crypto::selected_product_profile();
    const anopki::crypto::Backend &backend = anopki::crypto::selected_backend();

    assert(!profile.id.empty());
    assert(!profile.edition.empty());
    assert(profile.selected_backend == backend.info().id);
    assert(!profile.fallback_enabled);
    assert(backend.info().readiness == anopki::crypto::BackendReadiness::ready);
    for (const anopki::crypto::BackendCapability capability : profile.required_capabilities)
    {
        assert(anopki::crypto::has_capability(backend.info(), capability));
    }
    return 0;
}
