// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/runtime.hpp"

#ifndef ANOPKI_PRODUCT_PROFILE_ID
#define ANOPKI_PRODUCT_PROFILE_ID "unknown"
#endif
#ifndef ANOPKI_EDITION_ID
#define ANOPKI_EDITION_ID "unknown"
#endif
#ifndef ANOPKI_SELECTED_BACKEND_ID
#define ANOPKI_SELECTED_BACKEND_ID "unknown"
#endif
#ifndef ANOPKI_PROFILE_REQUIRES_FULL_OPERATIONS
#define ANOPKI_PROFILE_REQUIRES_FULL_OPERATIONS 0
#endif

namespace anopki::crypto {
namespace {

std::vector<BackendCapability> all_operation_capabilities()
{
    return {
        BackendCapability::csr_inspect,
        BackendCapability::certificate_issue,
        BackendCapability::crl_generate,
        BackendCapability::crl_inspect,
        BackendCapability::ocsp_request_inspect,
        BackendCapability::ocsp_issuer_inspect,
        BackendCapability::ocsp_response_generate,
        BackendCapability::ocsp_responder_validate,
    };
}

}  // namespace

const ProductProfileInfo &selected_product_profile() noexcept
{
    static const ProductProfileInfo profile{
        ANOPKI_PRODUCT_PROFILE_ID,
        ANOPKI_EDITION_ID,
        ANOPKI_SELECTED_BACKEND_ID,
        false,
#if ANOPKI_PROFILE_REQUIRES_FULL_OPERATIONS
        all_operation_capabilities(),
#else
        {},
#endif
    };
    return profile;
}

void require_backend_capability(const Backend &backend, BackendCapability capability)
{
    if (!has_capability(backend.info(), capability))
    {
        throw BackendError{BackendErrorCode::capability_unavailable};
    }
}

void validate_selected_backend()
{
    const Backend &backend = default_backend();
    const BackendInfo &info = backend.info();
    const ProductProfileInfo &profile = selected_product_profile();

    if (info.id != profile.selected_backend)
    {
        throw BackendError{BackendErrorCode::profile_mismatch};
    }
    if (info.readiness == BackendReadiness::unavailable)
    {
        throw BackendError{BackendErrorCode::dependency_unavailable};
    }
    if (info.readiness != BackendReadiness::ready)
    {
        throw BackendError{BackendErrorCode::module_not_operational};
    }
    for (const BackendCapability capability : profile.required_capabilities)
    {
        require_backend_capability(backend, capability);
    }
}

const Backend &selected_backend()
{
    validate_selected_backend();
    return default_backend();
}

ErrorDiagnostics drain_selected_backend_diagnostics() noexcept
{
    try
    {
        return default_backend().drain_error_diagnostics();
    }
    catch (...)
    {
        return {};
    }
}

}  // namespace anopki::crypto
