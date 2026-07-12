// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/backend.hpp"

#include <algorithm>
#include <utility>

namespace anopki::crypto {

std::string_view to_string(BackendReadiness readiness) noexcept
{
    switch (readiness)
    {
    case BackendReadiness::ready:
        return "ready";
    case BackendReadiness::unavailable:
        return "unavailable";
    case BackendReadiness::error:
        return "error";
    }
    return "error";
}

std::string_view to_string(BackendCapability capability) noexcept
{
    switch (capability)
    {
    case BackendCapability::csr_inspect:
        return "csr_inspect";
    case BackendCapability::certificate_issue:
        return "certificate_issue";
    case BackendCapability::crl_generate:
        return "crl_generate";
    case BackendCapability::crl_inspect:
        return "crl_inspect";
    case BackendCapability::ocsp_request_inspect:
        return "ocsp_request_inspect";
    case BackendCapability::ocsp_issuer_inspect:
        return "ocsp_issuer_inspect";
    case BackendCapability::ocsp_response_generate:
        return "ocsp_response_generate";
    case BackendCapability::ocsp_responder_validate:
        return "ocsp_responder_validate";
    }
    return "unknown";
}

std::string_view to_string(BackendErrorCode code) noexcept
{
    switch (code)
    {
    case BackendErrorCode::capability_unavailable:
        return "backend.capability_unavailable";
    case BackendErrorCode::dependency_unavailable:
        return "backend.dependency_unavailable";
    case BackendErrorCode::version_incompatible:
        return "backend.version_incompatible";
    case BackendErrorCode::initialization_failed:
        return "backend.initialization_failed";
    case BackendErrorCode::module_not_operational:
        return "backend.module_not_operational";
    case BackendErrorCode::profile_mismatch:
        return "backend.profile_mismatch";
    case BackendErrorCode::operation_failed:
        return "backend.operation_failed";
    }
    return "backend.operation_failed";
}

bool has_capability(const BackendInfo &info, BackendCapability capability) noexcept
{
    return std::find(info.capabilities.begin(), info.capabilities.end(), capability) != info.capabilities.end();
}

BackendError::BackendError(BackendErrorCode code)
    : std::runtime_error{std::string{to_string(code)}}, code_{code}
{
}

BackendError::BackendError(BackendErrorCode code, std::string message)
    : std::runtime_error{message.empty() ? std::string{to_string(code)} : std::move(message)}, code_{code}
{
}

BackendErrorCode BackendError::code() const noexcept
{
    return code_;
}

}  // namespace anopki::crypto
