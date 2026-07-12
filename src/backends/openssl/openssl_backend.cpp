// SPDX-License-Identifier: MPL-2.0
#include "openssl_backend.hpp"

#include "anopki/crypto/runtime.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>

namespace anopki::core
{

OpenSSLBackend::OpenSSLBackend()
{
    info_.id = "openssl";
    info_.dependency = "OpenSSL";
    const char *version = OpenSSL_version(OPENSSL_VERSION);
    info_.dependency_version = version == nullptr ? "unknown" : version;
    info_.readiness = crypto::BackendReadiness::ready;
    info_.capabilities = {
        crypto::BackendCapability::csr_inspect,
        crypto::BackendCapability::certificate_issue,
        crypto::BackendCapability::crl_generate,
        crypto::BackendCapability::crl_inspect,
        crypto::BackendCapability::ocsp_request_inspect,
        crypto::BackendCapability::ocsp_issuer_inspect,
        crypto::BackendCapability::ocsp_response_generate,
        crypto::BackendCapability::ocsp_responder_validate,
    };
}

const crypto::BackendInfo &OpenSSLBackend::info() const noexcept
{
    return info_;
}

crypto::ErrorDiagnostics OpenSSLBackend::drain_error_diagnostics() const
{
    crypto::ErrorDiagnostics diagnostics;
    diagnostics.field = "openssl_errors";
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error())
    {
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof(buffer));
        diagnostics.entries.emplace_back(buffer);
    }
    return diagnostics;
}

} // namespace anopki::core

namespace anopki::crypto
{

const Backend &default_backend()
{
    static const core::OpenSSLBackend backend;
    return backend;
}

} // namespace anopki::crypto
