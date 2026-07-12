// SPDX-License-Identifier: MPL-2.0
#include "openssl_backend.hpp"

#include "anopki/crypto/runtime.hpp"

#include <openssl/err.h>

namespace anopki::core
{

std::string_view OpenSSLBackend::name() const noexcept
{
    return "openssl";
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

const Backend &default_backend() noexcept
{
    static const core::OpenSSLBackend backend;
    return backend;
}

} // namespace anopki::crypto
