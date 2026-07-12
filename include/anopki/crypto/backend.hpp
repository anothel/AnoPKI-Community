// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "anopki/core/crl.hpp"
#include "anopki/core/csr.hpp"
#include "anopki/core/issue.hpp"
#include "anopki/core/ocsp.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace anopki::crypto {

struct ErrorDiagnostics
{
    std::string field;
    std::vector<std::string> entries;
};

class Backend {
public:
    virtual ~Backend() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    // The operation contract is dependency-neutral. Adapter-specific types and
    // raw dependency errors must remain below this boundary.
    [[nodiscard]] virtual core::CsrInfo inspect_csr_pem(const std::string &csr_pem) const = 0;
    [[nodiscard]] virtual core::IssueResult issue_certificate(const core::IssueRequest &request) const = 0;
    [[nodiscard]] virtual core::GenerateCRLResult generate_crl(const core::GenerateCRLRequest &request) const = 0;
    [[nodiscard]] virtual core::CRLInfo inspect_crl_pem(const std::string &crl_pem) const = 0;
    [[nodiscard]] virtual core::CRLInfo inspect_crl_der(const std::string &crl_der) const = 0;
    [[nodiscard]] virtual core::OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const = 0;
    [[nodiscard]] virtual core::OCSPIssuerInfo inspect_ocsp_issuer_pem(
        const std::string &issuer_certificate_pem,
        const std::string &hash_algorithm) const = 0;
    [[nodiscard]] virtual core::GenerateOCSPResponseResult generate_ocsp_response(
        const core::GenerateOCSPResponseRequest &request) const = 0;
    [[nodiscard]] virtual core::ValidateOCSPResponderResult validate_ocsp_responder(
        const std::string &issuer_certificate_pem,
        const std::string &responder_certificate_pem) const = 0;

    // Diagnostics are optional and profile-specific. Stable error codes remain
    // the cross-adapter contract; the OpenSSL adapter currently exposes the
    // legacy `openssl_errors` field through this hook.
    [[nodiscard]] virtual ErrorDiagnostics drain_error_diagnostics() const
    {
        return {};
    }
};

}  // namespace anopki::crypto
