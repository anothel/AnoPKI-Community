// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "anopki/core/crl.hpp"
#include "anopki/core/csr.hpp"
#include "anopki/core/issue.hpp"
#include "anopki/core/ocsp.hpp"

#include <string>
#include <string_view>

namespace anopki::crypto {

class Backend {
public:
    virtual ~Backend() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    // OpenSSL is the only Community implementation today; AnoCrypto remains an intended future backend.
    // Pending parity work must map backend-specific failures to stable core errors.
    // Raw OpenSSL or future AnoCrypto diagnostics stay below this contract.
    [[nodiscard]] virtual core::CsrInfo inspect_csr_pem(const std::string &csr_pem) const = 0;
    [[nodiscard]] virtual core::IssueResult issue_certificate(const core::IssueRequest &request) const = 0;
    [[nodiscard]] virtual core::GenerateCRLResult generate_crl(const core::GenerateCRLRequest &request) const = 0;
    [[nodiscard]] virtual core::OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const = 0;
    [[nodiscard]] virtual core::GenerateOCSPResponseResult generate_ocsp_response(const core::GenerateOCSPResponseRequest &request) const = 0;
    [[nodiscard]] virtual core::ValidateOCSPResponderResult validate_ocsp_responder(
        const std::string &issuer_certificate_pem,
        const std::string &responder_certificate_pem) const = 0;
};

}  // namespace anopki::crypto
