// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "anopki/crypto/backend.hpp"

namespace anopki::core
{

class OpenSSLBackend final : public crypto::Backend
{
public:
    OpenSSLBackend();

    [[nodiscard]] const crypto::BackendInfo &info() const noexcept override;

    [[nodiscard]] CsrInfo inspect_csr_pem(const std::string &csr_pem) const override;
    [[nodiscard]] IssueResult issue_certificate(const IssueRequest &request) const override;
    [[nodiscard]] GenerateCRLResult generate_crl(const GenerateCRLRequest &request) const override;
    [[nodiscard]] CRLInfo inspect_crl_pem(const std::string &crl_pem) const override;
    [[nodiscard]] CRLInfo inspect_crl_der(const std::string &crl_der) const override;
    [[nodiscard]] OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const override;
    [[nodiscard]] OCSPIssuerInfo inspect_ocsp_issuer_pem(
        const std::string &issuer_certificate_pem,
        const std::string &hash_algorithm) const override;
    [[nodiscard]] GenerateOCSPResponseResult generate_ocsp_response(
        const GenerateOCSPResponseRequest &request) const override;
    [[nodiscard]] ValidateOCSPResponderResult validate_ocsp_responder(
        const std::string &issuer_certificate_pem,
        const std::string &responder_certificate_pem) const override;
    [[nodiscard]] crypto::ErrorDiagnostics drain_error_diagnostics() const override;

private:
    crypto::BackendInfo info_;
};

} // namespace anopki::core
