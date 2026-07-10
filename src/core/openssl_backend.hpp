// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "anopki/crypto/backend.hpp"

namespace anopki::core
{

class OpenSSLBackend final : public crypto::Backend
{
public:
	[[nodiscard]] std::string_view name() const noexcept override
	{
		return "openssl";
	}

	[[nodiscard]] CsrInfo inspect_csr_pem(const std::string &csr_pem) const override;
	[[nodiscard]] IssueResult issue_certificate(const IssueRequest &request) const override;
	[[nodiscard]] GenerateCRLResult generate_crl(const GenerateCRLRequest &request) const override;
	[[nodiscard]] OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const override;
	[[nodiscard]] GenerateOCSPResponseResult generate_ocsp_response(const GenerateOCSPResponseRequest &request) const override;
	[[nodiscard]] ValidateOCSPResponderResult validate_ocsp_responder(
	    const std::string &issuer_certificate_pem,
	    const std::string &responder_certificate_pem) const override;
};

inline const crypto::Backend &default_crypto_backend() noexcept
{
	static const OpenSSLBackend backend;
	return backend;
}

} // namespace anopki::core
