// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/backend.hpp"

#include <cassert>
#include <string>
#include <string_view>

namespace
{

class FakeBackend final : public anopki::crypto::Backend
{
public:
	[[nodiscard]] std::string_view name() const noexcept override
	{
		return "fake";
	}

	[[nodiscard]] anopki::core::CsrInfo inspect_csr_pem(const std::string &csr_pem) const override
	{
		anopki::core::CsrInfo info;
		info.subject = csr_pem;
		return info;
	}

	[[nodiscard]] anopki::core::IssueResult issue_certificate(const anopki::core::IssueRequest &request) const override
	{
		anopki::core::IssueResult result;
		result.subject = request.subject;
		return result;
	}

	[[nodiscard]] anopki::core::GenerateCRLResult generate_crl(const anopki::core::GenerateCRLRequest &request) const override
	{
		anopki::core::GenerateCRLResult result;
		result.crl_pem = std::to_string(request.crl_number);
		return result;
	}

	[[nodiscard]] anopki::core::OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const override
	{
		anopki::core::OCSPRequestInfo info;
		info.nonce_hex = request_der;
		return info;
	}

	[[nodiscard]] anopki::core::GenerateOCSPResponseResult generate_ocsp_response(const anopki::core::GenerateOCSPResponseRequest &request) const override
	{
		anopki::core::GenerateOCSPResponseResult result;
		result.response_der = request.this_update;
		return result;
	}

	[[nodiscard]] anopki::core::ValidateOCSPResponderResult validate_ocsp_responder(const std::string &issuer_certificate_pem, const std::string &responder_certificate_pem) const override
	{
		anopki::core::ValidateOCSPResponderResult result;
		result.valid = !issuer_certificate_pem.empty() && !responder_certificate_pem.empty();
		return result;
	}
};

} // namespace

int main()
{
	FakeBackend fake;
	const anopki::crypto::Backend &backend = fake;

	anopki::core::IssueRequest issue;
	issue.subject = "CN=leaf";
	anopki::core::GenerateCRLRequest crl;
	crl.crl_number = 42;
	anopki::core::GenerateOCSPResponseRequest ocsp;
	ocsp.this_update = "2026-06-13T00:00:00Z";

	assert(backend.name() == "fake");
	assert(backend.inspect_csr_pem("CN=leaf").subject == "CN=leaf");
	assert(backend.issue_certificate(issue).subject == "CN=leaf");
	assert(backend.generate_crl(crl).crl_pem == "42");
	assert(backend.inspect_ocsp_request_der("0102").nonce_hex == "0102");
	assert(backend.generate_ocsp_response(ocsp).response_der == "2026-06-13T00:00:00Z");
	assert(backend.validate_ocsp_responder("issuer", "responder").valid);
	return 0;
}
