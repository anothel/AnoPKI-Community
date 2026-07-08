// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace anopki::core
{

struct RevokedCertificate
{
	std::string serial_number;
	std::string revoked_at;
	std::string reason;
};

struct GenerateCRLRequest
{
	std::string issuer_certificate_pem;
	std::string issuer_key_ref;
	std::int64_t crl_number = 0;
	std::string this_update;
	std::string next_update;
	std::vector<RevokedCertificate> revoked_certificates;
};

struct GenerateCRLResult
{
	std::string crl_pem;
};

struct CRLInfo
{
	std::string issuer;
	int revoked_certificate_count = 0;
	std::string crl_number;
};

[[nodiscard]] GenerateCRLResult generate_crl(const GenerateCRLRequest &request);
[[nodiscard]] CRLInfo inspect_crl_pem(const std::string &crl_pem);
[[nodiscard]] CRLInfo inspect_crl_der(const std::string &crl_der);

} // namespace anopki::core
