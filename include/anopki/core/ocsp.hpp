// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <string>
#include <vector>

namespace anopki::core
{

struct OCSPCertificateID
{
	std::string serial_number;
	std::string issuer_name_hash;
	std::string issuer_key_hash;
	std::string hash_algorithm;
};

struct OCSPRequestInfo
{
	std::vector<OCSPCertificateID> certificates;
	bool has_nonce = false;
	std::string nonce_hex;
};

struct OCSPIssuerInfo
{
	std::string issuer_name_hash;
	std::string issuer_key_hash;
	std::string hash_algorithm;
};

struct OCSPCertificateStatus
{
	std::string serial_number;
	std::string status;
	std::string revoked_at;
	std::string revocation_reason;
	std::string hash_algorithm;
	std::string issuer_name_hash;
	std::string issuer_key_hash;
};

struct GenerateOCSPResponseRequest
{
	std::string request_der;
	std::string issuer_certificate_pem;
	std::string issuer_key_ref;
	std::string this_update;
	std::string next_update;
	std::vector<OCSPCertificateStatus> certificates;
};

struct ValidateOCSPResponderResult
{
	bool valid = false;
};

struct GenerateOCSPResponseResult
{
	std::string response_der;
};

[[nodiscard]] OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der);
[[nodiscard]] OCSPIssuerInfo inspect_ocsp_issuer_pem(const std::string &issuer_certificate_pem, const std::string &hash_algorithm);
[[nodiscard]] ValidateOCSPResponderResult validate_ocsp_responder(const std::string &issuer_certificate_pem, const std::string &responder_certificate_pem);
[[nodiscard]] GenerateOCSPResponseResult generate_ocsp_response(const GenerateOCSPResponseRequest &request);

} // namespace anopki::core
