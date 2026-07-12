// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/ocsp.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der)
{
	return crypto::default_backend().inspect_ocsp_request_der(request_der);
}

OCSPIssuerInfo inspect_ocsp_issuer_pem(
    const std::string &issuer_certificate_pem,
    const std::string &hash_algorithm)
{
	return crypto::default_backend().inspect_ocsp_issuer_pem(issuer_certificate_pem, hash_algorithm);
}

ValidateOCSPResponderResult validate_ocsp_responder(
    const std::string &issuer_certificate_pem,
    const std::string &responder_certificate_pem)
{
	return crypto::default_backend().validate_ocsp_responder(issuer_certificate_pem, responder_certificate_pem);
}

GenerateOCSPResponseResult generate_ocsp_response(const GenerateOCSPResponseRequest &request)
{
	return crypto::default_backend().generate_ocsp_response(request);
}

} // namespace anopki::core
