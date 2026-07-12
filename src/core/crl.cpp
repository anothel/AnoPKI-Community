// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

GenerateCRLResult generate_crl(const GenerateCRLRequest &request)
{
	return crypto::default_backend().generate_crl(request);
}

CRLInfo inspect_crl_pem(const std::string &crl_pem)
{
	return crypto::default_backend().inspect_crl_pem(crl_pem);
}

CRLInfo inspect_crl_der(const std::string &crl_der)
{
	return crypto::default_backend().inspect_crl_der(crl_der);
}

} // namespace anopki::core
