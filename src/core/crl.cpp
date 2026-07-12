// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

GenerateCRLResult generate_crl(const GenerateCRLRequest &request)
{
	const crypto::Backend &backend = crypto::selected_backend();
	crypto::require_backend_capability(backend, crypto::BackendCapability::crl_generate);
	return backend.generate_crl(request);
}

CRLInfo inspect_crl_pem(const std::string &crl_pem)
{
	const crypto::Backend &backend = crypto::selected_backend();
	crypto::require_backend_capability(backend, crypto::BackendCapability::crl_inspect);
	return backend.inspect_crl_pem(crl_pem);
}

CRLInfo inspect_crl_der(const std::string &crl_der)
{
	const crypto::Backend &backend = crypto::selected_backend();
	crypto::require_backend_capability(backend, crypto::BackendCapability::crl_inspect);
	return backend.inspect_crl_der(crl_der);
}

} // namespace anopki::core
