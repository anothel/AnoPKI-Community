// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/csr.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

CsrInfo inspect_csr_pem(const std::string &csr_pem)
{
	return crypto::default_backend().inspect_csr_pem(csr_pem);
}

} // namespace anopki::core
