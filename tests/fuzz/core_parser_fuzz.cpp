// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "anopki/core/csr.hpp"
#include "anopki/core/ocsp.hpp"

#include <openssl/err.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string input{reinterpret_cast<const char *>(data), size};
	ERR_clear_error();
	try
	{
#if defined(ANOPKI_FUZZ_CSR)
		(void)anopki::core::inspect_csr_pem(input);
#elif defined(ANOPKI_FUZZ_OCSP)
		(void)anopki::core::inspect_ocsp_request_der(input);
#elif defined(ANOPKI_FUZZ_CRL)
		(void)anopki::core::inspect_crl_der(input);
#else
#error "No parser fuzzer selected"
#endif
	}
	catch (const std::exception &)
	{
	}
	catch (...)
	{
	}
	ERR_clear_error();
	return 0;
}
