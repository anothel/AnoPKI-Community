// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "openssl_backend.hpp"
#include "key_providers/file_key_provider.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace anopki::core
{
namespace
{

constexpr const char *kCRLCreateFailed = "crl.create_failed";
constexpr const char *kCRLIssuerParseFailed = "crl.issuer_parse_failed";
constexpr const char *kCRLInvalidTime = "crl.invalid_time";
constexpr const char *kCRLParseFailed = "crl.parse_failed";

template <typename T, void (*FreeFn)(T *)>
struct OpenSslDeleter
{
	void operator()(T *value) const noexcept
	{
		FreeFn(value);
	}
};

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

struct OpenSslFreeDeleter
{
	void operator()(char *value) const noexcept
	{
		OPENSSL_free(value);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using X509CrlPtr = std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, X509_CRL_free>>;
using X509RevokedPtr = std::unique_ptr<X509_REVOKED, OpenSslDeleter<X509_REVOKED, X509_REVOKED_free>>;
using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, OpenSslDeleter<X509_EXTENSION, X509_EXTENSION_free>>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, OpenSslDeleter<ASN1_INTEGER, ASN1_INTEGER_free>>;
using Asn1EnumeratedPtr = std::unique_ptr<ASN1_ENUMERATED, OpenSslDeleter<ASN1_ENUMERATED, ASN1_ENUMERATED_free>>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, OpenSslDeleter<ASN1_TIME, ASN1_TIME_free>>;
using OpenSslStringPtr = std::unique_ptr<char, OpenSslFreeDeleter>;

[[noreturn]] void throw_error(const char *code)
{
	throw std::runtime_error{code};
}

X509Ptr parse_certificate(std::string_view pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kCRLIssuerParseFailed);
	}
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	if (!certificate)
	{
		throw_error(kCRLIssuerParseFailed);
	}
	return certificate;
}

void require_mem_buf_size(std::string_view input)
{
	if (input.size() > static_cast<std::string_view::size_type>(std::numeric_limits<int>::max()))
	{
		throw_error(kCRLParseFailed);
	}
}

X509CrlPtr parse_crl_pem(std::string_view pem)
{
	require_mem_buf_size(pem);
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kCRLParseFailed);
	}
	X509CrlPtr crl{PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)};
	if (!crl)
	{
		throw_error(kCRLParseFailed);
	}
	return crl;
}

X509CrlPtr parse_crl_der(std::string_view der)
{
	require_mem_buf_size(der);
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	if (!bio)
	{
		throw_error(kCRLParseFailed);
	}
	X509CrlPtr crl{d2i_X509_CRL_bio(bio.get(), nullptr)};
	if (!crl)
	{
		throw_error(kCRLParseFailed);
	}
	return crl;
}

std::string crl_number(X509_CRL *crl)
{
	const int extension_index = X509_CRL_get_ext_by_NID(crl, NID_crl_number, -1);
	if (extension_index < 0)
	{
		return {};
	}
	X509_EXTENSION *extension = X509_CRL_get_ext(crl, extension_index);
	if (extension == nullptr)
	{
		throw_error(kCRLParseFailed);
	}
	Asn1IntegerPtr number{static_cast<ASN1_INTEGER *>(X509V3_EXT_d2i(extension))};
	if (!number)
	{
		throw_error(kCRLParseFailed);
	}
	BIGNUM *raw = ASN1_INTEGER_to_BN(number.get(), nullptr);
	if (raw == nullptr)
	{
		throw_error(kCRLParseFailed);
	}
	BignumPtr number_bn{raw};
	OpenSslStringPtr decimal{BN_bn2dec(number_bn.get())};
	if (!decimal)
	{
		throw_error(kCRLParseFailed);
	}
	return decimal.get();
}

CRLInfo inspect_crl(X509_CRL *crl)
{
	X509_NAME *issuer_name = X509_CRL_get_issuer(crl);
	if (issuer_name == nullptr)
	{
		throw_error(kCRLParseFailed);
	}
	OpenSslStringPtr issuer{X509_NAME_oneline(issuer_name, nullptr, 0)};
	if (!issuer)
	{
		throw_error(kCRLParseFailed);
	}
	const STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
	CRLInfo info;
	info.issuer = issuer.get();
	info.revoked_certificate_count = revoked == nullptr ? 0 : sk_X509_REVOKED_num(revoked);
	info.crl_number = crl_number(crl);
	return info;
}

bool all_digits(std::string_view value)
{
	if (value.empty())
	{
		return false;
	}
	for (const char ch : value)
	{
		if (!std::isdigit(static_cast<unsigned char>(ch)))
		{
			return false;
		}
	}
	return true;
}

std::string asn1_time_from_rfc3339(std::string_view value)
{
	if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' ||
	    value[16] != ':' || value[19] != 'Z')
	{
		throw_error(kCRLInvalidTime);
	}
	return std::string{value.substr(0, 4)} + std::string{value.substr(5, 2)} + std::string{value.substr(8, 2)} +
	       std::string{value.substr(11, 2)} + std::string{value.substr(14, 2)} + std::string{value.substr(17, 2)} + "Z";
}

Asn1TimePtr make_time(std::string_view value)
{
	Asn1TimePtr time{ASN1_TIME_new()};
	if (!time)
	{
		throw_error(kCRLCreateFailed);
	}
	const std::string asn1_time = asn1_time_from_rfc3339(value);
	if (ASN1_TIME_set_string(time.get(), asn1_time.c_str()) != 1)
	{
		throw_error(kCRLInvalidTime);
	}
	return time;
}

Asn1IntegerPtr serial_from_decimal(std::string_view value)
{
	if (!all_digits(value))
	{
		throw_error(kCRLCreateFailed);
	}
	BIGNUM *raw = nullptr;
	if (BN_dec2bn(&raw, std::string{value}.c_str()) == 0 || raw == nullptr)
	{
		throw_error(kCRLCreateFailed);
	}
	BignumPtr serial_bn{raw};
	Asn1IntegerPtr serial{BN_to_ASN1_INTEGER(serial_bn.get(), nullptr)};
	if (!serial)
	{
		throw_error(kCRLCreateFailed);
	}
	return serial;
}

Asn1IntegerPtr integer_from_int64(std::int64_t value)
{
	if (value < 0)
	{
		throw_error(kCRLCreateFailed);
	}
	BIGNUM *raw = nullptr;
	if (BN_dec2bn(&raw, std::to_string(value).c_str()) == 0 || raw == nullptr)
	{
		throw_error(kCRLCreateFailed);
	}
	BignumPtr number_bn{raw};
	Asn1IntegerPtr number{BN_to_ASN1_INTEGER(number_bn.get(), nullptr)};
	if (!number)
	{
		throw_error(kCRLCreateFailed);
	}
	return number;
}

long reason_code(std::string_view reason)
{
	if (reason == "key_compromise")
	{
		return 1;
	}
	if (reason == "ca_compromise")
	{
		return 2;
	}
	if (reason == "affiliation_changed")
	{
		return 3;
	}
	if (reason == "superseded")
	{
		return 4;
	}
	if (reason == "cessation_of_operation")
	{
		return 5;
	}
	if (reason == "privilege_withdrawn")
	{
		return 9;
	}
	if (reason == "unspecified" || reason.empty())
	{
		return 0;
	}
	throw_error(kCRLCreateFailed);
}

void add_crl_number_extension(X509_CRL *crl, std::int64_t crl_number)
{
	Asn1IntegerPtr number = integer_from_int64(crl_number);
	X509ExtensionPtr extension{X509V3_EXT_i2d(NID_crl_number, 0, number.get())};
	if (!extension || X509_CRL_add_ext(crl, extension.get(), -1) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
}

void add_revoked_entry(X509_CRL *crl, const RevokedCertificate &entry)
{
	X509RevokedPtr revoked{X509_REVOKED_new()};
	if (!revoked)
	{
		throw_error(kCRLCreateFailed);
	}
	Asn1IntegerPtr serial = serial_from_decimal(entry.serial_number);
	Asn1TimePtr revoked_at = make_time(entry.revoked_at);
	if (X509_REVOKED_set_serialNumber(revoked.get(), serial.get()) != 1 ||
	    X509_REVOKED_set_revocationDate(revoked.get(), revoked_at.get()) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	Asn1EnumeratedPtr reason{ASN1_ENUMERATED_new()};
	if (!reason || ASN1_ENUMERATED_set(reason.get(), reason_code(entry.reason)) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	X509ExtensionPtr reason_extension{X509V3_EXT_i2d(NID_crl_reason, 0, reason.get())};
	if (!reason_extension || X509_REVOKED_add_ext(revoked.get(), reason_extension.get(), -1) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	if (X509_CRL_add0_revoked(crl, revoked.get()) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	(void)revoked.release();
}

std::string crl_to_pem(X509_CRL *crl)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	if (!bio || PEM_write_bio_X509_CRL(bio.get(), crl) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	if (size <= 0 || data == nullptr)
	{
		throw_error(kCRLCreateFailed);
	}
	return std::string{data, static_cast<std::string::size_type>(size)};
}

} // namespace

GenerateCRLResult OpenSSLBackend::generate_crl(const GenerateCRLRequest &request) const
{
	X509Ptr issuer = parse_certificate(request.issuer_certificate_pem);
	openssl_key_providers::SigningKeyHandle issuer_key =
	    openssl_key_providers::resolve_crl_signing_key(
	        request.issuer_key_ref,
	        issuer.get(),
	        openssl_key_providers::provider_policy_from_environment());

	X509CrlPtr crl{X509_CRL_new()};
	if (!crl || X509_CRL_set_version(crl.get(), 1) != 1 ||
	    X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer.get())) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	Asn1TimePtr this_update = make_time(request.this_update);
	Asn1TimePtr next_update = make_time(request.next_update);
	if (X509_CRL_set1_lastUpdate(crl.get(), this_update.get()) != 1 ||
	    X509_CRL_set1_nextUpdate(crl.get(), next_update.get()) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	add_crl_number_extension(crl.get(), request.crl_number);
	for (const RevokedCertificate &entry : request.revoked_certificates)
	{
		add_revoked_entry(crl.get(), entry);
	}
	if (X509_CRL_sort(crl.get()) != 1)
	{
		throw_error(kCRLCreateFailed);
	}
	if (X509_CRL_sign(crl.get(), issuer_key.native_handle(), EVP_sha256()) <= 0)
	{
		openssl_key_providers::throw_provider_sign_failed(issuer_key);
	}

	GenerateCRLResult result;
	result.crl_pem = crl_to_pem(crl.get());
	return result;
}

CRLInfo OpenSSLBackend::inspect_crl_pem(const std::string &crl_pem) const
{
	return inspect_crl(parse_crl_pem(crl_pem).get());
}

CRLInfo OpenSSLBackend::inspect_crl_der(const std::string &crl_der) const
{
	return inspect_crl(parse_crl_der(crl_der).get());
}

} // namespace anopki::core
