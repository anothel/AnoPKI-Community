// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace
{

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

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using X509CrlPtr = std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, X509_CRL_free>>;
using Asn1IntegerPtr = std::unique_ptr<ASN1_INTEGER, OpenSslDeleter<ASN1_INTEGER, ASN1_INTEGER_free>>;

void require(bool condition)
{
	if (!condition)
	{
		std::abort();
	}
}

EvpPkeyPtr make_rsa_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	require(context != nullptr);
	require(EVP_PKEY_keygen_init(context.get()) == 1);
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1);
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1);
	return EvpPkeyPtr{key};
}

void set_name(X509_NAME *name, const char *common_name)
{
	require(X509_NAME_add_entry_by_txt(
	            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0) == 1);
}

void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr);
	require(X509_add_ext(certificate, extension, -1) == 1);
	X509_EXTENSION_free(extension);
}

X509Ptr make_ca_certificate(EVP_PKEY *key)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	BignumPtr serial{BN_new()};
	require(serial != nullptr);
	require(BN_set_word(serial.get(), 1) == 1);
	require(BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(certificate.get())) != nullptr);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), "Test CA");
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	require(X509_sign(certificate.get(), key, EVP_sha256()) > 0);
	return certificate;
}

std::string certificate_to_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_X509(bio.get(), certificate) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string private_key_to_pem(EVP_PKEY *key)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string crl_to_der(X509_CRL *crl)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(i2d_X509_CRL_bio(bio.get(), crl) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

X509CrlPtr crl_from_pem(const std::string &pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	require(bio != nullptr);
	X509CrlPtr crl{PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)};
	require(crl != nullptr);
	return crl;
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

} // namespace

int main(int argc, char *argv[])
{
	require(argc == 2);
	const std::filesystem::path work_dir = argv[1];
	const EvpPkeyPtr ca_key = make_rsa_key();
	const X509Ptr ca_certificate = make_ca_certificate(ca_key.get());
	const std::filesystem::path issuer_key_path = work_dir / "core_crl_issuer.key";
	write_file(issuer_key_path, private_key_to_pem(ca_key.get()));

	anopki::core::GenerateCRLRequest request;
	request.issuer_certificate_pem = certificate_to_pem(ca_certificate.get());
	request.issuer_key_ref = issuer_key_path.string();
	request.crl_number = 2147483648LL;
	request.this_update = "2026-06-13T00:00:00Z";
	request.next_update = "2026-06-14T00:00:00Z";
	request.revoked_certificates.push_back({"1234", "2026-06-13T01:00:00Z", "key_compromise"});

	const anopki::core::GenerateCRLResult result = anopki::core::generate_crl(request);
	const X509CrlPtr crl = crl_from_pem(result.crl_pem);
	require(X509_CRL_get_version(crl.get()) == 1);
	require(sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl.get())) == 1);

	const int crl_number_index = X509_CRL_get_ext_by_NID(crl.get(), NID_crl_number, -1);
	require(crl_number_index >= 0);
	X509_EXTENSION *crl_number_extension = X509_CRL_get_ext(crl.get(), crl_number_index);
	Asn1IntegerPtr crl_number{static_cast<ASN1_INTEGER *>(X509V3_EXT_d2i(crl_number_extension))};
	require(crl_number != nullptr);
	BIGNUM *raw_crl_number = ASN1_INTEGER_to_BN(crl_number.get(), nullptr);
	require(raw_crl_number != nullptr);
	BignumPtr decoded_crl_number{raw_crl_number};
	char *decoded_decimal_raw = BN_bn2dec(decoded_crl_number.get());
	require(decoded_decimal_raw != nullptr);
	const std::string decoded_decimal{decoded_decimal_raw};
	OPENSSL_free(decoded_decimal_raw);
	require(decoded_decimal == "2147483648");

	const anopki::core::CRLInfo pem_info = anopki::core::inspect_crl_pem(result.crl_pem);
	require(pem_info.issuer == "/CN=Test CA");
	require(pem_info.revoked_certificate_count == 1);
	require(pem_info.crl_number == "2147483648");

	const anopki::core::CRLInfo der_info = anopki::core::inspect_crl_der(crl_to_der(crl.get()));
	require(der_info.issuer == pem_info.issuer);
	require(der_info.revoked_certificate_count == pem_info.revoked_certificate_count);
	require(der_info.crl_number == pem_info.crl_number);
	return 0;
}
