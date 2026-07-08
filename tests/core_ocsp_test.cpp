// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/ocsp.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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
using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>;
using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

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

void set_serial(X509 *certificate, unsigned long serial)
{
	BignumPtr serial_bn{BN_new()};
	require(serial_bn != nullptr);
	require(BN_set_word(serial_bn.get(), serial) == 1);
	require(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate)) != nullptr);
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

X509Ptr make_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *common_name, unsigned long serial, bool ca)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	set_serial(certificate.get(), serial);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), common_name);
	require(X509_set_issuer_name(certificate.get(), issuer == nullptr ? X509_get_subject_name(certificate.get()) : X509_get_subject_name(issuer)) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	if (ca)
	{
		add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
		add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	}
	require(X509_sign(certificate.get(), issuer_key == nullptr ? key : issuer_key, EVP_sha256()) > 0);
	return certificate;
}

X509Ptr make_ocsp_responder_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *common_name, unsigned long serial, bool ocsp_signing, long not_before_offset_seconds, long not_after_offset_seconds)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	set_serial(certificate.get(), serial);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), not_before_offset_seconds);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), not_after_offset_seconds);
	set_name(X509_get_subject_name(certificate.get()), common_name);
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	add_extension(certificate.get(), issuer, NID_basic_constraints, "critical,CA:FALSE");
	add_extension(certificate.get(), issuer, NID_key_usage, "critical,digitalSignature");
	if (ocsp_signing)
	{
		add_extension(certificate.get(), issuer, NID_ext_key_usage, "OCSPSigning");
	}
	require(X509_sign(certificate.get(), issuer_key, EVP_sha256()) > 0);
	return certificate;
}

X509Ptr make_ocsp_responder_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *common_name, unsigned long serial, bool ocsp_signing)
{
	return make_ocsp_responder_certificate(key, issuer, issuer_key, common_name, serial, ocsp_signing, 0, 86400);
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

std::string ocsp_request_der(X509 *leaf, X509 *issuer, const EVP_MD *digest, OCSP_CERTID **out_id)
{
	OCSPRequestPtr request{OCSP_REQUEST_new()};
	require(request != nullptr);
	OCSP_CERTID *id = OCSP_cert_to_id(digest, leaf, issuer);
	require(id != nullptr);
	*out_id = OCSP_CERTID_dup(id);
	require(*out_id != nullptr);
	require(OCSP_request_add0_id(request.get(), id) != nullptr);
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string ocsp_request_der_with_nonce(X509 *leaf, X509 *issuer, const unsigned char *nonce, int nonce_size, OCSP_CERTID **out_id)
{
	OCSPRequestPtr request{OCSP_REQUEST_new()};
	require(request != nullptr);
	OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), leaf, issuer);
	require(id != nullptr);
	*out_id = OCSP_CERTID_dup(id);
	require(*out_id != nullptr);
	require(OCSP_request_add0_id(request.get(), id) != nullptr);
	require(OCSP_request_add1_nonce(request.get(), const_cast<unsigned char *>(nonce), nonce_size) == 1);
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string ocsp_request_der(X509 *leaf, X509 *issuer, OCSP_CERTID **out_id)
{
	return ocsp_request_der(leaf, issuer, EVP_sha1(), out_id);
}

std::string ocsp_request_der(X509 *leaf, X509 *issuer, const std::vector<const EVP_MD *> &digests, std::vector<OCSPCertIDPtr> &out_ids)
{
	OCSPRequestPtr request{OCSP_REQUEST_new()};
	require(request != nullptr);
	for (const EVP_MD *digest : digests)
	{
		OCSP_CERTID *id = OCSP_cert_to_id(digest, leaf, issuer);
		require(id != nullptr);
		OCSP_CERTID *copy = OCSP_CERTID_dup(id);
		require(copy != nullptr);
		out_ids.push_back(OCSPCertIDPtr{copy});
		require(OCSP_request_add0_id(request.get(), id) != nullptr);
	}
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input.good())
	{
		std::cerr << "failed to open fixture: " << path << "\n";
		std::exit(1);
	}
	std::ostringstream contents;
	contents << input.rdbuf();
	return contents.str();
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

OCSPResponsePtr ocsp_response_from_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	require(bio != nullptr);
	OCSPResponsePtr response{d2i_OCSP_RESPONSE_bio(bio.get(), nullptr)};
	require(response != nullptr);
	return response;
}

OCSPRequestPtr ocsp_request_from_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	require(bio != nullptr);
	OCSPRequestPtr request{d2i_OCSP_REQUEST_bio(bio.get(), nullptr)};
	require(request != nullptr);
	return request;
}

std::optional<unsigned char> base64_value(char value)
{
	if (value >= 'A' && value <= 'Z')
	{
		return static_cast<unsigned char>(value - 'A');
	}
	if (value >= 'a' && value <= 'z')
	{
		return static_cast<unsigned char>(value - 'a' + 26);
	}
	if (value >= '0' && value <= '9')
	{
		return static_cast<unsigned char>(value - '0' + 52);
	}
	if (value == '+')
	{
		return 62;
	}
	if (value == '/')
	{
		return 63;
	}
	return std::nullopt;
}

std::string decode_base64(std::string_view input)
{
	std::string output;
	unsigned int accumulator = 0;
	int bits = -8;
	for (char ch : input)
	{
		if (ch == '=')
		{
			break;
		}
		const std::optional<unsigned char> value = base64_value(ch);
		if (!value.has_value())
		{
			continue;
		}
		accumulator = ((accumulator << 6) | *value) & 0xffffff;
		bits += 6;
		if (bits >= 0)
		{
			output.push_back(static_cast<char>((accumulator >> bits) & 0xff));
			bits -= 8;
		}
	}
	return output;
}

void assert_curated_ocsp_request_vector(const std::filesystem::path &fixture_dir)
{
	const std::string request_der = decode_base64(read_file(fixture_dir / "curated-single-request.der.b64"));
	const anopki::core::OCSPRequestInfo info = anopki::core::inspect_ocsp_request_der(request_der);
	require(info.certificates.size() == 1);
	require(!info.has_nonce);
	require(info.nonce_hex.empty());
	require(info.certificates[0].serial_number == "1001");
	require(info.certificates[0].issuer_name_hash == "84378ae02c8a13718b0efda0e3a283b0006a4265");
	require(info.certificates[0].issuer_key_hash == "d5dcea91c8d109ec61e84d07bea04fab0b720ac3");
	require(info.certificates[0].hash_algorithm == "sha1");
}

} // namespace

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		std::cerr << "usage: anopki_core_ocsp_test <work-dir> <fixture-dir>\n";
		return 2;
	}
	const std::filesystem::path work_dir = argv[1];
	const std::filesystem::path fixture_dir = argv[2];
	const EvpPkeyPtr issuer_key = make_rsa_key();
	const X509Ptr issuer = make_certificate(issuer_key.get(), nullptr, nullptr, "Test CA", 1, true);
	const EvpPkeyPtr leaf_key = make_rsa_key();
	const X509Ptr leaf = make_certificate(leaf_key.get(), issuer.get(), issuer_key.get(), "Leaf", 1001, false);
	const std::filesystem::path issuer_key_path = work_dir / "core_ocsp_issuer.key";
	write_file(issuer_key_path, private_key_to_pem(issuer_key.get()));

	OCSP_CERTID *raw_id = nullptr;
	const std::string request_der = ocsp_request_der(leaf.get(), issuer.get(), &raw_id);
	OCSPCertIDPtr id{raw_id};

	const anopki::core::OCSPRequestInfo info = anopki::core::inspect_ocsp_request_der(request_der);
	require(info.certificates.size() == 1);
	require(info.certificates[0].serial_number == "1001");
	require(info.certificates[0].hash_algorithm == "sha1");
	require(!info.certificates[0].issuer_name_hash.empty());
	require(!info.certificates[0].issuer_key_hash.empty());
	const anopki::core::OCSPIssuerInfo issuer_info = anopki::core::inspect_ocsp_issuer_pem(certificate_to_pem(issuer.get()), "sha1");
	require(issuer_info.hash_algorithm == "sha1");
	require(issuer_info.issuer_name_hash == info.certificates[0].issuer_name_hash);
	require(issuer_info.issuer_key_hash == info.certificates[0].issuer_key_hash);

	OCSP_CERTID *sha256_raw_id = nullptr;
	const std::string sha256_request_der = ocsp_request_der(leaf.get(), issuer.get(), EVP_sha256(), &sha256_raw_id);
	OCSPCertIDPtr sha256_id{sha256_raw_id};
	const anopki::core::OCSPRequestInfo sha256_info = anopki::core::inspect_ocsp_request_der(sha256_request_der);
	require(sha256_info.certificates.size() == 1);
	require(sha256_info.certificates[0].serial_number == "1001");
	require(sha256_info.certificates[0].hash_algorithm == "sha256");
	const anopki::core::OCSPIssuerInfo sha256_issuer_info = anopki::core::inspect_ocsp_issuer_pem(certificate_to_pem(issuer.get()), "sha256");
	require(sha256_issuer_info.hash_algorithm == "sha256");
	require(sha256_issuer_info.issuer_name_hash == sha256_info.certificates[0].issuer_name_hash);
	require(sha256_issuer_info.issuer_key_hash == sha256_info.certificates[0].issuer_key_hash);

	anopki::core::GenerateOCSPResponseRequest response_request;
	response_request.request_der = request_der;
	response_request.issuer_certificate_pem = certificate_to_pem(issuer.get());
	response_request.issuer_key_ref = issuer_key_path.string();
	response_request.this_update = "2026-06-13T00:00:00Z";
	response_request.next_update = "2026-06-14T00:00:00Z";
	anopki::core::OCSPCertificateStatus revoked_status;
	revoked_status.serial_number = "1001";
	revoked_status.status = "revoked";
	revoked_status.revoked_at = "2026-06-13T01:00:00Z";
	revoked_status.revocation_reason = "key_compromise";
	revoked_status.hash_algorithm = info.certificates[0].hash_algorithm;
	revoked_status.issuer_name_hash = info.certificates[0].issuer_name_hash;
	revoked_status.issuer_key_hash = info.certificates[0].issuer_key_hash;
	response_request.certificates.push_back(revoked_status);

	const anopki::core::GenerateOCSPResponseResult response_result = anopki::core::generate_ocsp_response(response_request);
	const OCSPResponsePtr response = ocsp_response_from_der(response_result.response_der);
	require(OCSP_response_status(response.get()) == OCSP_RESPONSE_STATUS_SUCCESSFUL);
	OCSPBasicResponsePtr basic{OCSP_response_get1_basic(response.get())};
	require(basic != nullptr);
	int status = -1;
	int reason = -1;
	ASN1_GENERALIZEDTIME *revocation_time = nullptr;
	ASN1_GENERALIZEDTIME *this_update = nullptr;
	ASN1_GENERALIZEDTIME *next_update = nullptr;
	require(OCSP_resp_find_status(basic.get(), id.get(), &status, &reason, &revocation_time, &this_update, &next_update) == 1);
	require(status == V_OCSP_CERTSTATUS_REVOKED);
	require(reason == OCSP_REVOKED_STATUS_KEYCOMPROMISE);

	const EvpPkeyPtr responder_key = make_rsa_key();
	const X509Ptr responder = make_ocsp_responder_certificate(
	    responder_key.get(), issuer.get(), issuer_key.get(), "OCSP Responder", 2001, true);
	const std::filesystem::path responder_key_path = work_dir / "core_ocsp_responder.key";
	write_file(responder_key_path, private_key_to_pem(responder_key.get()));
	anopki::core::GenerateOCSPResponseRequest responder_response_request = response_request;
	responder_response_request.issuer_certificate_pem = certificate_to_pem(responder.get());
	responder_response_request.issuer_key_ref = responder_key_path.string();
	const anopki::core::GenerateOCSPResponseResult responder_response_result =
	    anopki::core::generate_ocsp_response(responder_response_request);
	const OCSPResponsePtr responder_response = ocsp_response_from_der(responder_response_result.response_der);
	require(OCSP_response_status(responder_response.get()) == OCSP_RESPONSE_STATUS_SUCCESSFUL);

	const EvpPkeyPtr invalid_responder_key = make_rsa_key();
	const X509Ptr invalid_responder = make_ocsp_responder_certificate(invalid_responder_key.get(), issuer.get(), issuer_key.get(), "Invalid OCSP Responder", 2002, false);
	const anopki::core::ValidateOCSPResponderResult valid_responder_result = anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(responder.get()));
	if (!valid_responder_result.valid)
	{
		throw std::runtime_error{"valid delegated responder was rejected"};
	}

	bool rejected_invalid_policy = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(invalid_responder.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_invalid_policy = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_invalid_policy)
	{
		throw std::runtime_error{"invalid delegated responder policy accepted"};
	}

	bool rejected_ca_responder = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(issuer.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_ca_responder = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_ca_responder)
	{
		throw std::runtime_error{"CA certificate accepted as registered OCSP responder"};
	}

	const X509Ptr other_issuer = make_certificate(issuer_key.get(), nullptr, nullptr, "Other Issuer", 9301, true);
	bool rejected_issuer_mismatch = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(other_issuer.get()), certificate_to_pem(responder.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_issuer_mismatch = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_issuer_mismatch)
	{
		throw std::runtime_error{"OCSP responder issuer mismatch accepted"};
	}

	const EvpPkeyPtr expired_responder_key = make_rsa_key();
	const X509Ptr expired_responder = make_ocsp_responder_certificate(expired_responder_key.get(), issuer.get(), issuer_key.get(), "Expired OCSP Responder", 2003, true, -172800, -86400);
	bool rejected_expired_responder = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(expired_responder.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_expired_responder = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_expired_responder)
	{
		throw std::runtime_error{"expired OCSP responder accepted"};
	}

	const EvpPkeyPtr future_responder_key = make_rsa_key();
	const X509Ptr future_responder = make_ocsp_responder_certificate(future_responder_key.get(), issuer.get(), issuer_key.get(), "Future OCSP Responder", 2004, true, 86400, 172800);
	bool rejected_future_responder = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(future_responder.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_future_responder = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_future_responder)
	{
		throw std::runtime_error{"not-yet-valid OCSP responder accepted"};
	}

	const EvpPkeyPtr wrong_issuer_key = make_rsa_key();
	const EvpPkeyPtr wrong_signature_responder_key = make_rsa_key();
	const X509Ptr wrong_signature_responder = make_ocsp_responder_certificate(
	    wrong_signature_responder_key.get(), issuer.get(), wrong_issuer_key.get(), "Wrong Signature OCSP Responder", 2005, true);
	bool rejected_wrong_signature_responder = false;
	try
	{
		(void)anopki::core::validate_ocsp_responder(certificate_to_pem(issuer.get()), certificate_to_pem(wrong_signature_responder.get()));
	}
	catch (const std::runtime_error &error)
	{
		rejected_wrong_signature_responder = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	if (!rejected_wrong_signature_responder)
	{
		throw std::runtime_error{"OCSP responder with invalid signature accepted"};
	}

	const std::filesystem::path invalid_responder_key_path = work_dir / "core_ocsp_invalid_responder.key";
	write_file(invalid_responder_key_path, private_key_to_pem(invalid_responder_key.get()));
	anopki::core::GenerateOCSPResponseRequest invalid_responder_response_request = response_request;
	invalid_responder_response_request.issuer_certificate_pem = certificate_to_pem(invalid_responder.get());
	invalid_responder_response_request.issuer_key_ref = invalid_responder_key_path.string();
	bool rejected_invalid_responder = false;
	try
	{
		(void)anopki::core::generate_ocsp_response(invalid_responder_response_request);
	}
	catch (const std::runtime_error &error)
	{
		rejected_invalid_responder = std::string_view{error.what()} == "ocsp.responder_invalid";
	}
	require(rejected_invalid_responder);

	const unsigned char nonce[] = {0x01, 0x02, 0x03, 0x04, 0xa5};
	OCSP_CERTID *nonce_raw_id = nullptr;
	const std::string nonce_request_der = ocsp_request_der_with_nonce(leaf.get(), issuer.get(), nonce, sizeof(nonce), &nonce_raw_id);
	OCSPCertIDPtr nonce_id{nonce_raw_id};
	const anopki::core::OCSPRequestInfo nonce_info = anopki::core::inspect_ocsp_request_der(nonce_request_der);
	require(nonce_info.has_nonce);
	require(nonce_info.nonce_hex == "01020304a5");

	anopki::core::GenerateOCSPResponseRequest nonce_response_request;
	nonce_response_request.request_der = nonce_request_der;
	nonce_response_request.issuer_certificate_pem = certificate_to_pem(issuer.get());
	nonce_response_request.issuer_key_ref = issuer_key_path.string();
	nonce_response_request.this_update = "2026-06-13T00:00:00Z";
	nonce_response_request.next_update = "2026-06-14T00:00:00Z";
	anopki::core::OCSPCertificateStatus nonce_status;
	nonce_status.serial_number = nonce_info.certificates[0].serial_number;
	nonce_status.status = "good";
	nonce_status.hash_algorithm = nonce_info.certificates[0].hash_algorithm;
	nonce_status.issuer_name_hash = nonce_info.certificates[0].issuer_name_hash;
	nonce_status.issuer_key_hash = nonce_info.certificates[0].issuer_key_hash;
	nonce_response_request.certificates.push_back(nonce_status);
	const anopki::core::GenerateOCSPResponseResult nonce_response_result = anopki::core::generate_ocsp_response(nonce_response_request);
	const OCSPRequestPtr nonce_request = ocsp_request_from_der(nonce_request_der);
	const OCSPResponsePtr nonce_response = ocsp_response_from_der(nonce_response_result.response_der);
	OCSPBasicResponsePtr nonce_basic{OCSP_response_get1_basic(nonce_response.get())};
	require(nonce_basic != nullptr);
	require(OCSP_check_nonce(nonce_request.get(), nonce_basic.get()) == 1);

	std::vector<OCSPCertIDPtr> mixed_ids;
	const std::string mixed_request_der = ocsp_request_der(leaf.get(), issuer.get(), {EVP_sha1(), EVP_sha256()}, mixed_ids);
	const anopki::core::OCSPRequestInfo mixed_info = anopki::core::inspect_ocsp_request_der(mixed_request_der);
	require(mixed_info.certificates.size() == 2);
	require(mixed_info.certificates[0].serial_number == mixed_info.certificates[1].serial_number);
	require(mixed_info.certificates[0].hash_algorithm == "sha1");
	require(mixed_info.certificates[1].hash_algorithm == "sha256");

	anopki::core::GenerateOCSPResponseRequest mixed_response_request;
	mixed_response_request.request_der = mixed_request_der;
	mixed_response_request.issuer_certificate_pem = certificate_to_pem(issuer.get());
	mixed_response_request.issuer_key_ref = issuer_key_path.string();
	mixed_response_request.this_update = "2026-06-13T00:00:00Z";
	mixed_response_request.next_update = "2026-06-14T00:00:00Z";
	anopki::core::OCSPCertificateStatus good_sha1;
	good_sha1.serial_number = mixed_info.certificates[0].serial_number;
	good_sha1.status = "good";
	good_sha1.hash_algorithm = mixed_info.certificates[0].hash_algorithm;
	good_sha1.issuer_name_hash = mixed_info.certificates[0].issuer_name_hash;
	good_sha1.issuer_key_hash = mixed_info.certificates[0].issuer_key_hash;
	anopki::core::OCSPCertificateStatus revoked_sha256;
	revoked_sha256.serial_number = mixed_info.certificates[1].serial_number;
	revoked_sha256.status = "revoked";
	revoked_sha256.revoked_at = "2026-06-13T01:00:00Z";
	revoked_sha256.revocation_reason = "key_compromise";
	revoked_sha256.hash_algorithm = mixed_info.certificates[1].hash_algorithm;
	revoked_sha256.issuer_name_hash = mixed_info.certificates[1].issuer_name_hash;
	revoked_sha256.issuer_key_hash = mixed_info.certificates[1].issuer_key_hash;
	mixed_response_request.certificates = {good_sha1, revoked_sha256};

	const anopki::core::GenerateOCSPResponseResult mixed_response_result = anopki::core::generate_ocsp_response(mixed_response_request);
	const OCSPResponsePtr mixed_response = ocsp_response_from_der(mixed_response_result.response_der);
	OCSPBasicResponsePtr mixed_basic{OCSP_response_get1_basic(mixed_response.get())};
	require(mixed_basic != nullptr);
	int sha1_status = -1;
	int sha1_reason = -1;
	int sha256_status = -1;
	int sha256_reason = -1;
	require(OCSP_resp_find_status(mixed_basic.get(), mixed_ids[0].get(), &sha1_status, &sha1_reason, nullptr, nullptr, nullptr) == 1);
	require(OCSP_resp_find_status(mixed_basic.get(), mixed_ids[1].get(), &sha256_status, &sha256_reason, nullptr, nullptr, nullptr) == 1);
	require(sha1_status == V_OCSP_CERTSTATUS_GOOD);
	require(sha256_status == V_OCSP_CERTSTATUS_REVOKED);
	require(sha256_reason == OCSP_REVOKED_STATUS_KEYCOMPROMISE);
	assert_curated_ocsp_request_vector(fixture_dir);
	return 0;
}
