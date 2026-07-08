// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "anopki/core/csr.hpp"
#include "anopki/core/issue.hpp"
#include "anopki/core/ocsp.hpp"

#include <openssl/asn1.h>
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
#include <map>
#include <memory>
#include <sstream>
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
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using X509CrlPtr = std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, X509_CRL_free>>;
using X509ReqPtr = std::unique_ptr<X509_REQ, OpenSslDeleter<X509_REQ, X509_REQ_free>>;

void require(bool condition, std::string_view message)
{
	if (!condition)
	{
		std::cerr << message << "\n";
		std::exit(1);
	}
}

std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input{path, std::ios::binary};
	require(input.good(), "failed to open fixture");
	std::ostringstream contents;
	contents << input.rdbuf();
	return contents.str();
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

std::map<std::string, std::string> load_expected(const std::filesystem::path &path)
{
	std::map<std::string, std::string> expected;
	std::istringstream lines{read_file(path)};
	std::string line;
	while (std::getline(lines, line))
	{
		if (line.empty() || line[0] == '#')
		{
			continue;
		}
		const auto separator = line.find('=');
		require(separator != std::string::npos, "malformed expected fixture line");
		expected.emplace(line.substr(0, separator), line.substr(separator + 1));
	}
	return expected;
}

void expect_eq(const std::map<std::string, std::string> &expected, const std::string &key, const std::string &actual)
{
	const auto item = expected.find(key);
	require(item != expected.end(), "missing expected fixture key: " + key);
	if (item->second != actual)
	{
		std::cerr << "OpenSSL golden mismatch for " << key << "\n"
		          << "expected: " << item->second << "\n"
		          << "actual:   " << actual << "\n";
		std::exit(1);
	}
}

EvpPkeyPtr make_rsa_key(int bits = 2048)
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	require(context != nullptr, "EVP_PKEY_CTX_new_id failed");
	require(EVP_PKEY_keygen_init(context.get()) == 1, "EVP_PKEY_keygen_init failed");
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) == 1, "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1, "EVP_PKEY_keygen failed");
	return EvpPkeyPtr{key};
}

void set_name(X509_NAME *name, const char *common_name)
{
	require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0) == 1, "set CN failed");
}

void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr, "X509V3_EXT_conf_nid failed");
	require(X509_add_ext(certificate, extension, -1) == 1, "X509_add_ext failed");
	X509_EXTENSION_free(extension);
}

X509_EXTENSION *make_extension(int nid, const char *value)
{
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
	require(extension != nullptr, "make extension failed");
	return extension;
}

void add_csr_extensions(X509_REQ *request)
{
	STACK_OF(X509_EXTENSION) *extensions = sk_X509_EXTENSION_new_null();
	require(extensions != nullptr, "sk_X509_EXTENSION_new_null failed");
	require(sk_X509_EXTENSION_push(extensions, make_extension(NID_subject_alt_name, "DNS:leaf.example.test,IP:127.0.0.1")) >= 1, "push SAN failed");
	require(sk_X509_EXTENSION_push(extensions, make_extension(NID_key_usage, "digitalSignature")) >= 1, "push KU failed");
	require(X509_REQ_add_extensions(request, extensions) == 1, "X509_REQ_add_extensions failed");
	sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

X509ReqPtr make_csr(EVP_PKEY *key)
{
	X509ReqPtr request{X509_REQ_new()};
	require(request != nullptr, "X509_REQ_new failed");
	require(X509_REQ_set_version(request.get(), 0) == 1, "X509_REQ_set_version failed");
	set_name(X509_REQ_get_subject_name(request.get()), "leaf");
	require(X509_REQ_set_pubkey(request.get(), key) == 1, "X509_REQ_set_pubkey failed");
	add_csr_extensions(request.get());
	require(X509_REQ_sign(request.get(), key, EVP_sha256()) > 0, "X509_REQ_sign failed");
	return request;
}

void set_serial(X509 *certificate, unsigned long serial)
{
	BignumPtr serial_bn{BN_new()};
	require(serial_bn != nullptr, "BN_new failed");
	require(BN_set_word(serial_bn.get(), serial) == 1, "BN_set_word failed");
	require(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate)) != nullptr, "BN_to_ASN1_INTEGER failed");
}

X509Ptr make_ca_certificate(EVP_PKEY *key)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr, "X509_new failed");
	require(X509_set_version(certificate.get(), 2) == 1, "X509_set_version failed");
	set_serial(certificate.get(), 1);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), "Test CA");
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1, "set issuer failed");
	require(X509_set_pubkey(certificate.get(), key) == 1, "X509_set_pubkey failed");
	add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	require(X509_sign(certificate.get(), key, EVP_sha256()) > 0, "X509_sign failed");
	return certificate;
}

X509Ptr make_leaf_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr, "leaf X509_new failed");
	require(X509_set_version(certificate.get(), 2) == 1, "leaf X509_set_version failed");
	set_serial(certificate.get(), 1001);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), "Leaf");
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) == 1, "leaf set issuer failed");
	require(X509_set_pubkey(certificate.get(), key) == 1, "leaf set pubkey failed");
	require(X509_sign(certificate.get(), issuer_key, EVP_sha256()) > 0, "leaf sign failed");
	return certificate;
}

std::string pem_from_csr(X509_REQ *request)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "BIO_new failed");
	require(PEM_write_bio_X509_REQ(bio.get(), request) == 1, "write csr failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "csr BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string pem_from_certificate(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "BIO_new failed");
	require(PEM_write_bio_X509(bio.get(), certificate) == 1, "write cert failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "cert BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string pem_from_private_key(EVP_PKEY *key)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "BIO_new failed");
	require(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1, "write key failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "key BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

X509Ptr certificate_from_pem(const std::string &pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	require(bio != nullptr, "BIO_new_mem_buf failed");
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	require(certificate != nullptr, "PEM_read_bio_X509 failed");
	return certificate;
}

X509CrlPtr crl_from_pem(const std::string &pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	require(bio != nullptr, "CRL BIO_new_mem_buf failed");
	X509CrlPtr crl{PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)};
	require(crl != nullptr, "PEM_read_bio_X509_CRL failed");
	return crl;
}

std::string extension_text(X509_EXTENSION *extension)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "extension BIO_new failed");
	require(X509V3_EXT_print(bio.get(), extension, 0, 0) == 1, "X509V3_EXT_print failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "extension BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

X509_EXTENSION *extension_by_nid(X509 *certificate, int nid)
{
	const int index = X509_get_ext_by_NID(certificate, nid, -1);
	require(index >= 0, "extension missing");
	X509_EXTENSION *extension = X509_get_ext(certificate, index);
	require(extension != nullptr, "X509_get_ext failed");
	return extension;
}

std::string asn1_time_text(const ASN1_TIME *time)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "time BIO_new failed");
	require(ASN1_TIME_print(bio.get(), time) == 1, "ASN1_TIME_print failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "time BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string ocsp_request_der_with_nonce(X509 *leaf, X509 *issuer, const unsigned char *nonce, int nonce_size, OCSP_CERTID **out_id)
{
	std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>> request{OCSP_REQUEST_new()};
	require(request != nullptr, "OCSP_REQUEST_new failed");
	OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), leaf, issuer);
	require(id != nullptr, "OCSP_cert_to_id failed");
	*out_id = OCSP_CERTID_dup(id);
	require(*out_id != nullptr, "OCSP_CERTID_dup failed");
	require(OCSP_request_add0_id(request.get(), id) != nullptr, "OCSP_request_add0_id failed");
	require(OCSP_request_add1_nonce(request.get(), const_cast<unsigned char *>(nonce), nonce_size) == 1, "OCSP_request_add1_nonce failed");
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr, "ocsp BIO_new failed");
	require(i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1, "i2d_OCSP_REQUEST_bio failed");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "ocsp request BIO_get_mem_data failed");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

OCSPResponsePtr ocsp_response_from_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	require(bio != nullptr, "ocsp response BIO_new_mem_buf failed");
	OCSPResponsePtr response{d2i_OCSP_RESPONSE_bio(bio.get(), nullptr)};
	require(response != nullptr, "d2i_OCSP_RESPONSE_bio failed");
	return response;
}

std::string join(const std::vector<std::string> &values)
{
	std::string joined;
	for (const std::string &value : values)
	{
		if (!joined.empty())
		{
			joined += ",";
		}
		joined += value;
	}
	return joined;
}

void assert_csr_baseline(const std::map<std::string, std::string> &expected, const std::string &csr_pem)
{
	const anopki::core::CsrInfo info = anopki::core::inspect_csr_pem(csr_pem);
	expect_eq(expected, "csr.subject", info.subject);
	expect_eq(expected, "csr.dns", join(info.dns_names));
	expect_eq(expected, "csr.ip", join(info.ip_addresses));
	expect_eq(expected, "csr.public_key_algorithm", info.public_key_algorithm);
	expect_eq(expected, "csr.public_key_size_bits", std::to_string(info.public_key_size_bits));
	expect_eq(expected, "csr.signature_algorithm", info.signature_algorithm);
	expect_eq(expected, "csr.extension_oids", join(info.extension_oids));
}

void assert_issue_baseline(
    const std::map<std::string, std::string> &expected,
    const std::filesystem::path &work_dir,
    const std::string &csr_pem,
    const std::string &issuer_certificate_pem,
    EVP_PKEY *issuer_key)
{
	const std::filesystem::path issuer_key_path = work_dir / "openssl_golden_issuer.key";
	write_file(issuer_key_path, pem_from_private_key(issuer_key));

	anopki::core::IssueRequest request;
	request.csr_pem = csr_pem;
	request.issuer_certificate_pem = issuer_certificate_pem;
	request.issuer_key_ref = issuer_key_path.string();
	request.subject = "CN=leaf";
	request.dns_names = {"leaf.example.test"};
	request.ip_addresses = {"127.0.0.1"};
	request.not_before = "2026-06-13T00:00:00Z";
	request.not_after = "2026-06-14T00:00:00Z";
	request.basic_constraints_critical = true;
	request.basic_constraints_ca = false;
	request.key_usage_critical = true;
	request.key_usage = {"digital_signature", "key_encipherment"};
	request.extended_key_usage = {"server_auth"};
	request.subject_key_identifier = true;
	request.authority_key_identifier = true;

	const anopki::core::IssueResult result = anopki::core::issue_certificate(request);
	expect_eq(expected, "issue.subject", result.subject);
	expect_eq(expected, "issue.result_not_before", result.not_before);
	expect_eq(expected, "issue.result_not_after", result.not_after);

	const X509Ptr certificate = certificate_from_pem(result.certificate_pem);
	expect_eq(expected, "issue.cert_not_before", asn1_time_text(X509_get0_notBefore(certificate.get())));
	expect_eq(expected, "issue.cert_not_after", asn1_time_text(X509_get0_notAfter(certificate.get())));
	expect_eq(expected, "issue.basic_constraints", extension_text(extension_by_nid(certificate.get(), NID_basic_constraints)));
	expect_eq(expected, "issue.key_usage", extension_text(extension_by_nid(certificate.get(), NID_key_usage)));
	expect_eq(expected, "issue.extended_key_usage", extension_text(extension_by_nid(certificate.get(), NID_ext_key_usage)));
}

void assert_crl_baseline(
    const std::map<std::string, std::string> &expected,
    const std::filesystem::path &work_dir,
    const std::string &issuer_certificate_pem,
    EVP_PKEY *issuer_key)
{
	const std::filesystem::path issuer_key_path = work_dir / "openssl_golden_crl_issuer.key";
	write_file(issuer_key_path, pem_from_private_key(issuer_key));

	anopki::core::GenerateCRLRequest request;
	request.issuer_certificate_pem = issuer_certificate_pem;
	request.issuer_key_ref = issuer_key_path.string();
	request.crl_number = 2147483648LL;
	request.this_update = "2026-06-13T00:00:00Z";
	request.next_update = "2026-06-14T00:00:00Z";
	request.revoked_certificates.push_back({"1234", "2026-06-13T01:00:00Z", "key_compromise"});

	const anopki::core::GenerateCRLResult result = anopki::core::generate_crl(request);
	const anopki::core::CRLInfo info = anopki::core::inspect_crl_pem(result.crl_pem);
	expect_eq(expected, "crl.issuer", info.issuer);
	expect_eq(expected, "crl.number", info.crl_number);
	expect_eq(expected, "crl.revoked_count", std::to_string(info.revoked_certificate_count));

	const X509CrlPtr crl = crl_from_pem(result.crl_pem);
	require(sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl.get())) == 1, "CRL revoked count mismatch");
}

void assert_ocsp_baseline(
    const std::map<std::string, std::string> &expected,
    const std::filesystem::path &work_dir,
    X509 *issuer,
    EVP_PKEY *issuer_key,
    X509 *leaf)
{
	const unsigned char nonce[] = {0x01, 0x02, 0x03, 0x04, 0xa5};
	OCSP_CERTID *raw_id = nullptr;
	const std::string request_der = ocsp_request_der_with_nonce(leaf, issuer, nonce, sizeof(nonce), &raw_id);
	OCSPCertIDPtr id{raw_id};
	const anopki::core::OCSPRequestInfo info = anopki::core::inspect_ocsp_request_der(request_der);
	require(info.certificates.size() == 1, "OCSP request count mismatch");
	expect_eq(expected, "ocsp.serial_number", info.certificates[0].serial_number);
	expect_eq(expected, "ocsp.hash_algorithm", info.certificates[0].hash_algorithm);
	expect_eq(expected, "ocsp.has_nonce", info.has_nonce ? "true" : "false");
	expect_eq(expected, "ocsp.nonce_hex", info.nonce_hex);

	const std::filesystem::path issuer_key_path = work_dir / "openssl_golden_ocsp_issuer.key";
	write_file(issuer_key_path, pem_from_private_key(issuer_key));
	anopki::core::GenerateOCSPResponseRequest response_request;
	response_request.request_der = request_der;
	response_request.issuer_certificate_pem = pem_from_certificate(issuer);
	response_request.issuer_key_ref = issuer_key_path.string();
	response_request.this_update = "2026-06-13T00:00:00Z";
	response_request.next_update = "2026-06-14T00:00:00Z";
	anopki::core::OCSPCertificateStatus status;
	status.serial_number = info.certificates[0].serial_number;
	status.status = "good";
	status.hash_algorithm = info.certificates[0].hash_algorithm;
	status.issuer_name_hash = info.certificates[0].issuer_name_hash;
	status.issuer_key_hash = info.certificates[0].issuer_key_hash;
	response_request.certificates.push_back(status);

	const anopki::core::GenerateOCSPResponseResult result = anopki::core::generate_ocsp_response(response_request);
	const OCSPResponsePtr response = ocsp_response_from_der(result.response_der);
	expect_eq(expected, "ocsp.response_status", OCSP_response_status_str(OCSP_response_status(response.get())));
}

} // namespace

int main(int argc, char *argv[])
{
	require(argc == 3, "usage: anopki_core_openssl_golden_test <work-dir> <fixture-dir>");
	const std::filesystem::path work_dir = argv[1];
	const std::filesystem::path fixture_dir = argv[2];
	const std::map<std::string, std::string> expected = load_expected(fixture_dir / "expected.txt");

	const EvpPkeyPtr issuer_key = make_rsa_key();
	const X509Ptr issuer = make_ca_certificate(issuer_key.get());
	const EvpPkeyPtr leaf_key = make_rsa_key();
	const X509ReqPtr csr = make_csr(leaf_key.get());
	const X509Ptr leaf = make_leaf_certificate(leaf_key.get(), issuer.get(), issuer_key.get());
	const std::string csr_pem = pem_from_csr(csr.get());
	const std::string issuer_certificate_pem = pem_from_certificate(issuer.get());

	assert_csr_baseline(expected, csr_pem);
	assert_issue_baseline(expected, work_dir, csr_pem, issuer_certificate_pem, issuer_key.get());
	assert_crl_baseline(expected, work_dir, issuer_certificate_pem, issuer_key.get());
	assert_ocsp_baseline(expected, work_dir, issuer.get(), issuer_key.get(), leaf.get());
	return 0;
}
