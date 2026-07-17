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
#include <stdexcept>
#include <string>
#include <string_view>

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
using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>;
using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

[[noreturn]] void fail(std::string_view message)
{
	throw std::runtime_error{std::string{message}};
}

void require(bool condition, std::string_view message)
{
	if (!condition)
	{
		fail(message);
	}
}

class TempDirectory final
{
public:
	explicit TempDirectory(const std::filesystem::path &root)
	    : path_{root / "ocsp-file-key-provider"}
	{
		std::error_code error;
		std::filesystem::remove_all(path_, error);
		error.clear();
		std::filesystem::create_directories(path_, error);
		require(!error, "failed to create temporary OCSP provider directory");
	}

	~TempDirectory()
	{
		std::error_code error;
		std::filesystem::remove_all(path_, error);
	}

	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

private:
	std::filesystem::path path_;
};

class EnvironmentGuard final
{
public:
	EnvironmentGuard()
	{
		const char *value = std::getenv("ANOPKI_ENV");
		if (value != nullptr)
		{
			had_value_ = true;
			value_ = value;
		}
	}

	~EnvironmentGuard()
	{
#ifdef _WIN32
		(void)_putenv_s("ANOPKI_ENV", had_value_ ? value_.c_str() : "");
#else
		if (had_value_)
		{
			(void)setenv("ANOPKI_ENV", value_.c_str(), 1);
		}
		else
		{
			(void)unsetenv("ANOPKI_ENV");
		}
#endif
	}

private:
	bool had_value_{false};
	std::string value_;
};

void set_environment(std::string_view value)
{
#ifdef _WIN32
	require(_putenv_s("ANOPKI_ENV", std::string{value}.c_str()) == 0, "failed to set ANOPKI_ENV");
#else
	require(setenv("ANOPKI_ENV", std::string{value}.c_str(), 1) == 0, "failed to set ANOPKI_ENV");
#endif
}

EvpPkeyPtr generate_rsa_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	require(context != nullptr, "failed to allocate RSA context");
	require(EVP_PKEY_keygen_init(context.get()) == 1, "failed to initialize RSA generation");
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1, "failed to set RSA size");
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1, "failed to generate RSA key");
	return EvpPkeyPtr{key};
}

EvpPkeyPtr generate_ec_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
	require(context != nullptr, "failed to allocate EC context");
	require(EVP_PKEY_keygen_init(context.get()) == 1, "failed to initialize EC generation");
	require(
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1,
	    "failed to select P-256");
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1, "failed to generate EC key");
	return EvpPkeyPtr{key};
}

#ifdef EVP_PKEY_ED25519
EvpPkeyPtr generate_ed25519_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr)};
	require(context != nullptr, "failed to allocate Ed25519 context");
	require(EVP_PKEY_keygen_init(context.get()) == 1, "failed to initialize Ed25519 generation");
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1, "failed to generate Ed25519 key");
	return EvpPkeyPtr{key};
}
#endif

void add_name(X509_NAME *name, const char *common_name)
{
	require(
	    X509_NAME_add_entry_by_txt(
	        name,
	        "CN",
	        MBSTRING_ASC,
	        reinterpret_cast<const unsigned char *>(common_name),
	        -1,
	        -1,
	        0) == 1,
	    "failed to add certificate name");
}

void set_serial(X509 *certificate, unsigned long serial)
{
	BignumPtr serial_bn{BN_new()};
	require(serial_bn != nullptr, "failed to allocate serial");
	require(BN_set_word(serial_bn.get(), serial) == 1, "failed to set serial");
	require(
	    BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate)) != nullptr,
	    "failed to encode serial");
}

void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr, "failed to create certificate extension");
	require(X509_add_ext(certificate, extension, -1) == 1, "failed to add certificate extension");
	X509_EXTENSION_free(extension);
}

X509Ptr make_ca_certificate(EVP_PKEY *key, const char *common_name, const EVP_MD *digest = EVP_sha256())
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr, "failed to allocate CA certificate");
	require(X509_set_version(certificate.get(), 2) == 1, "failed to set CA version");
	set_serial(certificate.get(), 1);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	add_name(X509_get_subject_name(certificate.get()), common_name);
	require(
	    X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1,
	    "failed to set CA issuer");
	require(X509_set_pubkey(certificate.get(), key) == 1, "failed to set CA public key");
	add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
	require(X509_sign(certificate.get(), key, digest) > 0, "failed to sign CA certificate");
	return certificate;
}

X509Ptr make_leaf_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr, "failed to allocate leaf certificate");
	require(X509_set_version(certificate.get(), 2) == 1, "failed to set leaf version");
	set_serial(certificate.get(), 1001);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	add_name(X509_get_subject_name(certificate.get()), "AnoPKI OCSP Provider Leaf");
	require(
	    X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) == 1,
	    "failed to set leaf issuer");
	require(X509_set_pubkey(certificate.get(), key) == 1, "failed to set leaf public key");
	require(X509_sign(certificate.get(), issuer_key, EVP_sha256()) > 0, "failed to sign leaf certificate");
	return certificate;
}

std::string certificate_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr && PEM_write_bio_X509(bio.get(), certificate) == 1, "failed to encode certificate PEM");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "empty certificate PEM");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

void write_private_key(const std::filesystem::path &path, EVP_PKEY *key)
{
	BioPtr bio{BIO_new_file(path.string().c_str(), "wb")};
	require(bio != nullptr, "failed to open private-key output");
	require(
	    PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
	    "failed to write private key");
}

void write_encrypted_private_key(const std::filesystem::path &path, EVP_PKEY *key)
{
	BioPtr bio{BIO_new_file(path.string().c_str(), "wb")};
	require(bio != nullptr, "failed to open encrypted private-key output");
	constexpr unsigned char password[] = "test-only-password";
	require(
	    PEM_write_bio_PrivateKey(
	        bio.get(),
	        key,
	        EVP_aes_256_cbc(),
	        password,
	        static_cast<int>(sizeof(password) - 1U),
	        nullptr,
	        nullptr) == 1,
	    "failed to write encrypted private key");
}

std::string request_der(X509 *leaf, X509 *issuer, OCSP_CERTID **out_id)
{
	OCSPRequestPtr request{OCSP_REQUEST_new()};
	require(request != nullptr, "failed to allocate OCSP request");
	OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), leaf, issuer);
	require(id != nullptr, "failed to create OCSP certificate ID");
	*out_id = OCSP_CERTID_dup(id);
	require(*out_id != nullptr, "failed to duplicate OCSP certificate ID");
	require(OCSP_request_add0_id(request.get(), id) != nullptr, "failed to add OCSP certificate ID");
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr && i2d_OCSP_REQUEST_bio(bio.get(), request.get()) == 1, "failed to encode OCSP request");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "empty OCSP request DER");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

OCSPResponsePtr parse_response(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	require(bio != nullptr, "failed to allocate OCSP response BIO");
	OCSPResponsePtr response{d2i_OCSP_RESPONSE_bio(bio.get(), nullptr)};
	require(response != nullptr, "failed to parse OCSP response DER");
	return response;
}

anopki::core::GenerateOCSPResponseRequest make_request(
    const std::string &request,
    const std::string &signer_certificate_pem,
    std::string signer_key_ref)
{
	anopki::core::GenerateOCSPResponseRequest response;
	response.request_der = request;
	response.issuer_certificate_pem = signer_certificate_pem;
	response.issuer_key_ref = std::move(signer_key_ref);
	response.this_update = "2026-07-17T00:00:00Z";
	response.next_update = "2026-07-18T00:00:00Z";
	anopki::core::OCSPCertificateStatus status;
	status.serial_number = "1001";
	status.status = "good";
	response.certificates.push_back(std::move(status));
	return response;
}

void verify_response(
    const std::string &der,
    X509 *signer_certificate,
    OCSP_CERTID *id,
    int expected_signature_nid = NID_undef)
{
	OCSPResponsePtr response = parse_response(der);
	require(
	    OCSP_response_status(response.get()) == OCSP_RESPONSE_STATUS_SUCCESSFUL,
	    "OCSP response status was not successful");
	OCSPBasicResponsePtr basic{OCSP_response_get1_basic(response.get())};
	require(basic != nullptr, "missing OCSP basic response");
	if (expected_signature_nid != NID_undef)
	{
		const X509_ALGOR *signature_algorithm = OCSP_resp_get0_tbs_sigalg(basic.get());
		const ASN1_OBJECT *signature_object = nullptr;
		X509_ALGOR_get0(&signature_object, nullptr, nullptr, signature_algorithm);
		require(signature_object != nullptr && OBJ_obj2nid(signature_object) == expected_signature_nid,
		        "OCSP response signature algorithm mismatch");
	}

	STACK_OF(X509) *certificates = sk_X509_new_null();
	require(certificates != nullptr, "failed to allocate OCSP signer stack");
	require(sk_X509_push(certificates, signer_certificate) == 1, "failed to add OCSP signer certificate");
	const int verified = OCSP_basic_verify(basic.get(), certificates, nullptr, OCSP_NOVERIFY);
	sk_X509_free(certificates);
	require(verified == 1, "provider-signed OCSP response verification failed");

	int status = -1;
	require(
	    OCSP_resp_find_status(basic.get(), id, &status, nullptr, nullptr, nullptr, nullptr) == 1,
	    "OCSP response did not contain requested certificate ID");
	require(status == V_OCSP_CERTSTATUS_GOOD, "OCSP response status entry changed");
}

template <typename Function>
void expect_error(Function function, std::string_view expected_code, std::string_view secret = {})
{
	try
	{
		function();
	}
	catch (const std::runtime_error &error)
	{
		const std::string_view message{error.what()};
		require(message == expected_code, "unexpected OCSP provider error code");
		if (!secret.empty())
		{
			require(message.find(secret) == std::string_view::npos, "OCSP provider error leaked sensitive input");
		}
		return;
	}
	fail("expected OCSP provider failure");
}

void test_success(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr leaf_key = generate_rsa_key();
	X509Ptr issuer = make_ca_certificate(issuer_key.get(), "AnoPKI OCSP Provider CA");
	X509Ptr leaf = make_leaf_certificate(leaf_key.get(), issuer.get(), issuer_key.get());
	const std::filesystem::path key_path = temp.path() / "issuer.pem";
	write_private_key(key_path, issuer_key.get());
	OCSP_CERTID *raw_id = nullptr;
	const std::string request = request_der(leaf.get(), issuer.get(), &raw_id);
	OCSPCertIDPtr id{raw_id};
	const std::string issuer_pem = certificate_pem(issuer.get());

	const auto bare_result = anopki::core::generate_ocsp_response(
	    make_request(request, issuer_pem, key_path.string()));
	verify_response(bare_result.response_der, issuer.get(), id.get());

	const auto file_result = anopki::core::generate_ocsp_response(
	    make_request(request, issuer_pem, "file:" + key_path.string()));
	verify_response(file_result.response_der, issuer.get(), id.get());
}

void test_ecdsa_success(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_ec_key();
	EvpPkeyPtr leaf_key = generate_rsa_key();
	X509Ptr issuer = make_ca_certificate(issuer_key.get(), "AnoPKI ECDSA OCSP Provider CA");
	X509Ptr leaf = make_leaf_certificate(leaf_key.get(), issuer.get(), issuer_key.get());
	const std::filesystem::path key_path = temp.path() / "ecdsa-issuer.pem";
	write_private_key(key_path, issuer_key.get());
	OCSP_CERTID *raw_id = nullptr;
	const std::string request = request_der(leaf.get(), issuer.get(), &raw_id);
	OCSPCertIDPtr id{raw_id};
	const std::string issuer_pem = certificate_pem(issuer.get());

	const auto bare_result = anopki::core::generate_ocsp_response(
	    make_request(request, issuer_pem, key_path.string()));
	verify_response(bare_result.response_der, issuer.get(), id.get(), NID_ecdsa_with_SHA256);

	const auto file_result = anopki::core::generate_ocsp_response(
	    make_request(request, issuer_pem, "file:" + key_path.string()));
	verify_response(file_result.response_der, issuer.get(), id.get(), NID_ecdsa_with_SHA256);
}

void test_failures_and_no_fallback(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr leaf_key = generate_rsa_key();
	EvpPkeyPtr other_key = generate_rsa_key();
	X509Ptr issuer = make_ca_certificate(issuer_key.get(), "AnoPKI OCSP Failure CA");
	X509Ptr leaf = make_leaf_certificate(leaf_key.get(), issuer.get(), issuer_key.get());
	OCSP_CERTID *raw_id = nullptr;
	const std::string request = request_der(leaf.get(), issuer.get(), &raw_id);
	OCSPCertIDPtr id{raw_id};
	(void)id;
	const std::string issuer_pem = certificate_pem(issuer.get());

	const std::filesystem::path valid_path = temp.path() / "valid.pem";
	const std::filesystem::path other_path = temp.path() / "other.pem";
	const std::filesystem::path malformed_path = temp.path() / "malformed.pem";
	const std::filesystem::path encrypted_path = temp.path() / "encrypted.pem";
	const std::filesystem::path directory_path = temp.path() / "directory";
	const std::filesystem::path missing_path = temp.path() / "missing-secret.pem";
	write_private_key(valid_path, issuer_key.get());
	write_private_key(other_path, other_key.get());
	write_encrypted_private_key(encrypted_path, issuer_key.get());
	std::ofstream{malformed_path} << "not a private key\n";
	std::filesystem::create_directory(directory_path);

	expect_error(
	    [&] { (void)anopki::core::generate_ocsp_response(make_request(request, issuer_pem, "")); },
	    "provider.invalid_reference");
	expect_error(
	    [&] { (void)anopki::core::generate_ocsp_response(make_request(request, issuer_pem, "file:")); },
	    "provider.invalid_reference");
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + missing_path.string()));
	    },
	    "provider.key_not_found",
	    missing_path.filename().string());
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + directory_path.string()));
	    },
	    "provider.not_ready",
	    directory_path.filename().string());
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + malformed_path.string()));
	    },
	    "provider.key_parse_failed",
	    malformed_path.filename().string());
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + encrypted_path.string()));
	    },
	    "provider.key_parse_failed",
	    "test-only-password");
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + other_path.string()));
	    },
	    "provider.key_binding_mismatch",
	    other_path.filename().string());

	// A valid file exists at the suffix, but an unsupported provider reference
	// must fail at resolution and never retry the suffix as a file path.
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "kms:" + valid_path.string()));
	    },
	    "provider.unavailable",
	    valid_path.filename().string());

	EnvironmentGuard environment_guard;
	set_environment("production");
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(
		        make_request(request, issuer_pem, "file:" + valid_path.string()));
	    },
	    "provider.exportability_violation",
	    valid_path.filename().string());

#ifdef EVP_PKEY_ED25519
	set_environment("development");
	EvpPkeyPtr ed25519_key = generate_ed25519_key();
	X509Ptr ed25519_signer = make_ca_certificate(
	    ed25519_key.get(), "AnoPKI OCSP Ed25519 Signer", nullptr);
	const std::filesystem::path ed25519_path = temp.path() / "ed25519.pem";
	write_private_key(ed25519_path, ed25519_key.get());
	expect_error(
	    [&] {
		    (void)anopki::core::generate_ocsp_response(make_request(
		        request,
		        certificate_pem(ed25519_signer.get()),
		        "file:" + ed25519_path.string()));
	    },
	    "provider.algorithm_mismatch",
	    ed25519_path.filename().string());
#endif
}

} // namespace

int main(int argc, char *argv[])
{
	try
	{
		require(argc == 2, "expected build directory argument");
		TempDirectory temp{argv[1]};
		test_success(temp);
		test_ecdsa_success(temp);
		test_failures_and_no_fallback(temp);
		std::cout << "OCSP file key provider tests passed\n";
		return 0;
	}
	catch (const std::exception &error)
	{
		std::cerr << "OCSP file key provider test failed: " << error.what() << '\n';
		return 1;
	}
}
