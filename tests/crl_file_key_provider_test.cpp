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
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using X509CrlPtr = std::unique_ptr<X509_CRL, OpenSslDeleter<X509_CRL, X509_CRL_free>>;

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
	    : path_{root / "crl-file-key-provider"}
	{
		std::error_code error;
		std::filesystem::remove_all(path_, error);
		error.clear();
		std::filesystem::create_directories(path_, error);
		require(!error, "failed to create temporary CRL provider directory");
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

void add_extension(X509 *certificate, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr, "failed to create certificate extension");
	require(X509_add_ext(certificate, extension, -1) == 1, "failed to add certificate extension");
	X509_EXTENSION_free(extension);
}

X509Ptr make_ca_certificate(EVP_PKEY *key, const char *common_name)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr, "failed to allocate CA certificate");
	require(X509_set_version(certificate.get(), 2) == 1, "failed to set CA version");
	BignumPtr serial{BN_new()};
	require(serial != nullptr && BN_set_word(serial.get(), 1) == 1, "failed to set CA serial");
	require(
	    BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(certificate.get())) != nullptr,
	    "failed to encode CA serial");
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	add_name(X509_get_subject_name(certificate.get()), common_name);
	require(
	    X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) == 1,
	    "failed to set CA issuer");
	require(X509_set_pubkey(certificate.get(), key) == 1, "failed to set CA public key");
	add_extension(certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	require(X509_sign(certificate.get(), key, EVP_sha256()) > 0, "failed to sign CA certificate");
	return certificate;
}

std::string certificate_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr && PEM_write_bio_X509(bio.get(), certificate) == 1, "failed to encode CA PEM");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "empty CA PEM");
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

X509CrlPtr parse_crl(const std::string &pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	require(bio != nullptr, "failed to allocate CRL input BIO");
	X509CrlPtr crl{PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)};
	require(crl != nullptr, "failed to parse CRL PEM");
	return crl;
}

std::string crl_der(X509_CRL *crl)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr && i2d_X509_CRL_bio(bio.get(), crl) == 1, "failed to encode CRL DER");
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr, "empty CRL DER");
	return std::string{data, static_cast<std::string::size_type>(size)};
}

anopki::core::GenerateCRLRequest make_request(
    const std::string &issuer_certificate_pem,
    std::string issuer_key_ref)
{
	anopki::core::GenerateCRLRequest request;
	request.issuer_certificate_pem = issuer_certificate_pem;
	request.issuer_key_ref = std::move(issuer_key_ref);
	request.crl_number = 42;
	request.this_update = "2026-07-17T00:00:00Z";
	request.next_update = "2026-07-18T00:00:00Z";
	request.revoked_certificates.push_back({"1234", "2026-07-17T01:00:00Z", "key_compromise"});
	return request;
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
		require(message == expected_code, "unexpected CRL provider error code");
		if (!secret.empty())
		{
			require(message.find(secret) == std::string_view::npos, "CRL provider error leaked sensitive input");
		}
		return;
	}
	fail("expected CRL provider failure");
}

void test_success_and_golden_equivalence(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	X509Ptr issuer = make_ca_certificate(issuer_key.get(), "AnoPKI CRL Provider CA");
	const std::string issuer_pem = certificate_pem(issuer.get());
	const std::filesystem::path key_path = temp.path() / "issuer.pem";
	write_private_key(key_path, issuer_key.get());

	const auto bare_result = anopki::core::generate_crl(make_request(issuer_pem, key_path.string()));
	const auto file_result = anopki::core::generate_crl(make_request(issuer_pem, "file:" + key_path.string()));
	X509CrlPtr bare_crl = parse_crl(bare_result.crl_pem);
	X509CrlPtr file_crl = parse_crl(file_result.crl_pem);
	require(crl_der(bare_crl.get()) == crl_der(file_crl.get()), "file reference changed deterministic CRL DER");
	EvpPkeyPtr issuer_public{X509_get_pubkey(issuer.get())};
	require(
	    issuer_public != nullptr && X509_CRL_verify(file_crl.get(), issuer_public.get()) == 1,
	    "provider-signed CRL verification failed");
}

void test_failures_and_no_fallback(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr other_key = generate_rsa_key();
	X509Ptr issuer = make_ca_certificate(issuer_key.get(), "AnoPKI CRL Failure CA");
	const std::string issuer_pem = certificate_pem(issuer.get());
	const std::filesystem::path valid_path = temp.path() / "valid.pem";
	const std::filesystem::path other_path = temp.path() / "other.pem";
	const std::filesystem::path malformed_path = temp.path() / "malformed.pem";
	const std::filesystem::path directory_path = temp.path() / "directory";
	const std::filesystem::path missing_path = temp.path() / "missing-secret.pem";
	write_private_key(valid_path, issuer_key.get());
	write_private_key(other_path, other_key.get());
	std::ofstream{malformed_path} << "not a private key\n";
	std::filesystem::create_directory(directory_path);

	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "file:" + missing_path.string())); },
	    "provider.key_not_found",
	    missing_path.filename().string());
	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "file:" + directory_path.string())); },
	    "provider.not_ready",
	    directory_path.filename().string());
	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "file:" + malformed_path.string())); },
	    "provider.key_parse_failed",
	    malformed_path.filename().string());
	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "file:" + other_path.string())); },
	    "provider.key_binding_mismatch",
	    other_path.filename().string());

	// The suffix names a valid file, but an unsupported provider reference must
	// fail at provider resolution and never retry the suffix as a file path.
	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "kms:" + valid_path.string())); },
	    "provider.unavailable",
	    valid_path.filename().string());

	EnvironmentGuard environment_guard;
	set_environment("production");
	expect_error(
	    [&] { (void)anopki::core::generate_crl(make_request(issuer_pem, "file:" + valid_path.string())); },
	    "provider.exportability_violation",
	    valid_path.filename().string());
}

} // namespace

int main(int argc, char *argv[])
{
	try
	{
		require(argc == 2, "expected build directory argument");
		TempDirectory temp{argv[1]};
		test_success_and_golden_equivalence(temp);
		test_failures_and_no_fallback(temp);
		std::cout << "CRL file key provider tests passed\n";
		return 0;
	}
	catch (const std::exception &error)
	{
		std::cerr << "CRL file key provider test failed: " << error.what() << '\n';
		return 1;
	}
}
