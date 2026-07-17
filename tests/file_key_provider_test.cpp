// SPDX-License-Identifier: MPL-2.0
#include "key_providers/file_key_provider.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace
{

using namespace anopki::core::openssl_key_providers;

template <typename T, void (*FreeFn)(T *)>
struct OpenSslDeleter
{
	void operator()(T *value) const noexcept
	{
		FreeFn(value);
	}
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

[[noreturn]] void fail(const std::string &message)
{
	throw std::runtime_error{message};
}

void require(bool condition, const std::string &message)
{
	if (!condition)
	{
		fail(message);
	}
}

EvpPkeyPtr generate_rsa_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0)
	{
		fail("RSA key generation setup failed");
	}
	EVP_PKEY *raw = nullptr;
	if (EVP_PKEY_keygen(context.get(), &raw) <= 0 || raw == nullptr)
	{
		fail("RSA key generation failed");
	}
	return EvpPkeyPtr{raw};
}

EvpPkeyPtr generate_ec_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
	if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) <= 0)
	{
		fail("EC key generation setup failed");
	}
	EVP_PKEY *raw = nullptr;
	if (EVP_PKEY_keygen(context.get(), &raw) <= 0 || raw == nullptr)
	{
		fail("EC key generation failed");
	}
	return EvpPkeyPtr{raw};
}

void add_extension(X509 *certificate, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char *>(value));
	if (extension == nullptr)
	{
		fail("extension creation failed");
	}
	const int result = X509_add_ext(certificate, extension, -1);
	X509_EXTENSION_free(extension);
	if (result != 1)
	{
		fail("extension add failed");
	}
}

X509Ptr make_issuer_certificate(EVP_PKEY *key, const char *common_name)
{
	X509Ptr certificate{X509_new()};
	if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1 ||
	    ASN1_TIME_set_string(X509_getm_notBefore(certificate.get()), "20260101000000Z") != 1 ||
	    ASN1_TIME_set_string(X509_getm_notAfter(certificate.get()), "20360101000000Z") != 1 ||
	    X509_set_pubkey(certificate.get(), key) != 1)
	{
		fail("issuer certificate setup failed");
	}
	X509_NAME *name = X509_get_subject_name(certificate.get());
	if (name == nullptr ||
	    X509_NAME_add_entry_by_txt(
	        name,
	        "CN",
	        MBSTRING_ASC,
	        reinterpret_cast<const unsigned char *>(common_name),
	        -1,
	        -1,
	        0) != 1 ||
	    X509_set_issuer_name(certificate.get(), name) != 1)
	{
		fail("issuer name setup failed");
	}
	add_extension(certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
	add_extension(certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	const EVP_MD *digest = EVP_PKEY_base_id(key) == EVP_PKEY_EC ? EVP_sha256() : EVP_sha256();
	if (X509_sign(certificate.get(), key, digest) <= 0)
	{
		fail("issuer certificate sign failed");
	}
	return certificate;
}

X509Ptr make_unsigned_leaf(X509 *issuer, EVP_PKEY *subject_key)
{
	X509Ptr certificate{X509_new()};
	if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 42) != 1 ||
	    ASN1_TIME_set_string(X509_getm_notBefore(certificate.get()), "20270101000000Z") != 1 ||
	    ASN1_TIME_set_string(X509_getm_notAfter(certificate.get()), "20280101000000Z") != 1 ||
	    X509_set_pubkey(certificate.get(), subject_key) != 1 ||
	    X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) != 1)
	{
		fail("leaf certificate setup failed");
	}
	X509_NAME *subject = X509_get_subject_name(certificate.get());
	const char *common_name = "provider-golden.example";
	if (subject == nullptr ||
	    X509_NAME_add_entry_by_txt(
	        subject,
	        "CN",
	        MBSTRING_ASC,
	        reinterpret_cast<const unsigned char *>(common_name),
	        -1,
	        -1,
	        0) != 1)
	{
		fail("leaf subject setup failed");
	}
	return certificate;
}

std::vector<unsigned char> certificate_der(X509 *certificate)
{
	const int size = i2d_X509(certificate, nullptr);
	if (size <= 0)
	{
		fail("DER size failed");
	}
	std::vector<unsigned char> output(static_cast<std::size_t>(size));
	unsigned char *cursor = output.data();
	if (i2d_X509(certificate, &cursor) != size)
	{
		fail("DER encode failed");
	}
	return output;
}

void write_private_key(const std::filesystem::path &path, EVP_PKEY *key)
{
	BIO *bio = BIO_new_file(path.string().c_str(), "wb");
	if (bio == nullptr)
	{
		fail("private key file open failed");
	}
	const int result = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
	BIO_free(bio);
	if (result != 1)
	{
		fail("private key write failed");
	}
}

void write_encrypted_private_key(const std::filesystem::path &path, EVP_PKEY *key)
{
	BIO *bio = BIO_new_file(path.string().c_str(), "wb");
	if (bio == nullptr)
	{
		fail("encrypted private key file open failed");
	}
	constexpr unsigned char password[] = "test-only-password";
	const int result = PEM_write_bio_PrivateKey(
	    bio,
	    key,
	    EVP_aes_256_cbc(),
	    password,
	    static_cast<int>(sizeof(password) - 1U),
	    nullptr,
	    nullptr);
	BIO_free(bio);
	if (result != 1)
	{
		fail("encrypted private key write failed");
	}
}

void expect_provider_error(
    const std::function<void()> &operation,
    ProviderErrorCode expected_code,
    std::string_view expected_stage,
    std::string_view secret_fragment = {})
{
	try
	{
		operation();
	}
	catch (const ProviderError &error)
	{
		require(error.code() == expected_code, "unexpected provider error code");
		require(error.what() == to_string(expected_code), "provider error message is not stable");
		require(error.diagnostics().provider_id == "file", "provider diagnostic identity mismatch");
		require(error.diagnostics().stage == expected_stage, "provider diagnostic stage mismatch");
		if (!secret_fragment.empty())
		{
			require(std::string{error.what()}.find(secret_fragment) == std::string::npos, "error leaked key reference");
			require(error.diagnostics().stage.find(secret_fragment) == std::string::npos, "diagnostic leaked key reference");
		}
		return;
	}
	fail("expected ProviderError");
}

class TempDirectory
{
public:
	TempDirectory()
	{
		const auto stamp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
		path_ = std::filesystem::temp_directory_path() / ("anopki-file-provider-" + std::to_string(stamp));
		std::filesystem::create_directories(path_);
	}

	~TempDirectory()
	{
		std::error_code ignored;
		std::filesystem::remove_all(path_, ignored);
	}

	[[nodiscard]] const std::filesystem::path &path() const noexcept
	{
		return path_;
	}

private:
	std::filesystem::path path_;
};


void set_anopki_env(const char *value)
{
#if defined(_WIN32)
	if (_putenv_s("ANOPKI_ENV", value == nullptr ? "" : value) != 0)
	{
		fail("ANOPKI_ENV update failed");
	}
#else
	const int result = value == nullptr ? unsetenv("ANOPKI_ENV") : setenv("ANOPKI_ENV", value, 1);
	if (result != 0)
	{
		fail("ANOPKI_ENV update failed");
	}
#endif
}

class EnvironmentGuard
{
public:
	EnvironmentGuard()
	{
		const char *current = std::getenv("ANOPKI_ENV");
		if (current != nullptr)
		{
			had_value_ = true;
			value_ = current;
		}
	}

	~EnvironmentGuard()
	{
		try
		{
			set_anopki_env(had_value_ ? value_.c_str() : nullptr);
		}
		catch (...)
		{
		}
	}

private:
	bool had_value_{false};
	std::string value_;
};

void test_metadata()
{
	FileKeyProvider provider;
	const ProviderMetadata &metadata = provider.metadata();
	require(metadata.id == "file", "provider id mismatch");
	require(metadata.provider_class == ProviderClass::file, "provider class mismatch");
	require(metadata.readiness == ProviderReadiness::ready, "provider readiness mismatch");
	require(metadata.exportable, "file provider must report exportable");
	require(metadata.reference_class == "file", "reference class mismatch");
	require(to_string(metadata.provider_class) == "file", "provider class string mismatch");
	require(to_string(ProviderReadiness::ready) == "ready", "provider readiness string mismatch");
	require(to_string(ProviderErrorCode::invalid_reference) == "provider.invalid_reference", "invalid reference code mismatch");
	require(to_string(ProviderErrorCode::unavailable) == "provider.unavailable", "unavailable code mismatch");
	require(to_string(ProviderErrorCode::not_ready) == "provider.not_ready", "not ready code mismatch");
	require(to_string(ProviderErrorCode::key_not_found) == "provider.key_not_found", "key not found code mismatch");
	require(to_string(ProviderErrorCode::key_parse_failed) == "provider.key_parse_failed", "parse code mismatch");
	require(to_string(ProviderErrorCode::algorithm_mismatch) == "provider.algorithm_mismatch", "algorithm code mismatch");
	require(to_string(ProviderErrorCode::key_binding_mismatch) == "provider.key_binding_mismatch", "binding code mismatch");
	require(to_string(ProviderErrorCode::exportability_violation) == "provider.exportability_violation", "exportability code mismatch");
	require(to_string(ProviderErrorCode::profile_mismatch) == "provider.profile_mismatch", "profile code mismatch");
	require(to_string(ProviderErrorCode::sign_failed) == "provider.sign_failed", "sign code mismatch");
}


void test_environment_policy()
{
	EnvironmentGuard guard;
	set_anopki_env("production");
	require(provider_policy_from_environment().production_mode, "production environment policy not detected");
	set_anopki_env("  Production  ");
	require(provider_policy_from_environment().production_mode, "normalized production environment policy not detected");
	set_anopki_env("development");
	require(!provider_policy_from_environment().production_mode, "development environment treated as production");
}

void test_success_and_golden_equivalence(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr subject_key = generate_rsa_key();
	X509Ptr issuer = make_issuer_certificate(issuer_key.get(), "AnoPKI File Provider Test CA");
	const std::filesystem::path key_path = temp.path() / "issuer.pem";
	write_private_key(key_path, issuer_key.get());

	SigningKeyHandle file_handle = resolve_certificate_signing_key(
	    "file:" + key_path.string(), "rsa_with_sha256", issuer.get(), ProviderPolicy{});
	require(file_handle.native_handle() != nullptr, "file reference did not return a key handle");
	require(file_handle.evidence().provider.id == "file", "file provider evidence missing");
	require(file_handle.evidence().operation == "certificate_issue", "certificate operation evidence mismatch");
	require(file_handle.evidence().provider.exportable, "file provider evidence must be exportable");
	require(file_handle.evidence().issuer_binding_verified, "issuer binding evidence missing");
	require(!file_handle.evidence().fallback_used, "fallback evidence must be false");
	require(file_handle.evidence().key_algorithm == "rsa", "key algorithm evidence mismatch");

	SigningKeyHandle bare_handle = resolve_certificate_signing_key(
	    key_path.string(), "sha256", issuer.get(), ProviderPolicy{});
	require(bare_handle.native_handle() != nullptr, "bare path did not return a key handle");
	require(!bare_handle.evidence().fallback_used, "bare path must not use fallback");

	SigningKeyHandle crl_handle = resolve_crl_signing_key(
	    "file:" + key_path.string(), issuer.get(), ProviderPolicy{});
	require(crl_handle.native_handle() != nullptr, "CRL resolver did not return a key handle");
	require(crl_handle.evidence().operation == "crl_generate_sign", "CRL operation evidence mismatch");
	require(crl_handle.evidence().requested_signature_algorithm == "sha256", "CRL signature algorithm evidence mismatch");
	require(crl_handle.evidence().issuer_binding_verified, "CRL issuer binding evidence missing");
	require(!crl_handle.evidence().fallback_used, "CRL resolver must not use fallback");

	SigningKeyHandle ocsp_handle = resolve_ocsp_signing_key(
	    "file:" + key_path.string(), issuer.get(), ProviderPolicy{});
	require(ocsp_handle.native_handle() != nullptr, "OCSP resolver did not return a key handle");
	require(ocsp_handle.evidence().operation == "ocsp_response_sign", "OCSP operation evidence mismatch");
	require(ocsp_handle.evidence().requested_signature_algorithm == "sha256", "OCSP signature algorithm evidence mismatch");
	require(ocsp_handle.evidence().issuer_binding_verified, "OCSP signer binding evidence missing");
	require(!ocsp_handle.evidence().fallback_used, "OCSP resolver must not use fallback");

	X509Ptr direct = make_unsigned_leaf(issuer.get(), subject_key.get());
	X509Ptr through_provider = make_unsigned_leaf(issuer.get(), subject_key.get());
	if (X509_sign(direct.get(), issuer_key.get(), EVP_sha256()) <= 0 ||
	    X509_sign(through_provider.get(), file_handle.native_handle(), EVP_sha256()) <= 0)
	{
		fail("golden equivalence signing failed");
	}
	require(certificate_der(direct.get()) == certificate_der(through_provider.get()),
	        "provider changed deterministic RSA certificate DER");
	EvpPkeyPtr issuer_public{X509_get_pubkey(issuer.get())};
	require(issuer_public != nullptr && X509_verify(through_provider.get(), issuer_public.get()) == 1,
	        "provider-signed certificate verification failed");
	expect_provider_error(
	    [&] { throw_provider_sign_failed(file_handle); },
	    ProviderErrorCode::sign_failed,
	    "sign");
}

void test_failures_and_no_fallback(const TempDirectory &temp)
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr other_key = generate_rsa_key();
	EvpPkeyPtr ec_key = generate_ec_key();
	X509Ptr issuer = make_issuer_certificate(issuer_key.get(), "AnoPKI Failure Test CA");
	X509Ptr other_issuer = make_issuer_certificate(other_key.get(), "AnoPKI Other CA");

	const std::filesystem::path valid_path = temp.path() / "valid.pem";
	const std::filesystem::path other_path = temp.path() / "other.pem";
	const std::filesystem::path ec_path = temp.path() / "ec.pem";
	const std::filesystem::path malformed_path = temp.path() / "malformed.pem";
	const std::filesystem::path encrypted_path = temp.path() / "encrypted.pem";
	const std::filesystem::path directory_path = temp.path() / "not-a-file";
	write_private_key(valid_path, issuer_key.get());
	write_private_key(other_path, other_key.get());
	write_private_key(ec_path, ec_key.get());
	write_encrypted_private_key(encrypted_path, issuer_key.get());
	std::ofstream{malformed_path} << "not a private key\n";
	std::filesystem::create_directory(directory_path);

	expect_provider_error(
	    [&] { (void)resolve_certificate_signing_key("", "sha256", issuer.get(), ProviderPolicy{}); },
	    ProviderErrorCode::invalid_reference,
	    "reference");
	expect_provider_error(
	    [&] { (void)resolve_certificate_signing_key("file:", "sha256", issuer.get(), ProviderPolicy{}); },
	    ProviderErrorCode::invalid_reference,
	    "reference");

	const std::filesystem::path missing_path = temp.path() / "missing-secret.pem";
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + missing_path.string(), "sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::key_not_found,
	    "open",
	    "missing-secret.pem");

	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + directory_path.string(), "sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::not_ready,
	    "open",
	    "not-a-file");

	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + malformed_path.string(), "sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::key_parse_failed,
	    "parse",
	    "malformed.pem");

	// Encrypted PEM is unsupported because this provider deliberately has no
	// password-input channel. It must fail without prompting on stdin/terminal.
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + encrypted_path.string(), "sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::key_parse_failed,
	    "parse",
	    "test-only-password");

	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + valid_path.string(), "ecdsa_with_sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::algorithm_mismatch,
	    "algorithm");

	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + other_path.string(), "rsa_with_sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::key_binding_mismatch,
	    "binding");

	ProviderPolicy unavailable;
	unavailable.file_provider_available = false;
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + valid_path.string(), "rsa_with_sha256", issuer.get(), unavailable);
	    },
	    ProviderErrorCode::unavailable,
	    "availability");

	ProviderPolicy production;
	production.production_mode = true;
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + valid_path.string(), "rsa_with_sha256", issuer.get(), production);
	    },
	    ProviderErrorCode::exportability_violation,
	    "policy");

	// A valid file exists at the suffix, but an unsupported provider reference
	// must fail at resolution and must not retry it as a file path.
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "kms:" + valid_path.string(), "rsa_with_sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::unavailable,
	    "resolve",
	    valid_path.filename().string());

	// A malformed selected file must fail as malformed even when another valid
	// key is present. There is no provider/file fallback search.
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + malformed_path.string(), "rsa_with_sha256", other_issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::key_parse_failed,
	    "parse");

	// EC keys are valid only for ECDSA/generic digest requests and must still bind
	// to the issuer certificate.
	expect_provider_error(
	    [&] {
		    (void)resolve_certificate_signing_key(
		        "file:" + ec_path.string(), "rsa_with_sha256", issuer.get(), ProviderPolicy{});
	    },
	    ProviderErrorCode::algorithm_mismatch,
	    "algorithm");
}

} // namespace

int main()
{
	try
	{
		TempDirectory temp;
		test_metadata();
		test_environment_policy();
		test_success_and_golden_equivalence(temp);
		test_failures_and_no_fallback(temp);
		std::cout << "file key provider tests passed\n";
		return 0;
	}
	catch (const std::exception &error)
	{
		std::cerr << "file key provider test failed: " << error.what() << '\n';
		return 1;
	}
}
