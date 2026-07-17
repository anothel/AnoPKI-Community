// SPDX-License-Identifier: MPL-2.0
#include "file_key_provider.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace anopki::core::openssl_key_providers
{
namespace
{

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;

// The current FileKeyProvider contract has no password-input channel. Returning
// zero makes encrypted private-key PEM fail closed instead of prompting on the
// process terminal or reading from standard input.
int reject_private_key_password(char *, int, int, void *) noexcept
{
	return 0;
}

[[nodiscard]] RedactedProviderDiagnostics diagnostic(std::string stage)
{
	return RedactedProviderDiagnostics{"file", std::move(stage)};
}

[[noreturn]] void fail(ProviderErrorCode code, std::string stage)
{
	ERR_clear_error();
	throw ProviderError{code, diagnostic(std::move(stage))};
}

[[nodiscard]] std::string lowercase(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return value;
}

[[nodiscard]] bool iequals_ascii(std::string_view left, std::string_view right) noexcept
{
	if (left.size() != right.size())
	{
		return false;
	}
	for (std::string_view::size_type index = 0; index < left.size(); ++index)
	{
		if (std::tolower(static_cast<unsigned char>(left[index])) !=
		    std::tolower(static_cast<unsigned char>(right[index])))
		{
			return false;
		}
	}
	return true;
}

[[nodiscard]] bool blank(std::string_view value) noexcept
{
	return value.empty() || std::all_of(value.begin(), value.end(), [](unsigned char ch) {
		return std::isspace(ch) != 0;
	});
}

[[nodiscard]] bool has_embedded_nul(std::string_view value) noexcept
{
	return value.find('\0') != std::string_view::npos;
}

[[nodiscard]] bool windows_drive_path(std::string_view value) noexcept
{
	return value.size() >= 3 && std::isalpha(static_cast<unsigned char>(value[0])) != 0 && value[1] == ':' &&
	       (value[2] == '\\' || value[2] == '/');
}

[[nodiscard]] std::string_view scheme_of(std::string_view value) noexcept
{
	if (windows_drive_path(value))
	{
		return {};
	}
	const std::string_view::size_type colon = value.find(':');
	if (colon == std::string_view::npos || colon == 0)
	{
		return {};
	}
	for (std::string_view::size_type index = 0; index < colon; ++index)
	{
		const unsigned char ch = static_cast<unsigned char>(value[index]);
		if ((index == 0 && std::isalpha(ch) == 0) ||
		    (index != 0 && std::isalnum(ch) == 0 && ch != '+' && ch != '-' && ch != '.'))
		{
			return {};
		}
	}
	return value.substr(0, colon);
}

[[nodiscard]] std::filesystem::path normalize_file_reference(std::string_view key_ref)
{
	if (blank(key_ref) || has_embedded_nul(key_ref))
	{
		fail(ProviderErrorCode::invalid_reference, "reference");
	}

	std::string_view path = key_ref;
	const std::string_view scheme = scheme_of(key_ref);
	if (!scheme.empty())
	{
		if (!iequals_ascii(scheme, "file"))
		{
			fail(ProviderErrorCode::unavailable, "resolve");
		}
		path.remove_prefix(scheme.size() + 1U);
	}

	if (blank(path) || has_embedded_nul(path))
	{
		fail(ProviderErrorCode::invalid_reference, "reference");
	}
	return std::filesystem::path{std::string{path}};
}

[[nodiscard]] std::string normalized_signature_algorithm(std::string_view value)
{
	std::string normalized;
	normalized.reserve(value.size());
	for (const unsigned char ch : value)
	{
		if (ch == '-' || ch == ' ')
		{
			normalized.push_back('_');
		}
		else
		{
			normalized.push_back(static_cast<char>(std::tolower(ch)));
		}
	}
	return normalized;
}

[[nodiscard]] std::string key_algorithm(EVP_PKEY *key)
{
	if (key == nullptr)
	{
		fail(ProviderErrorCode::algorithm_mismatch, "algorithm");
	}
	switch (EVP_PKEY_base_id(key))
	{
	case EVP_PKEY_RSA:
		return "rsa";
#ifdef EVP_PKEY_RSA_PSS
	case EVP_PKEY_RSA_PSS:
		return "rsa_pss";
#endif
	case EVP_PKEY_EC:
		return "ecdsa";
#ifdef EVP_PKEY_DSA
	case EVP_PKEY_DSA:
		return "dsa";
#endif
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519:
		return "ed25519";
#endif
	default:
		return "unknown";
	}
}

void verify_algorithm_compatibility(EVP_PKEY *key, std::string_view requested)
{
	const std::string algorithm = normalized_signature_algorithm(requested);
	const int key_type = EVP_PKEY_base_id(key);
	const bool is_rsa = key_type == EVP_PKEY_RSA
#ifdef EVP_PKEY_RSA_PSS
	                    || key_type == EVP_PKEY_RSA_PSS
#endif
	    ;
	const bool is_ec = key_type == EVP_PKEY_EC;
	const bool is_dsa =
#ifdef EVP_PKEY_DSA
	    key_type == EVP_PKEY_DSA;
#else
	    false;
#endif
	const bool is_ed25519 =
#ifdef EVP_PKEY_ED25519
	    key_type == EVP_PKEY_ED25519;
#else
	    false;
#endif

	const bool generic_digest = algorithm.empty() || algorithm == "sha256" || algorithm == "sha384" ||
	                            algorithm == "sha512";
	const bool rsa_digest = algorithm == "rsa_with_sha256" || algorithm == "rsa_with_sha384" ||
	                        algorithm == "rsa_with_sha512";
	const bool ecdsa_digest = algorithm == "ecdsa_with_sha256" || algorithm == "ecdsa_with_sha384" ||
	                          algorithm == "ecdsa_with_sha512";

	if ((generic_digest && (is_rsa || is_ec || is_dsa)) || (rsa_digest && is_rsa) ||
	    (ecdsa_digest && is_ec) || (algorithm == "ed25519" && is_ed25519))
	{
		return;
	}
	fail(ProviderErrorCode::algorithm_mismatch, "algorithm");
}

void verify_issuer_binding(X509 *issuer_certificate, EVP_PKEY *key)
{
	if (issuer_certificate == nullptr || key == nullptr)
	{
		fail(ProviderErrorCode::key_binding_mismatch, "binding");
	}
	if (X509_check_private_key(issuer_certificate, key) != 1)
	{
		fail(ProviderErrorCode::key_binding_mismatch, "binding");
	}
	ERR_clear_error();
}



} // namespace

std::string_view to_string(ProviderClass value) noexcept
{
	switch (value)
	{
	case ProviderClass::file:
		return "file";
	}
	return "file";
}

std::string_view to_string(ProviderReadiness value) noexcept
{
	switch (value)
	{
	case ProviderReadiness::ready:
		return "ready";
	case ProviderReadiness::unavailable:
		return "unavailable";
	}
	return "unavailable";
}

std::string_view to_string(ProviderErrorCode value) noexcept
{
	switch (value)
	{
	case ProviderErrorCode::invalid_reference:
		return "provider.invalid_reference";
	case ProviderErrorCode::unavailable:
		return "provider.unavailable";
	case ProviderErrorCode::not_ready:
		return "provider.not_ready";
	case ProviderErrorCode::key_not_found:
		return "provider.key_not_found";
	case ProviderErrorCode::key_parse_failed:
		return "provider.key_parse_failed";
	case ProviderErrorCode::algorithm_mismatch:
		return "provider.algorithm_mismatch";
	case ProviderErrorCode::key_binding_mismatch:
		return "provider.key_binding_mismatch";
	case ProviderErrorCode::exportability_violation:
		return "provider.exportability_violation";
	case ProviderErrorCode::profile_mismatch:
		return "provider.profile_mismatch";
	case ProviderErrorCode::sign_failed:
		return "provider.sign_failed";
	}
	return "provider.sign_failed";
}

ProviderError::ProviderError(ProviderErrorCode code, RedactedProviderDiagnostics diagnostics)
    : std::runtime_error{std::string{to_string(code)}}, code_{code}, diagnostics_{std::move(diagnostics)}
{
}

ProviderErrorCode ProviderError::code() const noexcept
{
	return code_;
}

const RedactedProviderDiagnostics &ProviderError::diagnostics() const noexcept
{
	return diagnostics_;
}

SigningKeyHandle::SigningKeyHandle(EVP_PKEY *key, SigningKeyEvidence evidence)
    : key_{key}, evidence_{std::move(evidence)}
{
	if (key_ == nullptr)
	{
		fail(ProviderErrorCode::not_ready, "handle");
	}
}

SigningKeyHandle::~SigningKeyHandle()
{
	EVP_PKEY_free(key_);
}

SigningKeyHandle::SigningKeyHandle(SigningKeyHandle &&other) noexcept
    : key_{std::exchange(other.key_, nullptr)}, evidence_{std::move(other.evidence_)}
{
}

SigningKeyHandle &SigningKeyHandle::operator=(SigningKeyHandle &&other) noexcept
{
	if (this != &other)
	{
		EVP_PKEY_free(key_);
		key_ = std::exchange(other.key_, nullptr);
		evidence_ = std::move(other.evidence_);
	}
	return *this;
}

EVP_PKEY *SigningKeyHandle::native_handle() const noexcept
{
	return key_;
}

const SigningKeyEvidence &SigningKeyHandle::evidence() const noexcept
{
	return evidence_;
}

FileKeyProvider::FileKeyProvider()
{
	metadata_.id = "file";
	metadata_.provider_class = ProviderClass::file;
	metadata_.readiness = ProviderReadiness::ready;
	metadata_.exportable = true;
	metadata_.reference_class = "file";
}

const ProviderMetadata &FileKeyProvider::metadata() const noexcept
{
	return metadata_;
}

bool FileKeyProvider::accepts(std::string_view key_ref) const noexcept
{
	if (blank(key_ref) || has_embedded_nul(key_ref))
	{
		return false;
	}
	const std::string_view scheme = scheme_of(key_ref);
	return scheme.empty() || iequals_ascii(scheme, "file");
}

SigningKeyHandle FileKeyProvider::acquire(const SigningKeyRequest &request) const
{
	if (!request.policy.file_provider_available)
	{
		fail(ProviderErrorCode::unavailable, "availability");
	}
	if (request.policy.production_mode && metadata_.exportable)
	{
		fail(ProviderErrorCode::exportability_violation, "policy");
	}

	const std::filesystem::path path = normalize_file_reference(request.key_ref);
	std::error_code error;
	const bool exists = std::filesystem::exists(path, error);
	if (error)
	{
		fail(ProviderErrorCode::not_ready, "open");
	}
	if (!exists)
	{
		fail(ProviderErrorCode::key_not_found, "open");
	}
	if (!std::filesystem::is_regular_file(path, error) || error)
	{
		fail(ProviderErrorCode::not_ready, "open");
	}

	ERR_clear_error();
	BioPtr bio{BIO_new_file(path.string().c_str(), "rb")};
	if (!bio)
	{
		fail(ProviderErrorCode::not_ready, "open");
	}
	EVP_PKEY *key = PEM_read_bio_PrivateKey(bio.get(), nullptr, reject_private_key_password, nullptr);
	if (key == nullptr)
	{
		fail(ProviderErrorCode::key_parse_failed, "parse");
	}

	try
	{
		verify_algorithm_compatibility(key, request.signature_algorithm);
		verify_issuer_binding(request.issuer_certificate, key);
	}
	catch (...)
	{
		EVP_PKEY_free(key);
		throw;
	}

	SigningKeyEvidence evidence;
	evidence.provider = metadata_;
	evidence.operation = request.operation;
	evidence.key_algorithm = key_algorithm(key);
	evidence.requested_signature_algorithm = request.signature_algorithm;
	evidence.issuer_binding_verified = true;
	evidence.fallback_used = false;
	return SigningKeyHandle{key, std::move(evidence)};
}

ProviderPolicy provider_policy_from_environment() noexcept
{
	ProviderPolicy policy;
	const char *value = std::getenv("ANOPKI_ENV");
	if (value != nullptr)
	{
		std::string normalized = lowercase(value);
		normalized.erase(normalized.begin(), std::find_if(normalized.begin(), normalized.end(), [](unsigned char ch) {
			return std::isspace(ch) == 0;
		}));
		normalized.erase(std::find_if(normalized.rbegin(), normalized.rend(), [](unsigned char ch) {
			return std::isspace(ch) == 0;
		}).base(), normalized.end());
		policy.production_mode = normalized == "production";
	}
	return policy;
}

namespace
{

SigningKeyHandle resolve_signing_key(
    std::string operation,
    const std::string &key_ref,
    const std::string &signature_algorithm,
    X509 *issuer_certificate,
    ProviderPolicy policy)
{
	FileKeyProvider provider;
	if (!provider.accepts(key_ref))
	{
		if (blank(key_ref) || has_embedded_nul(key_ref))
		{
			fail(ProviderErrorCode::invalid_reference, "reference");
		}
		fail(ProviderErrorCode::unavailable, "resolve");
	}
	return provider.acquire(SigningKeyRequest{
	    std::move(operation), key_ref, signature_algorithm, issuer_certificate, policy});
}

} // namespace

SigningKeyHandle resolve_certificate_signing_key(
    const std::string &key_ref,
    const std::string &signature_algorithm,
    X509 *issuer_certificate,
    ProviderPolicy policy)
{
	return resolve_signing_key(
	    "certificate_issue", key_ref, signature_algorithm, issuer_certificate, policy);
}

SigningKeyHandle resolve_crl_signing_key(
    const std::string &key_ref,
    X509 *issuer_certificate,
    ProviderPolicy policy)
{
	return resolve_signing_key(
	    "crl_generate_sign", key_ref, "sha256", issuer_certificate, policy);
}

SigningKeyHandle resolve_ocsp_signing_key(
    const std::string &key_ref,
    X509 *signer_certificate,
    ProviderPolicy policy)
{
	return resolve_signing_key(
	    "ocsp_response_sign", key_ref, "sha256", signer_certificate, policy);
}

void throw_provider_sign_failed(const SigningKeyHandle &handle)
{
	ERR_clear_error();
	throw ProviderError{
	    ProviderErrorCode::sign_failed,
	    RedactedProviderDiagnostics{handle.evidence().provider.id, "sign"},
	};
}

} // namespace anopki::core::openssl_key_providers
