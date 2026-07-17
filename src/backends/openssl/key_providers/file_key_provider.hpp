// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stdexcept>
#include <string>
#include <string_view>

namespace anopki::core::openssl_key_providers
{

enum class ProviderClass
{
	file,
};

enum class ProviderReadiness
{
	ready,
	unavailable,
};

enum class ProviderErrorCode
{
	invalid_reference,
	unavailable,
	not_ready,
	key_not_found,
	key_parse_failed,
	algorithm_mismatch,
	key_binding_mismatch,
	exportability_violation,
	profile_mismatch,
	sign_failed,
};

struct ProviderMetadata
{
	std::string id;
	ProviderClass provider_class{ProviderClass::file};
	ProviderReadiness readiness{ProviderReadiness::unavailable};
	bool exportable{true};
	std::string reference_class;
};

struct RedactedProviderDiagnostics
{
	std::string provider_id;
	std::string stage;
};

struct ProviderPolicy
{
	bool production_mode{false};
	bool file_provider_available{true};
};

struct SigningKeyEvidence
{
	ProviderMetadata provider;
	std::string operation;
	std::string key_algorithm;
	std::string requested_signature_algorithm;
	bool issuer_binding_verified{false};
	bool fallback_used{false};
};

[[nodiscard]] std::string_view to_string(ProviderClass value) noexcept;
[[nodiscard]] std::string_view to_string(ProviderReadiness value) noexcept;
[[nodiscard]] std::string_view to_string(ProviderErrorCode value) noexcept;

class ProviderError final : public std::runtime_error
{
public:
	ProviderError(ProviderErrorCode code, RedactedProviderDiagnostics diagnostics);

	[[nodiscard]] ProviderErrorCode code() const noexcept;
	[[nodiscard]] const RedactedProviderDiagnostics &diagnostics() const noexcept;

private:
	ProviderErrorCode code_;
	RedactedProviderDiagnostics diagnostics_;
};

class SigningKeyHandle final
{
public:
	SigningKeyHandle(EVP_PKEY *key, SigningKeyEvidence evidence);
	~SigningKeyHandle();

	SigningKeyHandle(const SigningKeyHandle &) = delete;
	SigningKeyHandle &operator=(const SigningKeyHandle &) = delete;
	SigningKeyHandle(SigningKeyHandle &&other) noexcept;
	SigningKeyHandle &operator=(SigningKeyHandle &&other) noexcept;

	[[nodiscard]] EVP_PKEY *native_handle() const noexcept;
	[[nodiscard]] const SigningKeyEvidence &evidence() const noexcept;

private:
	EVP_PKEY *key_{nullptr};
	SigningKeyEvidence evidence_;
};

struct SigningKeyRequest
{
	std::string operation;
	std::string key_ref;
	std::string signature_algorithm;
	X509 *issuer_certificate{nullptr};
	ProviderPolicy policy;
};

class SigningKeyProvider
{
public:
	virtual ~SigningKeyProvider() = default;

	[[nodiscard]] virtual const ProviderMetadata &metadata() const noexcept = 0;
	[[nodiscard]] virtual bool accepts(std::string_view key_ref) const noexcept = 0;
	[[nodiscard]] virtual SigningKeyHandle acquire(const SigningKeyRequest &request) const = 0;
};

class FileKeyProvider final : public SigningKeyProvider
{
public:
	FileKeyProvider();

	[[nodiscard]] const ProviderMetadata &metadata() const noexcept override;
	[[nodiscard]] bool accepts(std::string_view key_ref) const noexcept override;
	[[nodiscard]] SigningKeyHandle acquire(const SigningKeyRequest &request) const override;

private:
	ProviderMetadata metadata_;
};

[[nodiscard]] ProviderPolicy provider_policy_from_environment() noexcept;

// Provider resolution is intentionally single-shot. Unsupported references or
// provider failures are returned directly and are never retried through another
// provider, a bare file key, another backend, or another product profile.
[[nodiscard]] SigningKeyHandle resolve_certificate_signing_key(
    const std::string &key_ref,
    const std::string &signature_algorithm,
    X509 *issuer_certificate,
    ProviderPolicy policy);

[[nodiscard]] SigningKeyHandle resolve_crl_signing_key(
    const std::string &key_ref,
    X509 *issuer_certificate,
    ProviderPolicy policy);

[[nodiscard]] SigningKeyHandle resolve_ocsp_signing_key(
    const std::string &key_ref,
    X509 *signer_certificate,
    ProviderPolicy policy);

[[noreturn]] void throw_provider_sign_failed(const SigningKeyHandle &handle);

} // namespace anopki::core::openssl_key_providers
