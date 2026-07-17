// SPDX-License-Identifier: MPL-2.0
#include "key_providers/provider_resolver.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace anopki::core::openssl_key_providers;

struct EvpPkeyDeleter
{
	void operator()(EVP_PKEY *value) const noexcept
	{
		EVP_PKEY_free(value);
	}
};

struct EvpPkeyCtxDeleter
{
	void operator()(EVP_PKEY_CTX *value) const noexcept
	{
		EVP_PKEY_CTX_free(value);
	}
};

struct X509Deleter
{
	void operator()(X509 *value) const noexcept
	{
		X509_free(value);
	}
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

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

X509Ptr make_certificate(EVP_PKEY *key, const char *common_name, bool self_sign)
{
	X509Ptr certificate{X509_new()};
	if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
	    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), self_sign ? 1 : 2) != 1 ||
	    ASN1_TIME_set_string(X509_getm_notBefore(certificate.get()), "20260101000000Z") != 1 ||
	    ASN1_TIME_set_string(X509_getm_notAfter(certificate.get()), "20360101000000Z") != 1 ||
	    X509_set_pubkey(certificate.get(), key) != 1)
	{
		fail("certificate setup failed");
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
	        0) != 1)
	{
		fail("certificate name setup failed");
	}
	if (self_sign)
	{
		if (X509_set_issuer_name(certificate.get(), name) != 1 ||
		    X509_sign(certificate.get(), key, EVP_sha256()) <= 0)
		{
			fail("self-signed certificate setup failed");
		}
	}
	return certificate;
}

class SoftwareTokenKeyProvider final : public SigningKeyProvider
{
public:
	enum class Mode
	{
		success,
		provider_failure,
		mismatched_identity,
		mismatched_operation,
		mismatched_algorithm,
		unverified_binding,
		empty_key_algorithm,
		fallback_claim,
	};

	SoftwareTokenKeyProvider(EVP_PKEY *key, Mode mode = Mode::success, bool exportable = false)
	    : key_{key}, mode_{mode}
	{
		metadata_.id = "software-token-test";
		metadata_.provider_class = ProviderClass::software_token;
		metadata_.readiness = ProviderReadiness::ready;
		metadata_.exportable = exportable;
		metadata_.reference_class = "software-token";
	}

	[[nodiscard]] const ProviderMetadata &metadata() const noexcept override
	{
		return metadata_;
	}

	[[nodiscard]] bool accepts(std::string_view key_ref) const noexcept override
	{
		return key_ref == "softtoken:issuer";
	}

	[[nodiscard]] SigningKeyHandle acquire(const SigningKeyRequest &request) const override
	{
		++acquire_count_;
		if (mode_ == Mode::provider_failure)
		{
			throw ProviderError{
			    ProviderErrorCode::not_ready,
			    RedactedProviderDiagnostics{metadata_.id, "session"},
			};
		}
		if (key_ == nullptr || request.issuer_certificate == nullptr ||
		    X509_check_private_key(request.issuer_certificate, key_) != 1)
		{
			throw ProviderError{
			    ProviderErrorCode::key_binding_mismatch,
			    RedactedProviderDiagnostics{metadata_.id, "binding"},
			};
		}
		if (EVP_PKEY_up_ref(key_) != 1)
		{
			throw ProviderError{
			    ProviderErrorCode::not_ready,
			    RedactedProviderDiagnostics{metadata_.id, "handle"},
			};
		}

		SigningKeyEvidence evidence;
		evidence.provider = metadata_;
		evidence.operation = request.operation;
		evidence.key_algorithm = "rsa";
		evidence.requested_signature_algorithm = request.signature_algorithm;
		evidence.issuer_binding_verified = true;
		evidence.fallback_used = false;
		if (mode_ == Mode::mismatched_identity)
		{
			evidence.provider.id = "unexpected-provider";
		}
		else if (mode_ == Mode::mismatched_operation)
		{
			evidence.operation = "unexpected_operation";
		}
		else if (mode_ == Mode::mismatched_algorithm)
		{
			evidence.requested_signature_algorithm = "ecdsa_with_sha256";
		}
		else if (mode_ == Mode::unverified_binding)
		{
			evidence.issuer_binding_verified = false;
		}
		else if (mode_ == Mode::empty_key_algorithm)
		{
			evidence.key_algorithm.clear();
		}
		else if (mode_ == Mode::fallback_claim)
		{
			evidence.fallback_used = true;
		}
		return SigningKeyHandle{key_, std::move(evidence)};
	}

	void set_readiness(ProviderReadiness readiness) noexcept
	{
		metadata_.readiness = readiness;
	}

	[[nodiscard]] int acquire_count() const noexcept
	{
		return acquire_count_;
	}

private:
	EVP_PKEY *key_{nullptr};
	Mode mode_{Mode::success};
	ProviderMetadata metadata_;
	mutable int acquire_count_{0};
};

SigningKeyRequest request_for(X509 *issuer, ProviderPolicy policy = {})
{
	return SigningKeyRequest{
	    "certificate_issue",
	    "softtoken:issuer",
	    "rsa_with_sha256",
	    issuer,
	    policy,
	};
}

void expect_error(
    const std::function<void()> &operation,
    ProviderErrorCode expected_code,
    std::string_view expected_provider,
    std::string_view expected_stage)
{
	try
	{
		operation();
	}
	catch (const ProviderError &error)
	{
		require(error.code() == expected_code, "unexpected provider error code");
		require(error.what() == to_string(expected_code), "provider error message drift");
		require(error.diagnostics().provider_id == expected_provider, "provider diagnostic identity drift");
		require(error.diagnostics().stage == expected_stage, "provider diagnostic stage drift");
		return;
	}
	fail("expected ProviderError");
}

void test_non_exportable_software_token_signs_in_production()
{
	EvpPkeyPtr issuer_key = generate_rsa_key();
	EvpPkeyPtr leaf_key = generate_rsa_key();
	X509Ptr issuer = make_certificate(issuer_key.get(), "Software Token Test CA", true);
	X509Ptr leaf = make_certificate(leaf_key.get(), "software-token-leaf.example", false);
	if (X509_set_issuer_name(leaf.get(), X509_get_subject_name(issuer.get())) != 1)
	{
		fail("leaf issuer setup failed");
	}

	SoftwareTokenKeyProvider provider{issuer_key.get()};
	ProviderPolicy policy;
	policy.production_mode = true;
	SigningKeyHandle handle = resolve_signing_key_with_provider(provider, request_for(issuer.get(), policy));
	require(handle.evidence().provider.id == "software-token-test", "software-token identity mismatch");
	require(handle.evidence().provider.provider_class == ProviderClass::software_token, "software-token class mismatch");
	require(!handle.evidence().provider.exportable, "software-token test provider must be non-exportable");
	require(!handle.evidence().fallback_used, "software-token resolver recorded fallback");
	require(provider.acquire_count() == 1, "selected provider must be acquired exactly once");
	require(X509_sign(leaf.get(), handle.native_handle(), EVP_sha256()) > 0, "software-token signing failed");
	EvpPkeyPtr issuer_public{X509_get_pubkey(issuer.get())};
	require(issuer_public && X509_verify(leaf.get(), issuer_public.get()) == 1, "software-token signature verification failed");
	require(to_string(ProviderClass::software_token) == "software_token", "software-token class string mismatch");
}

void test_reference_and_readiness_fail_before_acquire()
{
	EvpPkeyPtr key = generate_rsa_key();
	X509Ptr issuer = make_certificate(key.get(), "Resolver Test CA", true);
	SoftwareTokenKeyProvider provider{key.get()};

	SigningKeyRequest invalid = request_for(issuer.get());
	invalid.key_ref.clear();
	expect_error(
	    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, invalid)); },
	    ProviderErrorCode::invalid_reference,
	    "software-token-test",
	    "reference");
	require(provider.acquire_count() == 0, "invalid reference reached provider acquire");

	SigningKeyRequest unsupported = request_for(issuer.get());
	unsupported.key_ref = "pkcs11:token=issuer";
	expect_error(
	    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, unsupported)); },
	    ProviderErrorCode::unavailable,
	    "software-token-test",
	    "resolve");
	require(provider.acquire_count() == 0, "unsupported reference reached provider acquire");

	provider.set_readiness(ProviderReadiness::unavailable);
	expect_error(
	    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, request_for(issuer.get()))); },
	    ProviderErrorCode::not_ready,
	    "software-token-test",
	    "readiness");
	require(provider.acquire_count() == 0, "unready provider reached acquire");
}

void test_exportable_provider_rejected_before_acquire()
{
	EvpPkeyPtr key = generate_rsa_key();
	X509Ptr issuer = make_certificate(key.get(), "Exportability Test CA", true);
	SoftwareTokenKeyProvider provider{key.get(), SoftwareTokenKeyProvider::Mode::success, true};
	ProviderPolicy policy;
	policy.production_mode = true;
	expect_error(
	    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, request_for(issuer.get(), policy))); },
	    ProviderErrorCode::exportability_violation,
	    "software-token-test",
	    "policy");
	require(provider.acquire_count() == 0, "exportable production provider reached acquire");
}

void test_provider_failure_has_no_fallback()
{
	EvpPkeyPtr key = generate_rsa_key();
	X509Ptr issuer = make_certificate(key.get(), "No Fallback Test CA", true);
	SoftwareTokenKeyProvider provider{key.get(), SoftwareTokenKeyProvider::Mode::provider_failure};
	expect_error(
	    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, request_for(issuer.get()))); },
	    ProviderErrorCode::not_ready,
	    "software-token-test",
	    "session");
	require(provider.acquire_count() == 1, "failed selected provider was retried");
}

void test_evidence_mismatch_fails_closed()
{
	EvpPkeyPtr key = generate_rsa_key();
	X509Ptr issuer = make_certificate(key.get(), "Evidence Test CA", true);
	for (const SoftwareTokenKeyProvider::Mode mode : {
	         SoftwareTokenKeyProvider::Mode::mismatched_identity,
	         SoftwareTokenKeyProvider::Mode::mismatched_operation,
	         SoftwareTokenKeyProvider::Mode::mismatched_algorithm,
	         SoftwareTokenKeyProvider::Mode::unverified_binding,
	         SoftwareTokenKeyProvider::Mode::empty_key_algorithm,
	         SoftwareTokenKeyProvider::Mode::fallback_claim,
	     })
	{
		SoftwareTokenKeyProvider provider{key.get(), mode};
		expect_error(
		    [&] { static_cast<void>(resolve_signing_key_with_provider(provider, request_for(issuer.get()))); },
		    ProviderErrorCode::profile_mismatch,
		    "software-token-test",
		    "evidence");
		require(provider.acquire_count() == 1, "evidence mismatch retried selected provider");
	}
}

} // namespace

int main()
{
	try
	{
		test_non_exportable_software_token_signs_in_production();
		test_reference_and_readiness_fail_before_acquire();
		test_exportable_provider_rejected_before_acquire();
		test_provider_failure_has_no_fallback();
		test_evidence_mismatch_fails_closed();
		return 0;
	}
	catch (const std::exception &error)
	{
		return error.what()[0] == '\0' ? 2 : 1;
	}
}
