// SPDX-License-Identifier: MPL-2.0
#include "provider_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace anopki::core::openssl_key_providers
{
namespace
{

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

[[nodiscard]] std::string provider_id(const ProviderMetadata &metadata)
{
	return metadata.id.empty() ? "unknown" : metadata.id;
}

[[noreturn]] void fail(
    ProviderErrorCode code,
    const ProviderMetadata &metadata,
    std::string stage)
{
	throw ProviderError{
	    code,
	    RedactedProviderDiagnostics{provider_id(metadata), std::move(stage)},
	};
}

[[nodiscard]] bool same_metadata(
    const ProviderMetadata &left,
    const ProviderMetadata &right) noexcept
{
	return left.id == right.id &&
	       left.provider_class == right.provider_class &&
	       left.readiness == right.readiness &&
	       left.exportable == right.exportable &&
	       left.reference_class == right.reference_class;
}

void verify_evidence(
    const SigningKeyRequest &request,
    const ProviderMetadata &selected,
    const SigningKeyHandle &handle)
{
	const SigningKeyEvidence &evidence = handle.evidence();
	if (!same_metadata(evidence.provider, selected) ||
	    evidence.operation != request.operation ||
	    evidence.requested_signature_algorithm != request.signature_algorithm ||
	    evidence.key_algorithm.empty() ||
	    !evidence.issuer_binding_verified ||
	    evidence.fallback_used)
	{
		fail(ProviderErrorCode::profile_mismatch, selected, "evidence");
	}
}

} // namespace

SigningKeyHandle resolve_signing_key_with_provider(
    const SigningKeyProvider &provider,
    const SigningKeyRequest &request)
{
	const ProviderMetadata &metadata = provider.metadata();
	if (blank(request.key_ref) || has_embedded_nul(request.key_ref))
	{
		fail(ProviderErrorCode::invalid_reference, metadata, "reference");
	}
	if (!provider.accepts(request.key_ref))
	{
		fail(ProviderErrorCode::unavailable, metadata, "resolve");
	}
	if (metadata.readiness != ProviderReadiness::ready)
	{
		fail(ProviderErrorCode::not_ready, metadata, "readiness");
	}
	if (request.policy.production_mode && metadata.exportable)
	{
		fail(ProviderErrorCode::exportability_violation, metadata, "policy");
	}

	SigningKeyHandle handle = provider.acquire(request);
	verify_evidence(request, metadata, handle);
	return handle;
}

} // namespace anopki::core::openssl_key_providers
