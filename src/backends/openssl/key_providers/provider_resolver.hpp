// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "file_key_provider.hpp"

namespace anopki::core::openssl_key_providers
{

// Resolves exactly one explicitly selected provider. The resolver never owns a
// provider list and never retries through another provider, a file key, another
// backend, or another product profile.
[[nodiscard]] SigningKeyHandle resolve_signing_key_with_provider(
    const SigningKeyProvider &provider,
    const SigningKeyRequest &request);

} // namespace anopki::core::openssl_key_providers
