// SPDX-License-Identifier: MPL-2.0
#pragma once

#include "anopki/crypto/backend.hpp"

namespace anopki::crypto {

// Defined by the selected product adapter. Community/OpenSSL currently links
// exactly one implementation from the OpenSSL adapter target.
[[nodiscard]] const Backend &default_backend() noexcept;

}  // namespace anopki::crypto
