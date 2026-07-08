// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <string_view>

namespace anopki::crypto {

class Backend {
public:
    virtual ~Backend() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

}  // namespace anopki::crypto
