// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <string_view>

namespace anopki {

struct Version {
    int major;
    int minor;
    int patch;
};

[[nodiscard]] Version library_version() noexcept;
[[nodiscard]] std::string_view library_version_string() noexcept;

}  // namespace anopki
