// SPDX-License-Identifier: MPL-2.0
#include "anopki/version.hpp"

#include <cassert>
#include <string_view>

int main()
{
    const auto version = anopki::library_version();

    assert(version.major == 0);
    assert(version.minor == 1);
    assert(version.patch == 0);
    assert(anopki::library_version_string() == std::string_view{"0.1.0-alpha.0"});

    return 0;
}
