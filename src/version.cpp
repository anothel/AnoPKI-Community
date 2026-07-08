// SPDX-License-Identifier: MPL-2.0
#include "anopki/version.hpp"

#include "anopki/version_config.hpp"

namespace anopki {

Version library_version() noexcept
{
    return {ANOPKI_VERSION_MAJOR, ANOPKI_VERSION_MINOR, ANOPKI_VERSION_PATCH};
}

std::string_view library_version_string() noexcept
{
    return ANOPKI_VERSION_STRING;
}

}  // namespace anopki
