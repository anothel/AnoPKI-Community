// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/issue.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

IssueResult issue_certificate(const IssueRequest &request)
{
	return crypto::default_backend().issue_certificate(request);
}

} // namespace anopki::core
