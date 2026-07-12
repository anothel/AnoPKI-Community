// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/issue.hpp"
#include "anopki/crypto/runtime.hpp"

namespace anopki::core
{

IssueResult issue_certificate(const IssueRequest &request)
{
	const crypto::Backend &backend = crypto::selected_backend();
	crypto::require_backend_capability(backend, crypto::BackendCapability::certificate_issue);
	return backend.issue_certificate(request);
}

} // namespace anopki::core
