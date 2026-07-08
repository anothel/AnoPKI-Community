// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <string>
#include <vector>

namespace anopki::core
{

struct IssueRequest
{
	std::string csr_pem;
	std::string issuer_certificate_pem;
	std::string issuer_key_ref;
	std::string aia_url;
	std::vector<std::string> crl_distribution_points;
	std::string subject;
	std::vector<std::string> dns_names;
	std::vector<std::string> ip_addresses;
	std::string not_before;
	std::string not_after;
	std::string signature_algorithm;
	std::string profile_id;
	bool basic_constraints_critical = false;
	bool basic_constraints_ca = false;
	int basic_constraints_max_path_len = -1;
	bool key_usage_critical = false;
	std::vector<std::string> key_usage;
	bool extended_key_usage_critical = false;
	std::vector<std::string> extended_key_usage;
	bool subject_key_identifier = false;
	bool authority_key_identifier = false;
};

struct IssueResult
{
	std::string certificate_pem;
	std::string serial_number;
	std::string subject;
	std::string not_before;
	std::string not_after;
};

[[nodiscard]] IssueResult issue_certificate(const IssueRequest &request);

} // namespace anopki::core
