// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/crl.hpp"
#include "anopki/core/csr.hpp"
#include "anopki/core/issue.hpp"
#include "anopki/core/ocsp.hpp"
#include "anopki/crypto/runtime.hpp"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

struct JsonValue
{
	bool is_array = false;
	bool is_null = false;
	bool is_bool = false;
	bool is_number = false;
	std::string string_value;
	std::vector<std::string> array_value;
	bool bool_value = false;
	std::int64_t number_value = 0;
};

using JsonObject = std::map<std::string, JsonValue>;

[[noreturn]] void throw_json_parse_failed()
{
	throw std::runtime_error{"cli.json_parse_failed"};
}

class JsonParser
{
public:
	explicit JsonParser(std::string_view input)
	    : input_{input}
	{
	}

	JsonObject parse_object()
	{
		JsonObject object;
		expect('{');
		skip_ws();
		if (consume('}'))
		{
			skip_ws();
			if (position_ != input_.size())
			{
				throw_json_parse_failed();
			}
			return object;
		}

		while (true)
		{
			std::string key = parse_string();
			expect(':');
			object[key] = parse_value();
			skip_ws();
			if (consume('}'))
			{
				break;
			}
			expect(',');
		}

		skip_ws();
		if (position_ != input_.size())
		{
			throw_json_parse_failed();
		}
		return object;
	}

private:
	void skip_ws()
	{
		while (position_ < input_.size())
		{
			const char ch = input_[position_];
			if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t')
			{
				return;
			}
			++position_;
		}
	}

	bool consume(char expected)
	{
		skip_ws();
		if (position_ < input_.size() && input_[position_] == expected)
		{
			++position_;
			return true;
		}
		return false;
	}

	void expect(char expected)
	{
		if (!consume(expected))
		{
			throw_json_parse_failed();
		}
	}

	JsonValue parse_value()
	{
		skip_ws();
		if (position_ >= input_.size())
		{
			throw_json_parse_failed();
		}

		if (input_[position_] == '"')
		{
			JsonValue value;
			value.string_value = parse_string();
			return value;
		}

		if (input_[position_] == '[')
		{
			JsonValue value;
			value.is_array = true;
			value.array_value = parse_string_array();
			return value;
		}

		if (consume_literal("null"))
		{
			JsonValue value;
			value.is_null = true;
			return value;
		}
		if (consume_literal("true"))
		{
			JsonValue value;
			value.is_bool = true;
			value.bool_value = true;
			return value;
		}
		if (consume_literal("false"))
		{
			JsonValue value;
			value.is_bool = true;
			return value;
		}
		if (input_[position_] == '-' || std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			JsonValue value;
			value.is_number = true;
			value.number_value = parse_integer();
			return value;
		}

		throw_json_parse_failed();
	}

	bool consume_literal(std::string_view literal)
	{
		if (input_.substr(position_, literal.size()) != literal)
		{
			return false;
		}
		position_ += literal.size();
		return true;
	}

	std::vector<std::string> parse_string_array()
	{
		std::vector<std::string> values;
		expect('[');
		skip_ws();
		if (consume(']'))
		{
			return values;
		}

		while (true)
		{
			values.push_back(parse_string());
			skip_ws();
			if (consume(']'))
			{
				break;
			}
			expect(',');
		}
		return values;
	}

	std::int64_t parse_integer()
	{
		bool negative = false;
		if (input_[position_] == '-')
		{
			negative = true;
			++position_;
		}
		if (position_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			throw_json_parse_failed();
		}
		std::uint64_t value = 0;
		const std::uint64_t max_value = negative
		                                    ? static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1U
		                                    : static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
		while (position_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_])))
		{
			const std::uint64_t digit = static_cast<std::uint64_t>(input_[position_] - '0');
			if (value > ((max_value - digit) / 10U))
			{
				throw_json_parse_failed();
			}
			value = (value * 10U) + digit;
			++position_;
		}
		if (negative && value == max_value)
		{
			return std::numeric_limits<std::int64_t>::min();
		}
		const auto signed_value = static_cast<std::int64_t>(value);
		return negative ? -signed_value : signed_value;
	}

	std::string parse_string()
	{
		skip_ws();
		if (position_ >= input_.size() || input_[position_] != '"')
		{
			throw_json_parse_failed();
		}
		++position_;

		std::string value;
		while (position_ < input_.size())
		{
			const char ch = input_[position_++];
			if (ch == '"')
			{
				return value;
			}
			if (ch != '\\')
			{
				value.push_back(ch);
				continue;
			}
			if (position_ >= input_.size())
			{
				throw_json_parse_failed();
			}
			const char escaped = input_[position_++];
			switch (escaped)
			{
			case '\\':
				value.push_back('\\');
				break;
			case '"':
				value.push_back('"');
				break;
			case 'n':
				value.push_back('\n');
				break;
			case 'r':
				value.push_back('\r');
				break;
			case 't':
				value.push_back('\t');
				break;
			default:
				throw_json_parse_failed();
			}
		}

		throw_json_parse_failed();
	}

	std::string_view input_;
	std::string_view::size_type position_ = 0;
};

std::string read_file(const std::string &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input)
	{
		throw std::runtime_error{"cli.read_failed"};
	}

	std::ostringstream contents;
	contents << input.rdbuf();
	if (input.bad())
	{
		throw std::runtime_error{"cli.read_failed"};
	}
	return contents.str();
}

void write_file(const std::string &path, std::string_view contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	if (!output)
	{
		throw std::runtime_error{"cli.write_failed"};
	}

	output << contents;
	if (!output)
	{
		throw std::runtime_error{"cli.write_failed"};
	}
}

std::string json_escape(std::string_view value)
{
	std::string escaped;
	for (const char ch : value)
	{
		switch (ch)
		{
		case '\\':
			escaped += "\\\\";
			break;
		case '"':
			escaped += "\\\"";
			break;
		case '\n':
			escaped += "\\n";
			break;
		case '\r':
			escaped += "\\r";
			break;
		case '\t':
			escaped += "\\t";
			break;
		default:
			escaped.push_back(ch);
			break;
		}
	}
	return escaped;
}

std::string json_string(std::string_view value)
{
	return "\"" + json_escape(value) + "\"";
}

std::string json_string_array(const std::vector<std::string> &values)
{
	std::string output = "[";
	for (std::vector<std::string>::size_type index = 0; index < values.size(); ++index)
	{
		if (index != 0)
		{
			output.push_back(',');
		}
		output += json_string(values[index]);
	}
	output.push_back(']');
	return output;
}

std::string json_error(std::string_view code, std::string_view message)
{
	return "{\"code\":" + json_string(code) + ",\"message\":" + json_string(message) + "}";
}

void write_error(std::string_view code, std::string_view message)
{
	const anopki::crypto::ErrorDiagnostics diagnostics =
	    anopki::crypto::default_backend().drain_error_diagnostics();
	if (diagnostics.field.empty() || diagnostics.entries.empty())
	{
		std::cerr << json_error(code, message) << '\n';
		return;
	}
	std::cerr << "{\"code\":" << json_string(code)
	          << ",\"message\":" << json_string(message)
	          << ',' << json_string(diagnostics.field) << ':' << json_string_array(diagnostics.entries) << "}\n";
}

std::string get_string_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end())
	{
		return {};
	}
	if (found->second.is_array || found->second.is_null || found->second.is_bool || found->second.is_number)
	{
		throw_json_parse_failed();
	}
	return found->second.string_value;
}

std::vector<std::string> get_string_array_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end())
	{
		return {};
	}
	if (found->second.is_null)
	{
		return {};
	}
	if (!found->second.is_array)
	{
		throw_json_parse_failed();
	}
	return found->second.array_value;
}

bool get_bool_field(const JsonObject &object, const std::string &key)
{
	const auto found = object.find(key);
	if (found == object.end() || found->second.is_null)
	{
		return false;
	}
	if (!found->second.is_bool)
	{
		throw_json_parse_failed();
	}
	return found->second.bool_value;
}

int get_int_field(const JsonObject &object, const std::string &key, int default_value)
{
	const auto found = object.find(key);
	if (found == object.end() || found->second.is_null)
	{
		return default_value;
	}
	if (!found->second.is_number)
	{
		throw_json_parse_failed();
	}
	if (found->second.number_value < std::numeric_limits<int>::min() ||
	    found->second.number_value > std::numeric_limits<int>::max())
	{
		throw_json_parse_failed();
	}
	return static_cast<int>(found->second.number_value);
}

std::int64_t get_int64_field(const JsonObject &object, const std::string &key, std::int64_t default_value)
{
	const auto found = object.find(key);
	if (found == object.end() || found->second.is_null)
	{
		return default_value;
	}
	if (!found->second.is_number)
	{
		throw_json_parse_failed();
	}
	return found->second.number_value;
}

anopki::core::IssueRequest issue_request_from_json(std::string_view json)
{
	const JsonObject object = JsonParser{json}.parse_object();

	anopki::core::IssueRequest request;
	request.csr_pem = get_string_field(object, "csr_pem");
	request.issuer_certificate_pem = get_string_field(object, "issuer_certificate_pem");
	request.issuer_key_ref = get_string_field(object, "issuer_key_ref");
	request.aia_url = get_string_field(object, "aia_url");
	request.crl_distribution_points = get_string_array_field(object, "crl_distribution_points");
	request.subject = get_string_field(object, "subject");
	request.dns_names = get_string_array_field(object, "dns_names");
	request.ip_addresses = get_string_array_field(object, "ip_addresses");
	request.not_before = get_string_field(object, "not_before");
	request.not_after = get_string_field(object, "not_after");
	request.signature_algorithm = get_string_field(object, "signature_algorithm");
	request.profile_id = get_string_field(object, "profile_id");
	request.basic_constraints_critical = get_bool_field(object, "basic_constraints_critical");
	request.basic_constraints_ca = get_bool_field(object, "basic_constraints_ca");
	request.basic_constraints_max_path_len = get_int_field(object, "basic_constraints_max_path_len", -1);
	request.key_usage_critical = get_bool_field(object, "key_usage_critical");
	request.key_usage = get_string_array_field(object, "key_usage");
	request.extended_key_usage_critical = get_bool_field(object, "extended_key_usage_critical");
	request.extended_key_usage = get_string_array_field(object, "extended_key_usage");
	request.subject_key_identifier = get_bool_field(object, "subject_key_identifier");
	request.authority_key_identifier = get_bool_field(object, "authority_key_identifier");
	return request;
}

anopki::core::GenerateCRLRequest crl_request_from_json(std::string_view json)
{
	const JsonObject object = JsonParser{json}.parse_object();

	anopki::core::GenerateCRLRequest request;
	request.issuer_certificate_pem = get_string_field(object, "issuer_certificate_pem");
	request.issuer_key_ref = get_string_field(object, "issuer_key_ref");
	request.crl_number = get_int64_field(object, "crl_number", 0);
	request.this_update = get_string_field(object, "this_update");
	request.next_update = get_string_field(object, "next_update");

	const std::vector<std::string> serials = get_string_array_field(object, "revoked_serial_numbers");
	const std::vector<std::string> revoked_at_times = get_string_array_field(object, "revoked_at_times");
	const std::vector<std::string> reasons = get_string_array_field(object, "revocation_reasons");
	if (serials.size() != revoked_at_times.size() || serials.size() != reasons.size())
	{
		throw_json_parse_failed();
	}
	for (std::vector<std::string>::size_type index = 0; index < serials.size(); ++index)
	{
		request.revoked_certificates.push_back({serials[index], revoked_at_times[index], reasons[index]});
	}
	return request;
}

anopki::core::GenerateOCSPResponseRequest ocsp_response_request_from_json(
    std::string_view json,
    std::string request_der)
{
	const JsonObject object = JsonParser{json}.parse_object();

	anopki::core::GenerateOCSPResponseRequest request;
	request.request_der = std::move(request_der);
	request.issuer_certificate_pem = get_string_field(object, "issuer_certificate_pem");
	request.issuer_key_ref = get_string_field(object, "issuer_key_ref");
	request.this_update = get_string_field(object, "this_update");
	request.next_update = get_string_field(object, "next_update");

	const std::vector<std::string> serials = get_string_array_field(object, "serial_numbers");
	const std::vector<std::string> statuses = get_string_array_field(object, "statuses");
	const std::vector<std::string> hash_algorithms = get_string_array_field(object, "hash_algorithms");
	const std::vector<std::string> issuer_name_hashes = get_string_array_field(object, "issuer_name_hashes");
	const std::vector<std::string> issuer_key_hashes = get_string_array_field(object, "issuer_key_hashes");
	const std::vector<std::string> revoked_at_times = get_string_array_field(object, "revoked_at_times");
	const std::vector<std::string> reasons = get_string_array_field(object, "revocation_reasons");
	if (serials.size() != statuses.size() || serials.size() != revoked_at_times.size() || serials.size() != reasons.size())
	{
		throw_json_parse_failed();
	}
	if ((!hash_algorithms.empty() && hash_algorithms.size() != serials.size()) ||
	    (!issuer_name_hashes.empty() && issuer_name_hashes.size() != serials.size()) ||
	    (!issuer_key_hashes.empty() && issuer_key_hashes.size() != serials.size()))
	{
		throw_json_parse_failed();
	}
	for (std::vector<std::string>::size_type index = 0; index < serials.size(); ++index)
	{
		anopki::core::OCSPCertificateStatus status;
		status.serial_number = serials[index];
		status.status = statuses[index];
		status.revoked_at = revoked_at_times[index];
		status.revocation_reason = reasons[index];
		if (!hash_algorithms.empty())
		{
			status.hash_algorithm = hash_algorithms[index];
		}
		if (!issuer_name_hashes.empty())
		{
			status.issuer_name_hash = issuer_name_hashes[index];
		}
		if (!issuer_key_hashes.empty())
		{
			status.issuer_key_hash = issuer_key_hashes[index];
		}
		request.certificates.push_back(status);
	}
	return request;
}

std::string csr_info_to_json(const anopki::core::CsrInfo &info)
{
	return "{\"subject\":" + json_string(info.subject) + ",\"dns_names\":" + json_string_array(info.dns_names) + ",\"ip_addresses\":" + json_string_array(info.ip_addresses) +
	       ",\"public_key_algorithm\":" + json_string(info.public_key_algorithm) +
	       ",\"public_key_size_bits\":" + std::to_string(info.public_key_size_bits) +
	       ",\"signature_algorithm\":" + json_string(info.signature_algorithm) +
	       ",\"extension_oids\":" + json_string_array(info.extension_oids) + "}";
}

std::string issue_result_to_json(const anopki::core::IssueResult &result)
{
	return "{\"certificate_pem\":" + json_string(result.certificate_pem) + ",\"serial_number\":" + json_string(result.serial_number) + ",\"subject\":" + json_string(result.subject) + ",\"not_before\":" + json_string(result.not_before) + ",\"not_after\":" + json_string(result.not_after) + "}";
}

std::string crl_result_to_json(const anopki::core::GenerateCRLResult &result)
{
	return "{\"crl_pem\":" + json_string(result.crl_pem) + "}";
}

std::string ocsp_info_to_json(const anopki::core::OCSPRequestInfo &info)
{
	std::string output = "{\"certificates\":[";
	for (std::vector<anopki::core::OCSPCertificateID>::size_type index = 0; index < info.certificates.size(); ++index)
	{
		if (index != 0)
		{
			output.push_back(',');
		}
		const anopki::core::OCSPCertificateID &certificate = info.certificates[index];
		output += "{\"serial_number\":" + json_string(certificate.serial_number) +
		          ",\"issuer_name_hash\":" + json_string(certificate.issuer_name_hash) +
		          ",\"issuer_key_hash\":" + json_string(certificate.issuer_key_hash) +
		          ",\"hash_algorithm\":" + json_string(certificate.hash_algorithm) + "}";
	}
	output += "],\"has_nonce\":";
	output += info.has_nonce ? "true" : "false";
	output += ",\"nonce_hex\":" + json_string(info.nonce_hex) + "}";
	return output;
}

std::string ocsp_issuer_info_to_json(const anopki::core::OCSPIssuerInfo &info)
{
	return "{\"issuer_name_hash\":" + json_string(info.issuer_name_hash) +
	       ",\"issuer_key_hash\":" + json_string(info.issuer_key_hash) +
	       ",\"hash_algorithm\":" + json_string(info.hash_algorithm) + "}";
}

std::string ocsp_responder_validation_to_json(const anopki::core::ValidateOCSPResponderResult &result)
{
	return std::string{"{\"valid\":"} + (result.valid ? "true" : "false") + "}";
}

bool arg_is(char *value, std::string_view expected)
{
	return value != nullptr && expected == value;
}

int run_csr_inspect(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "csr") || !arg_is(argv[2], "inspect") || !arg_is(argv[3], "--in") || !arg_is(argv[5], "--out") || !arg_is(argv[6], "json"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const std::string csr_pem = read_file(argv[4]);
	const anopki::core::CsrInfo info = anopki::core::inspect_csr_pem(csr_pem);
	std::cout << csr_info_to_json(info) << '\n';
	return 0;
}

int run_cert_issue(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "cert") || !arg_is(argv[2], "issue") || !arg_is(argv[3], "--request") || !arg_is(argv[5], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const anopki::core::IssueRequest request = issue_request_from_json(read_file(argv[4]));
	const anopki::core::IssueResult result = anopki::core::issue_certificate(request);
	write_file(argv[6], issue_result_to_json(result) + "\n");
	return 0;
}

int run_crl_generate(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "crl") || !arg_is(argv[2], "generate") || !arg_is(argv[3], "--request") || !arg_is(argv[5], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const anopki::core::GenerateCRLRequest request = crl_request_from_json(read_file(argv[4]));
	const anopki::core::GenerateCRLResult result = anopki::core::generate_crl(request);
	write_file(argv[6], crl_result_to_json(result) + "\n");
	return 0;
}

int run_ocsp_inspect(int argc, char *argv[])
{
	if (argc != 7 || !arg_is(argv[1], "ocsp") || !arg_is(argv[2], "inspect") || !arg_is(argv[3], "--in") || !arg_is(argv[5], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const anopki::core::OCSPRequestInfo info = anopki::core::inspect_ocsp_request_der(read_file(argv[4]));
	write_file(argv[6], ocsp_info_to_json(info) + "\n");
	return 0;
}

int run_ocsp_inspect_issuer(int argc, char *argv[])
{
	if ((argc != 7 && argc != 9) || !arg_is(argv[1], "ocsp") || !arg_is(argv[2], "inspect-issuer") ||
	    !arg_is(argv[3], "--issuer") || !arg_is(argv[5], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	std::string hash_algorithm = "sha1";
	if (argc == 9)
	{
		if (!arg_is(argv[7], "--hash"))
		{
			write_error("cli.invalid_args", "invalid arguments");
			return 2;
		}
		hash_algorithm = argv[8];
	}
	const anopki::core::OCSPIssuerInfo info = anopki::core::inspect_ocsp_issuer_pem(read_file(argv[4]), hash_algorithm);
	write_file(argv[6], ocsp_issuer_info_to_json(info) + "\n");
	return 0;
}

int run_ocsp_validate_responder(int argc, char *argv[])
{
	if (argc != 9 || !arg_is(argv[1], "ocsp") || !arg_is(argv[2], "validate-responder") || !arg_is(argv[3], "--issuer") || !arg_is(argv[5], "--responder") || !arg_is(argv[7], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const anopki::core::ValidateOCSPResponderResult result = anopki::core::validate_ocsp_responder(read_file(argv[4]), read_file(argv[6]));
	write_file(argv[8], ocsp_responder_validation_to_json(result) + "\n");
	return 0;
}

int run_ocsp_respond(int argc, char *argv[])
{
	if (argc != 9 || !arg_is(argv[1], "ocsp") || !arg_is(argv[2], "respond") || !arg_is(argv[3], "--in") ||
	    !arg_is(argv[5], "--request") || !arg_is(argv[7], "--out"))
	{
		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}

	const anopki::core::GenerateOCSPResponseRequest request =
	    ocsp_response_request_from_json(read_file(argv[6]), read_file(argv[4]));
	const anopki::core::GenerateOCSPResponseResult result = anopki::core::generate_ocsp_response(request);
	write_file(argv[8], result.response_der);
	return 0;
}

} // namespace

int main(int argc, char *argv[])
{
	try
	{
		if (argc >= 3 && arg_is(argv[1], "csr") && arg_is(argv[2], "inspect"))
		{
			return run_csr_inspect(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "cert") && arg_is(argv[2], "issue"))
		{
			return run_cert_issue(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "crl") && arg_is(argv[2], "generate"))
		{
			return run_crl_generate(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "ocsp") && arg_is(argv[2], "inspect"))
		{
			return run_ocsp_inspect(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "ocsp") && arg_is(argv[2], "inspect-issuer"))
		{
			return run_ocsp_inspect_issuer(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "ocsp") && arg_is(argv[2], "validate-responder"))
		{
			return run_ocsp_validate_responder(argc, argv);
		}
		if (argc >= 3 && arg_is(argv[1], "ocsp") && arg_is(argv[2], "respond"))
		{
			return run_ocsp_respond(argc, argv);
		}

		write_error("cli.invalid_args", "invalid arguments");
		return 2;
	}
	catch (const std::runtime_error &error)
	{
		write_error(error.what(), error.what());
		return 1;
	}
}
