// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/csr.hpp"
#include "anopki/core/issue.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

template <typename T, void (*FreeFn)(T *)>
struct OpenSslDeleter
{
	void operator()(T *value) const noexcept
	{
		FreeFn(value);
	}
};

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, OpenSslDeleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

void require(bool condition)
{
	if (!condition)
	{
		std::abort();
	}
}

std::string read_file(const std::filesystem::path &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input.good())
	{
		std::cerr << "failed to open file: " << path << "\n";
		std::exit(1);
	}
	std::ostringstream contents;
	contents << input.rdbuf();
	return contents.str();
}

void write_file(const std::filesystem::path &path, const std::string &contents)
{
	std::ofstream output{path, std::ios::binary | std::ios::trunc};
	output << contents;
}

std::string shell_quote(const std::filesystem::path &path)
{
	const std::string value = path.string();
#if defined(_WIN32)
	assert(value.find('"') == std::string::npos);
	return "\"" + value + "\"";
#else
	std::string quoted = "'";
	for (const char ch : value)
	{
		if (ch == '\'')
		{
			quoted += "'\\''";
		}
		else
		{
			quoted.push_back(ch);
		}
	}
	quoted.push_back('\'');
	return quoted;
#endif
}

void assert_cli_failure_contains(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &stdout_path,
    const std::filesystem::path &stderr_path,
    const std::string &args,
    const std::string &expected_code)
{
#if defined(_WIN32)
	const std::string command_prefix = "call ";
#else
	const std::string command_prefix;
#endif
	const std::string command = command_prefix + shell_quote(cli_path) + " " + args + " > " + shell_quote(stdout_path) + " 2> " + shell_quote(stderr_path);
	const int exit_code = std::system(command.c_str());
	const std::string stderr_output = read_file(stderr_path);

	if (exit_code == 0 || stderr_output.find(expected_code) == std::string::npos)
	{
		std::cerr << "CLI failure contract mismatch\n"
		          << "command: " << command << "\n"
		          << "exit_code: " << exit_code << "\n"
		          << "expected_code: " << expected_code << "\n"
		          << "stderr: " << stderr_output << "\n";
		std::exit(1);
	}
}

void assert_cli_success_contains(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &stdout_path,
    const std::filesystem::path &stderr_path,
    const std::string &args,
    const std::filesystem::path &output_path,
    const std::vector<std::string> &expected_fragments)
{
#if defined(_WIN32)
	const std::string command_prefix = "call ";
#else
	const std::string command_prefix;
#endif
	const std::string command = command_prefix + shell_quote(cli_path) + " " + args + " > " + shell_quote(stdout_path) + " 2> " + shell_quote(stderr_path);
	std::filesystem::remove(output_path);
	const int exit_code = std::system(command.c_str());
	const std::string stderr_output = read_file(stderr_path);
	const std::string output = read_file(output_path);

	for (const std::string &fragment : expected_fragments)
	{
		if (exit_code != 0 || output.find(fragment) == std::string::npos)
		{
			std::cerr << "CLI success contract mismatch\n"
			          << "command: " << command << "\n"
			          << "exit_code: " << exit_code << "\n"
			          << "expected_fragment: " << fragment << "\n"
			          << "stderr: " << stderr_output << "\n"
			          << "output: " << output << "\n";
			std::exit(1);
		}
	}
}

std::optional<unsigned char> base64_value(char value)
{
	if (value >= 'A' && value <= 'Z')
	{
		return static_cast<unsigned char>(value - 'A');
	}
	if (value >= 'a' && value <= 'z')
	{
		return static_cast<unsigned char>(value - 'a' + 26);
	}
	if (value >= '0' && value <= '9')
	{
		return static_cast<unsigned char>(value - '0' + 52);
	}
	if (value == '+')
	{
		return 62;
	}
	if (value == '/')
	{
		return 63;
	}
	return std::nullopt;
}

std::string decode_base64(std::string_view input)
{
	std::string output;
	unsigned int accumulator = 0;
	int bits = -8;
	for (char ch : input)
	{
		if (ch == '=')
		{
			break;
		}
		const std::optional<unsigned char> value = base64_value(ch);
		if (!value.has_value())
		{
			continue;
		}
		accumulator = ((accumulator << 6) | *value) & 0xffffff;
		bits += 6;
		if (bits >= 0)
		{
			output.push_back(static_cast<char>((accumulator >> bits) & 0xff));
			bits -= 8;
		}
	}
	return output;
}

EvpPkeyPtr make_rsa_key()
{
	EvpPkeyCtxPtr context{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	require(context != nullptr);
	require(EVP_PKEY_keygen_init(context.get()) == 1);
	require(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1);
	EVP_PKEY *key = nullptr;
	require(EVP_PKEY_keygen(context.get(), &key) == 1);
	return EvpPkeyPtr{key};
}

void set_name(X509_NAME *name, const char *common_name)
{
	require(X509_NAME_add_entry_by_txt(
	            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0) == 1);
}

void set_serial(X509 *certificate, unsigned long serial)
{
	BignumPtr serial_bn{BN_new()};
	require(serial_bn != nullptr);
	require(BN_set_word(serial_bn.get(), serial) == 1);
	require(BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(certificate)) != nullptr);
}

void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
	X509_EXTENSION *extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);
	require(extension != nullptr);
	require(X509_add_ext(certificate, extension, -1) == 1);
	X509_EXTENSION_free(extension);
}

X509Ptr make_certificate(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuer_key, const char *common_name, unsigned long serial, bool ca)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	set_serial(certificate.get(), serial);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), common_name);
	require(X509_set_issuer_name(certificate.get(), issuer == nullptr ? X509_get_subject_name(certificate.get()) : X509_get_subject_name(issuer)) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	if (ca)
	{
		add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
		add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
	}
	require(X509_sign(certificate.get(), issuer_key == nullptr ? key : issuer_key, EVP_sha256()) > 0);
	return certificate;
}

X509Ptr make_ocsp_responder_certificate(
    EVP_PKEY *key,
    X509 *issuer,
    EVP_PKEY *issuer_key,
    const char *common_name,
    unsigned long serial,
    bool ocsp_signing)
{
	X509Ptr certificate{X509_new()};
	require(certificate != nullptr);
	require(X509_set_version(certificate.get(), 2) == 1);
	set_serial(certificate.get(), serial);
	X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400);
	set_name(X509_get_subject_name(certificate.get()), common_name);
	require(X509_set_issuer_name(certificate.get(), X509_get_subject_name(issuer)) == 1);
	require(X509_set_pubkey(certificate.get(), key) == 1);
	add_extension(certificate.get(), issuer, NID_basic_constraints, "critical,CA:FALSE");
	add_extension(certificate.get(), issuer, NID_key_usage, "critical,digitalSignature");
	if (ocsp_signing)
	{
		add_extension(certificate.get(), issuer, NID_ext_key_usage, "OCSPSigning");
	}
	require(X509_sign(certificate.get(), issuer_key, EVP_sha256()) > 0);
	return certificate;
}

std::string certificate_to_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	require(bio != nullptr);
	require(PEM_write_bio_X509(bio.get(), certificate) == 1);
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	require(size > 0 && data != nullptr);
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string trim_line_ending(std::string value)
{
	while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
	{
		value.pop_back();
	}
	return value;
}

void assert_cli_ocsp_validate_responder(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &work_dir,
    const std::string &issuer_pem,
    const std::string &responder_pem,
    const std::string &expected_stderr,
    bool expect_success)
{
	const std::filesystem::path stdout_path = work_dir / "core_cli_contract_ocsp_validate_stdout.txt";
	const std::filesystem::path stderr_path = work_dir / "core_cli_contract_ocsp_validate_stderr.txt";
	const std::filesystem::path issuer_path = work_dir / "core_cli_contract_ocsp_issuer.pem";
	const std::filesystem::path responder_path = work_dir / "core_cli_contract_ocsp_responder.pem";
	const std::filesystem::path result_path = work_dir / "core_cli_contract_ocsp_result.json";

	write_file(issuer_path, issuer_pem);
	write_file(responder_path, responder_pem);
	std::filesystem::remove(result_path);

#if defined(_WIN32)
	const std::string command_prefix = "call ";
#else
	const std::string command_prefix;
#endif
	const std::string command = command_prefix + shell_quote(cli_path) +
	                            " ocsp validate-responder --issuer " + shell_quote(issuer_path) +
	                            " --responder " + shell_quote(responder_path) + " --out " + shell_quote(result_path) +
	                            " > " + shell_quote(stdout_path) + " 2> " + shell_quote(stderr_path);
	const int exit_code = std::system(command.c_str());

	if (expect_success ? (exit_code != 0) : (exit_code == 0))
	{
		std::cerr << "CLI validate-responder exit mismatch\n"
		          << "command: " << command << "\n"
		          << "exit_code: " << exit_code << "\n"
		          << "expected_success: " << std::boolalpha << expect_success << "\n";
		std::exit(1);
	}

	const std::string stderr_output = trim_line_ending(read_file(stderr_path));
	if (stderr_output != expected_stderr)
	{
		std::cerr << "CLI validate-responder stderr mismatch\n"
		          << "command: " << command << "\n"
		          << "stderr: " << stderr_output << "\n"
		          << "expected_stderr: " << expected_stderr << "\n";
		std::exit(1);
	}

	if (expect_success)
	{
		const std::string output = trim_line_ending(read_file(result_path));
		if (output != "{\"valid\":true}")
		{
			std::cerr << "CLI validate-responder result mismatch\n"
			          << "command: " << command << "\n"
			          << "output: " << output << "\n";
			std::exit(1);
		}
	}
}

void assert_cli_error_contract(const std::filesystem::path &cli_path, const std::filesystem::path &work_dir)
{
	const std::filesystem::path stdout_path = work_dir / "core_cli_contract_stdout.txt";
	const std::filesystem::path stderr_path = work_dir / "core_cli_contract_stderr.txt";
	const std::filesystem::path malformed_request_path = work_dir / "core_cli_contract_malformed_request.json";
	const std::filesystem::path malformed_csr_path = work_dir / "core_cli_contract_malformed_csr.pem";
	const std::filesystem::path result_path = work_dir / "core_cli_contract_result.json";

	assert_cli_failure_contains(cli_path, stdout_path, stderr_path, "invalid", "\"code\":\"cli.invalid_args\"");

	write_file(malformed_request_path, "{");
	assert_cli_failure_contains(
	    cli_path,
	    stdout_path,
	    stderr_path,
	    "cert issue --request " + shell_quote(malformed_request_path) + " --out " + shell_quote(result_path),
	    "\"code\":\"cli.json_parse_failed\"");

	write_file(malformed_csr_path, "not a csr");
	assert_cli_failure_contains(
	    cli_path,
	    stdout_path,
	    stderr_path,
	    "csr inspect --in " + shell_quote(malformed_csr_path) + " --out json",
	    "\"openssl_errors\":[");
}

void assert_cli_ocsp_fixture_inspect(
    const std::filesystem::path &cli_path,
    const std::filesystem::path &work_dir,
    const std::filesystem::path &fixture_dir)
{
	const std::filesystem::path stdout_path = work_dir / "core_cli_contract_ocsp_stdout.txt";
	const std::filesystem::path stderr_path = work_dir / "core_cli_contract_ocsp_stderr.txt";
	const std::filesystem::path request_path = work_dir / "core_cli_contract_ocsp_request.der";
	const std::filesystem::path result_path = work_dir / "core_cli_contract_ocsp_result.json";

	write_file(request_path, decode_base64(read_file(fixture_dir / "curated-single-request.der.b64")));
	assert_cli_success_contains(
	    cli_path,
	    stdout_path,
	    stderr_path,
	    "ocsp inspect --in " + shell_quote(request_path) + " --out " + shell_quote(result_path),
	    result_path,
	    {
	        "\"serial_number\":\"1001\"",
	        "\"issuer_name_hash\":\"84378ae02c8a13718b0efda0e3a283b0006a4265\"",
	        "\"issuer_key_hash\":\"d5dcea91c8d109ec61e84d07bea04fab0b720ac3\"",
	        "\"hash_algorithm\":\"sha1\"",
	        "\"has_nonce\":false",
	    });
}

void assert_cli_ocsp_validate_responder_contract(const std::filesystem::path &cli_path, const std::filesystem::path &work_dir)
{
	const EvpPkeyPtr issuer_key = make_rsa_key();
	const X509Ptr issuer = make_certificate(issuer_key.get(), nullptr, nullptr, "Test CA", 1, true);
	const EvpPkeyPtr responder_key = make_rsa_key();
	const X509Ptr responder = make_ocsp_responder_certificate(responder_key.get(), issuer.get(), issuer_key.get(), "OCSP Responder", 2, true);
	const EvpPkeyPtr invalid_responder_key = make_rsa_key();
	const X509Ptr invalid_responder = make_ocsp_responder_certificate(invalid_responder_key.get(), issuer.get(), issuer_key.get(), "Invalid OCSP Responder", 3, false);

	assert_cli_ocsp_validate_responder(cli_path, work_dir, certificate_to_pem(issuer.get()), certificate_to_pem(responder.get()), "", true);
	assert_cli_ocsp_validate_responder(cli_path, work_dir, certificate_to_pem(issuer.get()), certificate_to_pem(invalid_responder.get()), "{\"code\":\"ocsp.responder_invalid\",\"message\":\"ocsp.responder_invalid\"}",
	    false);
}

} // namespace

int main(int argc, char *argv[])
{
	assert(argc == 4);
	assert_cli_error_contract(argv[1], argv[2]);
	assert_cli_ocsp_fixture_inspect(argv[1], argv[2], argv[3]);
	assert_cli_ocsp_validate_responder_contract(argv[1], argv[2]);

	anopki::core::IssueRequest request;
	request.csr_pem = "csr";
	request.issuer_certificate_pem = "issuer";
	request.issuer_key_ref = "issuer.key";
	request.aia_url = "https://pki.example.test/issuers/issuer.pem";
	request.crl_distribution_points = {"https://pki.example.test/crl/issuer.crl"};
	request.subject = "CN=leaf";
	request.dns_names = {"leaf.example.test"};
	request.ip_addresses = {"127.0.0.1"};
	request.not_before = "2026-06-13T00:00:00Z";
	request.not_after = "2026-09-11T00:00:00Z";
	request.signature_algorithm = "rsa_with_sha256";
	request.profile_id = "profile-1";
	request.basic_constraints_critical = true;
	request.basic_constraints_ca = false;
	request.key_usage_critical = true;
	request.key_usage = {"digital_signature", "key_encipherment"};
	request.extended_key_usage = {"server_auth"};
	request.subject_key_identifier = true;
	request.authority_key_identifier = true;

	assert(request.csr_pem == "csr");
	assert(request.issuer_certificate_pem == "issuer");
	assert(request.issuer_key_ref == "issuer.key");
	assert(request.aia_url == "https://pki.example.test/issuers/issuer.pem");
	assert(request.crl_distribution_points == std::vector<std::string>{"https://pki.example.test/crl/issuer.crl"});
	assert(request.subject == "CN=leaf");
	assert(request.dns_names == std::vector<std::string>{"leaf.example.test"});
	assert(request.ip_addresses == std::vector<std::string>{"127.0.0.1"});
	assert(request.not_before == "2026-06-13T00:00:00Z");
	assert(request.not_after == "2026-09-11T00:00:00Z");
	assert(request.signature_algorithm == "rsa_with_sha256");
	assert(request.profile_id == "profile-1");
	assert(request.basic_constraints_critical);
	assert(!request.basic_constraints_ca);
	assert(request.key_usage_critical);
	const std::vector<std::string> expected_key_usage{"digital_signature", "key_encipherment"};
	const std::vector<std::string> expected_extended_key_usage{"server_auth"};
	const std::vector<std::string> expected_extension_oids{"2.5.29.17", "2.5.29.15"};
	assert(request.key_usage == expected_key_usage);
	assert(request.extended_key_usage == expected_extended_key_usage);
	assert(request.subject_key_identifier);
	assert(request.authority_key_identifier);

	anopki::core::IssueResult result;
	result.certificate_pem = "cert";
	result.serial_number = "123";
	result.subject = request.subject;
	result.not_before = request.not_before;
	result.not_after = request.not_after;

	assert(result.certificate_pem == "cert");
	assert(result.serial_number == "123");
	assert(result.subject == "CN=leaf");
	assert(result.not_before == "2026-06-13T00:00:00Z");
	assert(result.not_after == "2026-09-11T00:00:00Z");

	anopki::core::CsrInfo csr_info;
	csr_info.subject = "CN=leaf";
	csr_info.dns_names = {"leaf.example.test"};
	csr_info.ip_addresses = {"127.0.0.1"};
	csr_info.public_key_algorithm = "rsa";
	csr_info.public_key_size_bits = 2048;
	csr_info.signature_algorithm = "sha256";
	csr_info.extension_oids = {"2.5.29.17", "2.5.29.15"};

	assert(csr_info.subject == "CN=leaf");
	assert(csr_info.dns_names == std::vector<std::string>{"leaf.example.test"});
	assert(csr_info.ip_addresses == std::vector<std::string>{"127.0.0.1"});
	assert(csr_info.public_key_algorithm == "rsa");
	assert(csr_info.public_key_size_bits == 2048);
	assert(csr_info.signature_algorithm == "sha256");
	assert(csr_info.extension_oids == expected_extension_oids);

	return 0;
}
