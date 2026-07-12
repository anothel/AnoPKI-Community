// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/issue.hpp"
#include "openssl_backend.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace anopki::core
{
namespace
{

constexpr const char *kCsrParseFailed = "issue.csr_parse_failed";
constexpr const char *kIssuerCertificateParseFailed = "issue.issuer_certificate_parse_failed";
constexpr const char *kIssuerKeyParseFailed = "issue.issuer_key_parse_failed";
constexpr const char *kIssuerKeyMismatch = "issue.issuer_key_mismatch";
constexpr const char *kIssuerNotCA = "issue.issuer_not_ca";
constexpr const char *kCertificateCreateFailed = "issue.certificate_create_failed";
constexpr const char *kSignFailed = "issue.sign_failed";
constexpr const char *kInvalidTime = "issue.invalid_time";

struct BioDeleter
{
	void operator()(BIO *bio) const noexcept
	{
		BIO_free(bio);
	}
};

struct BignumDeleter
{
	void operator()(BIGNUM *value) const noexcept
	{
		BN_free(value);
	}
};

struct EvpPkeyDeleter
{
	void operator()(EVP_PKEY *key) const noexcept
	{
		EVP_PKEY_free(key);
	}
};

struct X509Deleter
{
	void operator()(X509 *certificate) const noexcept
	{
		X509_free(certificate);
	}
};

struct X509ReqDeleter
{
	void operator()(X509_REQ *request) const noexcept
	{
		X509_REQ_free(request);
	}
};

struct X509NameDeleter
{
	void operator()(X509_NAME *name) const noexcept
	{
		X509_NAME_free(name);
	}
};

struct X509ExtensionDeleter
{
	void operator()(X509_EXTENSION *extension) const noexcept
	{
		X509_EXTENSION_free(extension);
	}
};

struct NameConstraintsDeleter
{
	void operator()(NAME_CONSTRAINTS *constraints) const noexcept
	{
		NAME_CONSTRAINTS_free(constraints);
	}
};

struct OpenSslFreeDeleter
{
	void operator()(char *value) const noexcept
	{
		OPENSSL_free(value);
	}
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;
using X509NamePtr = std::unique_ptr<X509_NAME, X509NameDeleter>;
using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, X509ExtensionDeleter>;
using NameConstraintsPtr = std::unique_ptr<NAME_CONSTRAINTS, NameConstraintsDeleter>;
using OpenSslStringPtr = std::unique_ptr<char, OpenSslFreeDeleter>;

struct ResolvedTimes
{
	std::string not_before;
	std::string not_after;
};

[[noreturn]] void throw_error(const char *code)
{
	throw std::runtime_error{code};
}

BioPtr make_memory_bio(std::string_view pem, const char *code)
{
	if (pem.size() > static_cast<std::string_view::size_type>(std::numeric_limits<int>::max()))
	{
		throw_error(code);
	}

	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(code);
	}
	return bio;
}

X509ReqPtr parse_csr(std::string_view csr_pem)
{
	BioPtr bio = make_memory_bio(csr_pem, kCsrParseFailed);
	X509ReqPtr request{PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr)};
	if (!request)
	{
		throw_error(kCsrParseFailed);
	}
	return request;
}

EvpPkeyPtr verify_csr_proof_of_possession(X509_REQ *request)
{
	EvpPkeyPtr public_key{X509_REQ_get_pubkey(request)};
	if (!public_key)
	{
		throw_error(kCsrParseFailed);
	}
	if (X509_REQ_verify(request, public_key.get()) != 1)
	{
		throw_error(kCsrParseFailed);
	}
	return public_key;
}

X509Ptr parse_issuer_certificate(std::string_view issuer_certificate_pem)
{
	BioPtr bio = make_memory_bio(issuer_certificate_pem, kIssuerCertificateParseFailed);
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	if (!certificate || !X509_get_subject_name(certificate.get()))
	{
		throw_error(kIssuerCertificateParseFailed);
	}
	return certificate;
}

EvpPkeyPtr parse_issuer_key(const std::string &issuer_key_ref)
{
	BioPtr bio{BIO_new_file(issuer_key_ref.c_str(), "r")};
	if (!bio)
	{
		throw_error(kIssuerKeyParseFailed);
	}

	EvpPkeyPtr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
	if (!key)
	{
		throw_error(kIssuerKeyParseFailed);
	}
	return key;
}

void verify_issuer_ca_capable(X509 *issuer_certificate)
{
	if (X509_check_ca(issuer_certificate) <= 0)
	{
		throw_error(kIssuerNotCA);
	}
	const bool has_key_usage = X509_get_ext_by_NID(issuer_certificate, NID_key_usage, -1) >= 0;
	if (has_key_usage && (X509_get_key_usage(issuer_certificate) & static_cast<std::uint32_t>(KU_KEY_CERT_SIGN)) == 0)
	{
		throw_error(kIssuerNotCA);
	}
}

void verify_issuer_currently_valid(X509 *issuer_certificate)
{
	if (X509_cmp_current_time(X509_get0_notBefore(issuer_certificate)) > 0 ||
	    X509_cmp_current_time(X509_get0_notAfter(issuer_certificate)) < 0)
	{
		throw_error(kIssuerNotCA);
	}
}

std::string lowercase(std::string value)
{
	for (char &ch : value)
	{
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}
	return value;
}

std::string asn1_string_to_text(const ASN1_STRING *value)
{
	if (value == nullptr)
	{
		return {};
	}
	const unsigned char *data = ASN1_STRING_get0_data(value);
	const int size = ASN1_STRING_length(value);
	if (data == nullptr || size <= 0)
	{
		return {};
	}
	return std::string{reinterpret_cast<const char *>(data), static_cast<std::string::size_type>(size)};
}

bool has_suffix(std::string_view value, std::string_view suffix)
{
	return value.size() >= suffix.size() && value.substr(value.size() - suffix.size()) == suffix;
}

bool dns_matches_constraint(std::string_view dns_name, std::string_view constraint)
{
	if (dns_name.empty() || constraint.empty())
	{
		return false;
	}
	if (constraint.front() == '.')
	{
		return has_suffix(dns_name, constraint);
	}
	return dns_name == constraint || has_suffix(dns_name, "." + std::string{constraint});
}

bool subtree_matches_dns(const GENERAL_SUBTREE *subtree, const std::string &dns_name)
{
	if (subtree == nullptr || subtree->base == nullptr || subtree->base->type != GEN_DNS)
	{
		return false;
	}
	return dns_matches_constraint(lowercase(dns_name), lowercase(asn1_string_to_text(subtree->base->d.dNSName)));
}

bool has_dns_subtree(const STACK_OF(GENERAL_SUBTREE) *subtrees)
{
	for (int index = 0; index < sk_GENERAL_SUBTREE_num(subtrees); ++index)
	{
		const GENERAL_SUBTREE *subtree = sk_GENERAL_SUBTREE_value(subtrees, index);
		if (subtree != nullptr && subtree->base != nullptr && subtree->base->type == GEN_DNS)
		{
			return true;
		}
	}
	return false;
}

bool dns_permitted_by_name_constraints(const std::string &dns_name, const NAME_CONSTRAINTS *constraints)
{
	for (int index = 0; index < sk_GENERAL_SUBTREE_num(constraints->excludedSubtrees); ++index)
	{
		if (subtree_matches_dns(sk_GENERAL_SUBTREE_value(constraints->excludedSubtrees, index), dns_name))
		{
			return false;
		}
	}

	if (!has_dns_subtree(constraints->permittedSubtrees))
	{
		return true;
	}
	for (int index = 0; index < sk_GENERAL_SUBTREE_num(constraints->permittedSubtrees); ++index)
	{
		if (subtree_matches_dns(sk_GENERAL_SUBTREE_value(constraints->permittedSubtrees, index), dns_name))
		{
			return true;
		}
	}
	return false;
}

void verify_issuer_name_constraints(X509 *issuer_certificate, const IssueRequest &request)
{
	NameConstraintsPtr constraints{
	    static_cast<NAME_CONSTRAINTS *>(X509_get_ext_d2i(issuer_certificate, NID_name_constraints, nullptr, nullptr))};
	if (!constraints)
	{
		return;
	}
	for (const std::string &dns_name : request.dns_names)
	{
		if (!dns_permitted_by_name_constraints(dns_name, constraints.get()))
		{
			throw_error(kIssuerNotCA);
		}
	}
}

void verify_issuer_key_matches_certificate(X509 *issuer_certificate, EVP_PKEY *issuer_key)
{
	EvpPkeyPtr issuer_public_key{X509_get_pubkey(issuer_certificate)};
	if (!issuer_public_key)
	{
		throw_error(kIssuerCertificateParseFailed);
	}

#if OPENSSL_VERSION_MAJOR >= 3
	const int matches = EVP_PKEY_eq(issuer_public_key.get(), issuer_key);
#else
	const int matches = EVP_PKEY_cmp(issuer_public_key.get(), issuer_key);
#endif
	if (matches != 1)
	{
		throw_error(kIssuerKeyMismatch);
	}
}

bool has_subject_entries(X509_NAME *name)
{
	return name != nullptr && X509_NAME_entry_count(name) > 0;
}

void add_subject_part(X509_NAME *name, std::string_view part)
{
	const std::string_view::size_type equals = part.find('=');
	if (equals == std::string_view::npos || equals == 0)
	{
		throw_error(kCertificateCreateFailed);
	}

	const std::string key{part.substr(0, equals)};
	const std::string_view value = part.substr(equals + 1);
	if (value.size() > static_cast<std::string_view::size_type>(std::numeric_limits<int>::max()))
	{
		throw_error(kCertificateCreateFailed);
	}

	const auto *bytes = reinterpret_cast<const unsigned char *>(value.data());
	if (X509_NAME_add_entry_by_txt(
	        name, key.c_str(), MBSTRING_UTF8, bytes, static_cast<int>(value.size()), -1, 0) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}
}

X509NamePtr make_subject_from_request(std::string_view subject)
{
	X509NamePtr name{X509_NAME_new()};
	if (!name)
	{
		throw_error(kCertificateCreateFailed);
	}

	if (subject.empty())
	{
		return name;
	}

	if (subject.front() == '/')
	{
		subject.remove_prefix(1);
	}

	while (!subject.empty())
	{
		const std::string_view::size_type slash = subject.find('/');
		const std::string_view part = subject.substr(0, slash);
		if (!part.empty())
		{
			add_subject_part(name.get(), part);
		}
		if (slash == std::string_view::npos)
		{
			break;
		}
		subject.remove_prefix(slash + 1);
	}

	return name;
}

int digit_at(std::string_view value, std::string_view::size_type index)
{
	const unsigned char ch = static_cast<unsigned char>(value[index]);
	if (!std::isdigit(ch))
	{
		throw_error(kInvalidTime);
	}
	return value[index] - '0';
}

int parse_two_digits(std::string_view value, std::string_view::size_type index)
{
	return digit_at(value, index) * 10 + digit_at(value, index + 1);
}

int parse_four_digits(std::string_view value, std::string_view::size_type index)
{
	return parse_two_digits(value, index) * 100 + parse_two_digits(value, index + 2);
}

void expect_char(std::string_view value, std::string_view::size_type index, char expected)
{
	if (index >= value.size() || value[index] != expected)
	{
		throw_error(kInvalidTime);
	}
}

bool is_leap_year(int year)
{
	return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

int days_in_month(int year, int month)
{
	constexpr int kDays[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	if (month == 2 && is_leap_year(year))
	{
		return 29;
	}
	return kDays[month];
}

struct UtcDateTime
{
	int year = 0;
	int month = 0;
	int day = 0;
	int hour = 0;
	int minute = 0;
	int second = 0;
};

std::int64_t days_from_civil(int year, unsigned month, unsigned day)
{
	year -= month <= 2;
	const int era = (year >= 0 ? year : year - 399) / 400;
	const unsigned year_of_era = static_cast<unsigned>(year - era * 400);
	const unsigned adjusted_month = static_cast<unsigned>(static_cast<int>(month) + (month > 2 ? -3 : 9));
	const unsigned day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
	const unsigned day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

UtcDateTime civil_from_days(std::int64_t days)
{
	days += 719468;
	const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
	const unsigned day_of_era = static_cast<unsigned>(days - era * 146097);
	const unsigned year_of_era =
	    (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
	int year = static_cast<int>(year_of_era) + static_cast<int>(era) * 400;
	const unsigned day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
	const unsigned month_prime = (5 * day_of_year + 2) / 153;
	const unsigned day = day_of_year - (153 * month_prime + 2) / 5 + 1;
	const unsigned month = static_cast<unsigned>(static_cast<int>(month_prime) + (month_prime < 10 ? 3 : -9));
	year += month <= 2;

	UtcDateTime result;
	result.year = year;
	result.month = static_cast<int>(month);
	result.day = static_cast<int>(day);
	return result;
}

UtcDateTime utc_from_seconds(std::int64_t seconds)
{
	std::int64_t days = seconds / 86400;
	std::int64_t remaining = seconds % 86400;
	if (remaining < 0)
	{
		remaining += 86400;
		--days;
	}

	UtcDateTime result = civil_from_days(days);
	result.hour = static_cast<int>(remaining / 3600);
	remaining %= 3600;
	result.minute = static_cast<int>(remaining / 60);
	result.second = static_cast<int>(remaining % 60);
	return result;
}

void validate_local_time(const UtcDateTime &value)
{
	if (value.year < 1950 || value.month < 1 || value.month > 12 || value.day < 1 || value.day > days_in_month(value.year, value.month) || value.hour > 23 || value.minute > 59 || value.second > 59)
	{
		throw_error(kInvalidTime);
	}
}

std::string format_rfc3339_utc(const UtcDateTime &value)
{
	std::ostringstream stream;
	stream << std::setfill('0') << std::setw(4) << value.year << '-' << std::setw(2) << value.month << '-'
	       << std::setw(2) << value.day << 'T' << std::setw(2) << value.hour << ':' << std::setw(2)
	       << value.minute << ':' << std::setw(2) << value.second << 'Z';
	return stream.str();
}

UtcDateTime parse_rfc3339_to_utc(std::string_view value)
{
	if (value.size() < 20)
	{
		throw_error(kInvalidTime);
	}

	expect_char(value, 4, '-');
	expect_char(value, 7, '-');
	expect_char(value, 10, 'T');
	expect_char(value, 13, ':');
	expect_char(value, 16, ':');

	UtcDateTime local;
	local.year = parse_four_digits(value, 0);
	local.month = parse_two_digits(value, 5);
	local.day = parse_two_digits(value, 8);
	local.hour = parse_two_digits(value, 11);
	local.minute = parse_two_digits(value, 14);
	local.second = parse_two_digits(value, 17);
	validate_local_time(local);

	std::string_view::size_type position = 19;
	if (position < value.size() && value[position] == '.')
	{
		++position;
		const std::string_view::size_type fraction_start = position;
		while (position < value.size() && std::isdigit(static_cast<unsigned char>(value[position])))
		{
			++position;
		}
		if (position == fraction_start)
		{
			throw_error(kInvalidTime);
		}
	}

	int offset_seconds = 0;
	if (position < value.size() && value[position] == 'Z')
	{
		++position;
	}
	else if (position + 6 <= value.size() && (value[position] == '+' || value[position] == '-'))
	{
		const int sign = value[position] == '+' ? 1 : -1;
		const int offset_hours = parse_two_digits(value, position + 1);
		expect_char(value, position + 3, ':');
		const int offset_minutes = parse_two_digits(value, position + 4);
		if (offset_hours > 23 || offset_minutes > 59)
		{
			throw_error(kInvalidTime);
		}
		offset_seconds = sign * (offset_hours * 3600 + offset_minutes * 60);
		position += 6;
	}
	else
	{
		throw_error(kInvalidTime);
	}

	if (position != value.size())
	{
		throw_error(kInvalidTime);
	}

	const std::int64_t local_seconds = days_from_civil(local.year, static_cast<unsigned>(local.month),
	                                       static_cast<unsigned>(local.day)) *
	                                       86400 +
	                                   local.hour * 3600 + local.minute * 60 + local.second;
	UtcDateTime utc = utc_from_seconds(local_seconds - offset_seconds);
	if (utc.year < 1950 || utc.year > 9999)
	{
		throw_error(kInvalidTime);
	}
	return utc;
}

std::string asn1_time_from_utc(const UtcDateTime &value)
{
	const std::string formatted = format_rfc3339_utc(value);
	std::string compact;
	if (value.year < 2050)
	{
		compact.reserve(13);
		compact = formatted.substr(2, 2);
	}
	else
	{
		compact.reserve(15);
		compact = formatted.substr(0, 4);
	}
	compact.append(formatted.substr(5, 2));
	compact.append(formatted.substr(8, 2));
	compact.append(formatted.substr(11, 2));
	compact.append(formatted.substr(14, 2));
	compact.append(formatted.substr(17, 2));
	compact.push_back('Z');
	return compact;
}

std::string normalize_rfc3339_utc(std::string_view value)
{
	return format_rfc3339_utc(parse_rfc3339_to_utc(value));
}

std::string asn1_time_from_rfc3339(std::string_view value)
{
	return asn1_time_from_utc(parse_rfc3339_to_utc(value));
}

std::tm utc_tm(std::time_t value)
{
	std::tm result{};
#if defined(_WIN32)
	if (gmtime_s(&result, &value) != 0)
	{
		throw_error(kInvalidTime);
	}
#else
	if (gmtime_r(&value, &result) == nullptr)
	{
		throw_error(kInvalidTime);
	}
#endif
	return result;
}

std::string rfc3339_from_time(std::time_t value)
{
	const std::tm tm = utc_tm(value);
	std::ostringstream stream;
	stream << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
	return stream.str();
}

ResolvedTimes resolve_times(const IssueRequest &request)
{
	const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	constexpr std::time_t kNinetyDays = 90LL * 24LL * 60LL * 60LL;

	ResolvedTimes times;
	times.not_before = request.not_before.empty() ? rfc3339_from_time(now) : normalize_rfc3339_utc(request.not_before);
	times.not_after =
	    request.not_after.empty() ? rfc3339_from_time(now + kNinetyDays) : normalize_rfc3339_utc(request.not_after);
	return times;
}

void set_certificate_time(ASN1_TIME *target, std::string_view value)
{
	const std::string asn1_time = asn1_time_from_rfc3339(value);
	if (ASN1_TIME_set_string(target, asn1_time.c_str()) != 1)
	{
		throw_error(kInvalidTime);
	}
}

std::string assign_serial_number(X509 *certificate)
{
	BignumPtr serial{BN_new()};
	if (!serial || BN_rand(serial.get(), 64, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}

	if (!BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(certificate)))
	{
		throw_error(kCertificateCreateFailed);
	}

	OpenSslStringPtr decimal{BN_bn2dec(serial.get())};
	if (!decimal)
	{
		throw_error(kCertificateCreateFailed);
	}
	return decimal.get();
}

void append_alt_name(std::string &alt_names, std::string_view prefix, std::string_view value)
{
	if (!alt_names.empty())
	{
		alt_names.push_back(',');
	}
	alt_names.append(prefix);
	alt_names.append(value);
}

X509ExtensionPtr make_extension(X509 *certificate, X509 *issuer_certificate, int nid, const std::string &value)
{
	X509V3_CTX context{};
	X509V3_set_ctx_nodb(&context);
	X509V3_set_ctx(&context, issuer_certificate, certificate, nullptr, nullptr, 0);

	X509ExtensionPtr extension{X509V3_EXT_conf_nid(nullptr, &context, nid, value.c_str())};
	if (!extension)
	{
		throw_error(kCertificateCreateFailed);
	}
	return extension;
}

void add_extension(X509 *certificate, X509 *issuer_certificate, int nid, const std::string &value)
{
	X509ExtensionPtr extension = make_extension(certificate, issuer_certificate, nid, value);
	if (X509_add_ext(certificate, extension.get(), -1) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}
}

std::string with_critical(bool critical, std::string value)
{
	if (!critical)
	{
		return value;
	}
	return "critical," + value;
}

std::string mapped_value(const std::map<std::string, std::string> &mapping, const std::string &value)
{
	const auto found = mapping.find(value);
	if (found == mapping.end())
	{
		throw_error(kCertificateCreateFailed);
	}
	return found->second;
}

std::string join_mapped_values(const std::vector<std::string> &values, const std::map<std::string, std::string> &mapping)
{
	std::string result;
	for (const std::string &value : values)
	{
		if (!result.empty())
		{
			result.push_back(',');
		}
		result += mapped_value(mapping, value);
	}
	return result;
}

void add_basic_constraints(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	if (!request.basic_constraints_critical && !request.basic_constraints_ca && request.basic_constraints_max_path_len < 0)
	{
		return;
	}
	if (!request.basic_constraints_ca && request.basic_constraints_max_path_len >= 0)
	{
		throw_error(kCertificateCreateFailed);
	}

	std::string value = request.basic_constraints_ca ? "CA:TRUE" : "CA:FALSE";
	if (request.basic_constraints_max_path_len >= 0)
	{
		value += ",pathlen:" + std::to_string(request.basic_constraints_max_path_len);
	}
	add_extension(certificate, issuer_certificate, NID_basic_constraints, with_critical(request.basic_constraints_critical, value));
}

void add_key_usage(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	if (request.key_usage.empty())
	{
		return;
	}
	const std::map<std::string, std::string> mapping{
	    {"digital_signature", "digitalSignature"},
	    {"non_repudiation", "nonRepudiation"},
	    {"key_encipherment", "keyEncipherment"},
	    {"data_encipherment", "dataEncipherment"},
	    {"key_agreement", "keyAgreement"},
	    {"key_cert_sign", "keyCertSign"},
	    {"crl_sign", "cRLSign"},
	    {"encipher_only", "encipherOnly"},
	    {"decipher_only", "decipherOnly"},
	};
	add_extension(certificate, issuer_certificate, NID_key_usage,
	    with_critical(request.key_usage_critical, join_mapped_values(request.key_usage, mapping)));
}

void add_extended_key_usage(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	if (request.extended_key_usage.empty())
	{
		return;
	}
	const std::map<std::string, std::string> mapping{
	    {"server_auth", "serverAuth"},
	    {"client_auth", "clientAuth"},
	    {"code_signing", "codeSigning"},
	    {"email_protection", "emailProtection"},
	    {"time_stamping", "timeStamping"},
	    {"ocsp_signing", "OCSPSigning"},
	};
	add_extension(certificate, issuer_certificate, NID_ext_key_usage,
	    with_critical(request.extended_key_usage_critical, join_mapped_values(request.extended_key_usage, mapping)));
}

void add_key_identifiers(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	if (request.subject_key_identifier)
	{
		add_extension(certificate, issuer_certificate, NID_subject_key_identifier, "hash");
	}
	if (request.authority_key_identifier)
	{
		add_extension(certificate, issuer_certificate, NID_authority_key_identifier, "keyid,issuer");
	}
}

void add_issuer_distribution_extensions(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	if (!request.aia_url.empty())
	{
		add_extension(certificate, issuer_certificate, NID_info_access, "caIssuers;URI:" + request.aia_url);
	}
	if (!request.crl_distribution_points.empty())
	{
		std::string value;
		for (const std::string &distribution_point : request.crl_distribution_points)
		{
			if (!value.empty())
			{
				value.push_back(',');
			}
			value += "URI:" + distribution_point;
		}
		add_extension(certificate, issuer_certificate, NID_crl_distribution_points, value);
	}
}

void add_profile_extensions(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	add_basic_constraints(certificate, issuer_certificate, request);
	add_key_usage(certificate, issuer_certificate, request);
	add_extended_key_usage(certificate, issuer_certificate, request);
	add_key_identifiers(certificate, issuer_certificate, request);
	add_issuer_distribution_extensions(certificate, issuer_certificate, request);
}

void add_subject_alt_names(X509 *certificate, X509 *issuer_certificate, const IssueRequest &request)
{
	std::string alt_names;
	for (const std::string &dns_name : request.dns_names)
	{
		append_alt_name(alt_names, "DNS:", dns_name);
	}
	for (const std::string &ip_address : request.ip_addresses)
	{
		append_alt_name(alt_names, "IP:", ip_address);
	}
	if (alt_names.empty())
	{
		return;
	}

	add_extension(certificate, issuer_certificate, NID_subject_alt_name, alt_names);
}

std::string certificate_to_pem(X509 *certificate)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}

	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	if (size <= 0 || data == nullptr)
	{
		throw_error(kCertificateCreateFailed);
	}
	return std::string{data, static_cast<std::string::size_type>(size)};
}

std::string subject_to_string(X509_NAME *subject)
{
	if (!subject)
	{
		throw_error(kCertificateCreateFailed);
	}

	OpenSslStringPtr value{X509_NAME_oneline(subject, nullptr, 0)};
	if (!value)
	{
		throw_error(kCertificateCreateFailed);
	}
	std::string subject_text = value.get();
	if (!subject_text.empty() && subject_text.front() == '/')
	{
		subject_text.erase(0, 1);
	}
	return subject_text;
}

const EVP_MD *signature_digest(const IssueRequest &request)
{
	if (request.signature_algorithm.empty() ||
	    request.signature_algorithm == "sha256" ||
	    request.signature_algorithm == "rsa_with_sha256" ||
	    request.signature_algorithm == "ecdsa_with_sha256")
	{
		return EVP_sha256();
	}
	if (request.signature_algorithm == "sha384" ||
	    request.signature_algorithm == "rsa_with_sha384" ||
	    request.signature_algorithm == "ecdsa_with_sha384")
	{
		return EVP_sha384();
	}
	if (request.signature_algorithm == "sha512" ||
	    request.signature_algorithm == "rsa_with_sha512" ||
	    request.signature_algorithm == "ecdsa_with_sha512")
	{
		return EVP_sha512();
	}
	if (request.signature_algorithm == "ed25519")
	{
		return nullptr;
	}
	throw_error(kCertificateCreateFailed);
}

} // namespace

IssueResult OpenSSLBackend::issue_certificate(const IssueRequest &request) const
{
	X509ReqPtr csr = parse_csr(request.csr_pem);
	EvpPkeyPtr public_key = verify_csr_proof_of_possession(csr.get());
	X509Ptr issuer_certificate = parse_issuer_certificate(request.issuer_certificate_pem);
	EvpPkeyPtr issuer_key = parse_issuer_key(request.issuer_key_ref);
	verify_issuer_ca_capable(issuer_certificate.get());
	verify_issuer_key_matches_certificate(issuer_certificate.get(), issuer_key.get());
	verify_issuer_currently_valid(issuer_certificate.get());
	verify_issuer_name_constraints(issuer_certificate.get(), request);

	X509Ptr certificate{X509_new()};
	if (!certificate || X509_set_version(certificate.get(), 2) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}

	const std::string serial_number = assign_serial_number(certificate.get());

	X509_NAME *subject = nullptr;
	X509NamePtr request_subject;
	if (!request.subject.empty())
	{
		request_subject = make_subject_from_request(request.subject);
		subject = request_subject.get();
	}
	else
	{
		subject = X509_REQ_get_subject_name(csr.get());
		if (!has_subject_entries(subject))
		{
			request_subject = make_subject_from_request(request.subject);
			subject = request_subject.get();
		}
	}

	if (X509_set_subject_name(certificate.get(), subject) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}

	X509_NAME *issuer_name = X509_get_subject_name(issuer_certificate.get());
	if (!issuer_name || X509_set_issuer_name(certificate.get(), issuer_name) != 1)
	{
		throw_error(kIssuerCertificateParseFailed);
	}

	const ResolvedTimes times = resolve_times(request);
	set_certificate_time(X509_getm_notBefore(certificate.get()), times.not_before);
	set_certificate_time(X509_getm_notAfter(certificate.get()), times.not_after);

	if (X509_set_pubkey(certificate.get(), public_key.get()) != 1)
	{
		throw_error(kCertificateCreateFailed);
	}

	add_profile_extensions(certificate.get(), issuer_certificate.get(), request);
	add_subject_alt_names(certificate.get(), issuer_certificate.get(), request);

	if (X509_sign(certificate.get(), issuer_key.get(), signature_digest(request)) <= 0)
	{
		throw_error(kSignFailed);
	}

	IssueResult result;
	result.certificate_pem = certificate_to_pem(certificate.get());
	result.serial_number = serial_number;
	result.subject = subject_to_string(X509_get_subject_name(certificate.get()));
	result.not_before = times.not_before;
	result.not_after = times.not_after;
	return result;
}


} // namespace anopki::core
