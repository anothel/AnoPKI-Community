// SPDX-License-Identifier: MPL-2.0
#include "anopki/core/ocsp.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace anopki::core
{
namespace
{

constexpr const char *kOCSPParseFailed = "ocsp.parse_failed";
constexpr const char *kOCSPCreateFailed = "ocsp.create_failed";
constexpr const char *kOCSPSignFailed = "ocsp.sign_failed";
constexpr const char *kOCSPIssuerParseFailed = "ocsp.issuer_parse_failed";
constexpr const char *kOCSPKeyReadFailed = "ocsp.key_read_failed";
constexpr const char *kOCSPInvalidTime = "ocsp.invalid_time";
constexpr const char *kOCSPResponderInvalid = "ocsp.responder_invalid";

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

using Asn1TimePtr = std::unique_ptr<ASN1_TIME, OpenSslDeleter<ASN1_TIME, ASN1_TIME_free>>;
using Asn1OctetStringPtr = std::unique_ptr<ASN1_OCTET_STRING, OpenSslDeleter<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>>;
using BignumPtr = std::unique_ptr<BIGNUM, OpenSslDeleter<BIGNUM, BN_free>>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using OCSPBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, OpenSslDeleter<OCSP_BASICRESP, OCSP_BASICRESP_free>>;
using OCSPCertIDPtr = std::unique_ptr<OCSP_CERTID, OpenSslDeleter<OCSP_CERTID, OCSP_CERTID_free>>;
using OCSPRequestPtr = std::unique_ptr<OCSP_REQUEST, OpenSslDeleter<OCSP_REQUEST, OCSP_REQUEST_free>>;
using OCSPResponsePtr = std::unique_ptr<OCSP_RESPONSE, OpenSslDeleter<OCSP_RESPONSE, OCSP_RESPONSE_free>>;
using X509Ptr = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;

[[noreturn]] void throw_error(const char *code)
{
	throw std::runtime_error{code};
}

std::string read_file(const std::string &path)
{
	std::ifstream input{path, std::ios::binary};
	if (!input)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	std::string contents{std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
	if (input.bad())
	{
		throw_error(kOCSPKeyReadFailed);
	}
	return contents;
}

X509Ptr parse_certificate(std::string_view pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kOCSPIssuerParseFailed);
	}
	X509Ptr certificate{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
	if (!certificate)
	{
		throw_error(kOCSPIssuerParseFailed);
	}
	return certificate;
}

EvpPkeyPtr parse_private_key(std::string_view pem)
{
	BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
	if (!bio)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	EvpPkeyPtr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
	if (!key)
	{
		throw_error(kOCSPKeyReadFailed);
	}
	return key;
}

OCSPRequestPtr parse_request_der(const std::string &der)
{
	BioPtr bio{BIO_new_mem_buf(der.data(), static_cast<int>(der.size()))};
	if (!bio)
	{
		throw_error(kOCSPParseFailed);
	}
	OCSPRequestPtr request{d2i_OCSP_REQUEST_bio(bio.get(), nullptr)};
	if (!request)
	{
		throw_error(kOCSPParseFailed);
	}
	return request;
}

std::string octets_to_hex(const ASN1_OCTET_STRING *value)
{
	if (value == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	std::ostringstream output;
	output << std::hex << std::setfill('0');
	for (int index = 0; index < value->length; ++index)
	{
		output << std::setw(2) << static_cast<int>(value->data[index]);
	}
	return output.str();
}

std::string serial_to_decimal(const ASN1_INTEGER *serial)
{
	if (serial == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	BIGNUM *raw = ASN1_INTEGER_to_BN(serial, nullptr);
	if (raw == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	BignumPtr serial_bn{raw};
	char *decimal_raw = BN_bn2dec(serial_bn.get());
	if (decimal_raw == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	std::string decimal{decimal_raw};
	OPENSSL_free(decimal_raw);
	return decimal;
}

std::string normalize_hash_algorithm(std::string_view value)
{
	std::string normalized;
	normalized.reserve(value.size());
	for (char ch : value)
	{
		if (ch != '-' && ch != '_')
		{
			normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
		}
	}
	if (normalized.empty())
	{
		return "sha1";
	}
	if (normalized == "sha1" || normalized == "sha256" || normalized == "sha384" || normalized == "sha512")
	{
		return normalized;
	}
	throw_error(kOCSPCreateFailed);
}

const EVP_MD *message_digest(std::string_view hash_algorithm)
{
	const std::string normalized = normalize_hash_algorithm(hash_algorithm);
	if (normalized == "sha1")
	{
		return EVP_sha1();
	}
	if (normalized == "sha256")
	{
		return EVP_sha256();
	}
	if (normalized == "sha384")
	{
		return EVP_sha384();
	}
	if (normalized == "sha512")
	{
		return EVP_sha512();
	}
	throw_error(kOCSPCreateFailed);
}

std::string hash_algorithm_name(const ASN1_OBJECT *algorithm)
{
	if (algorithm == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	const int nid = OBJ_obj2nid(algorithm);
	if (nid == NID_sha1)
	{
		return "sha1";
	}
	if (nid == NID_sha256)
	{
		return "sha256";
	}
	if (nid == NID_sha384)
	{
		return "sha384";
	}
	if (nid == NID_sha512)
	{
		return "sha512";
	}
	throw_error(kOCSPParseFailed);
}

OCSPCertificateID certificate_id(OCSP_CERTID *id)
{
	ASN1_OCTET_STRING *issuer_name_hash = nullptr;
	ASN1_OBJECT *hash_algorithm = nullptr;
	ASN1_OCTET_STRING *issuer_key_hash = nullptr;
	ASN1_INTEGER *serial = nullptr;
	if (OCSP_id_get0_info(&issuer_name_hash, &hash_algorithm, &issuer_key_hash, &serial, id) != 1)
	{
		throw_error(kOCSPParseFailed);
	}
	return OCSPCertificateID{
	    serial_to_decimal(serial),
	    octets_to_hex(issuer_name_hash),
	    octets_to_hex(issuer_key_hash),
	    hash_algorithm_name(hash_algorithm),
	};
}

std::string request_nonce_hex(OCSP_REQUEST *request)
{
	const int extension_index = OCSP_REQUEST_get_ext_by_NID(request, NID_id_pkix_OCSP_Nonce, -1);
	if (extension_index < 0)
	{
		return {};
	}
	X509_EXTENSION *extension = OCSP_REQUEST_get_ext(request, extension_index);
	if (extension == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	const ASN1_OCTET_STRING *encoded_nonce = X509_EXTENSION_get_data(extension);
	if (encoded_nonce == nullptr)
	{
		throw_error(kOCSPParseFailed);
	}
	const unsigned char *cursor = encoded_nonce->data;
	Asn1OctetStringPtr nonce{d2i_ASN1_OCTET_STRING(nullptr, &cursor, encoded_nonce->length)};
	if (!nonce || cursor != encoded_nonce->data + encoded_nonce->length)
	{
		throw_error(kOCSPParseFailed);
	}
	return octets_to_hex(nonce.get());
}

void validate_ocsp_signer(X509 *certificate)
{
	if (X509_check_ca(certificate) > 0)
	{
		return;
	}
	const bool has_key_usage = X509_get_ext_by_NID(certificate, NID_key_usage, -1) >= 0;
	if (has_key_usage && (X509_get_key_usage(certificate) & KU_DIGITAL_SIGNATURE) == 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
	const bool has_extended_key_usage = X509_get_ext_by_NID(certificate, NID_ext_key_usage, -1) >= 0;
	if (!has_extended_key_usage || (X509_get_extended_key_usage(certificate) & XKU_OCSP_SIGN) == 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
}

void validate_delegated_ocsp_responder_policy(X509 *certificate)
{
	if (X509_check_ca(certificate) > 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
	const bool has_key_usage = X509_get_ext_by_NID(certificate, NID_key_usage, -1) >= 0;
	if (has_key_usage && (X509_get_key_usage(certificate) & KU_DIGITAL_SIGNATURE) == 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
	const bool has_extended_key_usage = X509_get_ext_by_NID(certificate, NID_ext_key_usage, -1) >= 0;
	if (!has_extended_key_usage || (X509_get_extended_key_usage(certificate) & XKU_OCSP_SIGN) == 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
}

void validate_responder_issued_by(X509 *issuer, X509 *responder)
{
	if (X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(responder)) != 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
	EVP_PKEY *issuer_key_raw = X509_get_pubkey(issuer);
	if (issuer_key_raw == nullptr)
	{
		throw_error(kOCSPResponderInvalid);
	}
	EvpPkeyPtr issuer_key{issuer_key_raw};
	if (X509_verify(responder, issuer_key.get()) != 1)
	{
		throw_error(kOCSPResponderInvalid);
	}
}

void validate_responder_currently_valid(X509 *responder)
{
	const int not_before_cmp = X509_cmp_current_time(X509_get0_notBefore(responder));
	const int not_after_cmp = X509_cmp_current_time(X509_get0_notAfter(responder));
	if (not_before_cmp == 0 || not_after_cmp == 0 || not_before_cmp > 0 || not_after_cmp <= 0)
	{
		throw_error(kOCSPResponderInvalid);
	}
}

std::string asn1_time_from_rfc3339(std::string_view value)
{
	if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' ||
	    value[16] != ':' || value[19] != 'Z')
	{
		throw_error(kOCSPInvalidTime);
	}
	return std::string{value.substr(0, 4)} + std::string{value.substr(5, 2)} + std::string{value.substr(8, 2)} +
	       std::string{value.substr(11, 2)} + std::string{value.substr(14, 2)} + std::string{value.substr(17, 2)} + "Z";
}

Asn1TimePtr make_time(std::string_view value)
{
	Asn1TimePtr time{ASN1_TIME_new()};
	if (!time)
	{
		throw_error(kOCSPCreateFailed);
	}
	const std::string asn1_time = asn1_time_from_rfc3339(value);
	if (ASN1_TIME_set_string(time.get(), asn1_time.c_str()) != 1)
	{
		throw_error(kOCSPInvalidTime);
	}
	return time;
}

int ocsp_status(std::string_view status)
{
	if (status == "good")
	{
		return V_OCSP_CERTSTATUS_GOOD;
	}
	if (status == "revoked")
	{
		return V_OCSP_CERTSTATUS_REVOKED;
	}
	if (status == "unknown")
	{
		return V_OCSP_CERTSTATUS_UNKNOWN;
	}
	throw_error(kOCSPCreateFailed);
}

int ocsp_revocation_reason(std::string_view reason)
{
	if (reason == "key_compromise")
	{
		return OCSP_REVOKED_STATUS_KEYCOMPROMISE;
	}
	if (reason == "ca_compromise")
	{
		return OCSP_REVOKED_STATUS_CACOMPROMISE;
	}
	if (reason == "affiliation_changed")
	{
		return OCSP_REVOKED_STATUS_AFFILIATIONCHANGED;
	}
	if (reason == "superseded")
	{
		return OCSP_REVOKED_STATUS_SUPERSEDED;
	}
	if (reason == "cessation_of_operation")
	{
		return OCSP_REVOKED_STATUS_CESSATIONOFOPERATION;
	}
	if (reason == "privilege_withdrawn")
	{
		return OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN;
	}
	return OCSP_REVOKED_STATUS_UNSPECIFIED;
}

std::string status_key(
    std::string_view serial_number,
    std::string_view hash_algorithm,
    std::string_view issuer_name_hash,
    std::string_view issuer_key_hash)
{
	return std::string{serial_number} + "\x00" + normalize_hash_algorithm(hash_algorithm) + "\x00" +
	       std::string{issuer_name_hash} + "\x00" + std::string{issuer_key_hash};
}

std::map<std::string, OCSPCertificateStatus> statuses_by_id(const std::vector<OCSPCertificateStatus> &statuses)
{
	std::map<std::string, OCSPCertificateStatus> by_id;
	for (const OCSPCertificateStatus &status : statuses)
	{
		if (status.hash_algorithm.empty() && status.issuer_name_hash.empty() && status.issuer_key_hash.empty())
		{
			by_id[status.serial_number] = status;
			continue;
		}
		by_id[status_key(status.serial_number, status.hash_algorithm, status.issuer_name_hash, status.issuer_key_hash)] = status;
	}
	return by_id;
}

std::string response_to_der(OCSP_RESPONSE *response)
{
	BioPtr bio{BIO_new(BIO_s_mem())};
	if (!bio || i2d_OCSP_RESPONSE_bio(bio.get(), response) != 1)
	{
		throw_error(kOCSPCreateFailed);
	}
	char *data = nullptr;
	const long size = BIO_get_mem_data(bio.get(), &data);
	if (size <= 0 || data == nullptr)
	{
		throw_error(kOCSPCreateFailed);
	}
	return std::string{data, static_cast<std::string::size_type>(size)};
}

} // namespace

OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der)
{
	const OCSPRequestPtr request = parse_request_der(request_der);
	OCSPRequestInfo info;
	info.nonce_hex = request_nonce_hex(request.get());
	info.has_nonce = !info.nonce_hex.empty();
	const int count = OCSP_request_onereq_count(request.get());
	for (int index = 0; index < count; ++index)
	{
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(request.get(), index);
		if (one == nullptr)
		{
			throw_error(kOCSPParseFailed);
		}
		info.certificates.push_back(certificate_id(OCSP_onereq_get0_id(one)));
	}
	return info;
}

OCSPIssuerInfo inspect_ocsp_issuer_pem(const std::string &issuer_certificate_pem, const std::string &hash_algorithm)
{
	const X509Ptr issuer = parse_certificate(issuer_certificate_pem);
	const std::string normalized_hash_algorithm = normalize_hash_algorithm(hash_algorithm);
	OCSPCertIDPtr id{OCSP_cert_to_id(message_digest(normalized_hash_algorithm), issuer.get(), issuer.get())};
	if (!id)
	{
		throw_error(kOCSPCreateFailed);
	}
	const OCSPCertificateID parsed_id = certificate_id(id.get());
	return OCSPIssuerInfo{parsed_id.issuer_name_hash, parsed_id.issuer_key_hash, parsed_id.hash_algorithm};
}

ValidateOCSPResponderResult validate_ocsp_responder(const std::string &issuer_certificate_pem, const std::string &responder_certificate_pem)
{
	const X509Ptr issuer = parse_certificate(issuer_certificate_pem);
	const X509Ptr responder = parse_certificate(responder_certificate_pem);
	validate_responder_issued_by(issuer.get(), responder.get());
	validate_delegated_ocsp_responder_policy(responder.get());
	validate_responder_currently_valid(responder.get());
	return ValidateOCSPResponderResult{true};
}

GenerateOCSPResponseResult generate_ocsp_response(const GenerateOCSPResponseRequest &request)
{
	const OCSPRequestPtr ocsp_request = parse_request_der(request.request_der);
	const X509Ptr issuer = parse_certificate(request.issuer_certificate_pem);
	const EvpPkeyPtr issuer_key = parse_private_key(read_file(request.issuer_key_ref));
	validate_ocsp_signer(issuer.get());
	const Asn1TimePtr this_update = make_time(request.this_update);
	const Asn1TimePtr next_update = make_time(request.next_update);
	const std::map<std::string, OCSPCertificateStatus> statuses = statuses_by_id(request.certificates);

	OCSPBasicResponsePtr basic{OCSP_BASICRESP_new()};
	if (!basic)
	{
		throw_error(kOCSPCreateFailed);
	}

	const int count = OCSP_request_onereq_count(ocsp_request.get());
	for (int index = 0; index < count; ++index)
	{
		OCSP_ONEREQ *one = OCSP_request_onereq_get0(ocsp_request.get(), index);
		if (one == nullptr)
		{
			throw_error(kOCSPParseFailed);
		}
		OCSP_CERTID *id = OCSP_onereq_get0_id(one);
		const OCSPCertificateID parsed_id = certificate_id(id);
		auto found = statuses.find(status_key(
		    parsed_id.serial_number,
		    parsed_id.hash_algorithm,
		    parsed_id.issuer_name_hash,
		    parsed_id.issuer_key_hash));
		if (found == statuses.end())
		{
			found = statuses.find(parsed_id.serial_number);
		}
		const OCSPCertificateStatus status =
		    found == statuses.end() ? OCSPCertificateStatus{parsed_id.serial_number, "unknown", {}, {}} : found->second;
		Asn1TimePtr revoked_at;
		ASN1_TIME *revoked_at_raw = nullptr;
		int reason = OCSP_REVOKED_STATUS_NOSTATUS;
		if (status.status == "revoked")
		{
			revoked_at = make_time(status.revoked_at);
			revoked_at_raw = revoked_at.get();
			reason = ocsp_revocation_reason(status.revocation_reason);
		}
		if (OCSP_basic_add1_status(
		        basic.get(),
		        id,
		        ocsp_status(status.status),
		        reason,
		        revoked_at_raw,
		        this_update.get(),
		        next_update.get()) == nullptr)
		{
			throw_error(kOCSPCreateFailed);
		}
	}

	if (OCSP_copy_nonce(basic.get(), ocsp_request.get()) <= 0)
	{
		throw_error(kOCSPCreateFailed);
	}

	if (OCSP_basic_sign(basic.get(), issuer.get(), issuer_key.get(), EVP_sha256(), nullptr, 0) != 1)
	{
		throw_error(kOCSPSignFailed);
	}
	OCSPResponsePtr response{OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get())};
	if (!response)
	{
		throw_error(kOCSPCreateFailed);
	}
	return GenerateOCSPResponseResult{response_to_der(response.get())};
}

} // namespace anopki::core
