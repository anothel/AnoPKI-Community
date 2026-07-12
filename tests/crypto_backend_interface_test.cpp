// SPDX-License-Identifier: MPL-2.0
#include "anopki/crypto/backend.hpp"
#include "anopki/crypto/runtime.hpp"

#include <cassert>
#include <string>
#include <string_view>

namespace
{

class FakeBackend final : public anopki::crypto::Backend
{
public:
    FakeBackend()
    {
        info_.id = "fake";
        info_.dependency = "fake-dependency";
        info_.dependency_version = "1";
        info_.readiness = anopki::crypto::BackendReadiness::ready;
        info_.capabilities = {
            anopki::crypto::BackendCapability::csr_inspect,
            anopki::crypto::BackendCapability::certificate_issue,
            anopki::crypto::BackendCapability::crl_generate,
            anopki::crypto::BackendCapability::crl_inspect,
            anopki::crypto::BackendCapability::ocsp_request_inspect,
            anopki::crypto::BackendCapability::ocsp_issuer_inspect,
            anopki::crypto::BackendCapability::ocsp_response_generate,
            anopki::crypto::BackendCapability::ocsp_responder_validate,
        };
    }

    [[nodiscard]] const anopki::crypto::BackendInfo &info() const noexcept override { return info_; }

    [[nodiscard]] anopki::core::CsrInfo inspect_csr_pem(const std::string &csr_pem) const override
    {
        anopki::core::CsrInfo info;
        info.subject = csr_pem;
        return info;
    }

    [[nodiscard]] anopki::core::IssueResult issue_certificate(const anopki::core::IssueRequest &request) const override
    {
        anopki::core::IssueResult result;
        result.subject = request.subject;
        return result;
    }

    [[nodiscard]] anopki::core::GenerateCRLResult generate_crl(const anopki::core::GenerateCRLRequest &request) const override
    {
        anopki::core::GenerateCRLResult result;
        result.crl_pem = std::to_string(request.crl_number);
        return result;
    }

    [[nodiscard]] anopki::core::CRLInfo inspect_crl_pem(const std::string &crl_pem) const override
    {
        anopki::core::CRLInfo info;
        info.crl_number = crl_pem;
        return info;
    }

    [[nodiscard]] anopki::core::CRLInfo inspect_crl_der(const std::string &crl_der) const override
    {
        anopki::core::CRLInfo info;
        info.crl_number = crl_der;
        return info;
    }

    [[nodiscard]] anopki::core::OCSPRequestInfo inspect_ocsp_request_der(const std::string &request_der) const override
    {
        anopki::core::OCSPRequestInfo info;
        info.nonce_hex = request_der;
        return info;
    }

    [[nodiscard]] anopki::core::OCSPIssuerInfo inspect_ocsp_issuer_pem(
        const std::string &issuer_certificate_pem,
        const std::string &hash_algorithm) const override
    {
        anopki::core::OCSPIssuerInfo info;
        info.issuer_name_hash = issuer_certificate_pem;
        info.hash_algorithm = hash_algorithm;
        return info;
    }

    [[nodiscard]] anopki::core::GenerateOCSPResponseResult generate_ocsp_response(
        const anopki::core::GenerateOCSPResponseRequest &request) const override
    {
        anopki::core::GenerateOCSPResponseResult result;
        result.response_der = request.this_update;
        return result;
    }

    [[nodiscard]] anopki::core::ValidateOCSPResponderResult validate_ocsp_responder(
        const std::string &issuer_certificate_pem,
        const std::string &responder_certificate_pem) const override
    {
        anopki::core::ValidateOCSPResponderResult result;
        result.valid = !issuer_certificate_pem.empty() && !responder_certificate_pem.empty();
        return result;
    }

private:
    anopki::crypto::BackendInfo info_;
};

} // namespace

int main()
{
    FakeBackend fake;
    const anopki::crypto::Backend &backend = fake;

    anopki::core::IssueRequest issue;
    issue.subject = "CN=leaf";
    anopki::core::GenerateCRLRequest crl;
    crl.crl_number = 42;
    anopki::core::GenerateOCSPResponseRequest ocsp;
    ocsp.this_update = "2026-06-13T00:00:00Z";

    assert(backend.name() == "fake");
    assert(backend.info().dependency == "fake-dependency");
    assert(anopki::crypto::has_capability(backend.info(), anopki::crypto::BackendCapability::certificate_issue));
    assert(anopki::crypto::to_string(anopki::crypto::BackendErrorCode::capability_unavailable) == "backend.capability_unavailable");
    assert(backend.inspect_csr_pem("CN=leaf").subject == "CN=leaf");
    assert(backend.issue_certificate(issue).subject == "CN=leaf");
    assert(backend.generate_crl(crl).crl_pem == "42");
    assert(backend.inspect_crl_pem("43").crl_number == "43");
    assert(backend.inspect_crl_der("44").crl_number == "44");
    assert(backend.inspect_ocsp_request_der("0102").nonce_hex == "0102");
    assert(backend.inspect_ocsp_issuer_pem("issuer", "sha256").hash_algorithm == "sha256");
    assert(backend.generate_ocsp_response(ocsp).response_der == "2026-06-13T00:00:00Z");
    assert(backend.validate_ocsp_responder("issuer", "responder").valid);

    anopki::crypto::BackendInfo limited = backend.info();
    limited.capabilities.clear();
    assert(!anopki::crypto::has_capability(limited, anopki::crypto::BackendCapability::certificate_issue));
    return 0;
}
