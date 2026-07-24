# v0.1.0-alpha.0 Closeout Evidence

This is a local engineering closeout record. It is not a release candidate,
release authorization, compatibility guarantee, or production-readiness claim.

```text
PROJECT=AnoPKI-Community
ENGINEERING_STATUS=CLOSED_AND_FROZEN
VERSION=0.1.0-alpha.0
ENGINEERING_BASELINE=5348a478ff1117482a8d168b655dad290367b188
ENTERPRISE_CONSUMED_BASELINE=ab9d76597df93ac1ac8b7938f4d25ba64f59f8dc
BASELINE_RELATION=ONE_COMMUNITY_ONLY_TEST_EVIDENCE_COMMIT_AHEAD
PUBLIC_TAG=NONE
PUBLIC_RELEASE=NOT_PUBLISHED
PRODUCTION_READY=NO
ACTIVE_NEXT_WORK=NONE
FUTURE_WORK=DEFERRED_NOT_SELECTED
REOPEN_REQUIRES_NEW_PRODUCT_DECISION
FINAL_CLOSEOUT_COMMIT=RECORDED_IN_EXTERNAL_CLOSEOUT_EVIDENCE
```

## Local validation

The closeout working tree passed the executable local Go baseline, document and
boundary validators, API/CLI compatibility validators, version and release
evidence validators, release-artifact self-test, secret and KeyProvider checks,
ACME harness self-test, and recovery, failover, authorization, outage, audit,
and issuer-rollover self-tests.

`scripts/verify-local.ps1` reached the authorization race phase after its
preceding checks passed. That phase requires CGO and a C toolchain, which were
not available on this host. The independently executable checks completed
without a repository validation failure.

```text
CPP_BUILD=NOT_RUN_ENVIRONMENT_UNAVAILABLE
CTEST=NOT_RUN_ENVIRONMENT_UNAVAILABLE
POSTGRES_FAILOVER_LIVE=NOT_RUN_ENVIRONMENT_UNAVAILABLE
HOSTED_CI=NOT_RUN
RELEASE_DRY_RUN=NOT_RUN
```

No OpenSSL execution version is recorded for this closeout run because the C++
build and CTest were not executable in the current environment. Historical
OpenSSL observations elsewhere do not establish a newly supported range.

## Deferred / not selected

HSM/KMS/PKCS#11, DNS-01, External Account Binding, SIEM anchoring/export, PQC,
and infrastructure-level failover are `DEFERRED / NOT_SELECTED`. They are not
closeout defects or active work.

No tag, release, package, repository archive setting, ZIP, or CURRENT ONLY pack
was created by this closeout.
