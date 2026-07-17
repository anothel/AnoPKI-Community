# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.20)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ANOPKI_VERSION)
string(STRIP "${ANOPKI_VERSION}" ANOPKI_VERSION)
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" ANOPKI_PROJECT_VERSION "${ANOPKI_VERSION}")

project(anopki VERSION ${ANOPKI_PROJECT_VERSION} LANGUAGES CXX)

set(ANOPKI_PRODUCT_PROFILE "community-openssl" CACHE STRING "AnoPKI product profile")
set_property(CACHE ANOPKI_PRODUCT_PROFILE PROPERTY STRINGS community-openssl)
if(NOT ANOPKI_PRODUCT_PROFILE STREQUAL "community-openssl")
    message(FATAL_ERROR "Community supports only ANOPKI_PRODUCT_PROFILE=community-openssl")
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

option(ANOPKI_ENABLE_FUZZING "Build local libFuzzer parser targets" OFF)

add_library(anopki_core
    src/core/backend.cpp
    src/core/crl.cpp
    src/core/csr.cpp
    src/core/issue.cpp
    src/core/ocsp.cpp
    src/core/runtime.cpp
    src/version.cpp
)
add_library(anopki::core ALIAS anopki_core)

configure_file(
    src/version_config.hpp.in
    generated/anopki/version_config.hpp
    @ONLY
)

target_compile_features(anopki_core PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(anopki_core PUBLIC /EHsc)
endif()
target_include_directories(anopki_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_compile_definitions(anopki_core
    PRIVATE
        ANOPKI_PRODUCT_PROFILE_ID="community-openssl"
        ANOPKI_EDITION_ID="community"
        ANOPKI_SELECTED_BACKEND_ID="openssl"
        ANOPKI_PROFILE_REQUIRES_FULL_OPERATIONS=1
)

add_library(anopki_openssl_adapter
    src/backends/openssl/crl.cpp
    src/backends/openssl/csr.cpp
    src/backends/openssl/issue.cpp
    src/backends/openssl/key_providers/file_key_provider.cpp
    src/backends/openssl/key_providers/provider_resolver.cpp
    src/backends/openssl/ocsp.cpp
    src/backends/openssl/openssl_backend.cpp
)
add_library(anopki::openssl_adapter ALIAS anopki_openssl_adapter)
target_compile_features(anopki_openssl_adapter PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(anopki_openssl_adapter PUBLIC /EHsc)
endif()
target_include_directories(anopki_openssl_adapter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/backends/openssl
)
target_link_libraries(anopki_openssl_adapter
    PRIVATE
        OpenSSL::Crypto
)

add_executable(anopki-core
    src/cli/main.cpp
)
target_link_libraries(anopki-core PRIVATE anopki::core anopki::openssl_adapter)
add_custom_target(anopki-community-openssl DEPENDS anopki-core)

if(WIN32 AND OPENSSL_ROOT_DIR)
    file(TO_CMAKE_PATH "${OPENSSL_ROOT_DIR}" OPENSSL_ROOT_DIR_CMAKE)
    file(GLOB OPENSSL_RUNTIME_DLLS CONFIGURE_DEPENDS "${OPENSSL_ROOT_DIR_CMAKE}/bin/*.dll")
    if(OPENSSL_RUNTIME_DLLS)
        add_custom_command(
            TARGET anopki-core
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${OPENSSL_RUNTIME_DLLS}
                    $<TARGET_FILE_DIR:anopki-core>
            COMMAND_EXPAND_LISTS
        )
    endif()
endif()

if(ANOPKI_ENABLE_FUZZING)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ANOPKI_ENABLE_FUZZING requires Clang with libFuzzer support")
    endif()

    function(add_anopki_parser_fuzzer target compile_definition)
        add_executable(${target}
            tests/fuzz/core_parser_fuzz.cpp
        )
        target_compile_definitions(${target} PRIVATE ${compile_definition})
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer,address)
        target_link_libraries(${target} PRIVATE anopki::core anopki::openssl_adapter)
    endfunction()

    add_anopki_parser_fuzzer(anopki_core_csr_fuzz ANOPKI_FUZZ_CSR)
    add_anopki_parser_fuzzer(anopki_core_ocsp_fuzz ANOPKI_FUZZ_OCSP)
    add_anopki_parser_fuzzer(anopki_core_crl_fuzz ANOPKI_FUZZ_CRL)
endif()

include(CTest)

if(BUILD_TESTING)
    add_executable(anopki_version_test
        tests/version_test.cpp
    )
    target_link_libraries(anopki_version_test PRIVATE anopki::core)
    add_test(NAME anopki.version COMMAND anopki_version_test)

    add_executable(anopki_core_cli_contract_test
        tests/core_cli_contract_test.cpp
    )
    target_link_libraries(anopki_core_cli_contract_test PRIVATE anopki::core anopki::openssl_adapter OpenSSL::Crypto)
    add_dependencies(anopki_core_cli_contract_test anopki-core)
    add_test(
        NAME anopki.core_cli_contract
        COMMAND anopki_core_cli_contract_test $<TARGET_FILE:anopki-core> ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/ocsp community-openssl community
    )

    add_executable(anopki_core_issue_profile_test
        tests/core_issue_profile_test.cpp
    )
    target_link_libraries(anopki_core_issue_profile_test PRIVATE anopki::core anopki::openssl_adapter OpenSSL::Crypto)
    add_dependencies(anopki_core_issue_profile_test anopki-core)
    add_test(
        NAME anopki.core_issue_profile
        COMMAND anopki_core_issue_profile_test $<TARGET_FILE:anopki-core> ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_core_crl_test
        tests/core_crl_test.cpp
    )
    target_link_libraries(anopki_core_crl_test PRIVATE anopki::core anopki::openssl_adapter OpenSSL::Crypto)
    add_test(
        NAME anopki.core_crl
        COMMAND anopki_core_crl_test ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_core_ocsp_test
        tests/core_ocsp_test.cpp
    )
    target_link_libraries(anopki_core_ocsp_test PRIVATE anopki::core anopki::openssl_adapter OpenSSL::Crypto)
    add_test(
        NAME anopki.core_ocsp
        COMMAND anopki_core_ocsp_test ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/ocsp
    )

    add_executable(anopki_core_openssl_golden_test
        tests/core_openssl_golden_test.cpp
    )
    target_link_libraries(anopki_core_openssl_golden_test PRIVATE anopki::core anopki::openssl_adapter OpenSSL::Crypto)
    add_test(
        NAME anopki.core_openssl_golden
        COMMAND anopki_core_openssl_golden_test ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/backend-parity
    )

    add_executable(anopki_crypto_backend_interface_test
        tests/crypto_backend_interface_test.cpp
    )
    target_link_libraries(anopki_crypto_backend_interface_test PRIVATE anopki::core)
    add_test(NAME anopki.crypto_backend_interface COMMAND anopki_crypto_backend_interface_test)

    add_executable(anopki_backend_profile_test
        tests/backend_profile_test.cpp
    )
    target_link_libraries(anopki_backend_profile_test PRIVATE anopki::core anopki::openssl_adapter)
    add_test(NAME anopki.backend_profile COMMAND anopki_backend_profile_test)

    add_executable(anopki_crl_file_key_provider_test
        tests/crl_file_key_provider_test.cpp
    )
    target_link_libraries(anopki_crl_file_key_provider_test
        PRIVATE
            anopki::core
            anopki::openssl_adapter
            OpenSSL::Crypto
    )
    add_test(
        NAME anopki.crl_file_key_provider
        COMMAND anopki_crl_file_key_provider_test ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_ocsp_file_key_provider_test
        tests/ocsp_file_key_provider_test.cpp
    )
    target_link_libraries(anopki_ocsp_file_key_provider_test
        PRIVATE
            anopki::core
            anopki::openssl_adapter
            OpenSSL::Crypto
    )
    add_test(
        NAME anopki.ocsp_file_key_provider
        COMMAND anopki_ocsp_file_key_provider_test ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_file_key_provider_test
        tests/file_key_provider_test.cpp
    )
    target_include_directories(anopki_file_key_provider_test
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backends/openssl
    )
    target_link_libraries(anopki_file_key_provider_test
        PRIVATE
            anopki::openssl_adapter
            OpenSSL::Crypto
    )
    add_test(NAME anopki.file_key_provider COMMAND anopki_file_key_provider_test)

    add_executable(anopki_software_token_key_provider_test
        tests/software_token_key_provider_test.cpp
    )
    target_include_directories(anopki_software_token_key_provider_test
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backends/openssl
    )
    target_link_libraries(anopki_software_token_key_provider_test
        PRIVATE
            anopki::openssl_adapter
            OpenSSL::Crypto
    )
    add_test(
        NAME anopki.software_token_key_provider
        COMMAND anopki_software_token_key_provider_test
    )

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
        NAME anopki.key_provider_boundary
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate-key-provider-boundary.py --root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME anopki.key_provider_boundary_validator_tests
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_validate_key_provider_boundary.py
    )

endif()
