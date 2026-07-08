# SPDX-License-Identifier: MPL-2.0

cmake_minimum_required(VERSION 3.20)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ANOPKI_VERSION)
string(STRIP "${ANOPKI_VERSION}" ANOPKI_VERSION)

project(anopki VERSION ${ANOPKI_VERSION} LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

option(ANOPKI_ENABLE_FUZZING "Build local libFuzzer parser targets" OFF)

add_library(anopki_core
    src/core/crl.cpp
    src/core/csr.cpp
    src/core/issue.cpp
    src/core/ocsp.cpp
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
target_link_libraries(anopki_core
    PRIVATE
        OpenSSL::Crypto
)

add_executable(anopki-core
    src/cli/main.cpp
)
target_link_libraries(anopki-core PRIVATE anopki::core OpenSSL::Crypto)

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
        target_link_libraries(${target} PRIVATE anopki::core OpenSSL::Crypto)
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
    target_link_libraries(anopki_core_cli_contract_test PRIVATE anopki::core OpenSSL::Crypto)
    add_dependencies(anopki_core_cli_contract_test anopki-core)
    add_test(
        NAME anopki.core_cli_contract
        COMMAND anopki_core_cli_contract_test $<TARGET_FILE:anopki-core> ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/ocsp
    )

    add_executable(anopki_core_issue_profile_test
        tests/core_issue_profile_test.cpp
    )
    target_link_libraries(anopki_core_issue_profile_test PRIVATE anopki::core OpenSSL::Crypto)
    add_dependencies(anopki_core_issue_profile_test anopki-core)
    add_test(
        NAME anopki.core_issue_profile
        COMMAND anopki_core_issue_profile_test $<TARGET_FILE:anopki-core> ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_core_crl_test
        tests/core_crl_test.cpp
    )
    target_link_libraries(anopki_core_crl_test PRIVATE anopki::core OpenSSL::Crypto)
    add_test(
        NAME anopki.core_crl
        COMMAND anopki_core_crl_test ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(anopki_core_ocsp_test
        tests/core_ocsp_test.cpp
    )
    target_link_libraries(anopki_core_ocsp_test PRIVATE anopki::core OpenSSL::Crypto)
    add_test(
        NAME anopki.core_ocsp
        COMMAND anopki_core_ocsp_test ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/ocsp
    )

    add_executable(anopki_core_openssl_golden_test
        tests/core_openssl_golden_test.cpp
    )
    target_link_libraries(anopki_core_openssl_golden_test PRIVATE anopki::core OpenSSL::Crypto)
    add_test(
        NAME anopki.core_openssl_golden
        COMMAND anopki_core_openssl_golden_test ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/openssl-baseline
    )
endif()
