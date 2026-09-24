# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Per-backend unit tests: compile the shared test source against the active
# backend's library. Each test links the selected provider target plus the
# stdlib allocator.

if(PUBNUB_PROVIDER_CRYPTO STREQUAL "openssl")
    pubnub_add_unit_test(
        test_provider_crypto_openssl_units
        SOURCES test_crypto_provider_common.c
        LIBS pubnub
    )
endif()

if(PUBNUB_PROVIDER_CRYPTO STREQUAL "mbedtls")
    pubnub_add_unit_test(
        test_provider_crypto_mbedtls_units
        SOURCES test_crypto_provider_common.c
        LIBS pubnub
    )
endif()

# Cross-provider test: compiles both backends' factory and primitive files from
# source. Excludes crypto_openssl.c / crypto_mbedtls.c to avoid ODR collision on
# pubnub_cryptor_* and pn_crypto_default().
if(APPLE AND EXISTS "/opt/homebrew/opt/mbedtls@3")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/mbedtls@3")
endif()

find_package(OpenSSL QUIET)
find_package(MbedTLS QUIET)

if(OpenSSL_FOUND AND MbedTLS_FOUND)
    set(PN_OPENSSL_CRYPTO_DIR "${CMAKE_SOURCE_DIR}/src/providers/crypto/openssl")
    set(PN_MBEDTLS_CRYPTO_DIR "${CMAKE_SOURCE_DIR}/src/providers/crypto/mbedtls")

    pubnub_add_unit_test(
        test_provider_crypto_cross_units
        SOURCES
            test_crypto_cross_provider.c
            "${PN_OPENSSL_CRYPTO_DIR}/openssl_factories.c"
            "${PN_OPENSSL_CRYPTO_DIR}/openssl_common.c"
            "${PN_OPENSSL_CRYPTO_DIR}/openssl_aes_cbc.c"
            "${PN_OPENSSL_CRYPTO_DIR}/openssl_legacy.c"
            "${PN_MBEDTLS_CRYPTO_DIR}/mbedtls_factories.c"
            "${PN_MBEDTLS_CRYPTO_DIR}/mbedtls_common.c"
            "${PN_MBEDTLS_CRYPTO_DIR}/mbedtls_aes_cbc.c"
            "${PN_MBEDTLS_CRYPTO_DIR}/mbedtls_legacy.c"
        LIBS pubnub_provider_allocator OpenSSL::Crypto MbedTLS::mbedcrypto
    )

    target_include_directories(
        test_provider_crypto_cross_units
        PRIVATE "${PN_OPENSSL_CRYPTO_DIR}" "${PN_MBEDTLS_CRYPTO_DIR}"
    )
endif()
