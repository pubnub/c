# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

set(PN_PROVIDER_CRYPTO_MBEDTLS_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/crypto_mbedtls.c"
    "${CMAKE_CURRENT_LIST_DIR}/mbedtls_factories.c"
    "${CMAKE_CURRENT_LIST_DIR}/mbedtls_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/mbedtls_aes_cbc.c"
    "${CMAKE_CURRENT_LIST_DIR}/mbedtls_legacy.c"
)
