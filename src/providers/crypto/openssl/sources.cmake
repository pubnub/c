# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

set(PN_PROVIDER_CRYPTO_OPENSSL_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/crypto_openssl.c"
    "${CMAKE_CURRENT_LIST_DIR}/openssl_factories.c"
    "${CMAKE_CURRENT_LIST_DIR}/openssl_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/openssl_aes_cbc.c"
    "${CMAKE_CURRENT_LIST_DIR}/openssl_legacy.c"
)
