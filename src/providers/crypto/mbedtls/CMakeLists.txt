# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_resolve_mbedtls()

_pn_sdk_library(
    pubnub_provider_crypto
    crypto_mbedtls.c
    mbedtls_factories.c
    mbedtls_common.c
    mbedtls_aes_cbc.c
    mbedtls_legacy.c
)

target_include_directories(pubnub_provider_crypto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(pubnub_provider_crypto PUBLIC pubnub_public_headers MbedTLS::mbedcrypto)

set_target_properties(
    pubnub_provider_crypto
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_crypto)
pubnub_target_sanitizers(pubnub_provider_crypto)
