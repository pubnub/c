# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

pubnub_resolve_openssl()

_pn_sdk_library(pubnub_provider_crypto)
target_sources(pubnub_provider_crypto PRIVATE ${PN_PROVIDER_CRYPTO_OPENSSL_SOURCES})

target_include_directories(pubnub_provider_crypto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(pubnub_provider_crypto PUBLIC pubnub_public_headers OpenSSL::Crypto)

set_target_properties(
    pubnub_provider_crypto
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_crypto)
pubnub_target_sanitizers(pubnub_provider_crypto)
