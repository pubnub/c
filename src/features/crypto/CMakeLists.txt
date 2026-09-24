# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

_pn_sdk_library(pn_feature_crypto)
target_sources(pn_feature_crypto PRIVATE ${PN_FEATURE_CRYPTO_SOURCES})

target_link_libraries(pn_feature_crypto PRIVATE pn_core)

target_include_directories(
    pn_feature_crypto
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIVATE "${PN_SDK_SOURCE_ROOT}/src"
)

set_target_properties(
    pn_feature_crypto
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_feature_crypto)
pubnub_target_sanitizers(pn_feature_crypto)
