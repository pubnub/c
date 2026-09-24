# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

_pn_sdk_library(pn_feature_time)
target_sources(pn_feature_time PRIVATE ${PN_FEATURE_TIME_SOURCES})

target_link_libraries(pn_feature_time PRIVATE pn_core)

target_include_directories(
    pn_feature_time
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${PN_SDK_SOURCE_ROOT}/src"
)

set_target_properties(
    pn_feature_time
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_feature_time)
pubnub_target_sanitizers(pn_feature_time)
