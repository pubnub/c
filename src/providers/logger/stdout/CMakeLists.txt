# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

_pn_sdk_library(pubnub_provider_logger)
target_sources(pubnub_provider_logger PRIVATE ${PN_PROVIDER_LOGGER_STDOUT_SOURCES})

target_link_libraries(pubnub_provider_logger PUBLIC pubnub_public_headers PRIVATE pn_core_fmt)

target_include_directories(pubnub_provider_logger PRIVATE "${PN_SDK_SOURCE_ROOT}/src/core")

set_target_properties(
    pubnub_provider_logger
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_logger)
pubnub_target_sanitizers(pubnub_provider_logger)
