# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

_pn_sdk_library(pn_core_protocol_common)
target_sources(pn_core_protocol_common PRIVATE ${PN_CORE_PROTOCOL_COMMON_SOURCES})

target_include_directories(pn_core_protocol_common PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

target_link_libraries(pn_core_protocol_common PRIVATE pubnub_public_headers)

set_target_properties(
    pn_core_protocol_common
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_core_protocol_common)
pubnub_target_visibility(pn_core_protocol_common)
pubnub_target_sanitizers(pn_core_protocol_common)
