# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# jsmn serialization: jsmn-backed provider for embedded profiles.
#
# jsmn is fetched via FetchContent (pinned to v1.1.0).
# See cmake/dependencies.cmake for the FetchContent declaration.

pubnub_resolve_jsmn()

_pn_sdk_library(pubnub_provider_serialization serialization_jsmn.c jsmn_impl.c pn_json_unescape.c)

target_link_libraries(
    pubnub_provider_serialization
    PUBLIC pubnub_public_headers
    PRIVATE pn_core_fmt
)

target_include_directories(
    pubnub_provider_serialization
    PRIVATE "${PN_JSMN_SOURCE_DIR}" "${PN_SDK_SOURCE_ROOT}/src/core" "${PN_SDK_BINARY_ROOT}/include"
)

set_target_properties(
    pubnub_provider_serialization
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_serialization)
pubnub_target_sanitizers(pubnub_provider_serialization)

# jsmn ships with implicit signed/unsigned conversions and similar style
# choices that conflict with the SDK's strict project warnings. Suppress
# those warnings on the vendored-implementation translation unit only,
# leaving the provider shim subject to the full warning set.
if(NOT MSVC)
    set_source_files_properties(jsmn_impl.c PROPERTIES COMPILE_OPTIONS "-w")
endif()
