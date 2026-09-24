# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

include(sources.cmake)

# Leaf utility: portable snprintf + variadic log bridge (no provider deps, no allocator).
# Defined before sub-components so they can link against it.
_pn_sdk_library(pn_core_fmt pn_format.c log_variadic.c error.c)
target_include_directories(pn_core_fmt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(pn_core_fmt PRIVATE pubnub_public_headers)
set_target_properties(
    pn_core_fmt
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(pn_core_fmt)
pubnub_target_visibility(pn_core_fmt)
pubnub_target_sanitizers(pn_core_fmt)

# Leaf utility: allocator-aware string helpers (pn_strdup, pn_strfree, pn_strlcpy).
# No provider deps beyond allocator vtable (public header). Transport providers link
# this directly so they can own string copies without depending on pn_core.
_pn_sdk_library(pn_core_str pn_string.c)
target_include_directories(pn_core_str PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(pn_core_str PRIVATE pubnub_public_headers)
set_target_properties(
    pn_core_str
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(pn_core_str)
pubnub_target_visibility(pn_core_str)
pubnub_target_sanitizers(pn_core_str)

# Sub-components (object libraries, linked into pn_core below).
add_subdirectory(protocol_common)
add_subdirectory(runtime)

# pn_format.c and log_variadic.c are compiled separately as pn_core_fmt (leaf
# with no provider deps) and linked PRIVATE into pn_core below.
set(PN_CORE_MAIN_SOURCES ${PN_CORE_BASE_SOURCES})
list(REMOVE_ITEM PN_CORE_MAIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/pn_format.c")
list(REMOVE_ITEM PN_CORE_MAIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/log_variadic.c")
list(REMOVE_ITEM PN_CORE_MAIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/error.c")
list(REMOVE_ITEM PN_CORE_MAIN_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/pn_string.c")

_pn_sdk_library(pn_core ${PN_CORE_MAIN_SOURCES})

target_link_libraries(
    pn_core
    PUBLIC pubnub_public_headers
    PRIVATE pn_core_fmt
    PRIVATE pn_core_str
    PRIVATE pn_core_protocol_common
    PRIVATE pn_core_runtime
    PRIVATE pn_core_timer
    PRIVATE pn_core_middleware
)

target_include_directories(
    pn_core
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../providers"
)

set_target_properties(
    pn_core
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_core)
pubnub_target_visibility(pn_core)
pubnub_target_sanitizers(pn_core)
