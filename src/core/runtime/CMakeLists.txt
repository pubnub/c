# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Core runtime: timers, future/request slots, pipeline, middleware,
# timeout resolution.

include(sources.cmake)

# Timer is a separate OBJECT library so both pn_core_runtime and
# pn_core_middleware (retry) can link against it without circular deps.
_pn_sdk_library(pn_core_timer timer.c timer_list.c)

target_include_directories(pn_core_timer PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

target_link_libraries(pn_core_timer PRIVATE pubnub_public_headers)

set_target_properties(
    pn_core_timer
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_core_timer)
pubnub_target_visibility(pn_core_timer)
pubnub_target_sanitizers(pn_core_timer)

# Middleware defined before runtime (runtime depends on middleware).
add_subdirectory(middleware)

_pn_sdk_library(pn_core_runtime request.c request_pool.c pending_queue.c pipeline.c)

target_include_directories(pn_core_runtime PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")

target_link_libraries(
    pn_core_runtime
    PRIVATE pubnub_public_headers
    PRIVATE pn_core_middleware pn_core_timer
)

set_target_properties(
    pn_core_runtime
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_core_runtime)
pubnub_target_visibility(pn_core_runtime)
pubnub_target_sanitizers(pn_core_runtime)
