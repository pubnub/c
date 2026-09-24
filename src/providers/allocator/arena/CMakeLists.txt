# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# arena allocator: two-zone free-list bump allocator for embedded profiles.

include(sources.cmake)

_pn_sdk_library(pubnub_provider_allocator)
target_sources(pubnub_provider_allocator PRIVATE ${PN_PROVIDER_ALLOCATOR_ARENA_SOURCES})

target_link_libraries(pubnub_provider_allocator PUBLIC pubnub_public_headers)

set_target_properties(
    pubnub_provider_allocator
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_allocator)
pubnub_target_sanitizers(pubnub_provider_allocator)
