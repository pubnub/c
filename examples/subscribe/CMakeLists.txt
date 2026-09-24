# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Subscribe feature examples.
#
#   callback.c -- listener callbacks with publish echo.
#   entities.c -- entities, subscriptions, subscription sets, and the
#                 three listener registration levels.
#
# Both use pubnub_create/pubnub_destroy — not available on no-heap
# embedded profiles (PUBNUB_CFG_NO_HEAP=1) — so both are gated on heap
# availability.

if(NOT PUBNUB_CFG_NO_HEAP)
    add_executable(example_subscribe_callback callback.c)
    target_link_libraries(example_subscribe_callback PRIVATE pubnub)
    set_target_properties(
        example_subscribe_callback
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_subscribe_callback)
    pubnub_target_sanitizers(example_subscribe_callback)

    add_executable(example_subscribe_entities entities.c)
    target_link_libraries(example_subscribe_entities PRIVATE pubnub)
    set_target_properties(
        example_subscribe_entities
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_subscribe_entities)
    pubnub_target_sanitizers(example_subscribe_entities)
endif()
