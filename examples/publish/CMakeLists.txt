# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the publish feature.
#
# One translation unit per ergonomics tier so each example stays
# a focused, readable demonstration of how to call the matching
# entry point and consume the future:
#
#   cooperative.c -- string-form publish (pubnub_publish): pumps
#                    pubnub_process() in a polling loop with an
#                    already-formatted JSON literal.
#   sync.c        -- blocking-await publish: calls pubnub_await()
#                    which blocks until the future completes.
#   async.c       -- callback-driven publish: registers pubnub_async()
#                    and drives the loop until the callback fires.
#   value.c       -- value-tree publish (pubnub_publish_value):
#                    builds a structured payload from C data via
#                    PUBNUB_JSON_OBJ and friends.
#   concurrent.c  -- multiple in-flight publishes; uses the slot
#                    pool's parallel-dispatch capacity and prints
#                    per-future timestamps so the overlap is
#                    visible.
#
# All examples below call pubnub_create/pubnub_destroy and require a
# heap-capable environment.  On no-heap embedded profiles
# (PUBNUB_CFG_NO_HEAP=1) use the arena_echo example instead.

if(NOT PUBNUB_CFG_NO_HEAP)
    add_executable(example_publish_cooperative cooperative.c)
    target_link_libraries(example_publish_cooperative PRIVATE pubnub)
    set_target_properties(
        example_publish_cooperative
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_publish_cooperative)
    pubnub_target_sanitizers(example_publish_cooperative)

    add_executable(example_publish_sync sync.c)
    target_link_libraries(example_publish_sync PRIVATE pubnub)
    set_target_properties(
        example_publish_sync
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_publish_sync)
    pubnub_target_sanitizers(example_publish_sync)

    add_executable(example_publish_async async.c)
    target_link_libraries(example_publish_async PRIVATE pubnub)
    set_target_properties(
        example_publish_async
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_publish_async)
    pubnub_target_sanitizers(example_publish_async)

    if(PUBNUB_CFG_JSON_HELPERS)
        add_executable(example_publish_value value.c)
        target_link_libraries(example_publish_value PRIVATE pubnub)
        set_target_properties(
            example_publish_value
            PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        )
        pubnub_target_warnings(example_publish_value)
        pubnub_target_sanitizers(example_publish_value)
    endif()

    add_executable(example_publish_concurrent concurrent.c)
    target_link_libraries(example_publish_concurrent PRIVATE pubnub)
    set_target_properties(
        example_publish_concurrent
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_publish_concurrent)
    pubnub_target_sanitizers(example_publish_concurrent)
endif()
