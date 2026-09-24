# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the time feature.
#   cooperative.c -- get server time using cooperative polling.
#   async.c       -- get server time using pubnub_async() callback.

add_executable(example_time_cooperative cooperative.c)
target_link_libraries(example_time_cooperative PRIVATE pubnub)
set_target_properties(
    example_time_cooperative
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_time_cooperative)
pubnub_target_sanitizers(example_time_cooperative)

add_executable(example_time_async async.c)
target_link_libraries(example_time_async PRIVATE pubnub)
set_target_properties(
    example_time_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_time_async)
pubnub_target_sanitizers(example_time_async)
