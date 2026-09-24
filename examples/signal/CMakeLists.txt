# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the signal feature.
#
#   cooperative.c -- send a signal using cooperative polling
#                    (pubnub_process loop).
#   async.c       -- send a signal using pubnub_async() callback.

add_executable(example_signal_cooperative cooperative.c)
target_link_libraries(example_signal_cooperative PRIVATE pubnub)
set_target_properties(
    example_signal_cooperative
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_signal_cooperative)
pubnub_target_sanitizers(example_signal_cooperative)

add_executable(example_signal_async async.c)
target_link_libraries(example_signal_async PRIVATE pubnub)
set_target_properties(
    example_signal_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_signal_async)
pubnub_target_sanitizers(example_signal_async)
