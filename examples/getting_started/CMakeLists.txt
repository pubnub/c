# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# The getting-started tutorial program.
#
#   getting_started.c -- configure, register a listener, subscribe,
#                        publish, receive the echo, shut down. Split into
#                        six contiguous doc snippets, one per tutorial
#                        step.
#
# Needs both publish and subscribe, so it is gated on both in
# examples/CMakeLists.txt.

add_executable(example_getting_started getting_started.c)
target_link_libraries(example_getting_started PRIVATE pubnub)
set_target_properties(
    example_getting_started
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_getting_started)
pubnub_target_sanitizers(example_getting_started)
