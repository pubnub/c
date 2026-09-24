# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Developer utility: measure the current pubnub_context_size() and print
# the suggested PUBNUB_CONTEXT_SIZE constant for CMakeLists.txt.
#
# Build:
#   cmake --preset dev && cmake --build build/dev --target pubnub_context_size_probe
# Run:
#   ./build/dev/tools/context_size/pubnub_context_size_probe
#
# Not built by default (EXCLUDE_FROM_ALL).

add_executable(pubnub_context_size_probe EXCLUDE_FROM_ALL main.c)

target_link_libraries(pubnub_context_size_probe PRIVATE pubnub)

set_target_properties(
    pubnub_context_size_probe
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
