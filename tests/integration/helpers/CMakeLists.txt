# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

add_library(
    pn_test_helpers
    OBJECT
    it_env.c
    it_channel.c
    it_wait.c
    it_context.c
    it_cleanup.c
    it_bus.c
)

target_link_libraries(
    pn_test_helpers
    PUBLIC ${PUBNUB_TEST_LINK_TARGET} $<$<NOT:$<PLATFORM_ID:Windows>>:pthread>
)
target_link_libraries(pn_test_helpers PUBLIC cmocka)

target_include_directories(
    pn_test_helpers
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIVATE "${CMAKE_SOURCE_DIR}/src" "${CMAKE_BINARY_DIR}/src/core"
)

target_compile_definitions(
    pn_test_helpers
    PRIVATE
        $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
        $<$<NOT:$<PLATFORM_ID:Windows>>:_DEFAULT_SOURCE>
)

set_target_properties(
    pn_test_helpers
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
