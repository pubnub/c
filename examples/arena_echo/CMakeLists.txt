# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Arena allocator echo example.
# Built only when PUBNUB_PROVIDER_ALLOCATOR=arena (embedded profile).

add_executable(example_arena_echo arena_echo.c)

# On hosted builds (not actual FreeRTOS targets), link POSIX platform to provide
# working monotonic_ms/sleep_ms/random_bytes ops. The freertos stub returns
# all-NULL on host builds, causing init to fail with PUBNUB_ERR_PROVIDER_MISSING.
# Link this BEFORE pubnub so the POSIX pn_platform_default() takes precedence.
if(UNIX OR WIN32)
    add_library(
        _arena_echo_posix_platform
        OBJECT
        ${CMAKE_SOURCE_DIR}/src/providers/platform/posix/platform_posix.c
    )
    target_link_libraries(_arena_echo_posix_platform PUBLIC pubnub_public_headers)
    target_compile_definitions(
        _arena_echo_posix_platform
        PRIVATE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE
    )
    find_package(Threads REQUIRED)
    target_link_libraries(_arena_echo_posix_platform PUBLIC Threads::Threads)
    target_link_libraries(example_arena_echo PRIVATE _arena_echo_posix_platform)
endif()

target_link_libraries(example_arena_echo PRIVATE pubnub)
target_include_directories(example_arena_echo PRIVATE "${CMAKE_SOURCE_DIR}/src")

set_target_properties(
    example_arena_echo
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(example_arena_echo)
pubnub_target_sanitizers(example_arena_echo)
