# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

if(NOT PUBNUB_BUILD_CROSS_SDK_TESTS)
    return()
endif()

add_subdirectory(c_runner)

find_program(NODE_EXECUTABLE node)

if(NODE_EXECUTABLE)
    add_test(
        NAME cross_sdk_compat
        COMMAND "${NODE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/runner/orchestrate.js"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    set_tests_properties(
        cross_sdk_compat
        PROPERTIES
            LABELS "cross_sdk"
            TIMEOUT 300
            ENVIRONMENT
                "PUBNUB_PUBLISH_KEY=$ENV{PUBNUB_PUBLISH_KEY};\
PUBNUB_SUBSCRIBE_KEY=$ENV{PUBNUB_SUBSCRIBE_KEY};\
CROSS_SDK_C_BINARY=$<TARGET_FILE:cross_sdk_c_runner>"
    )
else()
    message(STATUS "[PubNub] node not found — skipping cross_sdk_compat CTest entry")
endif()
