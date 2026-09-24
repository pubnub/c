# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

set(PN_XS_SCENARIO_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_publish.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_compressed_publish.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_json_publish.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_encrypted_publish.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_file_upload.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_encrypted_file_upload.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_set_uuid_metadata.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_set_channel_metadata.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_add_message_action.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_presence_state_set.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/c_channel_groups_add.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_publish_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_encrypted_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_file_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_metadata_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_json_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_encrypted_file_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_channel_metadata_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/js_message_action_verify.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/scenarios/cleanup.c"
)

add_executable(cross_sdk_c_runner main.c common.c ${PN_XS_SCENARIO_SOURCES})

target_link_libraries(cross_sdk_c_runner PRIVATE ${PUBNUB_TEST_LINK_TARGET})

target_include_directories(
    cross_sdk_c_runner
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/tests/integration/helpers"
        "${CMAKE_BINARY_DIR}/src/core"
)

set_target_properties(
    cross_sdk_c_runner
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_sanitizers(cross_sdk_c_runner)
