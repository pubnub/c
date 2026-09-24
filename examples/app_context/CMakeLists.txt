# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the App Context (Objects v2) feature.
#
# One translation unit per operation/style so each example is focused
# and readable:
#
#   get_uuid_metadata.c           -- cooperative: get single UUID metadata
#   set_uuid_metadata.c           -- cooperative: set UUID metadata fields
#   get_all_uuid_metadata.c       -- cooperative: paginated list with
#                                    include/filter/sort
#   get_all_uuid_metadata_async.c -- async callback: paginated UUID list
#   set_channel_metadata.c        -- cooperative: set channel metadata
#   get_memberships.c             -- cooperative: get UUID memberships
#   set_members.c                 -- cooperative: set channel members
#   set_memberships.c -- add and remove a user's channel memberships.
#   set_uuid_metadata_json_tree.c -- custom_value JSON tree and if_match.

add_executable(example_app_context_get_uuid_metadata get_uuid_metadata.c)
target_link_libraries(example_app_context_get_uuid_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_get_uuid_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_uuid_metadata)
pubnub_target_sanitizers(example_app_context_get_uuid_metadata)

add_executable(example_app_context_set_uuid_metadata set_uuid_metadata.c)
target_link_libraries(example_app_context_set_uuid_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_set_uuid_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_set_uuid_metadata)
pubnub_target_sanitizers(example_app_context_set_uuid_metadata)

add_executable(example_app_context_get_all_uuid_metadata get_all_uuid_metadata.c)
target_link_libraries(example_app_context_get_all_uuid_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_get_all_uuid_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_all_uuid_metadata)
pubnub_target_sanitizers(example_app_context_get_all_uuid_metadata)

add_executable(example_app_context_get_all_uuid_metadata_async get_all_uuid_metadata_async.c)
target_link_libraries(example_app_context_get_all_uuid_metadata_async PRIVATE pubnub)
set_target_properties(
    example_app_context_get_all_uuid_metadata_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_all_uuid_metadata_async)
pubnub_target_sanitizers(example_app_context_get_all_uuid_metadata_async)

add_executable(example_app_context_set_channel_metadata set_channel_metadata.c)
target_link_libraries(example_app_context_set_channel_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_set_channel_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_set_channel_metadata)
pubnub_target_sanitizers(example_app_context_set_channel_metadata)

add_executable(example_app_context_get_memberships get_memberships.c)
target_link_libraries(example_app_context_get_memberships PRIVATE pubnub)
set_target_properties(
    example_app_context_get_memberships
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_memberships)
pubnub_target_sanitizers(example_app_context_get_memberships)

add_executable(example_app_context_set_members set_members.c)
target_link_libraries(example_app_context_set_members PRIVATE pubnub)
set_target_properties(
    example_app_context_set_members
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_set_members)
pubnub_target_sanitizers(example_app_context_set_members)

add_executable(example_app_context_remove_uuid_metadata remove_uuid_metadata.c)
target_link_libraries(example_app_context_remove_uuid_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_remove_uuid_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_remove_uuid_metadata)
pubnub_target_sanitizers(example_app_context_remove_uuid_metadata)

add_executable(example_app_context_remove_channel_metadata remove_channel_metadata.c)
target_link_libraries(example_app_context_remove_channel_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_remove_channel_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_remove_channel_metadata)
pubnub_target_sanitizers(example_app_context_remove_channel_metadata)

add_executable(example_app_context_get_channel_metadata get_channel_metadata.c)
target_link_libraries(example_app_context_get_channel_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_get_channel_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_channel_metadata)
pubnub_target_sanitizers(example_app_context_get_channel_metadata)

add_executable(example_app_context_get_all_channel_metadata get_all_channel_metadata.c)
target_link_libraries(example_app_context_get_all_channel_metadata PRIVATE pubnub)
set_target_properties(
    example_app_context_get_all_channel_metadata
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_all_channel_metadata)
pubnub_target_sanitizers(example_app_context_get_all_channel_metadata)

add_executable(example_app_context_get_channel_members get_channel_members.c)
target_link_libraries(example_app_context_get_channel_members PRIVATE pubnub)
set_target_properties(
    example_app_context_get_channel_members
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_get_channel_members)
pubnub_target_sanitizers(example_app_context_get_channel_members)

add_executable(example_app_context_set_memberships set_memberships.c)
target_link_libraries(example_app_context_set_memberships PRIVATE pubnub)
set_target_properties(
    example_app_context_set_memberships
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_set_memberships)
pubnub_target_sanitizers(example_app_context_set_memberships)

add_executable(example_app_context_set_uuid_metadata_json_tree set_uuid_metadata_json_tree.c)
target_link_libraries(example_app_context_set_uuid_metadata_json_tree PRIVATE pubnub)
set_target_properties(
    example_app_context_set_uuid_metadata_json_tree
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_app_context_set_uuid_metadata_json_tree)
pubnub_target_sanitizers(example_app_context_set_uuid_metadata_json_tree)
