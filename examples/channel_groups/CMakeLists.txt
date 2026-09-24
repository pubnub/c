# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the channel_groups feature.
#
# One file per operation (cooperative polling) so each serves as a
# self-contained doc snippet:
#
#   add_channels.c    -- add channels to a group.
#   remove_channels.c -- remove channels from a group.
#   list_channels.c   -- list channels in a group.
#   delete_group.c    -- delete a channel group entirely.
#   list_channels_async.c -- list channels via pubnub_async() callback.

add_executable(example_channel_groups_add_channels add_channels.c)
target_link_libraries(example_channel_groups_add_channels PRIVATE pubnub)
set_target_properties(
    example_channel_groups_add_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_channel_groups_add_channels)
pubnub_target_sanitizers(example_channel_groups_add_channels)

add_executable(example_channel_groups_remove_channels remove_channels.c)
target_link_libraries(example_channel_groups_remove_channels PRIVATE pubnub)
set_target_properties(
    example_channel_groups_remove_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_channel_groups_remove_channels)
pubnub_target_sanitizers(example_channel_groups_remove_channels)

add_executable(example_channel_groups_list_channels list_channels.c)
target_link_libraries(example_channel_groups_list_channels PRIVATE pubnub)
set_target_properties(
    example_channel_groups_list_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_channel_groups_list_channels)
pubnub_target_sanitizers(example_channel_groups_list_channels)

add_executable(example_channel_groups_delete_group delete_group.c)
target_link_libraries(example_channel_groups_delete_group PRIVATE pubnub)
set_target_properties(
    example_channel_groups_delete_group
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_channel_groups_delete_group)
pubnub_target_sanitizers(example_channel_groups_delete_group)

add_executable(example_channel_groups_list_channels_async list_channels_async.c)
target_link_libraries(example_channel_groups_list_channels_async PRIVATE pubnub)
set_target_properties(
    example_channel_groups_list_channels_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_channel_groups_list_channels_async)
pubnub_target_sanitizers(example_channel_groups_list_channels_async)
