# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the push notifications feature.
#
# One translation unit per sub-feature operation so each example
# stays a focused, readable demonstration of how to call the
# matching entry point and consume the future:
#
#   add_channels.c       -- register channels for push on a device
#                           (cooperative polling loop).
#   remove_channels.c    -- unregister channels for push on a device
#                           (cooperative polling loop).
#   list_channels.c      -- list channels registered for push on a
#                           device (cooperative polling loop).
#   remove_device.c      -- remove all push registrations for a device
#                           (cooperative polling loop).
#   list_channels_async.c -- callback-driven variant of list_channels:
#                           registers pubnub_async() and drives the
#                           loop until the callback fires.
#   publish_with_payload.c -- publish carrying pn_apns / pn_fcm.

add_executable(example_push_add_channels add_channels.c)
target_link_libraries(example_push_add_channels PRIVATE pubnub)
set_target_properties(
    example_push_add_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_add_channels)
pubnub_target_sanitizers(example_push_add_channels)

add_executable(example_push_remove_channels remove_channels.c)
target_link_libraries(example_push_remove_channels PRIVATE pubnub)
set_target_properties(
    example_push_remove_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_remove_channels)
pubnub_target_sanitizers(example_push_remove_channels)

add_executable(example_push_list_channels list_channels.c)
target_link_libraries(example_push_list_channels PRIVATE pubnub)
set_target_properties(
    example_push_list_channels
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_list_channels)
pubnub_target_sanitizers(example_push_list_channels)

add_executable(example_push_remove_device remove_device.c)
target_link_libraries(example_push_remove_device PRIVATE pubnub)
set_target_properties(
    example_push_remove_device
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_remove_device)
pubnub_target_sanitizers(example_push_remove_device)

add_executable(example_push_list_channels_async list_channels_async.c)
target_link_libraries(example_push_list_channels_async PRIVATE pubnub)
set_target_properties(
    example_push_list_channels_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_list_channels_async)
pubnub_target_sanitizers(example_push_list_channels_async)

add_executable(example_push_publish_with_payload publish_with_payload.c)
target_link_libraries(example_push_publish_with_payload PRIVATE pubnub)
set_target_properties(
    example_push_publish_with_payload
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_push_publish_with_payload)
pubnub_target_sanitizers(example_push_publish_with_payload)
