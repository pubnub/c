# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the files feature.
#
# One file per operation (cooperative polling unless noted) so each
# serves as a self-contained doc snippet:
#
#   send_file.c                 -- send a file.
#   list_files.c                -- list files on a channel.
#   download_file.c             -- download a file.
#   send_file_async.c           -- send a file (async callback).
#   get_file_url.c              -- build a download URL locally (no request).
#   delete_file.c               -- delete a stored file.
#   publish_file_message.c      -- announce an already-uploaded file.
#   publish_file_message_push.c -- same, with an APNs/FCM payload.
#   recover_publish_failure.c   -- re-announce after a partial send_file.
#   receive_file_events.c       -- decode file events from subscribe.

add_executable(example_files_send_file send_file.c)
target_link_libraries(example_files_send_file PRIVATE pubnub)
set_target_properties(
    example_files_send_file
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_send_file)
pubnub_target_sanitizers(example_files_send_file)

add_executable(example_files_list_files list_files.c)
target_link_libraries(example_files_list_files PRIVATE pubnub)
set_target_properties(
    example_files_list_files
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_list_files)
pubnub_target_sanitizers(example_files_list_files)

add_executable(example_files_download_file download_file.c)
target_link_libraries(example_files_download_file PRIVATE pubnub)
set_target_properties(
    example_files_download_file
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_download_file)
pubnub_target_sanitizers(example_files_download_file)

add_executable(example_files_send_file_async send_file_async.c)
target_link_libraries(example_files_send_file_async PRIVATE pubnub)
set_target_properties(
    example_files_send_file_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_send_file_async)
pubnub_target_sanitizers(example_files_send_file_async)

add_executable(example_files_get_file_url get_file_url.c)
target_link_libraries(example_files_get_file_url PRIVATE pubnub)
set_target_properties(
    example_files_get_file_url
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_get_file_url)
pubnub_target_sanitizers(example_files_get_file_url)

add_executable(example_files_delete_file delete_file.c)
target_link_libraries(example_files_delete_file PRIVATE pubnub)
set_target_properties(
    example_files_delete_file
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_delete_file)
pubnub_target_sanitizers(example_files_delete_file)

add_executable(example_files_publish_file_message publish_file_message.c)
target_link_libraries(example_files_publish_file_message PRIVATE pubnub)
set_target_properties(
    example_files_publish_file_message
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_publish_file_message)
pubnub_target_sanitizers(example_files_publish_file_message)

add_executable(example_files_publish_file_message_push publish_file_message_push.c)
target_link_libraries(example_files_publish_file_message_push PRIVATE pubnub)
set_target_properties(
    example_files_publish_file_message_push
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_publish_file_message_push)
pubnub_target_sanitizers(example_files_publish_file_message_push)

add_executable(example_files_recover_publish_failure recover_publish_failure.c)
target_link_libraries(example_files_recover_publish_failure PRIVATE pubnub)
set_target_properties(
    example_files_recover_publish_failure
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_recover_publish_failure)
pubnub_target_sanitizers(example_files_recover_publish_failure)

add_executable(example_files_receive_file_events receive_file_events.c)
target_link_libraries(example_files_receive_file_events PRIVATE pubnub)
set_target_properties(
    example_files_receive_file_events
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_files_receive_file_events)
pubnub_target_sanitizers(example_files_receive_file_events)
