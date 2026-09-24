# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the history feature.
#
#   fetch_messages.c       -- cooperative polling with multi-channel fetch
#   fetch_messages_async.c -- async callback for fetch_messages
#   message_counts.c       -- blocking await for unread counts
#   delete_messages.c      -- blocking await for message deletion
#   fetch_messages_with_actions.c -- fetch with include_message_actions.

add_executable(example_history_fetch_messages fetch_messages.c)
target_link_libraries(example_history_fetch_messages PRIVATE pubnub)
set_target_properties(
    example_history_fetch_messages
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_history_fetch_messages)
pubnub_target_sanitizers(example_history_fetch_messages)

add_executable(example_history_fetch_messages_async fetch_messages_async.c)
target_link_libraries(example_history_fetch_messages_async PRIVATE pubnub)
set_target_properties(
    example_history_fetch_messages_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_history_fetch_messages_async)
pubnub_target_sanitizers(example_history_fetch_messages_async)

add_executable(example_history_message_counts message_counts.c)
target_link_libraries(example_history_message_counts PRIVATE pubnub)
set_target_properties(
    example_history_message_counts
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_history_message_counts)
pubnub_target_sanitizers(example_history_message_counts)

add_executable(example_history_delete_messages delete_messages.c)
target_link_libraries(example_history_delete_messages PRIVATE pubnub)
set_target_properties(
    example_history_delete_messages
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_history_delete_messages)
pubnub_target_sanitizers(example_history_delete_messages)

add_executable(example_history_fetch_messages_with_actions fetch_messages_with_actions.c)
target_link_libraries(example_history_fetch_messages_with_actions PRIVATE pubnub)
set_target_properties(
    example_history_fetch_messages_with_actions
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_history_fetch_messages_with_actions)
pubnub_target_sanitizers(example_history_fetch_messages_with_actions)
