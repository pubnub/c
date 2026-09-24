# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the message_actions feature.
#
#   add_message_action.c          -- add a reaction (cooperative polling).
#   get_message_actions.c         -- fetch with pagination (cooperative polling).
#   remove_message_action.c       -- remove an action (cooperative polling).
#   get_message_actions_async.c   -- fetch with async callback.
#   add_message_action_blocking.c  -- add via pubnub_await().
#   add_then_remove.c              -- chain an add result into a remove.
#   get_message_actions_page.c     -- fetch a single page.

add_executable(example_message_actions_add_message_action add_message_action.c)
target_link_libraries(example_message_actions_add_message_action PRIVATE pubnub)
set_target_properties(
    example_message_actions_add_message_action
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_add_message_action)
pubnub_target_sanitizers(example_message_actions_add_message_action)

add_executable(example_message_actions_get_message_actions get_message_actions.c)
target_link_libraries(example_message_actions_get_message_actions PRIVATE pubnub)
set_target_properties(
    example_message_actions_get_message_actions
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_get_message_actions)
pubnub_target_sanitizers(example_message_actions_get_message_actions)

add_executable(example_message_actions_remove_message_action remove_message_action.c)
target_link_libraries(example_message_actions_remove_message_action PRIVATE pubnub)
set_target_properties(
    example_message_actions_remove_message_action
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_remove_message_action)
pubnub_target_sanitizers(example_message_actions_remove_message_action)

add_executable(example_message_actions_get_message_actions_async get_message_actions_async.c)
target_link_libraries(example_message_actions_get_message_actions_async PRIVATE pubnub)
set_target_properties(
    example_message_actions_get_message_actions_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_get_message_actions_async)
pubnub_target_sanitizers(example_message_actions_get_message_actions_async)

add_executable(example_message_actions_add_message_action_blocking add_message_action_blocking.c)
target_link_libraries(example_message_actions_add_message_action_blocking PRIVATE pubnub)
set_target_properties(
    example_message_actions_add_message_action_blocking
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_add_message_action_blocking)
pubnub_target_sanitizers(example_message_actions_add_message_action_blocking)

add_executable(example_message_actions_add_then_remove add_then_remove.c)
target_link_libraries(example_message_actions_add_then_remove PRIVATE pubnub)
set_target_properties(
    example_message_actions_add_then_remove
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_add_then_remove)
pubnub_target_sanitizers(example_message_actions_add_then_remove)

add_executable(example_message_actions_get_message_actions_page get_message_actions_page.c)
target_link_libraries(example_message_actions_get_message_actions_page PRIVATE pubnub)
set_target_properties(
    example_message_actions_get_message_actions_page
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_message_actions_get_message_actions_page)
pubnub_target_sanitizers(example_message_actions_get_message_actions_page)
