# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the presence feature.
#
#   here_now.c        -- query channel occupancy (cooperative polling).
#   here_now_async.c  -- query channel occupancy (async callback).
#   where_now.c       -- query which channels a UUID is present on.
#   set_state.c       -- set presence state from a raw JSON string.
#   set_state_value.c -- set presence state from a JSON value tree.
#   get_state.c       -- retrieve per-channel presence state.

add_executable(example_presence_here_now here_now.c)
target_link_libraries(example_presence_here_now PRIVATE pubnub)
set_target_properties(
    example_presence_here_now
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_here_now)
pubnub_target_sanitizers(example_presence_here_now)

add_executable(example_presence_here_now_async here_now_async.c)
target_link_libraries(example_presence_here_now_async PRIVATE pubnub)
set_target_properties(
    example_presence_here_now_async
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_here_now_async)
pubnub_target_sanitizers(example_presence_here_now_async)

add_executable(example_presence_where_now where_now.c)
target_link_libraries(example_presence_where_now PRIVATE pubnub)
set_target_properties(
    example_presence_where_now
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_where_now)
pubnub_target_sanitizers(example_presence_where_now)

add_executable(example_presence_set_state set_state.c)
target_link_libraries(example_presence_set_state PRIVATE pubnub)
set_target_properties(
    example_presence_set_state
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_set_state)
pubnub_target_sanitizers(example_presence_set_state)

add_executable(example_presence_set_state_value set_state_value.c)
target_link_libraries(example_presence_set_state_value PRIVATE pubnub)
set_target_properties(
    example_presence_set_state_value
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_set_state_value)
pubnub_target_sanitizers(example_presence_set_state_value)

add_executable(example_presence_get_state get_state.c)
target_link_libraries(example_presence_get_state PRIVATE pubnub)
set_target_properties(
    example_presence_get_state
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_presence_get_state)
pubnub_target_sanitizers(example_presence_get_state)
