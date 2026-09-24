# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

set(PN_FEATURE_PRESENCE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/presence_api.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_effects.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_event_queue.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_manager.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_state.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_wire.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_wire_here_now.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_wire_user_state.c"
    "${CMAKE_CURRENT_LIST_DIR}/presence_wire_where_now.c"
)
