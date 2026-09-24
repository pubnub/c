# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

set(PN_FEATURE_APP_CONTEXT_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_uuid.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_channel.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_membership.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_member.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_api_subscribe.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_wire_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_wire_channel.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_wire_membership.c"
    "${CMAKE_CURRENT_LIST_DIR}/app_context_wire_uuid.c"
)
