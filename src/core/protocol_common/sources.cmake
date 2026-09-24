# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Source file list for the pn_core_protocol_common target.

set(PN_CORE_PROTOCOL_COMMON_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/pn_base64.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_base64url.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_buf_serialize.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_channel_dispatch_state.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_response_probe.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_url_encode.c"
)
