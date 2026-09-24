# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Base proxy sources (stub implementations for no-proxy builds).
# Full CONNECT proxy support files are added conditionally by the
# socket transport CMakeLists.txt when PUBNUB_ENABLE_PROXY is set.

set(PN_TRANSPORT_SOCKET_PROXY_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/proxy_none.c"
    "${CMAKE_CURRENT_LIST_DIR}/proxy_wpad_none.c"
)
