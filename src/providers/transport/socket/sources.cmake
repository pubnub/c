# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Base socket transport sources (core FSM, HTTP builder/parser, keepalive).
# Does NOT include sub-directory sources (dns, proxy, platform, tls, inflate).

set(PN_TRANSPORT_SOCKET_BASE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/transport_socket.c"
    "${CMAKE_CURRENT_LIST_DIR}/connection_fsm.c"
    "${CMAKE_CURRENT_LIST_DIR}/http_builder.c"
    "${CMAKE_CURRENT_LIST_DIR}/http_parser.c"
    "${CMAKE_CURRENT_LIST_DIR}/keepalive.c"
)
