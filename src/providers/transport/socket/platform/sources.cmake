# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Platform-specific socket operations. Only one of these is compiled per build.

set(PN_TRANSPORT_SOCKET_PLATFORM_POSIX_SOURCES "${CMAKE_CURRENT_LIST_DIR}/posix_socket_ops.c")

set(PN_TRANSPORT_SOCKET_PLATFORM_FREERTOS_SOURCES "${CMAKE_CURRENT_LIST_DIR}/freertos_socket_ops.c")

set(PN_TRANSPORT_SOCKET_PLATFORM_WINDOWS_SOURCES "${CMAKE_CURRENT_LIST_DIR}/windows_socket_ops.c")

set(PN_TRANSPORT_SOCKET_PLATFORM_ZEPHYR_SOURCES "${CMAKE_CURRENT_LIST_DIR}/zephyr_socket_ops.c")
