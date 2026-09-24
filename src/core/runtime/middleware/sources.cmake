# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Source file list for the base middleware (always compiled).

set(PN_CORE_MIDDLEWARE_BASE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/auth_middleware.c"
    "${CMAKE_CURRENT_LIST_DIR}/middleware_common.c"
    "${CMAKE_CURRENT_LIST_DIR}/pnsdk_middleware.c"
    "${CMAKE_CURRENT_LIST_DIR}/userid_middleware.c"
)
