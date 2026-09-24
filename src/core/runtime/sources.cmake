# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Source file list for the pn_core_timer and pn_core_runtime targets.

set(PN_CORE_RUNTIME_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/timer.c"
    "${CMAKE_CURRENT_LIST_DIR}/timer_list.c"
    "${CMAKE_CURRENT_LIST_DIR}/request.c"
    "${CMAKE_CURRENT_LIST_DIR}/request_pool.c"
    "${CMAKE_CURRENT_LIST_DIR}/pending_queue.c"
    "${CMAKE_CURRENT_LIST_DIR}/pipeline.c"
)
