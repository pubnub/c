# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Source file list for the pn_core target (context lifecycle, public API
# entry points) and the pn_core_fmt utility.

set(PN_CORE_BASE_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/pn_format.c"
    "${CMAKE_CURRENT_LIST_DIR}/client.c"
    "${CMAKE_CURRENT_LIST_DIR}/config.c"
    "${CMAKE_CURRENT_LIST_DIR}/response.c"
    "${CMAKE_CURRENT_LIST_DIR}/error.c"
    "${CMAKE_CURRENT_LIST_DIR}/version.c"
    "${CMAKE_CURRENT_LIST_DIR}/log_variadic.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_string.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_logger_manager.c"
    "${CMAKE_CURRENT_LIST_DIR}/future.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_feature_registry.c"
    "${CMAKE_CURRENT_LIST_DIR}/json_helpers.c"
    "${CMAKE_CURRENT_LIST_DIR}/service_error.c"
    "${CMAKE_CURRENT_LIST_DIR}/pn_crypto_module.c"
)
