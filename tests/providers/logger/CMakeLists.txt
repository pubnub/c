# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Logger manager — compiles pn_logger_manager.c directly for isolation.
pubnub_add_unit_test(
    test_provider_logger_manager_units
    SOURCES logger_manager_units.c ${CMAKE_SOURCE_DIR}/src/core/pn_logger_manager.c
)

target_include_directories(
    test_provider_logger_manager_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src/core"
)

# Public log-emission and logger-lifecycle API smoke tests.
# Requires the full pn_core + provider stack to spin up a real context.
pubnub_add_unit_test(test_provider_logger_log_api_units SOURCES logger_log_api_units.c LIBS pubnub)

# Stdout logger — compiles source directly.
pubnub_add_unit_test(
    test_provider_logger_stdout_units
    SOURCES logger_stdout_units.c ${PN_PROVIDERS_SRC_DIR}/logger/stdout/logger_stdout.c
    LIBS pn_core_fmt
)

target_include_directories(
    test_provider_logger_stdout_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src/core"
    PRIVATE "${PN_PROVIDERS_SRC_DIR}/logger/stdout"
)
