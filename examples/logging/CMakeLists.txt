# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for the logging API.
#
# One file per topic so each serves as a self-contained doc snippet:
#
#   runtime_level.c  -- pubnub_set_log_level / pubnub_logger_log_level.
#   emit_entries.c   -- pubnub_log_text / _text_formatted / _object / _error.
#   custom_logger.c  -- a pubnub_logger_provider_t implementation plus
#                       pubnub_logger_add / pubnub_logger_remove.
#
# Not gated on a PUBNUB_ENABLE_* feature: pubnub/log.h is always
# declared. Whether a level actually reaches a sink is decided by
# PUBNUB_CFG_LOG_LEVEL_COMPILED and the runtime threshold.

add_executable(example_logging_runtime_level runtime_level.c)
target_link_libraries(example_logging_runtime_level PRIVATE pubnub)
set_target_properties(
    example_logging_runtime_level
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_logging_runtime_level)
pubnub_target_sanitizers(example_logging_runtime_level)

add_executable(example_logging_emit_entries emit_entries.c)
target_link_libraries(example_logging_emit_entries PRIVATE pubnub)
set_target_properties(
    example_logging_emit_entries
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_logging_emit_entries)
pubnub_target_sanitizers(example_logging_emit_entries)

add_executable(example_logging_custom_logger custom_logger.c)
target_link_libraries(example_logging_custom_logger PRIVATE pubnub)
set_target_properties(
    example_logging_custom_logger
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)
pubnub_target_warnings(example_logging_custom_logger)
pubnub_target_sanitizers(example_logging_custom_logger)
