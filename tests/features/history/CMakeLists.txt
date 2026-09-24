# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_history_wire_units SOURCES history_wire_units.c LIBS pubnub)
target_include_directories(test_feature_history_wire_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_history_parse_units SOURCES history_parse_units.c LIBS pubnub)
target_include_directories(test_feature_history_parse_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_history_dispatch_units
    SOURCES history_dispatch_units.c
    LIBS pubnub
)
target_include_directories(test_feature_history_dispatch_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_history_timeout_units SOURCES history_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_history_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
