# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_signal_units SOURCES signal_units.c LIBS pubnub)
target_include_directories(test_feature_signal_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_signal_timeout_units SOURCES signal_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_signal_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_signal_wire_units SOURCES signal_wire_units.c LIBS pubnub)
target_include_directories(test_feature_signal_wire_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
