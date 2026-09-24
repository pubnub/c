# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_time_units SOURCES time_units.c LIBS pubnub)
target_include_directories(test_feature_time_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_time_timeout_units SOURCES time_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_time_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_time_result_units SOURCES time_result_units.c LIBS pubnub)
target_include_directories(test_feature_time_result_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
