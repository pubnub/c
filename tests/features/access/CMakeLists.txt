# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_access_units SOURCES access_units.c LIBS pubnub)
target_include_directories(test_feature_access_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_access_token_units SOURCES access_token_units.c LIBS pubnub)
target_include_directories(test_feature_access_token_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_access_dispatch_units SOURCES access_dispatch_units.c LIBS pubnub)
target_include_directories(test_feature_access_dispatch_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_access_timeout_units SOURCES access_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_access_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
