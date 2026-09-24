# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_publish_units SOURCES publish_units.c LIBS pubnub)
target_include_directories(test_feature_publish_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_publish_value_units SOURCES publish_value_units.c LIBS pubnub)
target_include_directories(test_feature_publish_value_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_publish_concurrency_units
    SOURCES publish_concurrency_units.c
    LIBS pubnub
)
target_include_directories(test_feature_publish_concurrency_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_publish_timeout_units SOURCES publish_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_publish_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_publish_compress_units
    SOURCES publish_compress_units.c
    LIBS pubnub
)
target_include_directories(test_feature_publish_compress_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
