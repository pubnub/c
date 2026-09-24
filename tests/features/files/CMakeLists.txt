# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_files_multipart_units SOURCES files_multipart_units.c LIBS pubnub)
target_include_directories(
    test_feature_files_multipart_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src/core"
)

pubnub_add_unit_test(test_feature_files_wire_units SOURCES files_wire_units.c LIBS pubnub)
target_include_directories(test_feature_files_wire_units PRIVATE "${CMAKE_SOURCE_DIR}/src/core")

pubnub_add_unit_test(test_feature_files_api_units SOURCES files_api_units.c LIBS pubnub)
target_include_directories(test_feature_files_api_units PRIVATE "${CMAKE_SOURCE_DIR}/src/core")

pubnub_add_unit_test(test_feature_files_dispatch_units SOURCES files_dispatch_units.c LIBS pubnub)
target_include_directories(test_feature_files_dispatch_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_files_timeout_units SOURCES files_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_files_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
