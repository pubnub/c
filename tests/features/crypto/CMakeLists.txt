# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_crypto_module_units SOURCES test_crypto_module.c LIBS pubnub)
target_include_directories(test_feature_crypto_module_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_crypto_header_units SOURCES test_crypto_header.c LIBS pubnub)
target_include_directories(test_feature_crypto_header_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
