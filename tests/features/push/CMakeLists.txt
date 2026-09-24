# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_push_api_units SOURCES push_api_units.c LIBS pubnub)
target_include_directories(test_feature_push_api_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_push_add_channels_wire_units
    SOURCES push_add_channels_wire_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_push_add_channels_wire_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_push_remove_channels_wire_units
    SOURCES push_remove_channels_wire_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_push_remove_channels_wire_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_push_list_channels_wire_units
    SOURCES push_list_channels_wire_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_push_list_channels_wire_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_push_remove_device_wire_units
    SOURCES push_remove_device_wire_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_push_remove_device_wire_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(test_feature_push_dispatch_units SOURCES push_dispatch_units.c LIBS pubnub)
target_include_directories(test_feature_push_dispatch_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_push_timeout_units SOURCES push_timeout_units.c LIBS pubnub)
target_include_directories(test_feature_push_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_push_lifecycle_units SOURCES push_lifecycle_units.c LIBS pubnub)
target_include_directories(test_feature_push_lifecycle_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_compile_definitions(
    test_feature_push_lifecycle_units
    PRIVATE $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
)
