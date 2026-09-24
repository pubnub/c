# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(
    test_feature_channel_groups_wire_units
    SOURCES channel_groups_wire_units.c
    LIBS pubnub
)
target_include_directories(test_feature_channel_groups_wire_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_channel_groups_wire_list_units
    SOURCES channel_groups_wire_list_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_channel_groups_wire_list_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_channel_groups_wire_membership_units
    SOURCES channel_groups_wire_membership_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_channel_groups_wire_membership_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_channel_groups_api_units
    SOURCES channel_groups_api_units.c
    LIBS pubnub
)
target_include_directories(test_feature_channel_groups_api_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_channel_groups_dispatch_units
    SOURCES channel_groups_dispatch_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_channel_groups_dispatch_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_channel_groups_timeout_units
    SOURCES channel_groups_timeout_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_channel_groups_timeout_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)
