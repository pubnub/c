# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(
    test_feature_app_context_wire_common_units
    SOURCES app_context_wire_common_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_wire_common_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_app_context_wire_uuid_units
    SOURCES app_context_wire_uuid_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_wire_uuid_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_app_context_wire_channel_units
    SOURCES app_context_wire_channel_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_wire_channel_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_app_context_wire_membership_units
    SOURCES app_context_wire_membership_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_wire_membership_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_app_context_dispatch_units
    SOURCES app_context_dispatch_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_dispatch_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_app_context_timeout_units
    SOURCES app_context_timeout_units.c
    LIBS pubnub
)
target_include_directories(test_feature_app_context_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_app_context_lifecycle_units
    SOURCES app_context_lifecycle_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_app_context_lifecycle_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)
target_compile_definitions(
    test_feature_app_context_lifecycle_units
    PRIVATE $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
)
