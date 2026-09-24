# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(
    test_feature_message_actions_wire_add_units
    SOURCES message_actions_wire_add_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_wire_add_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_message_actions_wire_get_units
    SOURCES message_actions_wire_get_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_wire_get_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_message_actions_wire_remove_units
    SOURCES message_actions_wire_remove_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_wire_remove_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_message_actions_dispatch_units
    SOURCES message_actions_dispatch_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_dispatch_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_message_actions_timeout_units
    SOURCES message_actions_timeout_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_timeout_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_message_actions_lifecycle_units
    SOURCES message_actions_lifecycle_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_message_actions_lifecycle_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)
target_compile_definitions(
    test_feature_message_actions_lifecycle_units
    PRIVATE $<$<NOT:$<PLATFORM_ID:Windows>>:_POSIX_C_SOURCE=200809L>
)
