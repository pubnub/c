# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_feature_presence_state_units SOURCES presence_state_units.c LIBS pubnub)
target_include_directories(test_feature_presence_state_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_presence_heartbeat_units
    SOURCES presence_heartbeat_units.c
    LIBS pubnub
)
target_include_directories(test_feature_presence_heartbeat_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_presence_leave_units SOURCES presence_leave_units.c LIBS pubnub)
target_include_directories(test_feature_presence_leave_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_presence_wire_here_now_units
    SOURCES presence_wire_here_now_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_presence_wire_here_now_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_presence_wire_where_now_units
    SOURCES presence_wire_where_now_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_presence_wire_where_now_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_presence_wire_user_state_units
    SOURCES presence_wire_user_state_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_presence_wire_user_state_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_presence_subscribe_heartbeat_units
    SOURCES presence_subscribe_heartbeat_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_presence_subscribe_heartbeat_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)

pubnub_add_unit_test(
    test_feature_presence_timeout_units
    SOURCES presence_timeout_units.c
    LIBS pubnub
)
target_include_directories(test_feature_presence_timeout_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_presence_dispatch_units
    SOURCES presence_dispatch_units.c
    LIBS pubnub
)
target_include_directories(test_feature_presence_dispatch_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_presence_cleanup_units
    SOURCES presence_cleanup_units.c
    LIBS pubnub
)
target_include_directories(test_feature_presence_cleanup_units PRIVATE "${CMAKE_SOURCE_DIR}/src")
