# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

find_package(Threads REQUIRED)

pubnub_add_unit_test(test_feature_subscribe_state_units SOURCES subscribe_state_units.c LIBS pubnub)
target_include_directories(test_feature_subscribe_state_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(test_feature_subscribe_wire_units SOURCES subscribe_wire_units.c LIBS pubnub)
target_include_directories(test_feature_subscribe_wire_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_subscribe_listener_units
    SOURCES subscribe_listener_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_subscribe_listener_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/src/core"
)
target_link_libraries(test_feature_subscribe_listener_units PRIVATE Threads::Threads)

pubnub_add_unit_test(
    test_feature_subscribe_cleanup_units
    SOURCES subscribe_cleanup_units.c
    LIBS pubnub
)
target_include_directories(test_feature_subscribe_cleanup_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_subscribe_effects_units
    SOURCES subscribe_effects_units.c
    LIBS pubnub
)
target_include_directories(test_feature_subscribe_effects_units PRIVATE "${CMAKE_SOURCE_DIR}/src")

pubnub_add_unit_test(
    test_feature_subscribe_slot_release_units
    SOURCES subscribe_slot_release_units.c
    LIBS pubnub
)
target_include_directories(
    test_feature_subscribe_slot_release_units
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
)
