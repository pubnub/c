# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

idf_component_register(
    SRCS
        "kitchensink_main.c"
        "ks_test_runner.c"
        "ks_protocol.c"
        "ks_tests_time.c"
        "ks_tests_publish.c"
        "ks_tests_subscribe.c"
        "ks_tests_presence.c"
        "ks_tests_history.c"
        "ks_tests_signal.c"
        "ks_tests_message_actions.c"
        "ks_tests_channel_groups.c"
        "ks_tests_app_context.c"
        "ks_tests_crypto.c"
        "ks_tests_files.c"
    INCLUDE_DIRS "."
    REQUIRES pubnub nvs_flash esp_wifi esp_netif esp_timer freertos lwip
)

if(DEFINED KS_TEST_FILTER)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE KS_TEST_FILTER="${KS_TEST_FILTER}")
    message(STATUS "[KS] Test filter: '${KS_TEST_FILTER}'")
endif()
