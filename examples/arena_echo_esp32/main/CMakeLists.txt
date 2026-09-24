# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

idf_component_register(
    SRCS "arena_echo_esp32.c"
    INCLUDE_DIRS "."
    REQUIRES pubnub nvs_flash esp_wifi esp_netif freertos lwip led_strip
)
