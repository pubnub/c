# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# FreeRTOS platform provider: xTaskGetTickCount + vTaskDelay + semaphores.
# Requires FreeRTOS headers in the include path. These are typically provided
# by the BSP/SDK (e.g., ESP-IDF component system, STM32CubeMX, Amazon
# FreeRTOS kernel port). Do NOT use find_package for FreeRTOS headers.

include(sources.cmake)

_pn_sdk_library(pubnub_provider_platform)
target_sources(pubnub_provider_platform PRIVATE ${PN_PROVIDER_PLATFORM_FREERTOS_SOURCES})

target_link_libraries(pubnub_provider_platform PUBLIC pubnub_public_headers)

set_target_properties(
    pubnub_provider_platform
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_platform)
pubnub_target_sanitizers(pubnub_provider_platform)
