# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Zephyr RTOS platform provider: k_uptime_get + k_sleep + k_sem locks.
# Requires Zephyr kernel headers (provided by the Zephyr build system).
# Do NOT use find_package for Zephyr headers - the Zephyr CMake
# integration provides them via the zephyr_interface target.

# Required Kconfig (Zephyr < 3.4): CONFIG_THREAD_JOIN=y
# NCS v2.4+ (Zephyr 3.4+) enables this by default.

include(sources.cmake)

_pn_sdk_library(pubnub_provider_platform)
target_sources(pubnub_provider_platform PRIVATE ${PN_PROVIDER_PLATFORM_ZEPHYR_SOURCES})

target_link_libraries(pubnub_provider_platform PUBLIC pubnub_public_headers)

if(TARGET zephyr_interface)
    target_link_libraries(pubnub_provider_platform PRIVATE zephyr_interface)
endif()

set_target_properties(
    pubnub_provider_platform
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_platform)
pubnub_target_sanitizers(pubnub_provider_platform)
