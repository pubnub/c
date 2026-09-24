# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Windows platform: QueryPerformanceCounter + Sleep + BCryptGenRandom +
# CRITICAL_SECTION backed provider for hosted profiles (Windows).

_pn_sdk_library(pubnub_provider_platform platform_windows.c)

target_link_libraries(pubnub_provider_platform PUBLIC pubnub_public_headers bcrypt)

set_target_properties(
    pubnub_provider_platform
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_platform)
pubnub_target_sanitizers(pubnub_provider_platform)
