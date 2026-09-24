# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# posix platform: clock_gettime + nanosleep + getentropy/urandom + pthreads
# backed provider for hosted profiles (Linux, macOS, BSDs).

include(sources.cmake)

find_package(Threads REQUIRED)

_pn_sdk_library(pubnub_provider_platform)
target_sources(pubnub_provider_platform PRIVATE ${PN_PROVIDER_PLATFORM_POSIX_SOURCES})

target_compile_definitions(pubnub_provider_platform PRIVATE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

target_link_libraries(pubnub_provider_platform PUBLIC pubnub_public_headers Threads::Threads)

set_target_properties(
    pubnub_provider_platform
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_platform)
pubnub_target_sanitizers(pubnub_provider_platform)
