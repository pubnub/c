# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

cmake_minimum_required(VERSION 3.20.0)

# Register the SDK as a Zephyr extra module BEFORE find_package(Zephyr)
# so that cmake/zephyr/Kconfig is loaded and CONFIG_PUBNUB_* symbols
# are available to the Kconfig system.
get_filename_component(PUBNUB_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
list(APPEND ZEPHYR_EXTRA_MODULES "${PUBNUB_SDK_DIR}")

# Override embedded profile log-stripping — enable full SDK logging for
# development/debugging. TRACE compiles in all levels; 256B message buffer
# enables the PUBNUB_LOG() variadic macro. Must precede find_package(Zephyr)
# because module loading triggers SDK configure_file() during that call.
set(PUBNUB_LOG_MIN_LEVEL "TRACE" CACHE STRING "" FORCE)
set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE "256" CACHE STRING "" FORCE)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(arena_echo_nrf7002)

# The SDK module CMakeLists was already loaded by ZEPHYR_EXTRA_MODULES;
# the include guard (if(TARGET pubnub) return()) makes this a no-op.
include("${PUBNUB_SDK_DIR}/cmake/zephyr/CMakeLists.txt")

target_sources(app PRIVATE src/main.c)
target_link_libraries(app PRIVATE pubnub)

# SDK examples use internal headers (logger init, serialization access).
target_include_directories(app PRIVATE "${PUBNUB_SDK_DIR}/src")

# NCS v3.3.x workaround: APP_SKIP_POSIX_TIMERS sets TC_PROVIDES_POSIX_TIMERS
# which skips clock.c (and clock_gettime) alongside the broken timer.c.
# Re-add clock.c here; it has no sigevent dependency and compiles cleanly.
if(CONFIG_APP_SKIP_POSIX_TIMERS)
    target_sources(app PRIVATE "$ENV{ZEPHYR_BASE}/lib/posix/options/clock.c")
endif()
