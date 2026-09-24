# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Zephyr module entry point.
#
# Loaded by Zephyr's module system during `west build`. Configures
# the SDK for Zephyr targets (socket transport, mbedTLS, arena
# allocator, jsmn serializer) and delegates to the main SDK build.
#
# The standalone CMake path (cmake -DCMAKE_SYSTEM_NAME=zephyr ...)
# uses the root CMakeLists.txt directly with equivalent -D flags.

if(TARGET pubnub)
    return()
endif()

# Defense-in-depth: reject shared builds and force PIC off for Zephyr.
# The root CMakeLists.txt has its own guards, but Zephyr's module path
# may diverge before those guards execute.
if(PUBNUB_BUILD_SHARED)
    message(
        FATAL_ERROR
        "[PubNub] PUBNUB_BUILD_SHARED is not supported for Zephyr targets. "
        "Zephyr builds produce flat firmware images; shared libraries are not applicable."
    )
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

# Tell the SDK warning function to skip strict flags — Zephyr kernel headers
# use GNU extensions that conflict with -Wpedantic, -Wsign-conversion, etc.
set(PUBNUB_ZEPHYR_BUILD ON CACHE BOOL "" FORCE)

get_filename_component(PN_SDK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

# Map SDK source path to a short prefix so __FILE__ expansions used in
# Zephyr section-name macros (K_THREAD_STACK_ARRAY_DEFINE, __in_section_unique)
# do not contain spaces or special characters that break the assembler.
add_compile_options("-fmacro-prefix-map=${PN_SDK_ROOT}/=pubnub-sdk/")

# Prepend shim module path so find_package(MbedTLS) resolves through
# Zephyr's zephyr_interface without triggering FetchContent.
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# ---------------------------------------------------------------------------
# Provider selection (Zephyr-appropriate)
# ---------------------------------------------------------------------------

set(PUBNUB_PROFILE "embedded" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_PLATFORM "zephyr" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_TRANSPORT "socket" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_ALLOCATOR "arena" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_SERIALIZATION "jsmn" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_CRYPTO "none" CACHE STRING "" FORCE)
set(PUBNUB_PROVIDER_LOGGER "stdout" CACHE STRING "" FORCE)
set(PUBNUB_SDK_PLATFORM "Zephyr" CACHE STRING "" FORCE)

# Use the bundled PEM file for TLS CA certificates instead of embedding
# a large string literal in certs_zephyr.c (exceeds ISO C99 4095-char limit).
# The file contains Starfield Root CA G2, Starfield Services Root CA G2,
# Amazon Root CA 1, and Amazon Root CA 3 — covering all PubNub/AWS endpoints.
if(NOT PUBNUB_TLS_CA_CERT_FILE)
    set(PUBNUB_TLS_CA_CERT_FILE
        "${PN_SDK_ROOT}/src/providers/transport/socket/tls/certs/pubnub_roots.pem"
        CACHE FILEPATH
        ""
        FORCE
    )
endif()

# ---------------------------------------------------------------------------
# Map Kconfig symbols to SDK feature toggles.
# Zephyr imports CONFIG_* as CMake variables (bool y -> TRUE, n -> undef).
# ---------------------------------------------------------------------------

if(CONFIG_PUBNUB_ENABLE_SUBSCRIBE)
    set(PUBNUB_ENABLE_SUBSCRIBE ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_SUBSCRIBE OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_PRESENCE)
    set(PUBNUB_ENABLE_PRESENCE ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_PRESENCE OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_CHANNEL_GROUPS)
    set(PUBNUB_ENABLE_CHANNEL_GROUPS ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_CHANNEL_GROUPS OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_CRYPTO)
    set(PUBNUB_ENABLE_CRYPTO ON CACHE BOOL "" FORCE)
    set(PUBNUB_PROVIDER_CRYPTO "mbedtls" CACHE STRING "" FORCE)
else()
    set(PUBNUB_ENABLE_CRYPTO OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_PUBLISH)
    set(PUBNUB_ENABLE_PUBLISH ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_PUBLISH OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_SIGNAL)
    set(PUBNUB_ENABLE_SIGNAL ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_SIGNAL OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_HISTORY)
    set(PUBNUB_ENABLE_HISTORY ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_HISTORY OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_MESSAGE_ACTIONS)
    set(PUBNUB_ENABLE_MESSAGE_ACTIONS ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_MESSAGE_ACTIONS OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_OBJECTS)
    set(PUBNUB_ENABLE_OBJECTS ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_OBJECTS OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_FILES)
    set(PUBNUB_ENABLE_FILES ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_FILES OFF CACHE BOOL "" FORCE)
endif()

if(CONFIG_PUBNUB_ENABLE_SECURE_TRANSPORT)
    set(PUBNUB_ENABLE_SECURE_TRANSPORT ON CACHE BOOL "" FORCE)
    set(PUBNUB_SOCKET_TLS_BACKEND "mbedtls" CACHE STRING "" FORCE)
else()
    set(PUBNUB_ENABLE_SECURE_TRANSPORT OFF CACHE BOOL "" FORCE)
endif()

if(DEFINED CONFIG_PUBNUB_CFG_ARENA_POOL_SIZE)
    set(PUBNUB_CFG_ARENA_POOL_SIZE "${CONFIG_PUBNUB_CFG_ARENA_POOL_SIZE}" CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Disable features/options that do not apply to Zephyr targets.
# ---------------------------------------------------------------------------

set(PUBNUB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(PUBNUB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

# Map Kconfig PUBNUB_ENABLE_CUSTOM_DNS → CMake variable.
# When the Kconfig symbol is set (CONFIG_PUBNUB_ENABLE_CUSTOM_DNS=y in
# prj.conf), enable the built-in UDP resolver; otherwise default OFF.
if(CONFIG_PUBNUB_ENABLE_CUSTOM_DNS)
    set(PUBNUB_ENABLE_CUSTOM_DNS ON CACHE BOOL "" FORCE)
else()
    set(PUBNUB_ENABLE_CUSTOM_DNS OFF CACHE BOOL "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Suppress SDK warning flags that conflict with Zephyr kernel headers.
# Zephyr kernel headers use GNU extensions (named variadic macros,
# #include_next, sign-conversion in inline functions) that are intentional
# GCC extensions but fail under ISO C strict mode.
# ---------------------------------------------------------------------------

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-pedantic -Wno-variadic-macros -Wno-sign-conversion -Wno-conversion)
endif()

# ---------------------------------------------------------------------------
# Include the SDK root build (nested project is valid CMake).
# ---------------------------------------------------------------------------

add_subdirectory("${PN_SDK_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/pubnub-sdk")

# ---------------------------------------------------------------------------
# Link ALL SDK static/object library targets against zephyr_interface so they
# receive Zephyr's board-specific compile flags (-mcpu=cortex-m33, -mthumb,
# etc.) and system include paths. Without this, objects are compiled for the
# wrong ARM architecture variant and fail to link into the Zephyr image.
# ---------------------------------------------------------------------------

if(TARGET zephyr_interface)
    # Recursively walk every source subdirectory of the SDK and apply
    # zephyr_interface to every static/object library target found there.
    function(_pn_apply_zephyr_interface_recursive src_dir)
        get_property(_subdirs DIRECTORY "${src_dir}" PROPERTY SUBDIRECTORIES)
        foreach(_sub IN LISTS _subdirs)
            _pn_apply_zephyr_interface_recursive("${_sub}")
        endforeach()
        get_property(_targets DIRECTORY "${src_dir}" PROPERTY BUILDSYSTEM_TARGETS)
        foreach(_tgt IN LISTS _targets)
            if(NOT TARGET "${_tgt}")
                continue()
            endif()
            get_property(_type TARGET "${_tgt}" PROPERTY TYPE)
            if(_type STREQUAL "STATIC_LIBRARY" OR _type STREQUAL "OBJECT_LIBRARY")
                target_link_libraries("${_tgt}" PRIVATE zephyr_interface)
            endif()
        endforeach()
    endfunction()
    _pn_apply_zephyr_interface_recursive("${PN_SDK_ROOT}")
endif()
