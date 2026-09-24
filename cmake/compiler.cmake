# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Compiler configuration: C standard selection, warning flags, sanitizers.

# ---------------------------------------------------------------------------
# C standard
# ---------------------------------------------------------------------------
option(PUBNUB_CFG_C99_COMPAT "Build in C99 compatibility mode instead of C11" OFF)

if(PUBNUB_CFG_C99_COMPAT)
    set(PUBNUB_C_STANDARD 99)
    message(STATUS "[PubNub] C standard: C99 (compatibility mode)")
else()
    set(PUBNUB_C_STANDARD 11)
    message(STATUS "[PubNub] C standard: C11")
endif()

# ---------------------------------------------------------------------------
# Source path prefix stripping — makes __FILE__ relative to repo root.
# Supported by GCC and Clang; no-op on MSVC (already relative there).
# ---------------------------------------------------------------------------
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=)
endif()

# ---------------------------------------------------------------------------
# Release hardening flags (hosted GCC/Clang only)
#
# Applied at directory scope alongside -fmacro-prefix-map above, so every SDK
# target picks them up. Skipped for Zephyr and the embedded profile: bare-metal
# and RTOS toolchains (IAR, ARMCC, newlib) do not ship _FORTIFY_SOURCE wrappers,
# RELRO is meaningless without a dynamic loader, and default stack canaries add
# code the smallest targets cannot always afford. MSVC has its own hardening
# switches and is intentionally excluded here.
# ---------------------------------------------------------------------------
if(
    CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang"
    AND NOT PUBNUB_ZEPHYR_BUILD
    AND NOT PUBNUB_PROFILE STREQUAL "embedded"
)
    # Stack canaries and -fno-strict-overflow are gated on known hosted OS
    # targets. A cross GCC/Clang build targeting bare-metal or RTOS
    # (CMAKE_SYSTEM_NAME=Generic) may not have a libc that ships the canary
    # runtime symbols (__stack_chk_guard / __stack_chk_fail), so we must not
    # apply -fstack-protector-strong unconditionally even when the profile is
    # not explicitly "embedded".
    if(CMAKE_SYSTEM_NAME MATCHES "Linux|Darwin|.*BSD")
        add_compile_options(-fstack-protector-strong -fno-strict-overflow)
    endif()

    # _FORTIFY_SOURCE=2 wraps libc calls with bounds checks but is a no-op (and
    # warns) below -O1, so restrict it to optimized configurations. -U guards
    # against a redefinition warning when the toolchain predefines it. Linux
    # only — the glibc/kernel wrappers are what implement the checks.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_compile_options(
            $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:-U_FORTIFY_SOURCE>
            $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:-D_FORTIFY_SOURCE=2>
        )
    endif()

    # Full RELRO plus immediate binding hardens the GOT against overwrite; only
    # meaningful for shared objects loaded by a dynamic linker on Linux.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_SHARED_LIBS)
        add_link_options(-Wl,-z,relro,-z,now)
    endif()
endif()

# ---------------------------------------------------------------------------
# Warning policy
# ---------------------------------------------------------------------------
function(pubnub_target_warnings target)
    # Zephyr kernel headers use GNU extensions that fail under -Wpedantic,
    # -Wsign-conversion, etc. Skip strict SDK warnings for Zephyr builds
    # so Zephyr's own compiler configuration applies instead.
    if(PUBNUB_ZEPHYR_BUILD)
        return()
    endif()

    if(MSVC)
        target_compile_options(
            ${target}
            PRIVATE
                /W4
                /WX
                /wd4127 # constant conditional (runtime-constant feature guards)
                /wd4200 # zero-sized array in struct (flexible member)
        )
    else()
        target_compile_options(
            ${target}
            PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Werror
                -Wconversion
                -Wsign-conversion
                -Wshadow
                -Wstrict-prototypes
                -Wmissing-prototypes
                -Wdouble-promotion
                -Wformat=2
                -Wnull-dereference
        )
        # C99 compat: only warn about C11-only features (e.g. _Static_assert,
        # _Generic) when explicitly building in C99-compat mode. In default
        # C11 builds, _Static_assert is a normal feature and SDK code uses it
        # via PUBNUB_STATIC_ASSERT — flagging it would block the build.
        if(PUBNUB_CFG_C99_COMPAT)
            include(CheckCCompilerFlag)
            check_c_compiler_flag(-Wc99-c11-compat _PN_HAS_WC99_C11_COMPAT)
            check_c_compiler_flag(-Wpre-c11-compat _PN_HAS_WPRE_C11_COMPAT)
            if(_PN_HAS_WC99_C11_COMPAT)
                target_compile_options(${target} PRIVATE -Wc99-c11-compat)
            elseif(_PN_HAS_WPRE_C11_COMPAT)
                target_compile_options(${target} PRIVATE -Wpre-c11-compat)
            endif()
        endif()
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Symbol visibility
# ---------------------------------------------------------------------------
function(pubnub_target_visibility target)
    set_target_properties(
        ${target}
        PROPERTIES C_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON
    )
endfunction()

# ---------------------------------------------------------------------------
# Sanitizers (development builds)
# ---------------------------------------------------------------------------
option(PUBNUB_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(PUBNUB_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(PUBNUB_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(PUBNUB_FORCE_ASAN "Force ASan even on platforms with known runtime bugs" OFF)

# ---------------------------------------------------------------------------
# ASan deadlock workaround (macOS 26 / Darwin 25+ with Apple Clang < 21)
#
# AddressSanitizer deadlocks during process initialization on macOS 26 due to
# a recursive malloc re-entry: libSystem_initializer -> ASan init -> shadow
# memory setup -> dyld_shared_cache_iterate_text_swift -> _Block_copy -> malloc
# -> ASan init (already holding StaticSpinMutex) -> infinite spin.
#
# Apple resolved this in Apple Clang 21 (Xcode 26.4+) by adding an internal
# bypass (_dyld_get_dyld_header()) that avoids dyld_shared_cache_iterate_text_swift
# during the allocator handshake.
# ---------------------------------------------------------------------------
if(PUBNUB_ENABLE_ASAN AND APPLE AND NOT PUBNUB_FORCE_ASAN)
    string(REGEX MATCH "^([0-9]+)" _PN_DARWIN_MAJOR "${CMAKE_SYSTEM_VERSION}")
    if(
        _PN_DARWIN_MAJOR
        AND _PN_DARWIN_MAJOR GREATER_EQUAL 25
        AND CMAKE_C_COMPILER_VERSION VERSION_LESS "21.0"
    )
        message(
            WARNING
            "[PubNub] ASan disabled: AddressSanitizer deadlocks during "
            "initialization on macOS 26+ (Darwin ${CMAKE_SYSTEM_VERSION}) "
            "with Apple Clang ${CMAKE_C_COMPILER_VERSION}. "
            "Upgrade to Xcode 26.4+ (Apple Clang 21+) or set "
            "PUBNUB_FORCE_ASAN=ON to override."
        )
        set(PUBNUB_ENABLE_ASAN OFF)
    endif()
endif()

function(pubnub_target_sanitizers target)
    if(MSVC)
        return()
    endif()

    set(_san_flags "")
    if(PUBNUB_ENABLE_ASAN)
        list(APPEND _san_flags -fsanitize=address -fno-omit-frame-pointer)
    endif()
    if(PUBNUB_ENABLE_UBSAN)
        list(APPEND _san_flags -fsanitize=undefined)
    endif()
    if(PUBNUB_ENABLE_TSAN)
        list(APPEND _san_flags -fsanitize=thread)
    endif()

    if(_san_flags)
        target_compile_options(${target} PRIVATE ${_san_flags})
        target_link_options(${target} PRIVATE ${_san_flags})
    endif()
endfunction()
