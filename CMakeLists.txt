# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

cmake_minimum_required(VERSION 3.16)

# ESP-IDF component build: delegate to cmake/PubnubESP.cmake and stop.
if(ESP_PLATFORM)
    include(cmake/PubnubESP.cmake)
    return()
endif()

project(pubnub VERSION 1.0.0 LANGUAGES C)

# SDK root paths — stable across standalone and subproject (Zephyr, ESP-IDF) builds.
# All SDK-internal CMakeLists must use PN_SDK_SOURCE_ROOT / PN_SDK_BINARY_ROOT
# instead of CMAKE_SOURCE_DIR / CMAKE_BINARY_DIR, which shift meaning when the SDK
# is consumed as a subdirectory.
set(PN_SDK_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "")
set(PN_SDK_BINARY_ROOT "${CMAKE_CURRENT_BINARY_DIR}" CACHE INTERNAL "")

# ---------------------------------------------------------------------------
# CMake module path
# ---------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Include profiles FIRST to define snapshot function, then snapshot
# user -D overrides BEFORE any other include sets cache defaults.
# Any variable already in the cache at this point was explicitly passed
# via -D on the command line (or via CMakePresets.json cacheVariables).
# ---------------------------------------------------------------------------
include(profiles)
pubnub_snapshot_user_overrides()

# ---------------------------------------------------------------------------
# Include remaining build helpers (these set cache defaults for features
# and providers, which the profile can later override via FORCE).
# ---------------------------------------------------------------------------
include(compiler)
include(helpers)
include(features)
include(providers)

# Must precede PIC and platform guards below.
option(PUBNUB_BUILD_SHARED "Build pubnub as a shared library instead of static" OFF)

# Needed by consumers who link static libpubnub.a into their own .so
# (e.g. Unreal Engine on Linux). Defaults to PUBNUB_BUILD_SHARED.
option(PUBNUB_BUILD_PIC "Build with position-independent code (-fPIC)" ${PUBNUB_BUILD_SHARED})

# Embedded: no dynamic linker, -fPIC wastes 8-20% code size.
if(PUBNUB_PROFILE STREQUAL "embedded" OR PUBNUB_CFG_NO_HEAP)
    if(PUBNUB_BUILD_PIC)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_BUILD_PIC=ON is not supported for embedded profiles. "
            "Embedded targets have no dynamic linker; -fPIC wastes 8-20% code size "
            "and up to 10% RAM (GOT entries) for zero benefit."
        )
    endif()
    if(PUBNUB_BUILD_SHARED)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_BUILD_SHARED=ON is not supported for embedded profiles. "
            "Shared libraries require a dynamic linker, which embedded targets lack."
        )
    endif()
endif()

# Apple App Store prohibits third-party dynamic frameworks.
if(PUBNUB_BUILD_SHARED)
    set(_pn_apple_device_platforms iOS tvOS watchOS visionOS)
    if(CMAKE_SYSTEM_NAME IN_LIST _pn_apple_device_platforms)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_BUILD_SHARED=ON is not supported on ${CMAKE_SYSTEM_NAME}. "
            "Apple App Store policy prohibits third-party dynamic frameworks."
        )
    endif()
    unset(_pn_apple_device_platforms)
endif()

if(PUBNUB_BUILD_SHARED AND NOT PUBNUB_BUILD_PIC)
    message(
        FATAL_ERROR
        "[PubNub] PUBNUB_BUILD_SHARED=ON requires PUBNUB_BUILD_PIC=ON. "
        "Shared libraries need position-independent code."
    )
endif()

# Bare-metal cross-compile — warn but do not block.
if(CMAKE_SYSTEM_NAME STREQUAL "Generic" AND PUBNUB_BUILD_SHARED)
    message(
        WARNING
        "[PubNub] PUBNUB_BUILD_SHARED=ON with CMAKE_SYSTEM_NAME=Generic "
        "(bare-metal cross-compile). Shared libraries are unlikely to work."
    )
endif()

# Set before FetchContent so vendored deps inherit -fPIC when needed.
set(CMAKE_POSITION_INDEPENDENT_CODE ${PUBNUB_BUILD_PIC})

# Set before add_subdirectory so all targets inherit visibility/RPATH.
if(PUBNUB_BUILD_SHARED)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
endif()

include(dependencies)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------
option(PUBNUB_BUILD_TESTS "Build test suite" OFF)
option(
    PUBNUB_BUILD_FUZZ_TESTS
    "Build libFuzzer fuzz harnesses (requires Clang + -fsanitize=fuzzer)"
    OFF
)
option(PUBNUB_BUILD_EXAMPLES "Build runnable example binaries" OFF)

# ---------------------------------------------------------------------------
# PUBNUB_CFG_* tunable cache variables — unconditional (always relevant).
# Both boolean footprint toggles and numeric tunables live here; the
# pn_<feature> wire toggles live in cmake/features.cmake.
# Profiles may override these; user -D flags take precedence over profiles.
# ---------------------------------------------------------------------------
option(PUBNUB_CFG_NO_HEAP "Disable heap allocation APIs (pubnub_create/pubnub_destroy)" OFF)
option(PUBNUB_CFG_THREAD_SAFETY "Enable per-context mutex for thread-safe same-context access" OFF)
option(PUBNUB_CFG_RES_STR "Compile in pubnub_res_str() label table" ON)
option(
    PUBNUB_CFG_JSON_DOUBLE
    "Compile in floating-point JSON value support (value_double / value_get_double)"
    ON
)
option(
    PUBNUB_CFG_JSON_HELPERS
    "Compile optional JSON helper layer (varargs builder, clone, debug stringify, macros)"
    ON
)
set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS
    "4"
    CACHE STRING
    "Max concurrent in-flight requests per context"
)
set(PUBNUB_CFG_MAX_PENDING_REQUESTS "8" CACHE STRING "Max queued pending requests per context")
set(PUBNUB_CFG_REQUEST_BUFFER_SIZE "4096" CACHE STRING "Request buffer size in bytes")
set(PUBNUB_CFG_RESPONSE_BUFFER_SIZE "32768" CACHE STRING "Response buffer size in bytes")
set(PUBNUB_CFG_OBJECT_BUFFER_SIZE
    "30000"
    CACHE STRING
    "POST/PATCH request body buffer size in bytes"
)
set(PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE
    "8388608"
    CACHE STRING
    "Max OBJ buffer growth in bytes (0=no SDK-level cap)"
)
set(PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
    "16777216"
    CACHE STRING
    "Max RX buffer growth in bytes (0=no SDK-level cap)"
)
set(PUBNUB_CFG_SCRATCH_BUFFER_SIZE
    "4096"
    CACHE STRING
    "Shared scratch buffer size for URL/JSON assembly in bytes"
)
set(PUBNUB_CFG_URL_BUFFER_SIZE "2048" CACHE STRING "URL encode scratch buffer size in bytes")
set(PUBNUB_CFG_MAX_POLL_MS
    "100"
    CACHE STRING
    "Maximum milliseconds to block in transport poll per iteration"
)
set(PUBNUB_CFG_TRANSACTION_TIMEOUT_MS
    "10000"
    CACHE STRING
    "Default transaction timeout for short-lived requests (ms)"
)

# PubNub service endpoint (compile-time default; no runtime override field
# yet -- dedicated servers / custom clusters will add one alongside the
# first enterprise deployment that needs it).
set(PUBNUB_CFG_ORIGIN "ps.pndsn.com" CACHE STRING "Default PubNub service host")

# Retry tunables (always defined so config.h substitution is valid;
# values are unused at runtime when PUBNUB_ENABLE_RETRY is OFF).
set(PUBNUB_CFG_RETRY_DELAY_MS "2000" CACHE STRING "Base retry delay (ms)")
set(PUBNUB_CFG_RETRY_MAX_DELAY_MS
    "150000"
    CACHE STRING
    "Max retry delay cap for exponential policy (ms)"
)
set(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS
    "30000"
    CACHE STRING
    "Upper bound on a server-provided Retry-After delay (ms)"
)
set(PUBNUB_CFG_LINEAR_MAX_RETRIES "10" CACHE STRING "Default max retries for linear policy")
set(PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES
    "6"
    CACHE STRING
    "Default max retries for exponential policy"
)
set(PUBNUB_CFG_FILE_PUBLISH_RETRY_LIMIT "5" CACHE STRING "Max publish retries after file upload")
set(PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS "300000" CACHE STRING "S3 file upload timeout (ms)")
set(PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE "0" CACHE STRING "Max download size in bytes (0=unlimited)")
set(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS "10" CACHE STRING "Max HTTP request path segments")
set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS "12" CACHE STRING "Max HTTP request query parameters")
set(PUBNUB_CFG_HTTP_MAX_HEADERS "8" CACHE STRING "Max HTTP request headers")
set(PUBNUB_CFG_HTTP_MAX_RESP_HEADERS "8" CACHE STRING "Max HTTP response headers")
set(PUBNUB_CFG_MAX_HEADER_BYTES
    "16384"
    CACHE STRING
    "Max total HTTP response header bytes before the parser rejects the response"
)
set(PUBNUB_CFG_HTTP_SCRATCH_SIZE "32768" CACHE STRING "HTTP request scratch buffer size in bytes")
set(PUBNUB_CFG_PUBLISH_META_BUF_SIZE
    "512"
    CACHE STRING
    "Stack buffer for serialized publish meta JSON (bytes); 4096 on hosted, 256 on embedded"
)
set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES
    "8"
    CACHE STRING
    "Max middleware layers the request pipeline can own"
)
# Always defined so config.h substitution is valid even when no profile is
# selected (dev preset). Profiles override this; user -D flags take precedence.
set(PUBNUB_CFG_JSON_MAX_NESTING_DEPTH
    "16"
    CACHE STRING
    "Max JSON object/array nesting depth accepted by the parser"
)
set(PUBNUB_CFG_MINIMAL_FORMATTER
    "0"
    CACHE STRING
    "Use minimal built-in formatter instead of libc snprintf (1=minimal, 0=libc)"
)
set(PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS
    "4"
    CACHE STRING
    "Max fallback cryptors in a crypto module"
)
set(PUBNUB_CFG_MAX_DNS_RESULTS
    "8"
    CACHE STRING
    "Maximum number of resolved addresses to store per DNS query"
)
set(PUBNUB_CFG_DNS_CACHE_SIZE "8" CACHE STRING "Number of hostname entries in the DNS result cache")
set(PUBNUB_CFG_MAX_DNS_SERVERS
    "8"
    CACHE STRING
    "Maximum number of user-configured DNS server addresses"
)
set(PUBNUB_CFG_MAX_HOSTNAME_LEN
    "256"
    CACHE STRING
    "Maximum hostname length (bytes) for connection and DNS buffers"
)
set(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE
    "512"
    CACHE STRING
    "Size (bytes) of platform-specific DNS resolver state"
)
set(PUBNUB_CFG_DNS_MAX_TTL_SEC
    "300"
    CACHE STRING
    "Maximum TTL cap for cached DNS entries (seconds). Clamps server-provided TTL."
)
set(PUBNUB_SDK_PLATFORM
    "${CMAKE_SYSTEM_NAME}"
    CACHE STRING
    "Platform identifier for pnsdk query param (e.g. Linux, Darwin, FreeRTOS)"
)

# ---------------------------------------------------------------------------
# Profile application (must come after cache defaults, before conditional vars)
# ---------------------------------------------------------------------------
pubnub_apply_profile()
pubnub_apply_feature_requirements()

# ---------------------------------------------------------------------------
# PUBNUB_CFG_* tunable cache variables — conditional on features/providers.
# These appear in cmake-gui / CLion only when their parent is enabled.
# Profile _pubnub_profile_set() creates these cache entries when a profile is
# active, so they exist even if the guard below would skip them.
# ---------------------------------------------------------------------------

# Subscribe-specific
if(PUBNUB_ENABLE_SUBSCRIBE)
    set(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS "64" CACHE STRING "Max subscribe channel list length")
    set(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS "8" CACHE STRING "Max subscribe listener registrations")
    set(PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE
        "100"
        CACHE STRING
        "Max messages parsed per subscribe response (server may return up to 100)"
    )
    set(PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS
        "310000"
        CACHE STRING
        "Non-transaction timeout for subscribe long-poll (ms)"
    )
endif()

# Arena allocator sizing (arena is primarily for embedded; these defaults match the
# embedded profile and are overridden by profiles via FORCE).
if(PUBNUB_PROVIDER_ALLOCATOR STREQUAL "arena")
    set(PUBNUB_CFG_ARENA_POOL_SIZE "20480" CACHE STRING "Arena allocator total pool size in bytes")
    set(PUBNUB_CFG_ARENA_ALLOC_BUDGET
        "4096"
        CACHE STRING
        "Arena allocator Zone B budget in bytes (POOL_SIZE - Zone_A)"
    )
endif()
set(PUBNUB_ARENA_POOL_OWNER
    "sdk"
    CACHE STRING
    "Arena pool ownership: sdk (static BSS in SDK) or user (caller provides pool)"
)
set_property(CACHE PUBNUB_ARENA_POOL_OWNER PROPERTY STRINGS "sdk" "user")

# Transport-identity signal for config.h generation. The socket/DNS tunables
# below are read only by the socket transport, so config.h.in gates their
# #defines behind PUBNUB_TRANSPORT_SOCKET to avoid emitting inert macros.
# Socket transport tunables (only visible when socket transport is selected)
if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "socket")
    set(PUBNUB_TRANSPORT_SOCKET 1)
    set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE
        "2048"
        CACHE STRING
        "Buffer for serializing outgoing HTTP request headers (bytes)"
    )
    set(PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS "10000" CACHE STRING "TCP connect() timeout (ms)")
    set(PUBNUB_CFG_TLS_SESSION_CACHE_SIZE
        "2"
        CACHE STRING
        "Number of TLS session cache entries per context (0 = disabled, max 64)"
    )
    set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS
        "50000"
        CACHE STRING
        "HTTP keep-alive max idle time before connection close (ms)"
    )
    set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS
        "1000"
        CACHE STRING
        "Max HTTP requests reusing a single keep-alive connection"
    )
    set(PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE
        "4194304"
        CACHE STRING
        "Max decompression output buffer (bytes); 0=unlimited (default 4 MB)"
    )
    set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS
        "3"
        CACHE STRING
        "Max HTTP redirect hops per request (0..8); 0 compiles the redirect path out"
    )
    if(PUBNUB_CFG_SOCKET_MAX_REDIRECTS LESS 0 OR PUBNUB_CFG_SOCKET_MAX_REDIRECTS GREATER 8)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_CFG_SOCKET_MAX_REDIRECTS must be 0..8 "
            "(got '${PUBNUB_CFG_SOCKET_MAX_REDIRECTS}')"
        )
    endif()
    option(PN_DEBUG_SOCKET_OPS "Enable verbose socket-level debug tracing" OFF)
else()
    set(PUBNUB_TRANSPORT_SOCKET 0)
endif()

# Logger tuning
set(PUBNUB_LOG_MIN_LEVEL
    ""
    CACHE STRING
    "Minimum compiled-in log level: TRACE DEBUG INFO WARNING ERROR NONE (empty = use PUBNUB_CFG_LOG_LEVEL_COMPILED directly)"
)
set_property(
    CACHE PUBNUB_LOG_MIN_LEVEL
    PROPERTY STRINGS "" TRACE DEBUG INFO WARNING ERROR NONE
)

# Translate PUBNUB_LOG_MIN_LEVEL string to bitmask, unless user set the raw
# PUBNUB_CFG_LOG_LEVEL_COMPILED directly (power-user override).
# Note: when a profile is active, it forces PUBNUB_LOG_MIN_LEVEL, and this
# block then FORCE-overwrites PUBNUB_CFG_LOG_LEVEL_COMPILED. To bypass
# translation and use the bitmask directly, pass -DPUBNUB_LOG_MIN_LEVEL=
# (empty string) alongside -DPUBNUB_CFG_LOG_LEVEL_COMPILED=<mask>.
if(NOT PUBNUB_LOG_MIN_LEVEL STREQUAL "")
    if(PUBNUB_LOG_MIN_LEVEL STREQUAL "TRACE")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x1F"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    elseif(PUBNUB_LOG_MIN_LEVEL STREQUAL "DEBUG")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x1E"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    elseif(PUBNUB_LOG_MIN_LEVEL STREQUAL "INFO")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x1C"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    elseif(PUBNUB_LOG_MIN_LEVEL STREQUAL "WARNING")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x18"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    elseif(PUBNUB_LOG_MIN_LEVEL STREQUAL "ERROR")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x10"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    elseif(PUBNUB_LOG_MIN_LEVEL STREQUAL "NONE")
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED
            "0x00"
            CACHE STRING
            "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
            FORCE
        )
    else()
        message(
            FATAL_ERROR
            "[PubNub] Unknown PUBNUB_LOG_MIN_LEVEL='${PUBNUB_LOG_MIN_LEVEL}'. "
            "Valid values: TRACE DEBUG INFO WARNING ERROR NONE"
        )
    endif()
endif()

# Deprecation: PUBNUB_CFG_LOG_NO_PRINTF → PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE=0
if(DEFINED CACHE{PUBNUB_CFG_LOG_NO_PRINTF})
    message(
        DEPRECATION
        "[PubNub] PUBNUB_CFG_LOG_NO_PRINTF is deprecated. "
        "Use -DPUBNUB_CFG_MAX_LOG_MESSAGE_SIZE=0 instead."
    )
    if(PUBNUB_CFG_LOG_NO_PRINTF)
        set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE "0" CACHE STRING "" FORCE)
    endif()
endif()

set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE
    "512"
    CACHE STRING
    "Stack buffer size for pubnub_log_text_formatted (bytes). 0 = exclude the function entirely."
)

set(PUBNUB_CFG_LOG_LEVEL_COMPILED
    "0x1F"
    CACHE STRING
    "Bitmask of compiled-in log levels (power-user override). Prefer PUBNUB_LOG_MIN_LEVEL."
)
set(PUBNUB_CFG_MAX_LOGGERS "4" CACHE STRING "Max child loggers in a mux logger instance")

# Custom provider directories (only visible when the family is set to "custom")
if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "custom")
    set(PUBNUB_PROVIDER_TRANSPORT_DIR "" CACHE PATH "Path to custom transport provider directory")
endif()
if(PUBNUB_PROVIDER_SERIALIZATION STREQUAL "custom")
    set(PUBNUB_PROVIDER_SERIALIZATION_DIR
        ""
        CACHE PATH
        "Path to custom serialization provider directory"
    )
endif()
if(PUBNUB_PROVIDER_CRYPTO STREQUAL "custom")
    set(PUBNUB_PROVIDER_CRYPTO_DIR "" CACHE PATH "Path to custom crypto provider directory")
endif()
if(PUBNUB_PROVIDER_LOGGER STREQUAL "custom")
    set(PUBNUB_PROVIDER_LOGGER_DIR "" CACHE PATH "Path to custom logger provider directory")
endif()
if(PUBNUB_PROVIDER_ALLOCATOR STREQUAL "custom")
    set(PUBNUB_PROVIDER_ALLOCATOR_DIR "" CACHE PATH "Path to custom allocator provider directory")
endif()
if(PUBNUB_PROVIDER_PLATFORM STREQUAL "custom")
    set(PUBNUB_PROVIDER_PLATFORM_DIR "" CACHE PATH "Path to custom platform provider directory")
endif()

# ---------------------------------------------------------------------------
# Feature dependency validation.
# ---------------------------------------------------------------------------
if(PUBNUB_ENABLE_PAM AND NOT PUBNUB_ENABLE_CRYPTO)
    message(
        FATAL_ERROR
        "[PubNub] PUBNUB_ENABLE_PAM requires PUBNUB_ENABLE_CRYPTO. "
        "PAM request signing depends on the crypto provider."
    )
endif()

# ---------------------------------------------------------------------------
# Auto-compute minimum pipeline middleware slots from enabled features.
# User -D override is respected if >= the computed floor.
# ---------------------------------------------------------------------------
set(PN_MIDDLEWARE_MINIMUM 3) # base: pnsdk + userid + auth
if(PUBNUB_ENABLE_PAM)
    math(EXPR PN_MIDDLEWARE_MINIMUM "${PN_MIDDLEWARE_MINIMUM} + 1")
endif()
if(PUBNUB_ENABLE_RETRY)
    math(EXPR PN_MIDDLEWARE_MINIMUM "${PN_MIDDLEWARE_MINIMUM} + 1")
endif()
if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    math(EXPR PN_MIDDLEWARE_MINIMUM "${PN_MIDDLEWARE_MINIMUM} + 1")
endif()

get_property(_user_set_mw GLOBAL PROPERTY _PN_USER_SET_PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES)
if(_user_set_mw)
    if(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES LESS PN_MIDDLEWARE_MINIMUM)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES=${PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES} "
            "is less than the minimum required (${PN_MIDDLEWARE_MINIMUM}) for enabled features. "
            "Either increase the value or disable features."
        )
    endif()
elseif(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES LESS PN_MIDDLEWARE_MINIMUM)
    set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES
        "${PN_MIDDLEWARE_MINIMUM}"
        CACHE STRING
        "Max middleware layers the request pipeline can own"
        FORCE
    )
    message(
        STATUS
        "[PubNub] Auto-adjusted PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES to ${PN_MIDDLEWARE_MINIMUM}"
        " (minimum for enabled features)"
    )
endif()

# ---------------------------------------------------------------------------
# Validate providers
# ---------------------------------------------------------------------------
pubnub_validate_providers()

# ---------------------------------------------------------------------------
# Print configuration summary
# ---------------------------------------------------------------------------
pubnub_print_feature_summary()
pubnub_print_provider_summary()

# ---------------------------------------------------------------------------
# Determine which provider families have compiled-in defaults.
# "custom" and "none" providers do NOT supply a pn_<family>_default().
# ---------------------------------------------------------------------------
foreach(
    _family
    ALLOCATOR
    TRANSPORT
    SERIALIZATION
    CRYPTO
    LOGGER
    PLATFORM
)
    if(PUBNUB_PROVIDER_${_family} STREQUAL "custom" OR PUBNUB_PROVIDER_${_family} STREQUAL "none")
        set(PN_USE_BUILTIN_${_family} 0)
    else()
        set(PN_USE_BUILTIN_${_family} 1)
    endif()
endforeach()

# ---------------------------------------------------------------------------
# Compile-time context size upper bound (for embedded pubnub_init callers)
# ---------------------------------------------------------------------------
# Upper bound for static context storage via pubnub_init().
# Measured by tools/context_size/pubnub_context_size_probe:
#   64-bit (arm64/x86_64): 1056 B  →  rounded to next 256-byte boundary: 1280 B
#   32-bit (Cortex-M):     ~636 B  →  fits within 1280 B
# PUBNUB_STATIC_ASSERT in src/core/client.c validates at compile time.
# Re-run the probe and update this value if the struct grows significantly.
set(PUBNUB_CONTEXT_SIZE 1536)
message(STATUS "[PubNub] PUBNUB_CONTEXT_SIZE: ${PUBNUB_CONTEXT_SIZE} bytes")

# ---------------------------------------------------------------------------
# Translate PUBNUB_ARENA_POOL_OWNER string -> integer for config.h.
# Always re-translate unconditionally so profile switches take effect
# without a cache wipe. FORCE ensures the cache value is updated each run.
# ---------------------------------------------------------------------------
if(PUBNUB_ARENA_POOL_OWNER STREQUAL "user")
    set(PUBNUB_CFG_ARENA_POOL_OWNER_SDK
        0
        CACHE STRING
        "1=SDK owns arena pool (BSS); 0=user provides pool"
        FORCE
    )
else()
    set(PUBNUB_CFG_ARENA_POOL_OWNER_SDK
        1
        CACHE STRING
        "1=SDK owns arena pool (BSS); 0=user provides pool"
        FORCE
    )
endif()
if(PUBNUB_CFG_ARENA_POOL_OWNER_SDK EQUAL 0 AND NOT PUBNUB_PROFILE STREQUAL "embedded")
    message(
        WARNING
        "[PubNub] PUBNUB_ARENA_POOL_OWNER=user on profile '${PUBNUB_PROFILE}': "
        "pn_allocator_default() returns NULL; cfg.allocator is mandatory."
    )
endif()

# Embedded-vs-hosted profile signal for config_internal.h (internal-only).
# Shared derivation (see cmake/helpers.cmake) — must run before the
# config_internal.h.in configure_file call below.
_pn_derive_profile_embedded(PN_PROFILE_EMBEDDED)

# ---------------------------------------------------------------------------
# Generate config.h from template (public)
# ---------------------------------------------------------------------------
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/pubnub/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/pubnub/config.h"
    @ONLY
)

# ---------------------------------------------------------------------------
# Generate config_internal.h from template (private, not installed)
# ---------------------------------------------------------------------------
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/core/config_internal.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/src/core/config_internal.h"
    @ONLY
)

# ---------------------------------------------------------------------------
# Top-level interface library for public headers
# ---------------------------------------------------------------------------
add_library(pubnub_public_headers INTERFACE)
target_include_directories(
    pubnub_public_headers
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_subdirectory(src/core)

# ---------------------------------------------------------------------------
# Provider backends
# ---------------------------------------------------------------------------
add_subdirectory(src/providers)

# ---------------------------------------------------------------------------
# Feature libraries
# ---------------------------------------------------------------------------
add_subdirectory(src/features)

# ---------------------------------------------------------------------------
# Aggregate SDK library
# ---------------------------------------------------------------------------
get_property(_pn_all_objs GLOBAL PROPERTY PN_ALL_OBJECT_TARGETS)

if(PUBNUB_BUILD_SHARED)
    add_library(pubnub SHARED)
    target_compile_definitions(pubnub INTERFACE PUBNUB_SHARED)
    set_target_properties(
        pubnub
        PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR}
    )
else()
    add_library(pubnub STATIC)
endif()

foreach(_pn_obj IN LISTS _pn_all_objs)
    target_link_libraries(pubnub PRIVATE ${_pn_obj})
    if(PUBNUB_BUILD_SHARED)
        target_compile_definitions(${_pn_obj} PRIVATE PUBNUB_SHARED_EXPORT)
    endif()
endforeach()
target_link_libraries(pubnub PUBLIC pubnub_public_headers)
pubnub_target_sanitizers(pubnub)

# Tests need pn_* symbols hidden by -fvisibility=hidden in shared builds.
if(PUBNUB_BUILD_SHARED AND (PUBNUB_BUILD_TESTS OR PUBNUB_BUILD_FUZZ_TESTS))
    add_library(pubnub_test_static STATIC)
    foreach(_pn_obj IN LISTS _pn_all_objs)
        target_link_libraries(pubnub_test_static PRIVATE ${_pn_obj})
    endforeach()
    target_link_libraries(pubnub_test_static PUBLIC pubnub_public_headers)
    pubnub_target_sanitizers(pubnub_test_static)
endif()

if(TARGET pubnub_test_static)
    set(PUBNUB_TEST_LINK_TARGET pubnub_test_static)
else()
    set(PUBNUB_TEST_LINK_TARGET pubnub)
endif()

# ---------------------------------------------------------------------------
# Install rules
# ---------------------------------------------------------------------------
install(TARGETS pubnub RUNTIME DESTINATION bin LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)

if(PUBNUB_BUILD_SHARED AND MSVC)
    install(FILES $<TARGET_PDB_FILE:pubnub> DESTINATION bin OPTIONAL)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(PUBNUB_BUILD_TESTS OR PUBNUB_BUILD_FUZZ_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(PUBNUB_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Developer tools (EXCLUDE_FROM_ALL — not built unless explicitly targeted)
# ---------------------------------------------------------------------------
add_subdirectory(tools/context_size)
