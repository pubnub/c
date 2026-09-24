# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# ESP-IDF component registration for the PubNub C SDK.
#
# Callers may set PUBNUB_ENABLE_* variables before including this file to
# enable or disable features. Set values take precedence over the defaults
# defined below.
#
# Usage from a component wrapper:
#   set(PUBNUB_ENABLE_PRESENCE 1)   # optional: enable presence
#   include("${PUBNUB_SDK_DIR}/cmake/PubnubESP.cmake")

if(NOT DEFINED PUBNUB_SDK_DIR)
    get_filename_component(PUBNUB_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
endif()

# Defense-in-depth: reject shared builds and force PIC off for ESP-IDF.
# The root CMakeLists.txt has its own guards, but ESP-IDF's component
# path return()s at line 9 before those guards execute.
if(PUBNUB_BUILD_SHARED)
    message(
        FATAL_ERROR
        "[PubNub] PUBNUB_BUILD_SHARED is not supported for ESP-IDF targets. "
        "ESP-IDF builds produce flat firmware images; shared libraries are not applicable."
    )
endif()
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

# ---------------------------------------------------------------------------
# Feature flag defaults (caller may override before including this file)
# ---------------------------------------------------------------------------

# Always-on for ESP (change only for a minimal firmware with no PubNub messaging).
if(NOT DEFINED PUBNUB_ENABLE_PUBLISH)
    set(PUBNUB_ENABLE_PUBLISH 1)
endif()
if(NOT DEFINED PUBNUB_ENABLE_SUBSCRIBE)
    set(PUBNUB_ENABLE_SUBSCRIBE 1)
endif()

# Optional features — all default off; set to 1 before including this file.
foreach(
    _opt
    PRESENCE
    HISTORY
    SIGNAL
    TIME
    CHANNEL_GROUPS
    MESSAGE_ACTIONS
    APP_CONTEXT
    FILES
    PAM
    CRYPTO
    PUSH_NOTIFICATIONS
    RETRY
    COMPRESSION
    REQUEST_COMPRESSION
)
    if(NOT DEFINED PUBNUB_ENABLE_${_opt})
        set(PUBNUB_ENABLE_${_opt} 0)
    endif()
endforeach()

# Non-feature toggles with fixed defaults for ESP.
if(NOT DEFINED PUBNUB_ENABLE_SECURE_TRANSPORT)
    set(PUBNUB_ENABLE_SECURE_TRANSPORT 1)
endif()
if(NOT DEFINED PUBNUB_ENABLE_PROXY)
    set(PUBNUB_ENABLE_PROXY 0)
endif()
if(NOT DEFINED PUBNUB_ENABLE_IPV6)
    set(PUBNUB_ENABLE_IPV6 0)
endif()
if(NOT DEFINED PUBNUB_ENABLE_FILESYSTEM)
    set(PUBNUB_ENABLE_FILESYSTEM 0)
endif()

# ---------------------------------------------------------------------------
# Core sources (always included)
# ---------------------------------------------------------------------------

include("${PUBNUB_SDK_DIR}/src/core/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/core/protocol_common/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/core/runtime/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/core/runtime/middleware/sources.cmake")

# ---------------------------------------------------------------------------
# Conditional middleware
# ---------------------------------------------------------------------------

if(PUBNUB_ENABLE_PAM)
    include("${PUBNUB_SDK_DIR}/src/core/runtime/middleware/signature_middleware/sources.cmake")
endif()
if(PUBNUB_ENABLE_RETRY)
    include("${PUBNUB_SDK_DIR}/src/core/runtime/middleware/retry_middleware_sources.cmake")
endif()
if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    include("${PUBNUB_SDK_DIR}/src/core/runtime/middleware/compression_middleware/sources.cmake")
endif()

# ---------------------------------------------------------------------------
# Feature sources (conditional on flags)
# ---------------------------------------------------------------------------

if(PUBNUB_ENABLE_PUBLISH)
    include("${PUBNUB_SDK_DIR}/src/features/publish/sources.cmake")
endif()
if(PUBNUB_ENABLE_SUBSCRIBE)
    include("${PUBNUB_SDK_DIR}/src/features/subscribe/sources.cmake")
endif()
if(PUBNUB_ENABLE_PRESENCE)
    include("${PUBNUB_SDK_DIR}/src/features/presence/sources.cmake")
endif()
if(PUBNUB_ENABLE_HISTORY)
    include("${PUBNUB_SDK_DIR}/src/features/history/sources.cmake")
endif()
if(PUBNUB_ENABLE_SIGNAL)
    include("${PUBNUB_SDK_DIR}/src/features/signal/sources.cmake")
endif()
if(PUBNUB_ENABLE_TIME)
    include("${PUBNUB_SDK_DIR}/src/features/time/sources.cmake")
endif()
if(PUBNUB_ENABLE_CHANNEL_GROUPS)
    include("${PUBNUB_SDK_DIR}/src/features/channel_groups/sources.cmake")
endif()
if(PUBNUB_ENABLE_MESSAGE_ACTIONS)
    include("${PUBNUB_SDK_DIR}/src/features/message_actions/sources.cmake")
endif()
if(PUBNUB_ENABLE_APP_CONTEXT)
    include("${PUBNUB_SDK_DIR}/src/features/app_context/sources.cmake")
endif()
if(PUBNUB_ENABLE_FILES)
    include("${PUBNUB_SDK_DIR}/src/features/files/sources.cmake")
endif()
if(PUBNUB_ENABLE_PAM)
    include("${PUBNUB_SDK_DIR}/src/features/access/sources.cmake")
endif()
if(PUBNUB_ENABLE_CRYPTO)
    include("${PUBNUB_SDK_DIR}/src/features/crypto/sources.cmake")
    include("${PUBNUB_SDK_DIR}/src/providers/crypto/mbedtls/sources.cmake")
endif()
if(PUBNUB_ENABLE_PUSH_NOTIFICATIONS)
    include("${PUBNUB_SDK_DIR}/src/features/push/sources.cmake")
endif()

# ---------------------------------------------------------------------------
# Provider sources (fixed for ESP-IDF)
# ---------------------------------------------------------------------------

include("${PUBNUB_SDK_DIR}/src/providers/allocator/arena/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/serialization/jsmn/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/dns/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/proxy/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/platform/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/tls/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/transport/socket/tls/certs/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/platform/freertos/sources.cmake")
include("${PUBNUB_SDK_DIR}/src/providers/logger/stdout/sources.cmake")

# ---------------------------------------------------------------------------
# Response decompression (gated by PUBNUB_ENABLE_COMPRESSION).
# Uses the tinfl subset of miniz — ESP-IDF's esp_rom ships miniz.h which
# exposes all tinfl symbols, but the header path differs from upstream
# (miniz_tinfl.h). We download the single upstream header to avoid coupling
# to esp_rom internal layout.
# ---------------------------------------------------------------------------

if(PUBNUB_ENABLE_COMPRESSION)
    set(_pn_miniz_dir "${CMAKE_CURRENT_BINARY_DIR}/miniz")
    if(NOT EXISTS "${_pn_miniz_dir}/miniz_tinfl.h")
        file(
            DOWNLOAD "https://raw.githubusercontent.com/richgel999/miniz/3.1.2/miniz_tinfl.h"
            "${_pn_miniz_dir}/miniz_tinfl.h"
            EXPECTED_HASH SHA256=da4850920fdf09f8877d9affabe1ebba1852ce4b1ebbd121f2ba7a7ea8e57e5d
            TIMEOUT 30
            STATUS _dl_tinfl_status
        )
        list(GET _dl_tinfl_status 0 _dl_tinfl_rc)
        if(NOT _dl_tinfl_rc EQUAL 0)
            message(
                FATAL_ERROR
                "[PubNub] Failed to download miniz_tinfl.h (${_dl_tinfl_status}).\n"
                "For air-gapped builds, place miniz 3.1.2 headers manually at:\n"
                "  ${_pn_miniz_dir}/miniz_tinfl.h\n"
                "  ${_pn_miniz_dir}/miniz_common.h"
            )
        endif()
    endif()
    if(NOT EXISTS "${_pn_miniz_dir}/miniz_common.h")
        file(
            DOWNLOAD "https://raw.githubusercontent.com/richgel999/miniz/3.1.2/miniz_common.h"
            "${_pn_miniz_dir}/miniz_common.h"
            EXPECTED_HASH SHA256=f1ba29821c8caef83585b328196aa346c5da7c82890a70a3d10d77c6cec0ed39
            TIMEOUT 30
            STATUS _dl_common_status
        )
        list(GET _dl_common_status 0 _dl_common_rc)
        if(NOT _dl_common_rc EQUAL 0)
            message(
                FATAL_ERROR
                "[PubNub] Failed to download miniz_common.h (${_dl_common_status}).\n"
                "For air-gapped builds, place miniz 3.1.2 headers manually at:\n"
                "  ${_pn_miniz_dir}/miniz_common.h"
            )
        endif()
    endif()
    # miniz_common.h includes miniz_export.h which is a CMake-generated file
    # not present in the miniz source tree. Provide a minimal stub — all it
    # contains in a static build is empty visibility macro definitions.
    if(NOT EXISTS "${_pn_miniz_dir}/miniz_export.h")
        file(
            WRITE "${_pn_miniz_dir}/miniz_export.h"
            "/* Stub generated by PubnubESP.cmake for static builds. */\n"
            "#ifndef MINIZ_EXPORT_H\n"
            "#define MINIZ_EXPORT_H\n"
            "#define MINIZ_EXPORT\n"
            "#define MINIZ_NO_EXPORT\n"
            "#define MINIZ_DEPRECATED\n"
            "#define MINIZ_DEPRECATED_EXPORT\n"
            "#define MINIZ_DEPRECATED_NO_EXPORT\n"
            "#endif /* MINIZ_EXPORT_H */\n"
        )
    endif()
    set(PN_ESP_INFLATE_SOURCES
        "${PUBNUB_SDK_DIR}/src/providers/transport/socket/inflate/pn_inflate.c"
    )
endif()

# ---------------------------------------------------------------------------
# Collect all sources
# ---------------------------------------------------------------------------

set(PN_ESP_SOURCES
    ${PN_CORE_BASE_SOURCES}
    ${PN_CORE_PROTOCOL_COMMON_SOURCES}
    ${PN_CORE_RUNTIME_SOURCES}
    ${PN_CORE_MIDDLEWARE_BASE_SOURCES}
    ${PN_MIDDLEWARE_SIGNATURE_SOURCES}
    ${PN_MIDDLEWARE_RETRY_SOURCES}
    ${PN_MIDDLEWARE_COMPRESSION_SOURCES}
    ${PN_FEATURE_PUBLISH_SOURCES}
    ${PN_FEATURE_SUBSCRIBE_SOURCES}
    ${PN_FEATURE_PRESENCE_SOURCES}
    ${PN_FEATURE_HISTORY_SOURCES}
    ${PN_FEATURE_SIGNAL_SOURCES}
    ${PN_FEATURE_TIME_SOURCES}
    ${PN_FEATURE_CHANNEL_GROUPS_SOURCES}
    ${PN_FEATURE_MESSAGE_ACTIONS_SOURCES}
    ${PN_FEATURE_APP_CONTEXT_SOURCES}
    ${PN_FEATURE_FILES_SOURCES}
    ${PN_FEATURE_ACCESS_SOURCES}
    ${PN_FEATURE_CRYPTO_SOURCES}
    ${PN_PROVIDER_CRYPTO_MBEDTLS_SOURCES}
    ${PN_FEATURE_PUSH_SOURCES}
    ${PN_ESP_INFLATE_SOURCES}
    ${PN_PROVIDER_ALLOCATOR_ARENA_SOURCES}
    ${PN_PROVIDER_SERIAL_JSMN_SOURCES}
    ${PN_TRANSPORT_SOCKET_BASE_SOURCES}
    ${PN_TRANSPORT_SOCKET_DNS_SOURCES}
    ${PN_TRANSPORT_SOCKET_PROXY_SOURCES}
    ${PN_TRANSPORT_SOCKET_PLATFORM_FREERTOS_SOURCES}
    ${PN_TRANSPORT_TLS_MBEDTLS_SOURCES}
    ${PN_TLS_CERT_LOADER_SOURCE}
    ${PN_PROVIDER_PLATFORM_FREERTOS_SOURCES}
    ${PN_PROVIDER_LOGGER_STDOUT_SOURCES}
)

# ---------------------------------------------------------------------------
# Register as ESP-IDF component
# ---------------------------------------------------------------------------

# mbedtls is needed when TLS transport or mbedtls crypto provider is used.
# esp_tls pulls in the certificate bundle (esp_crt_bundle_attach) used by
# certs_esp.c and is only needed when secure transport is enabled.
set(PN_ESP_REQUIRES freertos lwip)
if(PUBNUB_ENABLE_SECURE_TRANSPORT OR PUBNUB_ENABLE_CRYPTO)
    list(APPEND PN_ESP_REQUIRES mbedtls)
endif()

# gersemi: ignore
idf_component_register(
    SRCS
    ${PN_ESP_SOURCES}
    INCLUDE_DIRS
    "${PUBNUB_SDK_DIR}/include"
    "${PUBNUB_SDK_DIR}/src"
    REQUIRES
    ${PN_ESP_REQUIRES}
)

# ---------------------------------------------------------------------------
# Generate config.h via configure_file (same mechanism as host build)
# ---------------------------------------------------------------------------

# Version info
set(pubnub_VERSION_MAJOR 0)
set(pubnub_VERSION_MINOR 1)
set(pubnub_VERSION_PATCH 0)
set(pubnub_VERSION "0.1.0")
set(PUBNUB_SDK_PLATFORM "FreeRTOS")

# Footprint toggles
if(NOT DEFINED PUBNUB_CFG_NO_HEAP)
    set(PUBNUB_CFG_NO_HEAP 1)
endif()
if(NOT DEFINED PUBNUB_CFG_THREAD_SAFETY)
    set(PUBNUB_CFG_THREAD_SAFETY 0)
endif()
if(NOT DEFINED PUBNUB_CFG_RES_STR)
    set(PUBNUB_CFG_RES_STR 0)
endif()
if(NOT DEFINED PUBNUB_CFG_MINIMAL_FORMATTER)
    set(PUBNUB_CFG_MINIMAL_FORMATTER 1)
endif()
if(NOT DEFINED PUBNUB_CFG_JSON_HELPERS)
    set(PUBNUB_CFG_JSON_HELPERS 0)
endif()
if(NOT DEFINED PUBNUB_CFG_JSON_DOUBLE)
    set(PUBNUB_CFG_JSON_DOUBLE 0)
endif()
if(NOT DEFINED PUBNUB_ENABLE_CUSTOM_DNS)
    set(PUBNUB_ENABLE_CUSTOM_DNS 0)
endif()
# ESP-IDF always provides lwIP DNS (CONFIG_LWIP_DNS=y by default).
# If a custom ESP configuration disables lwIP DNS, override above to 1.

# Resource limits
if(NOT DEFINED PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS)
    set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS 2)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_PENDING_REQUESTS)
    set(PUBNUB_CFG_MAX_PENDING_REQUESTS 1)
endif()
if(NOT DEFINED PUBNUB_CFG_REQUEST_BUFFER_SIZE)
    set(PUBNUB_CFG_REQUEST_BUFFER_SIZE 1024)
endif()
if(NOT DEFINED PUBNUB_CFG_RESPONSE_BUFFER_SIZE)
    set(PUBNUB_CFG_RESPONSE_BUFFER_SIZE 4096)
endif()
if(NOT DEFINED PUBNUB_CFG_OBJECT_BUFFER_SIZE)
    set(PUBNUB_CFG_OBJECT_BUFFER_SIZE 2048)
endif()
# Growth caps disabled (0): the arena allocator's NULL buf_grow already
# prevents any buffer growth on this no-heap profile, so no SDK-level cap
# is needed. These MUST be set or config.h.in substitutes an empty macro,
# which breaks the `0 != PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE` guards.
if(NOT DEFINED PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE)
    set(PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE 0)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE)
    set(PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE 0)
endif()
if(NOT DEFINED PUBNUB_CFG_SCRATCH_BUFFER_SIZE)
    set(PUBNUB_CFG_SCRATCH_BUFFER_SIZE 1024)
endif()
if(NOT DEFINED PUBNUB_CFG_URL_BUFFER_SIZE)
    set(PUBNUB_CFG_URL_BUFFER_SIZE 512)
endif()

# HTTP limits
if(NOT DEFINED PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS)
    set(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS 10)
endif()
if(NOT DEFINED PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS)
    set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS 10)
endif()
if(NOT DEFINED PUBNUB_CFG_HTTP_MAX_HEADERS)
    set(PUBNUB_CFG_HTTP_MAX_HEADERS 6)
endif()
if(NOT DEFINED PUBNUB_CFG_HTTP_MAX_RESP_HEADERS)
    set(PUBNUB_CFG_HTTP_MAX_RESP_HEADERS 6)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_HEADER_BYTES)
    set(PUBNUB_CFG_MAX_HEADER_BYTES 4096)
endif()
if(NOT DEFINED PUBNUB_CFG_HTTP_SCRATCH_SIZE)
    set(PUBNUB_CFG_HTTP_SCRATCH_SIZE 256)
endif()
# Auto-compute minimum pipeline middleware slots from enabled features
# (mirrors the main build logic in CMakeLists.txt).
set(PN_ESP_MIDDLEWARE_MINIMUM 3) # base: pnsdk + userid + auth
if(PUBNUB_ENABLE_PAM)
    math(EXPR PN_ESP_MIDDLEWARE_MINIMUM "${PN_ESP_MIDDLEWARE_MINIMUM} + 1")
endif()
if(PUBNUB_ENABLE_RETRY)
    math(EXPR PN_ESP_MIDDLEWARE_MINIMUM "${PN_ESP_MIDDLEWARE_MINIMUM} + 1")
endif()
if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    math(EXPR PN_ESP_MIDDLEWARE_MINIMUM "${PN_ESP_MIDDLEWARE_MINIMUM} + 1")
endif()

if(NOT DEFINED PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES)
    set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES ${PN_ESP_MIDDLEWARE_MINIMUM})
elseif(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES LESS PN_ESP_MIDDLEWARE_MINIMUM)
    message(
        FATAL_ERROR
        "[PubNub] PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES=${PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES}"
        " is less than the minimum required (${PN_ESP_MIDDLEWARE_MINIMUM}) for enabled"
        " middlewares. Increase the value or disable features (PAM/RETRY)."
    )
endif()
if(NOT DEFINED PUBNUB_CFG_PUBLISH_META_BUF_SIZE)
    set(PUBNUB_CFG_PUBLISH_META_BUF_SIZE 256)
endif()

# Timeouts
if(NOT DEFINED PUBNUB_CFG_TRANSACTION_TIMEOUT_MS)
    set(PUBNUB_CFG_TRANSACTION_TIMEOUT_MS 10000)
endif()
if(NOT DEFINED PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS)
    set(PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS 310000)
endif()

# Subscribe limits
if(NOT DEFINED PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS)
    set(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS 8)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS)
    set(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS 4)
endif()
if(NOT DEFINED PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE)
    set(PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE 8)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_POLL_MS)
    set(PUBNUB_CFG_MAX_POLL_MS 100)
endif()

# Socket transport. ESP-IDF always uses the socket transport, so the
# socket/DNS tunables below are live; config.h.in gates them behind
# PUBNUB_TRANSPORT_SOCKET.
set(PUBNUB_TRANSPORT_SOCKET 1)
if(NOT DEFINED PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE)
    set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE 512)
endif()
if(NOT DEFINED PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS)
    set(PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS 8000)
endif()
if(NOT DEFINED PUBNUB_CFG_TLS_SESSION_CACHE_SIZE OR PUBNUB_CFG_TLS_SESSION_CACHE_SIZE STREQUAL "")
    set(PUBNUB_CFG_TLS_SESSION_CACHE_SIZE 2)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_DNS_RESULTS)
    set(PUBNUB_CFG_MAX_DNS_RESULTS 4)
endif()
if(NOT DEFINED PUBNUB_CFG_DNS_CACHE_SIZE)
    set(PUBNUB_CFG_DNS_CACHE_SIZE 2)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_DNS_SERVERS)
    set(PUBNUB_CFG_MAX_DNS_SERVERS 4)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_HOSTNAME_LEN)
    set(PUBNUB_CFG_MAX_HOSTNAME_LEN 64)
endif()
if(PUBNUB_ENABLE_FILES AND PUBNUB_CFG_MAX_HOSTNAME_LEN LESS 128)
    set(PUBNUB_CFG_MAX_HOSTNAME_LEN 128)
    message(
        STATUS
        "[PubNub] PUBNUB_CFG_MAX_HOSTNAME_LEN raised to 128"
        " (Files feature requires longer S3 bucket hostnames)"
    )
endif()
if(NOT DEFINED PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE)
    set(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE 256)
endif()
if(NOT DEFINED PUBNUB_CFG_DNS_MAX_TTL_SEC)
    set(PUBNUB_CFG_DNS_MAX_TTL_SEC 600)
endif()
if(NOT DEFINED PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE)
    set(PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE 8192)
endif()
if(NOT DEFINED PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS)
    set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS 10000)
endif()
if(NOT DEFINED PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS)
    set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS 100)
endif()
if(NOT DEFINED PUBNUB_CFG_SOCKET_MAX_REDIRECTS)
    # Files download follows a 307 to object storage; other features never
    # redirect, so the ~1KB redirect frame is only paid when Files is on.
    if(PUBNUB_ENABLE_FILES)
        set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS 1)
    else()
        set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS 0)
    endif()
endif()

# Retry (disabled by default but values required by config.h validation guards)
if(NOT DEFINED PUBNUB_CFG_RETRY_DELAY_MS)
    set(PUBNUB_CFG_RETRY_DELAY_MS 2000)
endif()
if(NOT DEFINED PUBNUB_CFG_RETRY_MAX_DELAY_MS)
    set(PUBNUB_CFG_RETRY_MAX_DELAY_MS 150000)
endif()
if(NOT DEFINED PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS)
    set(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS 30000)
endif()
if(NOT DEFINED PUBNUB_CFG_LINEAR_MAX_RETRIES)
    set(PUBNUB_CFG_LINEAR_MAX_RETRIES 10)
endif()
if(NOT DEFINED PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES)
    set(PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES 6)
endif()

# Files (disabled by default but values required)
if(NOT DEFINED PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS)
    set(PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS 300000)
endif()
if(NOT DEFINED PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE)
    set(PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE 5242880)
endif()

# Crypto (disabled by default but values required)
if(NOT DEFINED PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS)
    set(PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS 2)
endif()

# Logger
if(NOT DEFINED PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE)
    set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE 256)
endif()

# Translate PUBNUB_LOG_MIN_LEVEL string → PUBNUB_CFG_LOG_LEVEL_COMPILED bitmask.
# Mirrors the same translation in the root CMakeLists.txt so callers can use
# the human-readable name (TRACE, DEBUG, INFO, WARNING, ERROR, NONE) instead
# of the raw hex value.  Set PUBNUB_LOG_MIN_LEVEL before including this file.
if(DEFINED PUBNUB_LOG_MIN_LEVEL AND NOT PUBNUB_LOG_MIN_LEVEL STREQUAL "")
    set(_pn_level_map_TRACE "0x1F")
    set(_pn_level_map_DEBUG "0x1E")
    set(_pn_level_map_INFO "0x1C")
    set(_pn_level_map_WARNING "0x18")
    set(_pn_level_map_ERROR "0x10")
    set(_pn_level_map_NONE "0x00")
    if(DEFINED _pn_level_map_${PUBNUB_LOG_MIN_LEVEL})
        set(PUBNUB_CFG_LOG_LEVEL_COMPILED "${_pn_level_map_${PUBNUB_LOG_MIN_LEVEL}}")
    else()
        message(
            FATAL_ERROR
            "[PubNub] Unknown PUBNUB_LOG_MIN_LEVEL='${PUBNUB_LOG_MIN_LEVEL}'. "
            "Valid values: TRACE DEBUG INFO WARNING ERROR NONE"
        )
    endif()
endif()

if(NOT DEFINED PUBNUB_CFG_LOG_LEVEL_COMPILED)
    set(PUBNUB_CFG_LOG_LEVEL_COMPILED 0x1F)
endif()
if(NOT DEFINED PUBNUB_CFG_MAX_LOGGERS)
    set(PUBNUB_CFG_MAX_LOGGERS 2)
endif()

# JSON
if(NOT DEFINED PUBNUB_CFG_JSON_MAX_NESTING_DEPTH)
    set(PUBNUB_CFG_JSON_MAX_NESTING_DEPTH 8)
endif()

# Upper bound for struct pubnub_context. Validated at compile time by a
# static assertion in client.c — increase if the assertion fires.
if(NOT DEFINED PUBNUB_CONTEXT_SIZE)
    set(PUBNUB_CONTEXT_SIZE 1280)
endif()

# Origin
if(NOT DEFINED PUBNUB_CFG_ORIGIN)
    set(PUBNUB_CFG_ORIGIN "ps.pndsn.com")
endif()

# ---------------------------------------------------------------------------
# Arena allocator sizing (computed from buffer/feature/concurrency settings).
# Must come after all variables it reads (buffer sizes, DNS_CACHE_SIZE, etc.).
# ---------------------------------------------------------------------------

include("${CMAKE_CURRENT_LIST_DIR}/arena.cmake")
pubnub_compute_arena_sizes()

# ESP-IDF is a constrained target: enforce the tight embedded stack/resource
# ceilings via config_internal.h (internal-only). The derivation is shared with
# the host build (single source of truth in cmake/helpers.cmake); this flow does
# not include helpers.cmake elsewhere, so pull it in here before calling.
# Must run before the config_internal.h.in configure_file call below.
include("${CMAKE_CURRENT_LIST_DIR}/helpers.cmake")
_pn_derive_profile_embedded(PN_PROFILE_EMBEDDED)

configure_file(
    "${PUBNUB_SDK_DIR}/include/pubnub/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/pubnub/config.h"
    @ONLY
)

# Provider builtin selection flags for config_internal.h.
# Derived the same way as the root CMakeLists: providers that are
# neither "custom" nor "none" are compiled-in and auto-registered.
# On ESP-IDF all providers are compiled-in (sources are included above),
# so all flags are 1 except CRYPTO which depends on PUBNUB_ENABLE_CRYPTO.
set(PN_USE_BUILTIN_ALLOCATOR 1)
set(PN_USE_BUILTIN_TRANSPORT 1)
set(PN_USE_BUILTIN_SERIALIZATION 1)
if(PUBNUB_ENABLE_CRYPTO)
    set(PN_USE_BUILTIN_CRYPTO 1)
else()
    set(PN_USE_BUILTIN_CRYPTO 0)
endif()
# The stdout logger sources are always included; auto-register it so
# pubnub_set_log_level() is effective without a manual pubnub_add_logger()
# call. Callers who want no logging can set PUBNUB_PROVIDER_LOGGER=none
# before including this file (consistent with root CMakeLists behaviour).
if(PUBNUB_PROVIDER_LOGGER STREQUAL "custom" OR PUBNUB_PROVIDER_LOGGER STREQUAL "none")
    set(PN_USE_BUILTIN_LOGGER 0)
else()
    set(PN_USE_BUILTIN_LOGGER 1)
endif()
set(PN_USE_BUILTIN_PLATFORM 1)

configure_file(
    "${PUBNUB_SDK_DIR}/src/core/config_internal.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/src/core/config_internal.h"
    @ONLY
)

# ---------------------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------------------

# Generated headers must be found before any source-tree templates.
target_include_directories(${COMPONENT_LIB} PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/include")

# Internal SDK headers not under include/pubnub/ — each subdirectory that
# uses bare #include "foo_internal.h" needs its own directory on the path.
# jsmn is a single-header library fetched by the host build via FetchContent.
# Download just jsmn.h into the build directory so the ESP-IDF build has it
# without requiring a git clone during cross-compilation.
if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/jsmn/jsmn.h")
    file(
        DOWNLOAD "https://raw.githubusercontent.com/zserge/jsmn/v1.1.0/jsmn.h"
        "${CMAKE_CURRENT_BINARY_DIR}/jsmn/jsmn.h"
        EXPECTED_HASH SHA256=1ed6154dedf009212a08a397e9c4ed50a0ce31d5a8301bb294e137ae3188c13b
        TIMEOUT 30
        STATUS _dl_jsmn_status
    )
    list(GET _dl_jsmn_status 0 _dl_jsmn_rc)
    if(NOT _dl_jsmn_rc EQUAL 0)
        message(
            FATAL_ERROR
            "[PubNub] Failed to download jsmn.h (${_dl_jsmn_status}).\n"
            "For air-gapped builds, place jsmn v1.1.0 header manually at:\n"
            "  ${CMAKE_CURRENT_BINARY_DIR}/jsmn/jsmn.h"
        )
    endif()
endif()

target_include_directories(
    ${COMPONENT_LIB}
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/src/core"
        "${CMAKE_CURRENT_BINARY_DIR}/jsmn"
        "${PUBNUB_SDK_DIR}/src/core"
        "${PUBNUB_SDK_DIR}/src/core/runtime"
        "${PUBNUB_SDK_DIR}/src/providers"
        "${PUBNUB_SDK_DIR}/src/features/publish"
        "${PUBNUB_SDK_DIR}/src/features/subscribe"
        "${PUBNUB_SDK_DIR}/src/providers/transport/socket"
        "${PUBNUB_SDK_DIR}/src/providers/transport/socket/tls"
)

# Conditionally add include paths for enabled features.
if(PUBNUB_ENABLE_PRESENCE)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${PUBNUB_SDK_DIR}/src/features/presence")
endif()
if(PUBNUB_ENABLE_HISTORY)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${PUBNUB_SDK_DIR}/src/features/history")
endif()
if(PUBNUB_ENABLE_CHANNEL_GROUPS)
    target_include_directories(
        ${COMPONENT_LIB}
        PRIVATE "${PUBNUB_SDK_DIR}/src/features/channel_groups"
    )
endif()
if(PUBNUB_ENABLE_MESSAGE_ACTIONS)
    target_include_directories(
        ${COMPONENT_LIB}
        PRIVATE "${PUBNUB_SDK_DIR}/src/features/message_actions"
    )
endif()
if(PUBNUB_ENABLE_APP_CONTEXT)
    target_include_directories(
        ${COMPONENT_LIB}
        PRIVATE "${PUBNUB_SDK_DIR}/src/features/app_context"
    )
endif()
if(PUBNUB_ENABLE_FILES)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${PUBNUB_SDK_DIR}/src/features/files")
endif()
if(PUBNUB_ENABLE_PAM)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${PUBNUB_SDK_DIR}/src/features/access")
endif()
if(PUBNUB_ENABLE_CRYPTO)
    target_include_directories(
        ${COMPONENT_LIB}
        PRIVATE
            "${PUBNUB_SDK_DIR}/src/features/crypto"
            "${PUBNUB_SDK_DIR}/src/providers/crypto/mbedtls"
    )
endif()
if(PUBNUB_ENABLE_PUSH_NOTIFICATIONS)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${PUBNUB_SDK_DIR}/src/features/push")
endif()

# ---------------------------------------------------------------------------
# Source path prefix stripping — makes __FILE__ relative to repo root.
# Mirrors cmake/compiler.cmake; xtensa-GCC and ESP-IDF Clang both support
# -fmacro-prefix-map (same flag as upstream GCC/Clang).
# ---------------------------------------------------------------------------

target_compile_options(${COMPONENT_LIB} PRIVATE -fmacro-prefix-map=${PUBNUB_SDK_DIR}/=)

# ---------------------------------------------------------------------------
# Compile definitions for platform/backend selection
# ---------------------------------------------------------------------------

target_compile_definitions(
    ${COMPONENT_LIB}
    PRIVATE
        PUBNUB_PLATFORM_FREERTOS=1
        PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS=1
        PN_FREERTOS_HAS_ISR_DETECT=0
        $<$<BOOL:${PUBNUB_ENABLE_COMPRESSION}>:PUBNUB_COMPRESSION_BACKEND_TINFL>
        $<$<BOOL:${PN_DEBUG_SOCKET_OPS}>:PN_DEBUG_SOCKET_OPS>
)

if(PUBNUB_ENABLE_COMPRESSION)
    target_include_directories(
        ${COMPONENT_LIB}
        PRIVATE
            "${PUBNUB_SDK_DIR}/src/providers/transport/socket/inflate"
            "${CMAKE_CURRENT_BINARY_DIR}/miniz"
    )
endif()
