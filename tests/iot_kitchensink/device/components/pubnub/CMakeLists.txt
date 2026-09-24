# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# ESP-IDF component wrapper for the PubNub C SDK.
# Reads CONFIG_PUBNUB_KS_ENABLE_* Kconfig variables and maps them to
# PUBNUB_ENABLE_* flags before including PubnubESP.cmake.

get_filename_component(PUBNUB_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)

# ---------------------------------------------------------------------------
# PAM safety gate -- secret key must never be in device firmware.
# ---------------------------------------------------------------------------

if(CONFIG_PUBNUB_KS_ENABLE_PAM)
    message(
        FATAL_ERROR
        "[PubNub] PAM (Access Manager) requires a secret key which must NEVER "
        "be embedded in device firmware. Disable CONFIG_PUBNUB_KS_ENABLE_PAM "
        "in menuconfig. Use a server-side token grant flow instead."
    )
endif()

# ---------------------------------------------------------------------------
# Always-ON features (infrastructure and trivial-cost)
# ---------------------------------------------------------------------------

set(PUBNUB_ENABLE_PUBLISH 1)
set(PUBNUB_ENABLE_SUBSCRIBE 1)
set(PUBNUB_ENABLE_TIME 1)
set(PUBNUB_ENABLE_RETRY 1)
set(PUBNUB_ENABLE_SECURE_TRANSPORT 1)
set(PUBNUB_ENABLE_FILESYSTEM 1)

# ---------------------------------------------------------------------------
# Kconfig-selectable features
# ---------------------------------------------------------------------------

if(CONFIG_PUBNUB_KS_ENABLE_SIGNAL)
    set(PUBNUB_ENABLE_SIGNAL 1)
else()
    set(PUBNUB_ENABLE_SIGNAL 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_CHANNEL_GROUPS)
    set(PUBNUB_ENABLE_CHANNEL_GROUPS 1)
else()
    set(PUBNUB_ENABLE_CHANNEL_GROUPS 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_PRESENCE)
    set(PUBNUB_ENABLE_PRESENCE 1)
else()
    set(PUBNUB_ENABLE_PRESENCE 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_HISTORY)
    set(PUBNUB_ENABLE_HISTORY 1)
else()
    set(PUBNUB_ENABLE_HISTORY 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_MESSAGE_ACTIONS)
    set(PUBNUB_ENABLE_MESSAGE_ACTIONS 1)
else()
    set(PUBNUB_ENABLE_MESSAGE_ACTIONS 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_APP_CONTEXT)
    set(PUBNUB_ENABLE_APP_CONTEXT 1)
else()
    set(PUBNUB_ENABLE_APP_CONTEXT 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_CRYPTO)
    set(PUBNUB_ENABLE_CRYPTO 1)
else()
    set(PUBNUB_ENABLE_CRYPTO 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_FILES)
    set(PUBNUB_ENABLE_FILES 1)
    # Redundant but explicit: files needs filesystem support.
    set(PUBNUB_ENABLE_FILESYSTEM 1)
else()
    set(PUBNUB_ENABLE_FILES 0)
endif()

if(CONFIG_PUBNUB_KS_ENABLE_COMPRESSION)
    set(PUBNUB_ENABLE_COMPRESSION 1)
else()
    set(PUBNUB_ENABLE_COMPRESSION 0)
endif()

# ---------------------------------------------------------------------------
# Always-OFF features
# ---------------------------------------------------------------------------

set(PUBNUB_ENABLE_PAM 0)
set(PUBNUB_ENABLE_PUSH_NOTIFICATIONS 0)
set(PUBNUB_ENABLE_PROXY 0)
set(PUBNUB_ENABLE_REQUEST_COMPRESSION 0)
set(PUBNUB_ENABLE_IPV6 0)

# ---------------------------------------------------------------------------
# Resource limit overrides for kitchensink workload
# ---------------------------------------------------------------------------

# 5 slots cover the worst-case concurrent footprint:
#   1 subscribe long-poll
#   1 presence heartbeat
#   up to 3 presence-leave requests (one per channel group being unsubscribed)
# A simultaneous user REST call goes to the 2-slot pending queue and is
# dispatched the moment a leave slot frees — no "queue full" error.
# Reducing from 6 to 5 shrinks Zone A by 7,168 bytes, keeping the main
# pool BSS and heap footprints in balance with the increased Zone B budget.
set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS 5)

# 2 pending slots absorb bursts during subscribe state transitions where a
# new request arrives before a presence-leave slot frees.
set(PUBNUB_CFG_MAX_PENDING_REQUESTS 2)

# Human-readable error strings for UART diagnostics
set(PUBNUB_CFG_RES_STR 1)

# History uses many query params (start, end, count, reverse, etc.)
set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS 13)

# Files/S3 redirect URLs contain long hostnames
set(PUBNUB_CFG_MAX_HOSTNAME_LEN 128)

# App Context response bodies are ~200-400 bytes; 2048 provides comfortable
# headroom while reducing arena size by ~16 KB vs 4096 per context.
set(PUBNUB_CFG_OBJECT_BUFFER_SIZE 2048)

# App Context URL builder needs >= 512 bytes of HTTP scratch.
# Control channel publishes carry large JSON payloads (~250 chars raw,
# ~400 chars URL-encoded) that also need scratch space during request
# building — 1024 gives sufficient headroom for both use cases.
set(PUBNUB_CFG_HTTP_SCRATCH_SIZE 1024)

# The socket header buffer holds the full HTTP request line
# (GET /publish/{keys}/0/{channel}/0/{payload} HTTP/1.1).
# Control channel companion requests encode ~220-char JSON payloads
# that expand to ~380 chars URL-encoded, pushing the request line to
# ~540 chars — exceeding the 512-byte default and causing immediate
# Transport failure. 1024 provides comfortable headroom.
set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE 1024)

# ---------------------------------------------------------------------------
# Arena allocator budget override
# ---------------------------------------------------------------------------

# The auto-computed Zone B budget (28,672 bytes with compression OFF) covers
# core SDK structures (TLS sessions, request pool, middleware, serialization
# peak) but does NOT account for runtime allocations that accumulate during
# the 73-test suite:
#   - Entity/subscription objects per subscribed channel
#   - Listener handles
#   - Channel name string duplication in subscribe manager
#   - DNS cache entries (2 × 200 bytes)
#   - Free-list fragmentation (256-byte cells, mixed allocation sizes)
#
# The previous build (compression ON) auto-computed 48,128 bytes which
# included 19 KB for the transient decompression workspace. That workspace
# was allocated/freed per-inflate, so its budget served as headroom for
# the runtime objects above. With compression OFF, that headroom vanishes.
#
# Restore the budget to the previous working level (48 KB). The 20 KB
# over the auto-computed minimum absorbs runtime objects and free-list
# fragmentation across the full test suite.
set(PUBNUB_CFG_ARENA_ALLOC_BUDGET 56832)

# ---------------------------------------------------------------------------
# Log level
# ---------------------------------------------------------------------------

# Compile in WARNING and above by default. Change to DEBUG or TRACE before
# running the kitchensink to see HTTP-level or full state-machine traces.
# Values: TRACE DEBUG INFO WARNING ERROR NONE
if(NOT DEFINED PUBNUB_LOG_MIN_LEVEL)
    set(PUBNUB_LOG_MIN_LEVEL WARNING)
endif()

# ---------------------------------------------------------------------------
# Include the SDK's ESP-IDF integration
# ---------------------------------------------------------------------------

include("${PUBNUB_SDK_DIR}/cmake/PubnubESP.cmake")
