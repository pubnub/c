# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Feature toggle definitions and summary reporting.

# ---------------------------------------------------------------------------
# Feature options
# ---------------------------------------------------------------------------

# Core protocol (ON by default)
option(PUBNUB_ENABLE_PUBLISH "Enable Publish feature" ON)
option(PUBNUB_ENABLE_SUBSCRIBE "Enable Subscribe feature" ON)

# Security (ON by default — plaintext requires explicit opt-out at compile time)
option(PUBNUB_ENABLE_SECURE_TRANSPORT "Compile secure transport support into providers" ON)

# Infrastructure (ON by default for hosted; embedded profile overrides to OFF)
option(PUBNUB_ENABLE_RETRY "Enable automatic retry policy" ON)

# Optional API features (OFF by default — enable explicitly or use a named profile)
option(PUBNUB_ENABLE_PRESENCE "Enable Presence feature" OFF)
option(PUBNUB_ENABLE_HISTORY "Enable History feature" OFF)
option(PUBNUB_ENABLE_MESSAGE_ACTIONS "Enable Message Actions feature" OFF)
option(PUBNUB_ENABLE_SIGNAL "Enable Signal feature" OFF)
option(PUBNUB_ENABLE_PAM "Enable Access Manager (PAM)" OFF)
option(PUBNUB_ENABLE_APP_CONTEXT "Enable App Context" OFF)
option(PUBNUB_ENABLE_FILES "Enable File sharing feature" OFF)
option(PUBNUB_ENABLE_CHANNEL_GROUPS "Enable Channel Groups feature" OFF)
option(PUBNUB_ENABLE_CRYPTO "Enable Crypto feature" OFF)
option(PUBNUB_ENABLE_PUSH_NOTIFICATIONS "Enable Push Notifications feature" OFF)
option(PUBNUB_ENABLE_TIME "Enable Time feature" OFF)

# Platform capabilities (OFF by default — set explicitly or use a named profile)
option(PUBNUB_ENABLE_COMPRESSION "Enable response decompression (gzip/deflate Accept-Encoding)" OFF)
option(
    PUBNUB_ENABLE_CUSTOM_DNS
    "Enable built-in UDP DNS resolver for custom DNS server support (socket transport only)"
    OFF
)
option(
    PUBNUB_CFG_DNS_DISABLE_FALLBACKS
    "Disable hardcoded fallback DNS servers (8.8.8.8, 1.1.1.1) in the built-in UDP resolver. Only effective when PUBNUB_ENABLE_CUSTOM_DNS=ON and socket transport is selected."
    OFF
)
option(PUBNUB_ENABLE_FILESYSTEM "Enable platform filesystem support (file_load vtable method)" OFF)
option(PUBNUB_ENABLE_IPV6 "Enable IPv6 support in DNS resolution and socket transport" OFF)
option(PUBNUB_ENABLE_PROXY "Enable HTTP proxy support" OFF)
option(
    PUBNUB_ENABLE_REQUEST_COMPRESSION
    "Enable request body compression (gzip Content-Encoding)"
    OFF
)

# ---------------------------------------------------------------------------
# Feature-driven configuration adjustments
# ---------------------------------------------------------------------------
# Features that require more query param slots than the profile default must
# raise the limit here. Called after profile application (which sets the base).
function(pubnub_apply_feature_requirements)
    # fetch_messages: up to 8 feature params + 5 middleware = 13 needed.
    if(PUBNUB_ENABLE_HISTORY AND PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS LESS 13)
        set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS
            "13"
            CACHE STRING
            "Max HTTP request query parameters"
            FORCE
        )
        message(
            STATUS
            "[PubNub] Raised PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS to 13 (required by history feature)"
        )
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Print feature summary (call after profile application)
# ---------------------------------------------------------------------------
function(pubnub_print_feature_summary)
    set(_features "")
    foreach(
        _pair
        "publish:PUBNUB_ENABLE_PUBLISH"
        "subscribe:PUBNUB_ENABLE_SUBSCRIBE"
        "presence:PUBNUB_ENABLE_PRESENCE"
        "history:PUBNUB_ENABLE_HISTORY"
        "message_actions:PUBNUB_ENABLE_MESSAGE_ACTIONS"
        "signal:PUBNUB_ENABLE_SIGNAL"
        "access:PUBNUB_ENABLE_PAM"
        "app_context:PUBNUB_ENABLE_APP_CONTEXT"
        "files:PUBNUB_ENABLE_FILES"
        "filesystem:PUBNUB_ENABLE_FILESYSTEM"
        "channel_groups:PUBNUB_ENABLE_CHANNEL_GROUPS"
        "crypto:PUBNUB_ENABLE_CRYPTO"
        "push_notifications:PUBNUB_ENABLE_PUSH_NOTIFICATIONS"
        "time:PUBNUB_ENABLE_TIME"
        "retry:PUBNUB_ENABLE_RETRY"
        "secure_transport:PUBNUB_ENABLE_SECURE_TRANSPORT"
        "compression:PUBNUB_ENABLE_COMPRESSION"
        "custom_dns:PUBNUB_ENABLE_CUSTOM_DNS"
        "dns_disable_fallbacks:PUBNUB_CFG_DNS_DISABLE_FALLBACKS"
        "request_compression:PUBNUB_ENABLE_REQUEST_COMPRESSION"
        "proxy:PUBNUB_ENABLE_PROXY"
        "ipv6:PUBNUB_ENABLE_IPV6"
    )
        string(REPLACE ":" ";" _pair_list "${_pair}")
        list(GET _pair_list 0 _name)
        list(GET _pair_list 1 _option)
        if(${_option})
            list(APPEND _features "${_name}")
        endif()
    endforeach()

    message(STATUS "")
    message(STATUS "[PubNub] ===== Feature Summary =====")
    foreach(_feat IN LISTS _features)
        message(STATUS "[PubNub]   + ${_feat}")
    endforeach()
    message(STATUS "[PubNub] ==============================")
    message(STATUS "")
endfunction()
