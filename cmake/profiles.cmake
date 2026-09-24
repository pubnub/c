# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Named build profiles.
#
# Profiles set feature and provider defaults. Explicit user -D overrides
# take precedence: pubnub_snapshot_user_overrides() records which variables
# the user explicitly set on the command line BEFORE profile application.
# _pn_profile_set() skips FORCE for those variables.

set(PUBNUB_PROFILE "" CACHE STRING "Named build profile: full, minimal, embedded (optional)")

include(arena)

option(PUBNUB_CFG_ARENA_DEBUG "Enable verbose arena allocator debug output to stderr" OFF)
option(PUBNUB_CFG_ASSERT_POOL_CLEAN "Warn about unreleased futures at context teardown" OFF)

# ---------------------------------------------------------------------------
# Variables tracked for user-override detection.
# ---------------------------------------------------------------------------
set(_PN_PROFILE_TRACKED_VARS
    # Wire feature toggles
    PUBNUB_ENABLE_PUBLISH
    PUBNUB_ENABLE_SUBSCRIBE
    PUBNUB_ENABLE_PRESENCE
    PUBNUB_ENABLE_HISTORY
    PUBNUB_ENABLE_MESSAGE_ACTIONS
    PUBNUB_ENABLE_SIGNAL
    PUBNUB_ENABLE_PAM
    PUBNUB_ENABLE_APP_CONTEXT
    PUBNUB_ENABLE_FILES
    PUBNUB_ENABLE_FILESYSTEM
    PUBNUB_ENABLE_CHANNEL_GROUPS
    PUBNUB_ENABLE_CRYPTO
    PUBNUB_ENABLE_PUSH_NOTIFICATIONS
    PUBNUB_ENABLE_TIME
    PUBNUB_ENABLE_RETRY
    PUBNUB_ENABLE_SECURE_TRANSPORT
    PUBNUB_ENABLE_PROXY
    PUBNUB_ENABLE_COMPRESSION
    PUBNUB_ENABLE_REQUEST_COMPRESSION
    PUBNUB_ENABLE_IPV6
    # Provider selections
    PUBNUB_PROVIDER_TRANSPORT
    PUBNUB_PROVIDER_SERIALIZATION
    PUBNUB_PROVIDER_CRYPTO
    PUBNUB_PROVIDER_LOGGER
    PUBNUB_PROVIDER_ALLOCATOR
    PUBNUB_PROVIDER_PLATFORM
    # Numeric / structural tunables
    PUBNUB_CFG_NO_HEAP
    PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS
    PUBNUB_CFG_MAX_PENDING_REQUESTS
    PUBNUB_CFG_REQUEST_BUFFER_SIZE
    PUBNUB_CFG_RESPONSE_BUFFER_SIZE
    PUBNUB_CFG_OBJECT_BUFFER_SIZE
    PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE
    PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE
    PUBNUB_CFG_SCRATCH_BUFFER_SIZE
    PUBNUB_CFG_URL_BUFFER_SIZE
    PUBNUB_CFG_ORIGIN
    PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
    PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS
    PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE
    PUBNUB_CFG_MAX_POLL_MS
    PUBNUB_CFG_TRANSACTION_TIMEOUT_MS
    PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS
    PUBNUB_CFG_RETRY_DELAY_MS
    PUBNUB_CFG_RETRY_MAX_DELAY_MS
    PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS
    PUBNUB_CFG_LINEAR_MAX_RETRIES
    PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES
    PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS
    PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE
    PUBNUB_CFG_ARENA_POOL_SIZE
    PUBNUB_CFG_ARENA_ALLOC_BUDGET
    PUBNUB_ARENA_POOL_OWNER
    PUBNUB_LOG_MIN_LEVEL
    PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE
    PUBNUB_CFG_LOG_LEVEL_COMPILED
    PUBNUB_CFG_MAX_LOGGERS
    PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS
    PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS
    PUBNUB_CFG_HTTP_MAX_HEADERS
    PUBNUB_CFG_HTTP_MAX_RESP_HEADERS
    PUBNUB_CFG_MAX_HEADER_BYTES
    PUBNUB_CFG_HTTP_SCRATCH_SIZE
    PUBNUB_CFG_PUBLISH_META_BUF_SIZE
    PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES
    PUBNUB_CFG_MINIMAL_FORMATTER
    PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS
    # Compile-time footprint / quality toggles
    PUBNUB_CFG_THREAD_SAFETY
    PUBNUB_CFG_RES_STR
    PUBNUB_CFG_JSON_MAX_NESTING_DEPTH
    PUBNUB_CFG_JSON_HELPERS
    PUBNUB_CFG_JSON_DOUBLE
    # Socket transport tunables
    PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE
    PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS
    PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS
    PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS
    PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE
    # Maximum HTTP redirect hops (0 to disable and compile the path out).
    PUBNUB_CFG_SOCKET_MAX_REDIRECTS
    PUBNUB_CFG_MAX_DNS_RESULTS
    PUBNUB_CFG_DNS_CACHE_SIZE
    PUBNUB_CFG_MAX_DNS_SERVERS
    PUBNUB_CFG_MAX_HOSTNAME_LEN
    PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE
    PUBNUB_CFG_DNS_MAX_TTL_SEC
    PUBNUB_CFG_TLS_SESSION_CACHE_SIZE
    PUBNUB_ENABLE_CUSTOM_DNS
)

# ---------------------------------------------------------------------------
# Snapshot: record which variables the user explicitly set via -D.
# Must be called BEFORE pubnub_apply_profile().
# ---------------------------------------------------------------------------
function(pubnub_snapshot_user_overrides)
    foreach(_var IN LISTS _PN_PROFILE_TRACKED_VARS)
        if(DEFINED CACHE{${_var}})
            # Variable is in cache. Check if it was user-supplied on
            # this configure invocation by checking CMAKE_CACHE_ARGS or
            # the CMake 3.21+ CACHE property. For broad compatibility
            # we use the MODIFIED property where available and fall back
            # to checking if the cache TYPE differs from the default.
            #
            # Heuristic: if the variable was set on the command line
            # (-D<var>=<val>) it appears in the cache before includes run.
            # We mark it as user-set in a global property so profile
            # application can check.
            get_property(_is_set CACHE ${_var} PROPERTY VALUE SET)
            if(_is_set)
                set_property(GLOBAL PROPERTY _PN_USER_SET_${_var} TRUE)
            endif()
        endif()
    endforeach()
endfunction()

# ---------------------------------------------------------------------------
# Helper: set a cache variable as a profile default.
#
# Skips FORCE when the user explicitly provided the variable via -D.
# ---------------------------------------------------------------------------
macro(_pn_profile_set _var _value)
    get_property(_user_set GLOBAL PROPERTY _PN_USER_SET_${_var})
    if(_user_set)
        message(STATUS "[PubNub]   ${_var} = ${${_var}} (user override, profile skipped)")
    else()
        set(${_var} "${_value}" CACHE STRING "" FORCE)
    endif()
endmacro()

# ---------------------------------------------------------------------------
# Profile application
# ---------------------------------------------------------------------------
function(pubnub_apply_profile)
    if(PUBNUB_PROFILE STREQUAL "")
        message(STATUS "[PubNub] No profile selected; using individual option values.")
        return()
    endif()

    message(STATUS "[PubNub] Applying profile: ${PUBNUB_PROFILE}")

    if(PUBNUB_PROFILE STREQUAL "full")
        # All features ON, hosted providers.
        # Wire features
        _pn_profile_set(PUBNUB_ENABLE_PUBLISH ON)
        _pn_profile_set(PUBNUB_ENABLE_SUBSCRIBE ON)
        _pn_profile_set(PUBNUB_ENABLE_PRESENCE ON)
        _pn_profile_set(PUBNUB_ENABLE_HISTORY ON)
        _pn_profile_set(PUBNUB_ENABLE_MESSAGE_ACTIONS ON)
        _pn_profile_set(PUBNUB_ENABLE_SIGNAL ON)
        _pn_profile_set(PUBNUB_ENABLE_PAM ON)
        _pn_profile_set(PUBNUB_ENABLE_APP_CONTEXT ON)
        _pn_profile_set(PUBNUB_ENABLE_FILES ON)
        _pn_profile_set(PUBNUB_ENABLE_FILESYSTEM ON)
        _pn_profile_set(PUBNUB_ENABLE_CHANNEL_GROUPS ON)
        _pn_profile_set(PUBNUB_ENABLE_CRYPTO ON)
        _pn_profile_set(PUBNUB_ENABLE_PUSH_NOTIFICATIONS ON)
        _pn_profile_set(PUBNUB_ENABLE_TIME ON)
        _pn_profile_set(PUBNUB_ENABLE_RETRY ON)
        _pn_profile_set(PUBNUB_ENABLE_SECURE_TRANSPORT ON)
        _pn_profile_set(PUBNUB_ENABLE_COMPRESSION ON)
        _pn_profile_set(PUBNUB_ENABLE_IPV6 ON)
        _pn_profile_set(PUBNUB_ENABLE_PROXY ON)
        _pn_profile_set(PUBNUB_ENABLE_REQUEST_COMPRESSION ON)

        _pn_profile_set(PUBNUB_PROVIDER_TRANSPORT "curl")
        # cjson is incompatible with non-stdlib allocators and would
        # hard-fail in _pubnub_validate_provider_combinations().
        _pn_profile_set(PUBNUB_PROVIDER_SERIALIZATION "cjson")
        _pn_profile_set(PUBNUB_PROVIDER_CRYPTO "openssl")
        _pn_profile_set(PUBNUB_PROVIDER_LOGGER "stdout")
        _pn_profile_set(PUBNUB_PROVIDER_ALLOCATOR "stdlib")
        if(WIN32)
            _pn_profile_set(PUBNUB_PROVIDER_PLATFORM "windows")
        else()
            _pn_profile_set(PUBNUB_PROVIDER_PLATFORM "posix")
        endif()

        _pn_profile_set(PUBNUB_CFG_NO_HEAP "0")
        _pn_profile_set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS "16")
        _pn_profile_set(PUBNUB_CFG_MAX_PENDING_REQUESTS "32")
        _pn_profile_set(PUBNUB_CFG_REQUEST_BUFFER_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_RESPONSE_BUFFER_SIZE "32768")
        _pn_profile_set(PUBNUB_CFG_OBJECT_BUFFER_SIZE "33792")
        _pn_profile_set(PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE "8388608")
        _pn_profile_set(PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE "16777216")
        _pn_profile_set(PUBNUB_CFG_SCRATCH_BUFFER_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_URL_BUFFER_SIZE "2048")
        _pn_profile_set(PUBNUB_CFG_ORIGIN "ps.pndsn.com")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS "64")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS "8")
        _pn_profile_set(PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE "100")
        _pn_profile_set(PUBNUB_CFG_MAX_POLL_MS "100")
        _pn_profile_set(PUBNUB_CFG_TRANSACTION_TIMEOUT_MS "10000")
        _pn_profile_set(PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS "310000")
        _pn_profile_set(PUBNUB_CFG_RETRY_DELAY_MS "2000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_DELAY_MS "150000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS "30000")
        _pn_profile_set(PUBNUB_CFG_LINEAR_MAX_RETRIES "10")
        _pn_profile_set(PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES "6")

        _pn_profile_set(PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS "300000")
        _pn_profile_set(PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE "0")
        _pn_profile_set(PUBNUB_CFG_ARENA_POOL_SIZE "65536")
        _pn_profile_set(PUBNUB_ARENA_POOL_OWNER "sdk")
        _pn_profile_set(PUBNUB_LOG_MIN_LEVEL "INFO")
        _pn_profile_set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE "512")
        _pn_profile_set(PUBNUB_CFG_MAX_LOGGERS "4")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS "10")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS "12")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_HEADERS "8")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_RESP_HEADERS "8")
        _pn_profile_set(PUBNUB_CFG_MAX_HEADER_BYTES "16384")
        _pn_profile_set(PUBNUB_CFG_HTTP_SCRATCH_SIZE "32768")
        _pn_profile_set(PUBNUB_CFG_PUBLISH_META_BUF_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES "8")
        _pn_profile_set(PUBNUB_CFG_MINIMAL_FORMATTER "0")
        # Footprint / quality toggles
        _pn_profile_set(PUBNUB_CFG_THREAD_SAFETY ON)
        _pn_profile_set(PUBNUB_CFG_RES_STR ON)
        _pn_profile_set(PUBNUB_CFG_JSON_MAX_NESTING_DEPTH "16")
        _pn_profile_set(PUBNUB_CFG_JSON_HELPERS ON)
        _pn_profile_set(PUBNUB_CFG_JSON_DOUBLE ON)
        # The context stores the origin hostname regardless of transport, so
        # this bound is always defined.
        _pn_profile_set(PUBNUB_CFG_MAX_HOSTNAME_LEN "256")
        # Socket/DNS tunables are read only by the socket transport. Set them
        # only when it is the effective (possibly user-overridden) transport;
        # under curl they would be inert. Read the transport AFTER it was set
        # above so a user -D override (e.g. ci-lint = full + socket) is honored.
        if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "socket")
            _pn_profile_set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE "2048")
            _pn_profile_set(PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS "10000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS "50000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS "1000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE "4194304")
            _pn_profile_set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS "3")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_RESULTS "8")
            _pn_profile_set(PUBNUB_CFG_DNS_CACHE_SIZE "8")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_SERVERS "8")
            _pn_profile_set(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE "512")
            _pn_profile_set(PUBNUB_CFG_DNS_MAX_TTL_SEC "300")
            _pn_profile_set(PUBNUB_CFG_TLS_SESSION_CACHE_SIZE "4")
        endif()
        _pn_profile_set(PUBNUB_ENABLE_CUSTOM_DNS OFF)

    elseif(PUBNUB_PROFILE STREQUAL "minimal")
        # Core features only, minimal providers.
        # Wire features
        _pn_profile_set(PUBNUB_ENABLE_PUBLISH ON)
        _pn_profile_set(PUBNUB_ENABLE_SUBSCRIBE ON)
        _pn_profile_set(PUBNUB_ENABLE_PRESENCE OFF)
        _pn_profile_set(PUBNUB_ENABLE_HISTORY OFF)
        _pn_profile_set(PUBNUB_ENABLE_MESSAGE_ACTIONS OFF)
        _pn_profile_set(PUBNUB_ENABLE_SIGNAL OFF)
        _pn_profile_set(PUBNUB_ENABLE_PAM OFF)
        _pn_profile_set(PUBNUB_ENABLE_APP_CONTEXT OFF)
        _pn_profile_set(PUBNUB_ENABLE_FILES OFF)
        _pn_profile_set(PUBNUB_ENABLE_CHANNEL_GROUPS OFF)
        _pn_profile_set(PUBNUB_ENABLE_CRYPTO OFF)
        _pn_profile_set(PUBNUB_ENABLE_PUSH_NOTIFICATIONS OFF)
        _pn_profile_set(PUBNUB_ENABLE_TIME OFF)
        _pn_profile_set(PUBNUB_ENABLE_RETRY ON)
        _pn_profile_set(PUBNUB_ENABLE_SECURE_TRANSPORT ON)
        _pn_profile_set(PUBNUB_ENABLE_COMPRESSION ON)
        _pn_profile_set(PUBNUB_ENABLE_FILESYSTEM OFF)
        _pn_profile_set(PUBNUB_ENABLE_IPV6 ON)
        _pn_profile_set(PUBNUB_ENABLE_PROXY ON)
        _pn_profile_set(PUBNUB_ENABLE_REQUEST_COMPRESSION ON)

        _pn_profile_set(PUBNUB_PROVIDER_TRANSPORT "curl")
        # cjson is incompatible with non-stdlib allocators and would
        # hard-fail in _pubnub_validate_provider_combinations().
        _pn_profile_set(PUBNUB_PROVIDER_SERIALIZATION "cjson")
        _pn_profile_set(PUBNUB_PROVIDER_CRYPTO "none")
        _pn_profile_set(PUBNUB_PROVIDER_LOGGER "stdout")
        _pn_profile_set(PUBNUB_PROVIDER_ALLOCATOR "stdlib")
        if(WIN32)
            _pn_profile_set(PUBNUB_PROVIDER_PLATFORM "windows")
        else()
            _pn_profile_set(PUBNUB_PROVIDER_PLATFORM "posix")
        endif()

        _pn_profile_set(PUBNUB_CFG_NO_HEAP "0")
        _pn_profile_set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS "8")
        _pn_profile_set(PUBNUB_CFG_MAX_PENDING_REQUESTS "8")
        _pn_profile_set(PUBNUB_CFG_REQUEST_BUFFER_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_RESPONSE_BUFFER_SIZE "32768")
        _pn_profile_set(PUBNUB_CFG_OBJECT_BUFFER_SIZE "33792")
        _pn_profile_set(PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE "8388608")
        _pn_profile_set(PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE "16777216")
        _pn_profile_set(PUBNUB_CFG_SCRATCH_BUFFER_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_URL_BUFFER_SIZE "2048")
        _pn_profile_set(PUBNUB_CFG_ORIGIN "ps.pndsn.com")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS "64")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS "8")
        _pn_profile_set(PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE "32")
        _pn_profile_set(PUBNUB_CFG_MAX_POLL_MS "100")
        _pn_profile_set(PUBNUB_CFG_TRANSACTION_TIMEOUT_MS "10000")
        _pn_profile_set(PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS "310000")
        _pn_profile_set(PUBNUB_CFG_RETRY_DELAY_MS "2000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_DELAY_MS "150000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS "30000")
        _pn_profile_set(PUBNUB_CFG_LINEAR_MAX_RETRIES "10")
        _pn_profile_set(PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES "6")

        _pn_profile_set(PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS "300000")
        _pn_profile_set(PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE "0")
        _pn_profile_set(PUBNUB_CFG_ARENA_POOL_SIZE "65536")
        _pn_profile_set(PUBNUB_ARENA_POOL_OWNER "sdk")
        _pn_profile_set(PUBNUB_LOG_MIN_LEVEL "INFO")
        _pn_profile_set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE "512")
        _pn_profile_set(PUBNUB_CFG_MAX_LOGGERS "4")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS "10")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS "12")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_HEADERS "8")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_RESP_HEADERS "8")
        _pn_profile_set(PUBNUB_CFG_MAX_HEADER_BYTES "16384")
        _pn_profile_set(PUBNUB_CFG_HTTP_SCRATCH_SIZE "32768")
        _pn_profile_set(PUBNUB_CFG_PUBLISH_META_BUF_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES "8")
        _pn_profile_set(PUBNUB_CFG_MINIMAL_FORMATTER "0")
        # Footprint / quality toggles
        _pn_profile_set(PUBNUB_CFG_THREAD_SAFETY ON)
        _pn_profile_set(PUBNUB_CFG_RES_STR ON)
        _pn_profile_set(PUBNUB_CFG_JSON_MAX_NESTING_DEPTH "16")
        _pn_profile_set(PUBNUB_CFG_JSON_HELPERS ON)
        _pn_profile_set(PUBNUB_CFG_JSON_DOUBLE ON)
        # The context stores the origin hostname regardless of transport, so
        # this bound is always defined.
        _pn_profile_set(PUBNUB_CFG_MAX_HOSTNAME_LEN "128")
        # Socket/DNS tunables are read only by the socket transport. Set them
        # only when it is the effective (possibly user-overridden) transport;
        # under curl they would be inert. Read the transport AFTER it was set
        # above so a user -D override is honored.
        if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "socket")
            _pn_profile_set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE "1024")
            _pn_profile_set(PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS "10000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS "50000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS "1000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE "4194304")
            _pn_profile_set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS "3")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_RESULTS "4")
            _pn_profile_set(PUBNUB_CFG_DNS_CACHE_SIZE "4")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_SERVERS "4")
            _pn_profile_set(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE "512")
            _pn_profile_set(PUBNUB_CFG_DNS_MAX_TTL_SEC "300")
            _pn_profile_set(PUBNUB_CFG_TLS_SESSION_CACHE_SIZE "4")
        endif()
        _pn_profile_set(PUBNUB_ENABLE_CUSTOM_DNS OFF)

    elseif(PUBNUB_PROFILE STREQUAL "embedded")
        # Core features, arena allocator, no-heap friendly.
        # Wire features
        _pn_profile_set(PUBNUB_ENABLE_PUBLISH ON)
        _pn_profile_set(PUBNUB_ENABLE_SUBSCRIBE ON)
        _pn_profile_set(PUBNUB_ENABLE_PRESENCE OFF)
        _pn_profile_set(PUBNUB_ENABLE_HISTORY OFF)
        _pn_profile_set(PUBNUB_ENABLE_MESSAGE_ACTIONS OFF)
        _pn_profile_set(PUBNUB_ENABLE_SIGNAL OFF)
        _pn_profile_set(PUBNUB_ENABLE_PAM OFF)
        _pn_profile_set(PUBNUB_ENABLE_APP_CONTEXT OFF)
        _pn_profile_set(PUBNUB_ENABLE_FILES OFF)
        _pn_profile_set(PUBNUB_ENABLE_FILESYSTEM OFF)
        _pn_profile_set(PUBNUB_ENABLE_CHANNEL_GROUPS OFF)
        _pn_profile_set(PUBNUB_ENABLE_CRYPTO OFF)
        _pn_profile_set(PUBNUB_ENABLE_PUSH_NOTIFICATIONS OFF)
        _pn_profile_set(PUBNUB_ENABLE_TIME OFF)
        _pn_profile_set(PUBNUB_ENABLE_RETRY ON)
        _pn_profile_set(PUBNUB_ENABLE_SECURE_TRANSPORT ON)
        _pn_profile_set(PUBNUB_ENABLE_PROXY OFF)
        _pn_profile_set(PUBNUB_ENABLE_COMPRESSION OFF)
        _pn_profile_set(PUBNUB_ENABLE_FILESYSTEM OFF)
        _pn_profile_set(PUBNUB_ENABLE_IPV6 OFF)
        _pn_profile_set(PUBNUB_ENABLE_REQUEST_COMPRESSION OFF)

        _pn_profile_set(PUBNUB_PROVIDER_TRANSPORT "socket")
        _pn_profile_set(PUBNUB_PROVIDER_SERIALIZATION "jsmn")
        _pn_profile_set(PUBNUB_PROVIDER_CRYPTO "none")
        _pn_profile_set(PUBNUB_PROVIDER_LOGGER "none")
        _pn_profile_set(PUBNUB_PROVIDER_ALLOCATOR "arena")
        _pn_profile_set(PUBNUB_PROVIDER_PLATFORM "freertos")

        # Reduced resource limits for constrained targets.
        _pn_profile_set(PUBNUB_CFG_NO_HEAP "1")
        _pn_profile_set(PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS "2")
        _pn_profile_set(PUBNUB_CFG_MAX_PENDING_REQUESTS "2")
        _pn_profile_set(PUBNUB_CFG_REQUEST_BUFFER_SIZE "1024")
        _pn_profile_set(PUBNUB_CFG_RESPONSE_BUFFER_SIZE "4096")
        _pn_profile_set(PUBNUB_CFG_OBJECT_BUFFER_SIZE "2048")
        _pn_profile_set(PUBNUB_CFG_MAX_OBJ_BUFFER_SIZE "0")
        _pn_profile_set(PUBNUB_CFG_MAX_RESPONSE_BUFFER_SIZE "0")
        _pn_profile_set(PUBNUB_CFG_SCRATCH_BUFFER_SIZE "1024")
        _pn_profile_set(PUBNUB_CFG_URL_BUFFER_SIZE "512")
        _pn_profile_set(PUBNUB_CFG_ORIGIN "ps.pndsn.com")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS "8")
        _pn_profile_set(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS "4")
        _pn_profile_set(PUBNUB_CFG_SUBSCRIBE_MAX_BATCH_SIZE "8")
        _pn_profile_set(PUBNUB_CFG_MAX_POLL_MS "100")
        _pn_profile_set(PUBNUB_CFG_TRANSACTION_TIMEOUT_MS "10000")
        _pn_profile_set(PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS "310000")
        _pn_profile_set(PUBNUB_CFG_RETRY_DELAY_MS "2000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_DELAY_MS "150000")
        _pn_profile_set(PUBNUB_CFG_RETRY_MAX_RETRY_AFTER_MS "30000")
        _pn_profile_set(PUBNUB_CFG_LINEAR_MAX_RETRIES "10")
        _pn_profile_set(PUBNUB_CFG_EXPONENTIAL_MAX_RETRIES "6")

        _pn_profile_set(PUBNUB_CFG_FILE_UPLOAD_TIMEOUT_MS "300000")
        _pn_profile_set(PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE "5242880")
        _pn_profile_set(PUBNUB_LOG_MIN_LEVEL "NONE")
        _pn_profile_set(PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE "0")
        _pn_profile_set(PUBNUB_CFG_MAX_LOGGERS "2")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_PATH_SEGMENTS "10")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS "10")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_HEADERS "6")
        _pn_profile_set(PUBNUB_CFG_HTTP_MAX_RESP_HEADERS "6")
        _pn_profile_set(PUBNUB_CFG_MAX_HEADER_BYTES "4096")
        _pn_profile_set(PUBNUB_CFG_HTTP_SCRATCH_SIZE "256")
        _pn_profile_set(PUBNUB_CFG_PUBLISH_META_BUF_SIZE "256")
        _pn_profile_set(PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES "4")
        _pn_profile_set(PUBNUB_CFG_MINIMAL_FORMATTER "1")
        _pn_profile_set(PUBNUB_CFG_CRYPTO_MAX_FALLBACK_CRYPTORS "2")
        # Footprint / quality toggles
        _pn_profile_set(PUBNUB_CFG_THREAD_SAFETY OFF)
        _pn_profile_set(PUBNUB_CFG_RES_STR OFF)
        _pn_profile_set(PUBNUB_CFG_JSON_MAX_NESTING_DEPTH "8")
        _pn_profile_set(PUBNUB_CFG_JSON_HELPERS OFF)
        _pn_profile_set(PUBNUB_CFG_JSON_DOUBLE OFF)
        # The context stores the origin hostname regardless of transport, so
        # this bound is always defined.
        _pn_profile_set(PUBNUB_CFG_MAX_HOSTNAME_LEN "64")
        # Socket/DNS tunables are read only by the socket transport. The
        # embedded profile always selects socket, but guard on the effective
        # transport for consistency with the hosted profiles.
        if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "socket")
            _pn_profile_set(PUBNUB_CFG_SOCKET_HEADER_BUF_SIZE "512")
            _pn_profile_set(PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS "8000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS "10000")
            _pn_profile_set(PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS "100")
            _pn_profile_set(PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE "8192")
            # 0 compiles the redirect path out: following one costs ~1KB of
            # stack for the second request descriptor. Raised automatically
            # below when the Files feature (307 to object storage) is enabled.
            _pn_profile_set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS "0")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_RESULTS "4")
            _pn_profile_set(PUBNUB_CFG_DNS_CACHE_SIZE "2")
            _pn_profile_set(PUBNUB_CFG_MAX_DNS_SERVERS "4")
            _pn_profile_set(PUBNUB_CFG_DNS_PLATFORM_STATE_SIZE "256")
            _pn_profile_set(PUBNUB_CFG_DNS_MAX_TTL_SEC "600")
            _pn_profile_set(PUBNUB_CFG_TLS_SESSION_CACHE_SIZE "2")
        endif()
        _pn_profile_set(PUBNUB_ENABLE_CUSTOM_DNS OFF)

        _pn_profile_set(PUBNUB_ARENA_POOL_OWNER "user")

        # Arena pool/budget computed from buffer sizes and feature flags.
        # Must be last: depends on DNS_CACHE_SIZE, ENABLE_SUBSCRIBE, etc.
        pubnub_compute_arena_sizes()

    else()
        message(
            FATAL_ERROR
            "[PubNub] Unknown profile: '${PUBNUB_PROFILE}'. "
            "Known profiles: full, minimal, embedded"
        )
    endif()

    # Warn when crypto is enabled on a user-owned-pool profile: NULL allocator
    # is not available (pn_allocator_default returns NULL). Pass an explicit
    # allocator to pubnub_crypto_module_aes_cbc() and related functions.
    if(PUBNUB_ENABLE_CRYPTO AND NOT PUBNUB_CFG_ARENA_POOL_OWNER_SDK)
        message(
            STATUS
            "[PubNub] PUBNUB_ENABLE_CRYPTO=ON with user-owned arena (PUBNUB_CFG_ARENA_POOL_OWNER_SDK=0). "
            "NULL allocator returns NULL on this profile — pass an explicit allocator to "
            "pubnub_crypto_module_aes_cbc(), pubnub_crypto_module_legacy(), and "
            "pubnub_crypto_module_create()."
        )
    endif()

    # Files feature connects to S3 bucket origins whose hostnames exceed the
    # embedded default. Raise the limit when it is too small.
    if(PUBNUB_ENABLE_FILES AND PUBNUB_CFG_MAX_HOSTNAME_LEN LESS 128)
        _pn_profile_set(PUBNUB_CFG_MAX_HOSTNAME_LEN "128")
        message(
            STATUS
            "[PubNub] PUBNUB_CFG_MAX_HOSTNAME_LEN raised to 128 (Files feature requires longer S3 bucket hostnames)"
        )
    endif()

    # Files download returns 307 to object storage, so the redirect path
    # cannot be compiled out when the feature is on. Only relevant for the
    # socket transport (curl handles redirects internally and the knob is not
    # defined there), so guard on the effective transport before comparing.
    if(PUBNUB_PROVIDER_TRANSPORT STREQUAL "socket")
        if(PUBNUB_ENABLE_FILES AND PUBNUB_CFG_SOCKET_MAX_REDIRECTS LESS 1)
            _pn_profile_set(PUBNUB_CFG_SOCKET_MAX_REDIRECTS "1")
            message(
                STATUS
                "[PubNub] PUBNUB_CFG_SOCKET_MAX_REDIRECTS raised to 1 (Files feature follows a 307 to object storage)"
            )
        endif()
    endif()
endfunction()
