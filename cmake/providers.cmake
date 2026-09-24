# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Provider family resolution and validation.
#
# Each provider family must resolve to exactly one implementation.
# Configuration fails if a required family is unresolved or an unknown
# provider name is given.
#
# Custom providers:
#   Set PUBNUB_PROVIDER_<FAMILY>=custom and provide the path to your
#   implementation directory via PUBNUB_PROVIDER_<FAMILY>_DIR.
#   That directory must contain a CMakeLists.txt that defines the
#   `pubnub_provider_<family>` CMake target (STATIC library).
#   The target should link against pubnub_public_headers to access
#   the provider interface headers.

# ---------------------------------------------------------------------------
# Known provider names per family
# ---------------------------------------------------------------------------
set(_PN_KNOWN_TRANSPORT "curl;socket;custom")
set(_PN_KNOWN_SERIALIZATION "cjson;jsmn;custom")
set(_PN_KNOWN_CRYPTO "openssl;mbedtls;none;custom")
set(_PN_KNOWN_LOGGER "stdout;none;custom")
set(_PN_KNOWN_ALLOCATOR "stdlib;arena;custom")
set(_PN_KNOWN_PLATFORM "posix;windows;freertos;zephyr;custom")

# ---------------------------------------------------------------------------
# Provider option variables
# ---------------------------------------------------------------------------
set(PUBNUB_PROVIDER_TRANSPORT "curl" CACHE STRING "Transport provider backend")
set(PUBNUB_PROVIDER_SERIALIZATION "cjson" CACHE STRING "Serialization provider backend")
set(PUBNUB_PROVIDER_CRYPTO "openssl" CACHE STRING "Crypto provider backend")
set(PUBNUB_PROVIDER_LOGGER "none" CACHE STRING "Logger provider backend")
set(PUBNUB_PROVIDER_ALLOCATOR "stdlib" CACHE STRING "Allocator provider backend")
set(PUBNUB_PROVIDER_PLATFORM "" CACHE STRING "Platform abstraction provider backend")

set(PUBNUB_TLS_CA_CERT_FILE
    ""
    CACHE FILEPATH
    "Path to a PEM file to embed as the TLS CA bundle (mbedTLS backend only). \
Empty = use the platform's built-in trust source. \
When set, overrides all platform-specific cert files and embeds only the specified certs. \
Useful for reducing binary size by providing only the CAs your endpoints use."
)

# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------
# _pn_validate_provider(<family> <chosen> <known_list>)
#   Fails if <chosen> is not in <known_list>.
function(_pn_validate_provider family chosen known_list)
    if("${chosen}" STREQUAL "")
        string(TOUPPER "${family}" _upper)
        message(
            FATAL_ERROR
            "[PubNub] ${family} provider is not set. "
            "Set -DPUBNUB_PROVIDER_${_upper}=<value> or select a profile "
            "(-DPUBNUB_PROFILE=full|minimal|embedded). "
            "Known providers: ${known_list}"
        )
    endif()
    list(FIND known_list "${chosen}" _idx)
    if(_idx EQUAL -1)
        message(
            FATAL_ERROR
            "[PubNub] Unknown ${family} provider: '${chosen}'. "
            "Known providers: ${known_list}"
        )
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Custom provider directory validation
# ---------------------------------------------------------------------------
# _pn_validate_custom_dir(<FAMILY> <dir_var>)
#   When provider is "custom", checks that the directory variable is set
#   and points to an existing directory with a CMakeLists.txt.
function(_pn_validate_custom_dir family dir_var)
    string(TOUPPER "${family}" _upper)
    set(_provider_var "PUBNUB_PROVIDER_${_upper}")
    if(NOT "${${_provider_var}}" STREQUAL "custom")
        return()
    endif()

    if(NOT DEFINED ${dir_var} OR "${${dir_var}}" STREQUAL "")
        message(
            FATAL_ERROR
            "[PubNub] ${family} provider is 'custom' but ${dir_var} is not set. "
            "Provide the path to your ${family} provider implementation directory."
        )
    endif()

    if(NOT EXISTS "${${dir_var}}/CMakeLists.txt")
        message(
            FATAL_ERROR
            "[PubNub] Custom ${family} provider directory '${${dir_var}}' "
            "does not contain a CMakeLists.txt. The directory must define "
            "the pubnub_provider_${family} CMake target."
        )
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Cross-family combination validation
# ---------------------------------------------------------------------------
# Some provider implementations carry hard requirements on what other
# providers must resolve to. Enforce those at configure time so the
# diagnostic is loud and the failure mode is unambiguous.
#
# Current rule:
#   - cjson serialization REQUIRES the stdlib allocator. cJSON's memory
#     hooks (`cJSON_InitHooks`) are global state, which does not fit
#     the per-context allocator-provider model. Mixing cjson with any
#     non-stdlib allocator (arena, custom, etc.) would route cJSON's
#     internal allocations through libc malloc while every other SDK
#     allocation goes through the configured allocator -- a silent
#     correctness/budget trap on no-heap targets.
function(_pn_validate_provider_combinations)
    if(
        "${PUBNUB_PROVIDER_SERIALIZATION}" STREQUAL "cjson"
        AND NOT "${PUBNUB_PROVIDER_ALLOCATOR}" STREQUAL "stdlib"
    )
        message(
            FATAL_ERROR
            "[PubNub] Invalid provider combination: "
            "PUBNUB_PROVIDER_SERIALIZATION=cjson requires "
            "PUBNUB_PROVIDER_ALLOCATOR=stdlib (got "
            "'${PUBNUB_PROVIDER_ALLOCATOR}'). cJSON exposes its memory "
            "hooks as global state, which is incompatible with "
            "per-context allocator providers. Two resolutions: "
            "(1) switch serialization to jsmn "
            "(-DPUBNUB_PROVIDER_SERIALIZATION=jsmn), or "
            "(2) switch allocator to stdlib "
            "(-DPUBNUB_PROVIDER_ALLOCATOR=stdlib)."
        )
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Validate all families
# ---------------------------------------------------------------------------
function(pubnub_validate_providers)
    _pn_validate_provider("transport" "${PUBNUB_PROVIDER_TRANSPORT}" "${_PN_KNOWN_TRANSPORT}")
    _pn_validate_provider(
        "serialization"
        "${PUBNUB_PROVIDER_SERIALIZATION}"
        "${_PN_KNOWN_SERIALIZATION}"
    )
    _pn_validate_provider("crypto" "${PUBNUB_PROVIDER_CRYPTO}" "${_PN_KNOWN_CRYPTO}")
    _pn_validate_provider("logger" "${PUBNUB_PROVIDER_LOGGER}" "${_PN_KNOWN_LOGGER}")
    _pn_validate_provider("allocator" "${PUBNUB_PROVIDER_ALLOCATOR}" "${_PN_KNOWN_ALLOCATOR}")
    _pn_validate_provider("platform" "${PUBNUB_PROVIDER_PLATFORM}" "${_PN_KNOWN_PLATFORM}")

    # Validate custom provider directories
    _pn_validate_custom_dir("transport" PUBNUB_PROVIDER_TRANSPORT_DIR)
    _pn_validate_custom_dir("serialization" PUBNUB_PROVIDER_SERIALIZATION_DIR)
    _pn_validate_custom_dir("crypto" PUBNUB_PROVIDER_CRYPTO_DIR)
    _pn_validate_custom_dir("logger" PUBNUB_PROVIDER_LOGGER_DIR)
    _pn_validate_custom_dir("allocator" PUBNUB_PROVIDER_ALLOCATOR_DIR)
    _pn_validate_custom_dir("platform" PUBNUB_PROVIDER_PLATFORM_DIR)

    # Cross-family combination rules.
    _pn_validate_provider_combinations()
endfunction()

# ---------------------------------------------------------------------------
# Print resolved providers
# ---------------------------------------------------------------------------
function(_pn_provider_display family provider dir_var)
    set(_display "${provider}")
    if("${provider}" STREQUAL "custom" AND DEFINED ${dir_var})
        set(_display "custom (${${dir_var}})")
    endif()
    message(STATUS "[PubNub]   ${family} : ${_display}")
endfunction()

function(pubnub_print_provider_summary)
    message(STATUS "")
    message(STATUS "[PubNub] ===== Provider Summary =====")
    _pn_provider_display("transport" "${PUBNUB_PROVIDER_TRANSPORT}" PUBNUB_PROVIDER_TRANSPORT_DIR)
    _pn_provider_display(
        "serialization"
        "${PUBNUB_PROVIDER_SERIALIZATION}"
        PUBNUB_PROVIDER_SERIALIZATION_DIR
    )
    _pn_provider_display("crypto" "${PUBNUB_PROVIDER_CRYPTO}" PUBNUB_PROVIDER_CRYPTO_DIR)
    _pn_provider_display("logger" "${PUBNUB_PROVIDER_LOGGER}" PUBNUB_PROVIDER_LOGGER_DIR)
    _pn_provider_display("allocator" "${PUBNUB_PROVIDER_ALLOCATOR}" PUBNUB_PROVIDER_ALLOCATOR_DIR)
    _pn_provider_display("platform" "${PUBNUB_PROVIDER_PLATFORM}" PUBNUB_PROVIDER_PLATFORM_DIR)
    if(PUBNUB_CFG_THREAD_SAFETY)
        message(STATUS "[PubNub]   thread_safety : on")
    else()
        message(STATUS "[PubNub]   thread_safety : off")
    endif()
    if(PUBNUB_TLS_CA_CERT_FILE)
        message(STATUS "[PubNub]   tls_ca_bundle : custom (${PUBNUB_TLS_CA_CERT_FILE})")
    else()
        message(STATUS "[PubNub]   tls_ca_bundle : platform default")
    endif()
    message(STATUS "[PubNub] ================================")
    message(STATUS "")
endfunction()

# ---------------------------------------------------------------------------
# Get provider subdirectory for a family
# ---------------------------------------------------------------------------
# Returns the path segment for the chosen provider implementation.
# For "custom" providers, returns the absolute path from the _DIR variable.
function(pubnub_provider_subdir family out_var)
    if(family STREQUAL "transport")
        set(_val "${PUBNUB_PROVIDER_TRANSPORT}")
        set(_dir "${PUBNUB_PROVIDER_TRANSPORT_DIR}")
    elseif(family STREQUAL "serialization")
        set(_val "${PUBNUB_PROVIDER_SERIALIZATION}")
        set(_dir "${PUBNUB_PROVIDER_SERIALIZATION_DIR}")
    elseif(family STREQUAL "crypto")
        set(_val "${PUBNUB_PROVIDER_CRYPTO}")
        set(_dir "${PUBNUB_PROVIDER_CRYPTO_DIR}")
    elseif(family STREQUAL "logger")
        set(_val "${PUBNUB_PROVIDER_LOGGER}")
        set(_dir "${PUBNUB_PROVIDER_LOGGER_DIR}")
    elseif(family STREQUAL "allocator")
        set(_val "${PUBNUB_PROVIDER_ALLOCATOR}")
        set(_dir "${PUBNUB_PROVIDER_ALLOCATOR_DIR}")
    elseif(family STREQUAL "platform")
        set(_val "${PUBNUB_PROVIDER_PLATFORM}")
        set(_dir "${PUBNUB_PROVIDER_PLATFORM_DIR}")
    else()
        message(FATAL_ERROR "[PubNub] Unknown provider family: ${family}")
    endif()

    if("${_val}" STREQUAL "custom")
        set(${out_var} "${_dir}" PARENT_SCOPE)
    else()
        set(${out_var} "${_val}" PARENT_SCOPE)
    endif()
endfunction()
