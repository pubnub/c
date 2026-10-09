# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# curl transport: libcurl-backed provider for hosted profiles.
#
# Minimum libcurl version: 7.66 (Sep 2019).  `curl_multi_poll` -
# used in curl_transport_poll - was introduced in 7.66.0; earlier
# libcurls have only `curl_multi_wait`, which does not wake on
# pending transfers added between wait calls. Pinning the version
# in find_package surfaces the mismatch as an actionable configure-
# time error on long-tail distros (RHEL 7 ships curl 7.29).
#
# Resolution strategy:
#   1. Try the system-installed libcurl (find_package QUIET).
#   2. If absent, fetch curl 8.12.0 from GitHub via FetchContent and
#      build it as a static library with HTTP(S)-only protocols.
#      TLS backend is selected based on PUBNUB_ENABLE_SECURE_TRANSPORT:
#        ON  -> OpenSSL (preferred; resolved via pubnub_resolve_openssl,
#               so PUBNUB_OPENSSL_LIB_DIR / OPENSSL_*_LIBRARY apply and are
#               forwarded to curl's own FindOpenSSL) or mbedTLS (fallback).
#        OFF -> TLS disabled entirely.

include(sources.cmake)

find_package(CURL 7.66 QUIET)

if(NOT CURL_FOUND)
    include(FetchContent)

    # --- TLS backend selection for bundled libcurl ---
    if(PUBNUB_ENABLE_SECURE_TRANSPORT)
        pubnub_resolve_openssl(OPTIONAL)
        if(TARGET OpenSSL::Crypto)
            set(PN_CURL_TLS_BACKEND "OpenSSL")
            set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
            set(CURL_USE_MBEDTLS OFF CACHE BOOL "" FORCE)

            # curl runs its own find_package(OpenSSL).  Point it at the exact
            # install the SDK resolved (it can differ from what FindOpenSSL
            # would pick, e.g. with PUBNUB_OPENSSL_LIB_DIR).  The cache values
            # are forced only for the FetchContent_MakeAvailable call below and
            # restored afterwards so they never look like user input later.
            set(PN_CURL_SSL_CRYPTO_LIB "")
            set(PN_CURL_SSL_SSL_LIB "")
            foreach(PN_SUFFIX IN ITEMS "" _RELEASE _NOCONFIG _DEBUG)
                if(NOT PN_CURL_SSL_CRYPTO_LIB)
                    get_target_property(
                        PN_CURL_SSL_CRYPTO_LIB
                        OpenSSL::Crypto
                        IMPORTED_LOCATION${PN_SUFFIX}
                    )
                endif()
                if(NOT PN_CURL_SSL_SSL_LIB)
                    get_target_property(
                        PN_CURL_SSL_SSL_LIB
                        OpenSSL::SSL
                        IMPORTED_LOCATION${PN_SUFFIX}
                    )
                endif()
            endforeach()
            get_target_property(PN_CURL_SSL_INC OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
            if(PN_CURL_SSL_INC)
                list(GET PN_CURL_SSL_INC 0 PN_CURL_SSL_INC)
            endif()

            set(PN_CURL_FWD_VARS "")
            if(PN_CURL_SSL_CRYPTO_LIB AND PN_CURL_SSL_SSL_LIB AND PN_CURL_SSL_INC)
                set(PN_CURL_FWD_VARS OPENSSL_CRYPTO_LIBRARY OPENSSL_SSL_LIBRARY OPENSSL_INCLUDE_DIR)
                set(PN_CURL_FWD_OPENSSL_CRYPTO_LIBRARY "${PN_CURL_SSL_CRYPTO_LIB}")
                set(PN_CURL_FWD_OPENSSL_SSL_LIBRARY "${PN_CURL_SSL_SSL_LIB}")
                set(PN_CURL_FWD_OPENSSL_INCLUDE_DIR "${PN_CURL_SSL_INC}")
                set(PN_CURL_FWD_TYPE_OPENSSL_CRYPTO_LIBRARY FILEPATH)
                set(PN_CURL_FWD_TYPE_OPENSSL_SSL_LIBRARY FILEPATH)
                set(PN_CURL_FWD_TYPE_OPENSSL_INCLUDE_DIR PATH)
                # MSVC: FindOpenSSL ignores OPENSSL_*_LIBRARY and rebuilds them
                # from the LIB_EAY_*/SSL_EAY_* searches, so pre-seed those.
                # UNTESTED on MSVC.
                if(WIN32 AND MSVC)
                    foreach(PN_CFG IN ITEMS DEBUG RELEASE)
                        list(APPEND PN_CURL_FWD_VARS LIB_EAY_${PN_CFG} SSL_EAY_${PN_CFG})
                        set(PN_CURL_FWD_LIB_EAY_${PN_CFG} "${PN_CURL_SSL_CRYPTO_LIB}")
                        set(PN_CURL_FWD_SSL_EAY_${PN_CFG} "${PN_CURL_SSL_SSL_LIB}")
                        set(PN_CURL_FWD_TYPE_LIB_EAY_${PN_CFG} FILEPATH)
                        set(PN_CURL_FWD_TYPE_SSL_EAY_${PN_CFG} FILEPATH)
                    endforeach()
                endif()
                if(NOT OPENSSL_ROOT_DIR AND "${PN_CURL_SSL_INC}" MATCHES "^(.+)/include/?$")
                    set(OPENSSL_ROOT_DIR "${CMAKE_MATCH_1}")
                endif()
                foreach(PN_VAR IN LISTS PN_CURL_FWD_VARS)
                    if(DEFINED CACHE{${PN_VAR}})
                        set(PN_CURL_SAVED_SET_${PN_VAR} TRUE)
                        set(PN_CURL_SAVED_VAL_${PN_VAR} "$CACHE{${PN_VAR}}")
                        get_property(PN_CURL_SAVED_TYPE_${PN_VAR} CACHE ${PN_VAR} PROPERTY TYPE)
                    else()
                        set(PN_CURL_SAVED_SET_${PN_VAR} FALSE)
                    endif()
                    set(${PN_VAR}
                        "${PN_CURL_FWD_${PN_VAR}}"
                        CACHE ${PN_CURL_FWD_TYPE_${PN_VAR}}
                        "Forwarded to bundled libcurl"
                        FORCE
                    )
                endforeach()
            endif()
        else()
            find_package(MbedTLS QUIET)
            if(MbedTLS_FOUND)
                set(PN_CURL_TLS_BACKEND "mbedTLS")
                set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
                set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
            else()
                message(
                    FATAL_ERROR
                    "[PubNub] PUBNUB_ENABLE_SECURE_TRANSPORT is ON but neither "
                    "OpenSSL nor mbedTLS was found. Install one of them or set "
                    "PUBNUB_ENABLE_SECURE_TRANSPORT=OFF."
                )
            endif()
        endif()
    else()
        set(PN_CURL_TLS_BACKEND "none")
        set(CURL_ENABLE_SSL OFF CACHE BOOL "" FORCE)
    endif()

    # --- Disable protocols we don't need ---
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(CURL_DISABLE_FTP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_SMTP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_POP3 ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_IMAP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_LDAPS ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_TELNET ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_TFTP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_SFTP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_SCP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_DICT ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_FILE ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_RTSP ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_GOPHER ON CACHE BOOL "" FORCE)
    set(CURL_DISABLE_MQTT ON CACHE BOOL "" FORCE)
    set(CURL_ZLIB OFF CACHE BOOL "" FORCE)
    # curl 8.12.0 guards find_package(Libpsl REQUIRED) with option(CURL_USE_LIBPSL).
    # Setting CURL_USE_LIBPSL=OFF in the cache before FetchContent_MakeAvailable
    # causes option() to use the existing cache value and skip the find_package call.
    set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)

    # --- Fetch curl 8.12.0 ---
    FetchContent_Declare(
        curl_upstream
        URL https://github.com/curl/curl/archive/refs/tags/curl-8_12_0.tar.gz
        URL_HASH SHA256=3ce803f8b2f58f0e2d159a0c5fb62d216ca6b0df704715d9cb6ef73fbe62a6d0
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )

    message(
        STATUS
        "[PubNub] System libcurl not found - fetching curl-8.12.0 "
        "with ${PN_CURL_TLS_BACKEND} TLS"
    )

    FetchContent_MakeAvailable(curl_upstream)

    foreach(PN_VAR IN LISTS PN_CURL_FWD_VARS)
        if(PN_CURL_SAVED_SET_${PN_VAR})
            set(${PN_VAR}
                "${PN_CURL_SAVED_VAL_${PN_VAR}}"
                CACHE ${PN_CURL_SAVED_TYPE_${PN_VAR}}
                ""
                FORCE
            )
        else()
            unset(${PN_VAR} CACHE)
        endif()
    endforeach()

    # Ensure the CURL::libcurl imported target exists for uniform
    # consumption regardless of system vs. fetched resolution.
    if(NOT TARGET CURL::libcurl)
        add_library(CURL::libcurl ALIAS libcurl)
    endif()
endif()

_pn_sdk_library(pubnub_provider_transport)
target_sources(pubnub_provider_transport PRIVATE ${PN_TRANSPORT_CURL_SOURCES})

target_link_libraries(
    pubnub_provider_transport
    PUBLIC pubnub_public_headers CURL::libcurl
    PRIVATE pn_core_fmt pn_core_str
)

# pn_format.h lives at src/core/pn_format.h; the curl transport uses it for
# pn_snprintf (the SDK-wide bounded formatter) instead of libc snprintf.
target_include_directories(pubnub_provider_transport PRIVATE "${PN_SDK_SOURCE_ROOT}/src/core")

set_target_properties(
    pubnub_provider_transport
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_transport)
pubnub_target_sanitizers(pubnub_provider_transport)
