# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Socket transport provider — raw TCP/TLS implementation for embedded/constrained targets.

include(sources.cmake)
include(dns/sources.cmake)
include(proxy/sources.cmake)
include(platform/sources.cmake)
include(tls/sources.cmake)

# Path to the resolv.conf file used for DNS server discovery on Linux/BSD.
# Platforms that use a different resolver config path (e.g. custom embedded Linux
# distributions) can set this at configure time. Not used on macOS (res_ninit) or
# Windows (GetAdaptersAddresses).
set(PUBNUB_CFG_RESOLV_CONF_PATH
    ""
    CACHE STRING
    "Override path to resolv.conf for DNS discovery (Linux/BSD only). Empty = use built-in default /etc/resolv.conf."
)

# Custom platform ops override.
# Set PUBNUB_SOCKET_PLATFORM_OPS=custom and point PUBNUB_SOCKET_PLATFORM_OPS_DIR
# at a directory containing a CMakeLists.txt that adds its sources to the
# pubnub_provider_transport target and defines the pn_custom_socket_platform_ops
# symbol. The built-in OS implementations (platform/posix_socket_ops.c etc.) are
# excluded when custom is active so the user's file is the sole implementation.
set(PUBNUB_SOCKET_PLATFORM_OPS
    "auto"
    CACHE STRING
    "Socket platform ops: 'auto' selects by OS; 'custom' requires PUBNUB_SOCKET_PLATFORM_OPS_DIR."
)
set_property(CACHE PUBNUB_SOCKET_PLATFORM_OPS PROPERTY STRINGS auto custom)

set(PUBNUB_SOCKET_PLATFORM_OPS_DIR
    ""
    CACHE PATH
    "Path to a directory with a CMakeLists.txt that supplies the pn_custom_socket_platform_ops symbol."
)

set(PN_SOCKET_TRANSPORT_SOURCES
    ${PN_TRANSPORT_SOCKET_BASE_SOURCES}
    ${PN_TRANSPORT_SOCKET_DNS_SOURCES}
    ${PN_TRANSPORT_SOCKET_PROXY_SOURCES}
)

# Proxy CONNECT support (gated by PUBNUB_ENABLE_PROXY)
if(PUBNUB_ENABLE_PROXY)
    list(
        APPEND PN_SOCKET_TRANSPORT_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/proxy/proxy_connect.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/proxy/pn_proxy_md4.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/proxy/pn_proxy_md5.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/proxy/pn_proxy_ntlm.c"
    )

    # WPAD auto-discovery (platform-specific, overrides stub)
    if(WIN32)
        list(
            REMOVE_ITEM PN_SOCKET_TRANSPORT_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/proxy/proxy_wpad_none.c"
        )
        list(
            APPEND PN_SOCKET_TRANSPORT_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/proxy/proxy_wpad_win.c"
        )
    elseif(APPLE)
        list(
            REMOVE_ITEM PN_SOCKET_TRANSPORT_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/proxy/proxy_wpad_none.c"
        )
        list(
            APPEND PN_SOCKET_TRANSPORT_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/proxy/proxy_wpad_mac.c"
        )
    endif()
endif()

# Platform-specific socket operations
if(PUBNUB_SOCKET_PLATFORM_OPS STREQUAL "custom")
    if(NOT PUBNUB_SOCKET_PLATFORM_OPS_DIR)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_SOCKET_PLATFORM_OPS=custom requires PUBNUB_SOCKET_PLATFORM_OPS_DIR to be set."
        )
    endif()
    if(NOT EXISTS "${PUBNUB_SOCKET_PLATFORM_OPS_DIR}/CMakeLists.txt")
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_SOCKET_PLATFORM_OPS_DIR='${PUBNUB_SOCKET_PLATFORM_OPS_DIR}' does not contain a CMakeLists.txt."
        )
    endif()
    message(STATUS "[PubNub] Socket platform ops: custom (${PUBNUB_SOCKET_PLATFORM_OPS_DIR})")
else()
    if(WIN32)
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_SOCKET_PLATFORM_WINDOWS_SOURCES})
    elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeRTOS" OR PUBNUB_PLATFORM STREQUAL "freertos")
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_SOCKET_PLATFORM_FREERTOS_SOURCES})
        set(PN_SOCKET_PLATFORM_IS_FREERTOS TRUE)
    elseif(
        DEFINED BOARD
        OR ZEPHYR_TOOLCHAIN_VARIANT STREQUAL "zephyr"
        OR CMAKE_SYSTEM_NAME STREQUAL "zephyr"
    )
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_SOCKET_PLATFORM_ZEPHYR_SOURCES})
    else()
        # POSIX (Linux, macOS, BSD)
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_SOCKET_PLATFORM_POSIX_SOURCES})
    endif()
    message(STATUS "[PubNub] Socket platform ops: auto (${CMAKE_SYSTEM_NAME})")
endif()

# TLS backend selection
if(PUBNUB_ENABLE_SECURE_TRANSPORT)
    if(NOT DEFINED PUBNUB_SOCKET_TLS_BACKEND)
        set(PUBNUB_SOCKET_TLS_BACKEND "openssl")
    endif()

    # Cert loader sources are compiled for all TLS backends — each
    # certs_*.c file is internally guarded by PUBNUB_SOCKET_TLS_BACKEND_*
    # macros and compiles cleanly for both OpenSSL and mbedTLS.
    include(tls/certs/sources.cmake)

    if(PUBNUB_SOCKET_TLS_BACKEND STREQUAL "openssl")
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_TLS_OPENSSL_SOURCES})
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TLS_CERT_LOADER_SOURCE})
    elseif(PUBNUB_SOCKET_TLS_BACKEND STREQUAL "mbedtls")
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_TLS_MBEDTLS_SOURCES})
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TLS_CERT_LOADER_SOURCE})
    else()
        list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_TLS_NONE_SOURCES})
    endif()
else()
    list(APPEND PN_SOCKET_TRANSPORT_SOURCES ${PN_TRANSPORT_TLS_NONE_SOURCES})
endif()

# Compression (response decompression)
if(PUBNUB_ENABLE_COMPRESSION)
    list(APPEND PN_SOCKET_TRANSPORT_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/inflate/pn_inflate.c")
endif()

_pn_sdk_library(pubnub_provider_transport ${PN_SOCKET_TRANSPORT_SOURCES})

target_include_directories(
    pubnub_provider_transport
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_BINARY_DIR}/src/core
)

target_link_libraries(
    pubnub_provider_transport
    PUBLIC pubnub_public_headers
    PRIVATE pn_core_fmt pn_core_str pn_core_protocol_common
)

target_compile_definitions(
    pubnub_provider_transport
    PRIVATE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>
)

if(PUBNUB_CFG_RESOLV_CONF_PATH)
    target_compile_definitions(
        pubnub_provider_transport
        PRIVATE "PUBNUB_CFG_RESOLV_CONF_PATH=\"${PUBNUB_CFG_RESOLV_CONF_PATH}\""
    )
endif()

if(PN_SOCKET_PLATFORM_IS_FREERTOS)
    target_compile_definitions(pubnub_provider_transport PRIVATE PUBNUB_PLATFORM_FREERTOS=1)
endif()

if(PUBNUB_SOCKET_PLATFORM_OPS STREQUAL "custom")
    target_compile_definitions(
        pubnub_provider_transport
        PRIVATE PUBNUB_SOCKET_PLATFORM_OPS_CUSTOM=1
    )
    add_subdirectory(
        "${PUBNUB_SOCKET_PLATFORM_OPS_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/custom_socket_platform_ops"
    )
endif()

# TLS library linkage + preprocessor define so pn_transport_default() can
# select the correct singleton at compile time without a runtime string compare.
if(PUBNUB_ENABLE_SECURE_TRANSPORT)
    if(PUBNUB_SOCKET_TLS_BACKEND STREQUAL "openssl")
        pubnub_resolve_openssl()
        target_compile_definitions(
            pubnub_provider_transport
            PRIVATE PUBNUB_SOCKET_TLS_BACKEND_OPENSSL
        )
        target_link_libraries(pubnub_provider_transport PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    elseif(PUBNUB_SOCKET_TLS_BACKEND STREQUAL "mbedtls")
        pubnub_resolve_mbedtls()
        target_compile_definitions(
            pubnub_provider_transport
            PRIVATE PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS
        )
        target_link_libraries(
            pubnub_provider_transport
            PUBLIC MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509
        )
    endif()
    # certs_windows.c uses CertOpenSystemStore / CertEnumCertificatesInStore from
    # crypt32.dll for both the OpenSSL and mbedTLS backends. Link unconditionally
    # when any TLS backend that compiles the cert files is active on Windows.
    if(WIN32)
        target_link_libraries(pubnub_provider_transport PUBLIC crypt32)
    endif()
endif()

# Compression backend selection
if(PUBNUB_ENABLE_COMPRESSION)
    if(PUBNUB_PROFILE STREQUAL "embedded")
        pubnub_resolve_miniz()
        target_compile_definitions(
            pubnub_provider_transport
            PRIVATE PUBNUB_COMPRESSION_BACKEND_TINFL
        )
        target_sources(pubnub_provider_transport PRIVATE ${PN_MINIZ_SOURCE_DIR}/miniz_tinfl.c)
        target_include_directories(pubnub_provider_transport PRIVATE ${PN_MINIZ_SOURCE_DIR})
    else()
        target_compile_definitions(
            pubnub_provider_transport
            PRIVATE PUBNUB_COMPRESSION_BACKEND_ZLIB
        )
        find_package(ZLIB QUIET)
        if(NOT ZLIB_FOUND)
            include(FetchContent)
            FetchContent_Declare(
                zlib_upstream
                GIT_REPOSITORY https://github.com/madler/zlib.git
                # Pinned to immutable commit SHA (tags are mutable / repointable).
                GIT_TAG
                    51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf # v1.3.1
                GIT_SHALLOW TRUE
            )
            FetchContent_MakeAvailable(zlib_upstream)
            target_link_libraries(pubnub_provider_transport PUBLIC zlibstatic)
            target_include_directories(
                pubnub_provider_transport
                PRIVATE "${zlib_upstream_SOURCE_DIR}" "${zlib_upstream_BINARY_DIR}"
            )
        else()
            target_link_libraries(pubnub_provider_transport PUBLIC ZLIB::ZLIB)
        endif()
    endif()
endif()

# macOS needs libresolv for DNS server discovery (res_getservers) — only when
# custom DNS is enabled (the built-in UDP resolver queries discovered nameservers).
if(PUBNUB_ENABLE_CUSTOM_DNS AND APPLE)
    target_link_libraries(pubnub_provider_transport PUBLIC resolv)
endif()

# Windows needs dnsapi for DnsQueryEx (native async DNS resolution)
if(NOT PUBNUB_ENABLE_CUSTOM_DNS AND WIN32)
    target_link_libraries(pubnub_provider_transport PUBLIC dnsapi)
endif()

# Disable hardcoded fallback DNS servers when requested (custom DNS only).
if(PUBNUB_ENABLE_CUSTOM_DNS AND PUBNUB_CFG_DNS_DISABLE_FALLBACKS)
    target_compile_definitions(pubnub_provider_transport PRIVATE PUBNUB_CFG_DNS_DISABLE_FALLBACKS=1)
endif()

if(PN_DEBUG_SOCKET_OPS)
    target_compile_definitions(pubnub_provider_transport PRIVATE PN_DEBUG_SOCKET_OPS)
endif()

# Windows Winsock library (GCC/MinGW does not process #pragma comment(lib, ...)).
if(WIN32)
    target_link_libraries(pubnub_provider_transport PUBLIC ws2_32)
endif()

# iphlpapi (GetAdaptersAddresses / GetBestRoute2) is only needed when the
# built-in UDP DNS resolver is compiled in.
if(WIN32 AND PUBNUB_ENABLE_CUSTOM_DNS)
    target_link_libraries(pubnub_provider_transport PUBLIC iphlpapi)
endif()

# WPAD auto-discovery platform libraries
if(PUBNUB_ENABLE_PROXY)
    if(WIN32)
        target_link_libraries(pubnub_provider_transport PUBLIC winhttp)
    elseif(APPLE)
        target_link_libraries(
            pubnub_provider_transport
            PUBLIC "-framework CoreFoundation" "-framework CFNetwork"
        )
    endif()
endif()

set_target_properties(
    pubnub_provider_transport
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_transport)
pubnub_target_sanitizers(pubnub_provider_transport)
