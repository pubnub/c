# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Third-party dependency resolution via FetchContent.
#
# Both cJSON and jsmn are fetched from their upstream GitHub repos at
# specific pinned tags.

# Keep vendored deps static even when SDK builds shared.
set(_pn_saved_bsl ${BUILD_SHARED_LIBS})
set(BUILD_SHARED_LIBS OFF)

include(FetchContent)

# Set policy to CMP0169 to suppress the warning because of
# FetchContent_Populate() with declared details usage as it has been
# deprecated in favor of FetchContent_MakeAvailable().
# FetchContent_Populate() will be used to avoid add_subdirectory() call for
# fetched dependencies.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

# ---------------------------------------------------------------------------
# cJSON v1.7.18
# ---------------------------------------------------------------------------
FetchContent_Declare(
    cjson_upstream
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    # Pinned to immutable commit SHA (tags are mutable / repointable).
    GIT_TAG
        acc76239bee01d8e9c858ae2cab296704e52d916 # v1.7.18
    GIT_SHALLOW TRUE
)

# ---------------------------------------------------------------------------
# jsmn v1.1.0
# ---------------------------------------------------------------------------
FetchContent_Declare(
    jsmn_upstream
    GIT_REPOSITORY https://github.com/zserge/jsmn.git
    # Pinned to immutable commit SHA (tags are mutable / repointable).
    GIT_TAG
        fdcef3ebf886fa210d14956d3c068a653e76a24e # v1.1.0
    GIT_SHALLOW TRUE
)

# ---------------------------------------------------------------------------
# miniz 3.1.2 (tinfl inflate-only subset for embedded response decompression)
# ---------------------------------------------------------------------------
FetchContent_Declare(
    miniz_upstream
    GIT_REPOSITORY https://github.com/richgel999/miniz.git
    # Pinned to immutable commit SHA (tags are mutable / repointable).
    GIT_TAG
        77d0dce8627735138c51770d1799a1ef48f2117d # 3.1.2
    GIT_SHALLOW TRUE
)

# ---------------------------------------------------------------------------
# pubnub_resolve_miniz()
#
# Populates miniz_upstream and sets PN_MINIZ_SOURCE_DIR in caller scope and as
# an INTERNAL cache variable.
# ---------------------------------------------------------------------------
function(pubnub_resolve_miniz)
    FetchContent_GetProperties(miniz_upstream)
    if(NOT miniz_upstream_POPULATED)
        FetchContent_Populate(miniz_upstream)
    endif()
    set(PN_MINIZ_SOURCE_DIR "${miniz_upstream_SOURCE_DIR}" PARENT_SCOPE)
    set(PN_MINIZ_SOURCE_DIR "${miniz_upstream_SOURCE_DIR}" CACHE INTERNAL "miniz source directory")
    message(STATUS "[PubNub] miniz v3.1.2: ${miniz_upstream_SOURCE_DIR}")
endfunction()

# ---------------------------------------------------------------------------
# pubnub_resolve_cjson()
#
# Populates cjson_upstream and sets PN_CJSON_SOURCE_DIR in caller scope and as
# an INTERNAL cache variable.
# ---------------------------------------------------------------------------
function(pubnub_resolve_cjson)
    FetchContent_GetProperties(cjson_upstream)
    if(NOT cjson_upstream_POPULATED)
        FetchContent_Populate(cjson_upstream)
    endif()
    set(PN_CJSON_SOURCE_DIR "${cjson_upstream_SOURCE_DIR}" PARENT_SCOPE)
    set(PN_CJSON_SOURCE_DIR "${cjson_upstream_SOURCE_DIR}" CACHE INTERNAL "cJSON source directory")
    message(STATUS "[PubNub] cJSON v1.7.18: ${cjson_upstream_SOURCE_DIR}")
endfunction()

# ---------------------------------------------------------------------------
# pubnub_resolve_jsmn()
#
# Populates jsmn_upstream and sets PN_JSMN_SOURCE_DIR in caller scope and as
# an INTERNAL cache variable.
# ---------------------------------------------------------------------------
function(pubnub_resolve_jsmn)
    FetchContent_GetProperties(jsmn_upstream)
    if(NOT jsmn_upstream_POPULATED)
        FetchContent_Populate(jsmn_upstream)
    endif()
    set(PN_JSMN_SOURCE_DIR "${jsmn_upstream_SOURCE_DIR}" PARENT_SCOPE)
    set(PN_JSMN_SOURCE_DIR "${jsmn_upstream_SOURCE_DIR}" CACHE INTERNAL "jsmn source directory")
    message(STATUS "[PubNub] jsmn v1.1.0: ${jsmn_upstream_SOURCE_DIR}")
endfunction()

# ---------------------------------------------------------------------------
# pubnub_resolve_openssl()
#
# Resolves OpenSSL via find_package(OpenSSL REQUIRED).  When OPENSSL_ROOT_DIR
# and PUBNUB_OPENSSL_LIB_DIR are both set, pre-populates library paths for
# non-standard directory layouts (e.g. Unreal Engine, cross-compilation).
# ---------------------------------------------------------------------------
function(pubnub_resolve_openssl)
    if(TARGET OpenSSL::Crypto)
        return()
    endif()

    set(PUBNUB_OPENSSL_LIB_DIR
        ""
        CACHE STRING
        "Relative path from OPENSSL_ROOT_DIR to the library directory (for non-standard layouts)."
    )

    if(OPENSSL_ROOT_DIR AND PUBNUB_OPENSSL_LIB_DIR)
        set(_pn_openssl_lib_path "${OPENSSL_ROOT_DIR}/${PUBNUB_OPENSSL_LIB_DIR}")
        if(NOT OPENSSL_CRYPTO_LIBRARY)
            find_library(
                OPENSSL_CRYPTO_LIBRARY
                NAMES crypto libcrypto
                PATHS "${_pn_openssl_lib_path}"
                NO_DEFAULT_PATH
            )
            if(NOT OPENSSL_CRYPTO_LIBRARY)
                message(
                    FATAL_ERROR
                    "[PubNub] OpenSSL crypto library not found in ${_pn_openssl_lib_path}"
                )
            endif()
        endif()
        if(NOT OPENSSL_SSL_LIBRARY)
            find_library(
                OPENSSL_SSL_LIBRARY
                NAMES ssl libssl
                PATHS "${_pn_openssl_lib_path}"
                NO_DEFAULT_PATH
            )
            if(NOT OPENSSL_SSL_LIBRARY)
                message(
                    FATAL_ERROR
                    "[PubNub] OpenSSL SSL library not found in ${_pn_openssl_lib_path}"
                )
            endif()
        endif()
    endif()

    find_package(OpenSSL REQUIRED)
    set(OPENSSL_VERSION "${OPENSSL_VERSION}" CACHE INTERNAL "Resolved OpenSSL version")
    message(STATUS "[PubNub] OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_CRYPTO_LIBRARY}")
endfunction()

# ---------------------------------------------------------------------------
# pubnub_resolve_mbedtls()
#
# Resolves mbedTLS via find_package, falling back to FetchContent v3.6.3.
# Creates MbedTLS::mbedtls, MbedTLS::mbedcrypto, and MbedTLS::mbedx509
# imported targets when fetching from source.
# ---------------------------------------------------------------------------
function(pubnub_resolve_mbedtls)
    if(TARGET MbedTLS::mbedcrypto)
        return()
    endif()

    set(MBEDTLS_ROOT_DIR
        ""
        CACHE PATH
        "Root directory for a custom mbedTLS installation (prepended to CMAKE_PREFIX_PATH)."
    )

    # Homebrew keg-only: mbedtls@3 is not symlinked into the default prefix
    # on macOS, so CMake needs the explicit path.
    if(APPLE AND EXISTS "/opt/homebrew/opt/mbedtls@3")
        list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/mbedtls@3")
    endif()

    if(MBEDTLS_ROOT_DIR)
        list(PREPEND CMAKE_PREFIX_PATH "${MBEDTLS_ROOT_DIR}")
    endif()

    find_package(MbedTLS QUIET)
    if(MbedTLS_FOUND)
        message(STATUS "[PubNub] mbedTLS found (system)")
        return()
    endif()

    message(STATUS "[PubNub] System mbedTLS not found -- fetching mbedTLS 3.6.3")
    FetchContent_Declare(
        mbedtls_upstream
        URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.3.tar.gz
        URL_HASH SHA256=e69c4c13377e89b9d696006ef9c8258e3be75b6dbd464cfd573360482b1a1f4e
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    # Keep vendored mbedTLS static even when parent sets BUILD_SHARED_LIBS.
    set(_pn_bsl_save ${BUILD_SHARED_LIBS})
    set(BUILD_SHARED_LIBS OFF)
    FetchContent_MakeAvailable(mbedtls_upstream)
    set(BUILD_SHARED_LIBS ${_pn_bsl_save})

    foreach(_tgt IN ITEMS mbedtls mbedcrypto mbedx509)
        if(NOT TARGET MbedTLS::${_tgt} AND TARGET ${_tgt})
            add_library(MbedTLS::${_tgt} ALIAS ${_tgt})
        endif()
    endforeach()

    message(STATUS "[PubNub] mbedTLS 3.6.3 (fetched)")
endfunction()

set(BUILD_SHARED_LIBS ${_pn_saved_bsl})
