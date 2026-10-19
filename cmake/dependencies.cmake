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

set(PUBNUB_OPENSSL_LIB_DIR
    ""
    CACHE STRING
    "Directory with the OpenSSL libraries (for non-standard layouts): absolute,
or relative to OPENSSL_ROOT_DIR (which is then required). When set, bypasses
FindOpenSSL and takes precedence over OPENSSL_CRYPTO_LIBRARY / OPENSSL_SSL_LIBRARY."
)

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
# pubnub_resolve_openssl([OPTIONAL])
#
# Creates the global OpenSSL::Crypto and OpenSSL::SSL imported targets and
# sets OPENSSL_VERSION (INTERNAL cache).
#
# Resolution paths, in precedence order:
#   1. Non-empty PUBNUB_OPENSSL_LIB_DIR. An absolute path is used as-is
#      (OPENSSL_ROOT_DIR not required); a relative path is resolved against
#      OPENSSL_ROOT_DIR, and is a fatal error when the root is unset.
#      Libraries are searched only in that directory (CMAKE_FIND_ROOT_PATH is
#      ignored there) and FindOpenSSL is bypassed. Wins over any
#      OPENSSL_CRYPTO_LIBRARY / OPENSSL_SSL_LIBRARY values.
#      Searched names: crypto, libcrypto, libcrypto_static and ssl, libssl,
#      libssl_static (with the usual platform prefixes/suffixes).
#   2. Both OPENSSL_CRYPTO_LIBRARY and OPENSSL_SSL_LIBRARY supplied by the
#      user (full paths).
#   3. Otherwise plain find_package(OpenSSL REQUIRED).
#
# Pass OPTIONAL to make path 3 non-fatal: when no OpenSSL is found the
# function returns without creating any target (callers test
# TARGET OpenSSL::Crypto). An explicit PUBNUB_OPENSSL_LIB_DIR or
# OPENSSL_*_LIBRARY (paths 1 and 2) makes every failure fatal even under
# OPTIONAL, because the user explicitly asked for that location.
#
# Header search in the custom paths (1 and 2): OPENSSL_INCLUDE_DIR (strict),
# else OPENSSL_ROOT_DIR/include when the root is set (strict), else
# <crypto lib dir>/../include and ../../include, then default system paths.
# The explicit locations ignore CMAKE_FIND_ROOT_PATH; the final default-path
# search honours it.
#
# Re-configure: FindOpenSSL fills the same cache variables a user would set
# (OPENSSL_CRYPTO_LIBRARY, OPENSSL_SSL_LIBRARY, OPENSSL_INCLUDE_DIR). After a
# find_package run, each value that was NOT user-supplied is recorded in an
# INTERNAL cache entry (PN_OPENSSL_FP_*); a variable equal to its entry is
# treated as find_package output, anything else as user input. A value the
# user supplied before find_package ran is never recorded.
#
# Static OpenSSL: the custom OpenSSL::Crypto always carries the system
# libraries a static libcrypto needs (ws2_32/crypt32/... on Windows, dl and
# threads elsewhere); they are harmless for shared libraries.
# ---------------------------------------------------------------------------
function(pubnub_resolve_openssl)
    cmake_parse_arguments(PARSE_ARGV 0 PN_OSSL "OPTIONAL" "" "")

    if(TARGET OpenSSL::Crypto)
        return()
    endif()

    # A value is user input when set and different from what find_package left.
    set(PN_USER_CRYPTO FALSE)
    if(
        OPENSSL_CRYPTO_LIBRARY
        AND NOT "${OPENSSL_CRYPTO_LIBRARY}" STREQUAL "${PN_OPENSSL_FP_CRYPTO}"
    )
        set(PN_USER_CRYPTO TRUE)
    endif()
    set(PN_USER_SSL FALSE)
    if(OPENSSL_SSL_LIBRARY AND NOT "${OPENSSL_SSL_LIBRARY}" STREQUAL "${PN_OPENSSL_FP_SSL}")
        set(PN_USER_SSL TRUE)
    endif()
    set(PN_USER_INCLUDE "")
    set(PN_USER_INC FALSE)
    if(OPENSSL_INCLUDE_DIR AND NOT "${OPENSSL_INCLUDE_DIR}" STREQUAL "${PN_OPENSSL_FP_INCLUDE}")
        set(PN_USER_INCLUDE "${OPENSSL_INCLUDE_DIR}")
        set(PN_USER_INC TRUE)
    endif()

    set(PN_EXPLICIT_LIBS FALSE)
    if(PN_USER_CRYPTO AND PN_USER_SSL)
        set(PN_EXPLICIT_LIBS TRUE)
    endif()

    set(PN_LIBDIR_MODE FALSE)
    if(PUBNUB_OPENSSL_LIB_DIR)
        set(PN_LIBDIR_MODE TRUE)
        set(PN_EXPLICIT_LIBS FALSE)
        file(TO_CMAKE_PATH "${PUBNUB_OPENSSL_LIB_DIR}" PN_LIBDIR_NORM)
        if(IS_ABSOLUTE "${PN_LIBDIR_NORM}")
            set(PN_OPENSSL_LIB_PATH "${PN_LIBDIR_NORM}")
        elseif(OPENSSL_ROOT_DIR)
            set(PN_OPENSSL_LIB_PATH "${OPENSSL_ROOT_DIR}/${PN_LIBDIR_NORM}")
        else()
            message(
                FATAL_ERROR
                "[PubNub] PUBNUB_OPENSSL_LIB_DIR='${PUBNUB_OPENSSL_LIB_DIR}' is relative but "
                "OPENSSL_ROOT_DIR is not set. Pass an absolute PUBNUB_OPENSSL_LIB_DIR or set "
                "OPENSSL_ROOT_DIR."
            )
        endif()
    endif()

    if(NOT PN_LIBDIR_MODE AND NOT PN_EXPLICIT_LIBS)
        if(PN_OSSL_OPTIONAL)
            find_package(OpenSSL QUIET)
            if(NOT OpenSSL_FOUND)
                return()
            endif()
        else()
            find_package(OpenSSL REQUIRED)
        endif()
        foreach(PN_TGT IN ITEMS OpenSSL::SSL OpenSSL::Crypto)
            if(TARGET ${PN_TGT})
                set_target_properties(${PN_TGT} PROPERTIES IMPORTED_GLOBAL TRUE)
            endif()
        endforeach()

        set(PN_FP_NAMES PN_OPENSSL_FP_CRYPTO PN_OPENSSL_FP_SSL PN_OPENSSL_FP_INCLUDE)
        set(PN_FP_SOURCES OPENSSL_CRYPTO_LIBRARY OPENSSL_SSL_LIBRARY OPENSSL_INCLUDE_DIR)
        set(PN_FP_USER ${PN_USER_CRYPTO} ${PN_USER_SSL} ${PN_USER_INC})
        foreach(PN_IDX RANGE 2)
            list(GET PN_FP_NAMES ${PN_IDX} PN_FP_NAME)
            list(GET PN_FP_SOURCES ${PN_IDX} PN_FP_SOURCE)
            list(GET PN_FP_USER ${PN_IDX} PN_FP_IS_USER)
            if(PN_FP_IS_USER)
                unset(${PN_FP_NAME} CACHE)
            else()
                set(${PN_FP_NAME}
                    "${${PN_FP_SOURCE}}"
                    CACHE INTERNAL
                    "Value produced by find_package"
                )
            endif()
        endforeach()

        set(OPENSSL_VERSION "${OPENSSL_VERSION}" CACHE INTERNAL "Resolved OpenSSL version")
        message(STATUS "[PubNub] OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_CRYPTO_LIBRARY}")
        return()
    endif()

    # Libraries.
    set(PN_OPENSSL_CRYPTO_LIB "")
    set(PN_OPENSSL_SSL_LIB "")
    if(PN_EXPLICIT_LIBS)
        set(PN_OPENSSL_CRYPTO_LIB "${OPENSSL_CRYPTO_LIBRARY}")
        set(PN_OPENSSL_SSL_LIB "${OPENSSL_SSL_LIBRARY}")
        foreach(PN_LIB IN ITEMS "${PN_OPENSSL_CRYPTO_LIB}" "${PN_OPENSSL_SSL_LIB}")
            if(NOT EXISTS "${PN_LIB}")
                message(FATAL_ERROR "[PubNub] OpenSSL library does not exist: ${PN_LIB}")
            endif()
        endforeach()
    else()
        unset(PN_OSSL_TMP_CRYPTO CACHE)
        unset(PN_OSSL_TMP_SSL CACHE)
        find_library(
            PN_OSSL_TMP_CRYPTO
            NAMES crypto libcrypto libcrypto_static
            PATHS "${PN_OPENSSL_LIB_PATH}"
            NO_DEFAULT_PATH
            NO_CMAKE_FIND_ROOT_PATH
        )
        find_library(
            PN_OSSL_TMP_SSL
            NAMES ssl libssl libssl_static
            PATHS "${PN_OPENSSL_LIB_PATH}"
            NO_DEFAULT_PATH
            NO_CMAKE_FIND_ROOT_PATH
        )
        set(PN_OPENSSL_CRYPTO_LIB "${PN_OSSL_TMP_CRYPTO}")
        set(PN_OPENSSL_SSL_LIB "${PN_OSSL_TMP_SSL}")
        unset(PN_OSSL_TMP_CRYPTO CACHE)
        unset(PN_OSSL_TMP_SSL CACHE)
        if(NOT PN_OPENSSL_CRYPTO_LIB)
            message(
                FATAL_ERROR
                "[PubNub] OpenSSL crypto library not found in ${PN_OPENSSL_LIB_PATH}"
            )
        endif()
        if(NOT PN_OPENSSL_SSL_LIB)
            message(FATAL_ERROR "[PubNub] OpenSSL SSL library not found in ${PN_OPENSSL_LIB_PATH}")
        endif()
    endif()

    # Headers.
    unset(PN_OSSL_TMP_INC CACHE)
    if(PN_USER_INCLUDE)
        find_path(
            PN_OSSL_TMP_INC
            NAMES openssl/ssl.h
            PATHS "${PN_USER_INCLUDE}"
            NO_DEFAULT_PATH
            NO_CMAKE_FIND_ROOT_PATH
        )
        set(PN_INC_WHERE "${PN_USER_INCLUDE}")
    elseif(OPENSSL_ROOT_DIR)
        find_path(
            PN_OSSL_TMP_INC
            NAMES openssl/ssl.h
            PATHS "${OPENSSL_ROOT_DIR}/include"
            NO_DEFAULT_PATH
            NO_CMAKE_FIND_ROOT_PATH
        )
        set(PN_INC_WHERE "${OPENSSL_ROOT_DIR}/include")
    else()
        get_filename_component(PN_LIB_DIR "${PN_OPENSSL_CRYPTO_LIB}" DIRECTORY)
        find_path(
            PN_OSSL_TMP_INC
            NAMES openssl/ssl.h
            PATHS "${PN_LIB_DIR}/../include" "${PN_LIB_DIR}/../../include"
            NO_DEFAULT_PATH
            NO_CMAKE_FIND_ROOT_PATH
        )
        if(NOT PN_OSSL_TMP_INC)
            find_path(PN_OSSL_TMP_INC NAMES openssl/ssl.h)
        endif()
        set(PN_INC_WHERE
            "${PN_LIB_DIR}/../include, ${PN_LIB_DIR}/../../include or the default include paths"
        )
    endif()
    set(PN_OPENSSL_INC "${PN_OSSL_TMP_INC}")
    unset(PN_OSSL_TMP_INC CACHE)
    if(NOT PN_OPENSSL_INC)
        message(
            FATAL_ERROR
            "[PubNub] openssl/ssl.h not found in ${PN_INC_WHERE}; set OPENSSL_INCLUDE_DIR"
        )
    endif()

    # Version: OPENSSL_VERSION_STR (3.x), else OPENSSL_VERSION_TEXT (1.1.x).
    set(PN_OPENSSL_VER "")
    set(PN_OPENSSLV_H "${PN_OPENSSL_INC}/openssl/opensslv.h")
    if(NOT EXISTS "${PN_OPENSSLV_H}")
        message(FATAL_ERROR "[PubNub] openssl/opensslv.h not found in ${PN_OPENSSL_INC}")
    endif()
    file(
        STRINGS "${PN_OPENSSLV_H}"
        PN_VER_LINE
        REGEX "^#[ \t]*define[ \t]+OPENSSL_VERSION_STR[ \t]+\"[^\"]+\""
        LIMIT_COUNT 1
    )
    if(PN_VER_LINE MATCHES "OPENSSL_VERSION_STR[ \t]+\"([^\"]+)\"")
        set(PN_OPENSSL_VER "${CMAKE_MATCH_1}")
    else()
        file(
            STRINGS "${PN_OPENSSLV_H}"
            PN_VER_LINE
            REGEX "^#[ \t]*define[ \t]+OPENSSL_VERSION_TEXT[ \t]+\"OpenSSL [^\"]+\""
            LIMIT_COUNT 1
        )
        if(PN_VER_LINE MATCHES "OPENSSL_VERSION_TEXT[ \t]+\"OpenSSL ([^ \"]+)")
            set(PN_OPENSSL_VER "${CMAKE_MATCH_1}")
        endif()
    endif()
    if(NOT PN_OPENSSL_VER)
        message(FATAL_ERROR "[PubNub] Unable to determine OpenSSL version from ${PN_OPENSSLV_H}")
    endif()

    # System libraries needed when libcrypto is static.
    set(PN_OPENSSL_SYSLIBS "")
    if(WIN32)
        set(PN_OPENSSL_SYSLIBS
            ws2_32
            crypt32
            advapi32
            user32
            gdi32
        )
    else()
        find_package(Threads REQUIRED)
        set_target_properties(Threads::Threads PROPERTIES IMPORTED_GLOBAL TRUE)
        set(PN_OPENSSL_SYSLIBS ${CMAKE_DL_LIBS} Threads::Threads)
    endif()

    add_library(OpenSSL::Crypto UNKNOWN IMPORTED GLOBAL)
    set_target_properties(
        OpenSSL::Crypto
        PROPERTIES
            IMPORTED_LOCATION "${PN_OPENSSL_CRYPTO_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${PN_OPENSSL_INC}"
            INTERFACE_LINK_LIBRARIES "${PN_OPENSSL_SYSLIBS}"
    )
    add_library(OpenSSL::SSL UNKNOWN IMPORTED GLOBAL)
    set_target_properties(
        OpenSSL::SSL
        PROPERTIES
            IMPORTED_LOCATION "${PN_OPENSSL_SSL_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${PN_OPENSSL_INC}"
            INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
    )

    set(OPENSSL_VERSION "${PN_OPENSSL_VER}" CACHE INTERNAL "Resolved OpenSSL version")
    message(
        STATUS
        "[PubNub] OpenSSL ${OPENSSL_VERSION}: ${PN_OPENSSL_CRYPTO_LIB} (headers: ${PN_OPENSSL_INC})"
    )
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
