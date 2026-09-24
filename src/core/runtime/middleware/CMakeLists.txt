# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Middleware: transport decorators that enrich requests.

include(sources.cmake)
include(signature_middleware/sources.cmake)
include(retry_middleware_sources.cmake)
include(compression_middleware/sources.cmake)

# Dependency resolution (conditional).
if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
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
    endif()
endif()

set(PN_MIDDLEWARE_SOURCES ${PN_CORE_MIDDLEWARE_BASE_SOURCES})

if(PUBNUB_ENABLE_PAM)
    list(APPEND PN_MIDDLEWARE_SOURCES ${PN_MIDDLEWARE_SIGNATURE_SOURCES})
endif()

if(PUBNUB_ENABLE_RETRY)
    list(APPEND PN_MIDDLEWARE_SOURCES ${PN_MIDDLEWARE_RETRY_SOURCES})
endif()

if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    list(APPEND PN_MIDDLEWARE_SOURCES ${PN_MIDDLEWARE_COMPRESSION_SOURCES})
endif()

_pn_sdk_library(pn_core_middleware ${PN_MIDDLEWARE_SOURCES})

target_include_directories(pn_core_middleware PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../..")

target_link_libraries(
    pn_core_middleware
    PRIVATE pubnub_public_headers
    PRIVATE pn_core_protocol_common
    PRIVATE pn_core_fmt
)

if(PUBNUB_ENABLE_RETRY)
    target_link_libraries(pn_core_middleware PRIVATE pn_core_timer)
endif()

if(PUBNUB_ENABLE_REQUEST_COMPRESSION)
    if(ZLIB_FOUND)
        target_link_libraries(pn_core_middleware PUBLIC ZLIB::ZLIB)
    else()
        target_link_libraries(pn_core_middleware PUBLIC zlibstatic)
        target_include_directories(
            pn_core_middleware
            PUBLIC "${zlib_upstream_SOURCE_DIR}" "${zlib_upstream_BINARY_DIR}"
        )
    endif()
endif()

set_target_properties(
    pn_core_middleware
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pn_core_middleware)
pubnub_target_visibility(pn_core_middleware)
pubnub_target_sanitizers(pn_core_middleware)
