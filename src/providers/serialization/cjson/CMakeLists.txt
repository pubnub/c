# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# cjson serialization: cJSON-backed provider for hosted profiles.
#
# cJSON is fetched via FetchContent (pinned to v1.7.18).
# See cmake/dependencies.cmake for the FetchContent declaration.

pubnub_resolve_cjson()

# cJSON keeps its last-parse-error in a file-scope `static error global_error`
# that every cJSON_Parse*() call overwrites. With several contexts parsing on
# their own background threads that is a (benign, the SDK never reads it)
# data race. When thread safety is enabled and the toolchain supports
# thread-local storage, compile a copy of cJSON.c in which that one object is
# thread-local; the upstream source is untouched. Otherwise the upstream file
# is used as is and the object stays shared.
option(PN_CJSON_FORCE_NO_TLS "Use the untouched upstream cJSON.c (global_error stays shared)" OFF)

set(PN_CJSON_SOURCE "${PN_CJSON_SOURCE_DIR}/cJSON.c")
set(PN_CJSON_USE_TLS OFF)
if(PUBNUB_CFG_THREAD_SAFETY)
    if(MSVC)
        set(PN_CJSON_TLS_KEYWORD "__declspec(thread)")
    else()
        set(PN_CJSON_TLS_KEYWORD "__thread")
    endif()

    if(PN_CJSON_FORCE_NO_TLS)
        # Plain (non-cache) variable: a cached result would make the probe
        # skip itself on every later configure.
        set(PN_CJSON_HAVE_TLS OFF)
    else()
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_DEFINITIONS "-DPN_CJSON_THREAD_LOCAL=${PN_CJSON_TLS_KEYWORD}")
        # Cross toolchains that cannot link a host-style executable get a
        # compile-only answer: the probe then proves that the keyword
        # compiles, not that it links. Toolchains that compile __thread but
        # lack TLS at link time (arm-none-eabi without TLS support, Zephyr
        # without CONFIG_THREAD_LOCAL_STORAGE) must pass
        # -DPN_CJSON_FORCE_NO_TLS=ON.
        set(PN_CJSON_SAVED_TARGET_TYPE "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
        if(CMAKE_CROSSCOMPILING)
            set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
        endif()
        check_c_source_compiles(
            "PN_CJSON_THREAD_LOCAL int pn_tls_probe; int main(void) { pn_tls_probe = 1; return pn_tls_probe - 1; }"
            PN_CJSON_HAVE_TLS
        )
        set(CMAKE_TRY_COMPILE_TARGET_TYPE "${PN_CJSON_SAVED_TARGET_TYPE}")
        unset(CMAKE_REQUIRED_DEFINITIONS)
    endif()

    if(PN_CJSON_HAVE_TLS)
        set(PN_CJSON_USE_TLS ON)
        set(PN_CJSON_ERROR_DECL "static error global_error")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${PN_CJSON_SOURCE}")
        file(READ "${PN_CJSON_SOURCE}" PN_CJSON_TEXT)
        string(FIND "${PN_CJSON_TEXT}" "${PN_CJSON_ERROR_DECL}" PN_CJSON_DECL_POS)
        if(PN_CJSON_DECL_POS EQUAL -1)
            message(
                FATAL_ERROR
                "[PubNub] cJSON.c no longer declares '${PN_CJSON_ERROR_DECL}'; "
                "update the thread-local transform in "
                "src/providers/serialization/cjson/CMakeLists.txt"
            )
        endif()
        string(
            REPLACE "${PN_CJSON_ERROR_DECL}"
            "static PN_CJSON_THREAD_LOCAL error global_error"
            PN_CJSON_TEXT
            "${PN_CJSON_TEXT}"
        )
        # Under _deps so the generated copy is treated like the fetched
        # upstream source by the static-analysis file filters.
        set(PN_CJSON_TLS_DIR "${CMAKE_BINARY_DIR}/_deps/cjson_tls")
        file(WRITE "${PN_CJSON_TLS_DIR}/cJSON_tls.c.in" "${PN_CJSON_TEXT}")
        configure_file("${PN_CJSON_TLS_DIR}/cJSON_tls.c.in" "${PN_CJSON_TLS_DIR}/cJSON.c" COPYONLY)
        set(PN_CJSON_SOURCE "${PN_CJSON_TLS_DIR}/cJSON.c")
    else()
        message(
            WARNING
            "[PubNub] cJSON global_error stays shared: no thread-local storage support "
            "(or PN_CJSON_FORCE_NO_TLS=ON was set; pass it explicitly on toolchains "
            "whose TLS support fails only at link time)"
        )
    endif()
endif()

_pn_sdk_library(pubnub_provider_serialization serialization_cjson.c "${PN_CJSON_SOURCE}")

target_link_libraries(pubnub_provider_serialization PUBLIC pubnub_public_headers)

target_include_directories(pubnub_provider_serialization PRIVATE "${PN_CJSON_SOURCE_DIR}")

# Cross-check: cJSON's global memory hooks force the SDK to use libc
# malloc/free for cJSON allocations regardless of the configured
# allocator. The CMake-level guard in _pubnub_validate_provider_combinations()
# fails configure for any cjson + non-stdlib allocator combination; this
# compile-definition lets the C source `#error` defensively cross-check
# the same invariant when consumers invoke the build out-of-band.
if("${PUBNUB_PROVIDER_ALLOCATOR}" STREQUAL "stdlib")
    target_compile_definitions(pubnub_provider_serialization PRIVATE PN_BUILTIN_ALLOCATOR_STDLIB=1)
else()
    target_compile_definitions(pubnub_provider_serialization PRIVATE PN_BUILTIN_ALLOCATOR_STDLIB=0)
endif()

# Cap cJSON's parse-time recursion at the SDK-wide nesting-depth budget so a
# deeply nested payload fails parse cleanly instead of exhausting the stack.
target_compile_definitions(
    pubnub_provider_serialization
    PRIVATE CJSON_NESTING_LIMIT=${PUBNUB_CFG_JSON_MAX_NESTING_DEPTH}
)

if(PUBNUB_CFG_THREAD_SAFETY)
    if(MSVC)
        target_compile_definitions(
            pubnub_provider_serialization
            PRIVATE "PN_CJSON_THREAD_LOCAL=__declspec(thread)"
        )
    else()
        target_compile_definitions(
            pubnub_provider_serialization
            PRIVATE PN_CJSON_THREAD_LOCAL=__thread
        )
    endif()
endif()

set_target_properties(
    pubnub_provider_serialization
    PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
)

pubnub_target_warnings(pubnub_provider_serialization)
pubnub_target_sanitizers(pubnub_provider_serialization)

# Vendored cJSON.c uses libc sprintf for number-to-string conversion, which
# Apple's SDK marks deprecated. The combination of -Wall + -Werror + Apple
# clang's UBSan instrumentation surfaces it as a fatal warning. Suppress
# deprecated-declarations for the vendored TU only — our own code under
# serialization_cjson.c still gets the full warning treatment.
if(NOT MSVC)
    set_source_files_properties(
        "${PN_CJSON_SOURCE}"
        PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-declarations;-Wno-float-conversion"
    )
endif()
