# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# cjson serialization: cJSON-backed provider for hosted profiles.
#
# cJSON is fetched via FetchContent (pinned to v1.7.18).
# See cmake/dependencies.cmake for the FetchContent declaration.

pubnub_resolve_cjson()

_pn_sdk_library(
    pubnub_provider_serialization
    serialization_cjson.c
    "${PN_CJSON_SOURCE_DIR}/cJSON.c"
)

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
        "${PN_CJSON_SOURCE_DIR}/cJSON.c"
        PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-declarations;-Wno-float-conversion"
    )
endif()
