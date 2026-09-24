# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

if(NOT PUBNUB_BUILD_FUZZ_TESTS)
    return()
endif()

# Fuzz targets require a compiler that supports -fsanitize=fuzzer.
# The fuzzer flag needs both compile AND link support; check_c_compiler_flag
# only tests compilation, so we use check_c_source_compiles with link options.
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer,address")
set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer,address")
check_c_source_compiles(
    "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { (void)d; (void)s; return 0; }"
    PUBNUB_HAS_FUZZER
)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
if(NOT PUBNUB_HAS_FUZZER)
    message(WARNING "[PubNub] Compiler does not support -fsanitize=fuzzer; skipping fuzz targets")
    return()
endif()

function(pubnub_add_fuzz_target name source)
    add_executable(${name} ${source})
    # Link only against the pubnub INTERFACE target. The INTERFACE expansion
    # places pn_core before the provider archives, giving GNU ld the correct
    # left-to-right order: pn_core (references pn_allocator_default) ->
    # pubnub_provider_allocator (defines it). Listing providers explicitly
    # would put them before pn_core in the link command and break GNU ld.
    target_link_libraries(${name} PRIVATE ${PUBNUB_TEST_LINK_TARGET})
    target_include_directories(
        ${name}
        PRIVATE "${CMAKE_SOURCE_DIR}/src" "${CMAKE_BINARY_DIR}/src/core"
    )
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address)
    set_target_properties(
        ${name}
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
endfunction()

pubnub_add_fuzz_target(fuzz_service_error fuzz_service_error.c)
pubnub_add_fuzz_target(fuzz_serialization fuzz_serialization.c)
pubnub_add_fuzz_target(fuzz_url_encode fuzz_url_encode.c)
pubnub_add_fuzz_target(fuzz_publish_response fuzz_publish_response.c)
pubnub_add_fuzz_target(fuzz_base64 fuzz_base64.c)
pubnub_add_fuzz_target(fuzz_cbor_decode fuzz_cbor_decode.c)

# HTTP parser fuzz target: compile http_parser.c directly (the parser is
# a self-contained module regardless of which transport is the default).
pubnub_add_fuzz_target(fuzz_http_parse fuzz_http_parse.c)
target_sources(
    fuzz_http_parse
    PRIVATE "${CMAKE_SOURCE_DIR}/src/providers/transport/socket/http_parser.c"
)
