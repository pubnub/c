# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# cjson serialization -- always built against the selected
# serialization target (which maps to the cjson implementation when
# PUBNUB_PROVIDER_SERIALIZATION=cjson) rather than pulling the source
# directly. That way the test exercises the same binary consumers
# will see.
if(PUBNUB_PROVIDER_SERIALIZATION STREQUAL "cjson")
    pubnub_add_unit_test(
        test_provider_serialization_cjson_units
        SOURCES cjson_serialization_units.c
        LIBS pubnub
    )
endif()

# jsmn serialization -- when the active provider is jsmn we link
# against the resolved pubnub_provider_serialization library.
# Otherwise we compile the backend directly into the test executable
# so coverage is retained even when the active configuration selects
# a different backend (e.g. cjson). The direct-source path resolves
# jsmn via FetchContent (idempotent if already resolved by the
# provider build).
if(PUBNUB_PROVIDER_SERIALIZATION STREQUAL "jsmn")
    pubnub_add_unit_test(
        test_provider_serialization_jsmn_units
        SOURCES jsmn_serialization_units.c
        LIBS pubnub
    )
else()
    # Resolve jsmn sources (no-op if already populated by provider build)
    pubnub_resolve_jsmn()

    pubnub_add_unit_test(
        test_provider_serialization_jsmn_units
        SOURCES
            jsmn_serialization_units.c
            ${PN_PROVIDERS_SRC_DIR}/serialization/jsmn/serialization_jsmn.c
            ${PN_PROVIDERS_SRC_DIR}/serialization/jsmn/jsmn_impl.c
            ${CMAKE_SOURCE_DIR}/src/core/pn_format.c
            ${PN_PROVIDERS_SRC_DIR}/serialization/jsmn/pn_json_unescape.c
    )
    target_include_directories(
        test_provider_serialization_jsmn_units
        PRIVATE ${PN_JSMN_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src/core
    )
    if(NOT MSVC)
        set_source_files_properties(
            ${PN_PROVIDERS_SRC_DIR}/serialization/jsmn/jsmn_impl.c
            PROPERTIES COMPILE_OPTIONS "-w"
        )
    endif()
endif()
