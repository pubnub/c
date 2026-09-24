# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# ---------------------------------------------------------------------------
# Unit / integration test infrastructure (requires PUBNUB_BUILD_TESTS=ON).
# Fuzz tests live in tests/fuzz/ and are gated separately.
# ---------------------------------------------------------------------------
if(NOT PUBNUB_BUILD_TESTS AND NOT PUBNUB_BUILD_FUZZ_TESTS AND NOT PUBNUB_BUILD_IOT_TESTS)
    return()
endif()

if(PUBNUB_BUILD_TESTS)
    # ---------------------------------------------------------------------------
    # CMocka resolution: system install / user path -> FetchContent fallback.
    #
    # Use -Dcmocka_ROOT=<path> or -DCMAKE_PREFIX_PATH=<path> to point at a
    # local cmocka installation. When not found, cmocka 2.0.2 is fetched
    # from the upstream repository automatically.
    # ---------------------------------------------------------------------------

    find_package(cmocka 2.0 QUIET)

    if(cmocka_FOUND)
        message(STATUS "[PubNub] Found system cmocka: ${cmocka_VERSION}")
    else()
        message(STATUS "[PubNub] cmocka not found locally — fetching 2.0.2 via FetchContent")

        include(FetchContent)
        FetchContent_Declare(
            cmocka
            GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
            # Pinned to immutable commit SHA (tags are mutable / repointable).
            GIT_TAG
                fefa2b8a023121f7235e18ed17249e4012dd144f # cmocka-2.0.2
            EXCLUDE_FROM_ALL
        )

        set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "" FORCE)
        set(UNIT_TESTING ON CACHE BOOL "" FORCE)

        FetchContent_MakeAvailable(cmocka)
    endif()

    set(PN_PROVIDERS_SRC_DIR "${CMAKE_SOURCE_DIR}/src/providers")

    # ---------------------------------------------------------------------------
    # pubnub_add_unit_test(<name> SOURCES src... [LIBS lib...])
    #
    # Compiles the listed SOURCES (test code + module-under-test sources)
    # into a standalone executable. Links cmocka and pubnub_public_headers
    # only — no SDK, no provider libraries.
    # ---------------------------------------------------------------------------
    function(pubnub_add_unit_test name)
        cmake_parse_arguments(_T "" "" "SOURCES;LIBS" ${ARGN})
        if(NOT _T_SOURCES)
            message(FATAL_ERROR "pubnub_add_unit_test(${name}): SOURCES is required")
        endif()

        add_executable(${name} ${_T_SOURCES})

        list(TRANSFORM _T_LIBS REPLACE "^pubnub$" "${PUBNUB_TEST_LINK_TARGET}")
        target_link_libraries(${name} PRIVATE cmocka pubnub_public_headers ${_T_LIBS})

        # tests/ is on the path so shared helpers resolve as
        # "support/<helper>.h" from any test subdirectory.
        target_include_directories(
            ${name}
            PRIVATE
                "${CMAKE_SOURCE_DIR}/src"
                "${CMAKE_SOURCE_DIR}/tests"
                "${CMAKE_BINARY_DIR}/src/core"
        )

        set_target_properties(
            ${name}
            PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        )

        pubnub_target_sanitizers(${name})

        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    # ---------------------------------------------------------------------------
    # pubnub_add_integration_test(<name> SOURCES src... [LIBS lib...])
    #
    # Links against the full SDK (pubnub aggregate library with the
    # selected provider set) and cmocka. Used by CI matrix jobs that
    # test a specific provider combination end-to-end.
    # ---------------------------------------------------------------------------
    function(pubnub_add_integration_test name)
        cmake_parse_arguments(_T "" "" "SOURCES;LIBS" ${ARGN})
        if(NOT _T_SOURCES)
            message(FATAL_ERROR "pubnub_add_integration_test(${name}): SOURCES is required")
        endif()

        add_executable(${name} ${_T_SOURCES})

        target_link_libraries(${name} PRIVATE ${_T_LIBS})

        target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}/src")

        set_target_properties(
            ${name}
            PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        )

        pubnub_target_sanitizers(${name})

        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    # ---------------------------------------------------------------------------
    # Subdirectories
    # ---------------------------------------------------------------------------
    add_subdirectory(core)
    add_subdirectory(features)
    add_subdirectory(providers)

    option(
        PUBNUB_BUILD_INTEGRATION_TESTS
        "Build integration tests that make real HTTP requests to PubNub sandbox"
        OFF
    )
    option(
        PUBNUB_BUILD_CROSS_SDK_TESTS
        "Build cross-SDK parity tests (requires PUBNUB_BUILD_INTEGRATION_TESTS=ON and Node.js)"
        OFF
    )
    if(PUBNUB_BUILD_CROSS_SDK_TESTS AND NOT PUBNUB_BUILD_INTEGRATION_TESTS)
        message(
            FATAL_ERROR
            "[PubNub] PUBNUB_BUILD_CROSS_SDK_TESTS requires PUBNUB_BUILD_INTEGRATION_TESTS=ON"
        )
    endif()
    if(PUBNUB_BUILD_INTEGRATION_TESTS)
        add_subdirectory(integration)
    endif()
    if(PUBNUB_BUILD_CROSS_SDK_TESTS)
        add_subdirectory(cross_sdk)
    endif()
endif() # PUBNUB_BUILD_TESTS

# ---------------------------------------------------------------------------
# Fuzz test targets (independent of unit/integration test infrastructure).
# ---------------------------------------------------------------------------
if(PUBNUB_BUILD_FUZZ_TESTS)
    add_subdirectory(fuzz)
endif()

# ---------------------------------------------------------------------------
# IoT kitchensink end-to-end test (ESP-IDF only, built via idf.py).
# ---------------------------------------------------------------------------
add_subdirectory(iot_kitchensink)
