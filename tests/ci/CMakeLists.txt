# Standalone CI probe (NOT part of the SDK build; not add_subdirectory'd).
#
# Pins the documented MSVC limitation that PUBNUB_CLEAR_VALUE is not a
# constant expression when the SDK is consumed as a DLL (PUBNUB_SHARED).
#
#   cmake -S tests/ci -B build/ci-clear-value \
#       -DPN_SDK_INCLUDE_DIR=<repo>/include \
#       -DPN_SDK_CONFIG_INCLUDE_DIR=<sdk-build>/include
cmake_minimum_required(VERSION 3.20)
project(pubnub_ci_clear_value_probe LANGUAGES C)

set(PN_SDK_INCLUDE_DIR "" CACHE PATH "Public header directory (<repo>/include)")
set(PN_SDK_CONFIG_INCLUDE_DIR "" CACHE PATH "Directory containing generated pubnub/config.h")

if(NOT PN_SDK_INCLUDE_DIR OR NOT PN_SDK_CONFIG_INCLUDE_DIR)
    message(FATAL_ERROR "PN_SDK_INCLUDE_DIR and PN_SDK_CONFIG_INCLUDE_DIR are required")
endif()

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(PN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/shared_clear_value_check.c")
set(PN_INCLUDES "-DINCLUDE_DIRECTORIES=${PN_SDK_INCLUDE_DIR};${PN_SDK_CONFIG_INCLUDE_DIR}")

# Case 1: block-scope usage against a DLL consumer must compile.
try_compile(
    PN_BLOCK_SHARED_OK
    "${CMAKE_BINARY_DIR}/probe_block_shared"
    SOURCES "${PN_SRC}"
    COMPILE_DEFINITIONS -DPUBNUB_SHARED
    CMAKE_FLAGS "${PN_INCLUDES}"
    OUTPUT_VARIABLE PN_BLOCK_SHARED_LOG
)
if(NOT PN_BLOCK_SHARED_OK)
    message(
        FATAL_ERROR
        "block-scope PUBNUB_CLEAR_VALUE failed with PUBNUB_SHARED:\n${PN_BLOCK_SHARED_LOG}"
    )
endif()
message(STATUS "OK: block-scope + PUBNUB_SHARED compiles")

# Case 2 (control): file-scope initializer compiles for static consumers.
try_compile(
    PN_FILE_STATIC_OK
    "${CMAKE_BINARY_DIR}/probe_file_static"
    SOURCES "${PN_SRC}"
    COMPILE_DEFINITIONS -DPN_CHECK_FILE_SCOPE
    CMAKE_FLAGS "${PN_INCLUDES}"
    OUTPUT_VARIABLE PN_FILE_STATIC_LOG
)
if(NOT PN_FILE_STATIC_OK)
    message(
        FATAL_ERROR
        "file-scope PUBNUB_CLEAR_VALUE failed for static consumer:\n${PN_FILE_STATIC_LOG}"
    )
endif()
message(STATUS "OK: file-scope + static consumer compiles")

if(NOT MSVC)
    message(STATUS "SKIP: C2099 expectation is MSVC-specific")
    return()
endif()

# Case 3 (expectation, MSVC only; other compilers accept the initializer): file-scope initializer against dllimport data must
# fail with C2099. If this starts compiling, the limitation (and the note in
# pubnub/types.h) must be revisited; if it fails differently, investigate.
try_compile(
    PN_FILE_SHARED_OK
    "${CMAKE_BINARY_DIR}/probe_file_shared"
    SOURCES "${PN_SRC}"
    COMPILE_DEFINITIONS -DPN_CHECK_FILE_SCOPE -DPUBNUB_SHARED
    CMAKE_FLAGS "${PN_INCLUDES}"
    OUTPUT_VARIABLE PN_FILE_SHARED_LOG
)
if(PN_FILE_SHARED_OK)
    message(
        FATAL_ERROR
        "EXPECTATION CHANGED: file-scope PUBNUB_CLEAR_VALUE now compiles with PUBNUB_SHARED (expected C2099). Update docs in pubnub/types.h."
    )
endif()
if(NOT PN_FILE_SHARED_LOG MATCHES "C2099")
    message(
        FATAL_ERROR
        "file-scope + PUBNUB_SHARED failed, but not with C2099:\n${PN_FILE_SHARED_LOG}"
    )
endif()
message(STATUS "OK: file-scope + PUBNUB_SHARED fails with C2099 as expected")
