# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

pubnub_add_unit_test(test_core_client_units SOURCES client_units.c LIBS pubnub)

# Timer unit tests need the runtime OBJECT library.
# pn_core_middleware provides middleware symbols (pipeline dep).
# pn_core_protocol_common provides pn_url_encode (middleware dep).
# pn_core_fmt provides pn_snprintf (middleware dep).
pubnub_add_unit_test(test_core_timer_units SOURCES timer_units.c LIBS pubnub)

# Timer list (scheduler) unit tests.
pubnub_add_unit_test(test_core_timer_list_units SOURCES timer_list_units.c LIBS pubnub)

# Request descriptor unit tests need the runtime library (timer + request).
pubnub_add_unit_test(test_core_request_units SOURCES request_units.c LIBS pubnub)

# Request-pool unit tests (pool in isolation).
pubnub_add_unit_test(test_core_request_pool_units SOURCES request_pool_units.c LIBS pubnub)

# pubnub_compat.h smoke test: ensures PUBNUB_STATIC_ASSERT compiles in
# every build configuration. The macro is shipped standalone in PR1 with
# no in-tree consumer until PR2/PR3 -- this TU exercises it so a broken
# C99-fallback cascade fails the build before later PRs land.
pubnub_add_unit_test(
    test_core_compat_static_assert_units
    SOURCES compat_static_assert_units.c
    LIBS pubnub
)

# Compile-only checks of PUBNUB_STATIC_ASSERT in strict C99 and C11 modes:
# assertions from different headers that share a line number must coexist
# (PUBNUB_STATIC_ASSERT must be collision-free in every mode), and a false
# assertion must be rejected with the assertion diagnostic (a bare WILL_FAIL
# would also pass on a missing compiler or header). Driven through the project
# C compiler directly so the language mode is independent of the build's
# PUBNUB_C_STANDARD.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CROSSCOMPILING)
    set(PN_COMPAT_SA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/compat_static_assert")
    separate_arguments(PN_COMPAT_SA_CC_ARG1 UNIX_COMMAND "${CMAKE_C_COMPILER_ARG1}")
    foreach(PN_STD IN ITEMS c99 c11)
        set(PN_COMPAT_SA_CMD
            "${CMAKE_C_COMPILER}"
            ${PN_COMPAT_SA_CC_ARG1}
            -std=${PN_STD}
            -fdiagnostics-color=never
            -pedantic-errors
            -Wall
            -Wextra
            -Werror
            -fsyntax-only
            "-I${CMAKE_SOURCE_DIR}/include"
            "-I${PN_COMPAT_SA_DIR}"
        )
        add_test(
            NAME test_core_compat_static_assert_collision_${PN_STD}
            COMMAND ${PN_COMPAT_SA_CMD} "${PN_COMPAT_SA_DIR}/collision_main.c"
        )
        add_test(
            NAME test_core_compat_static_assert_false_${PN_STD}
            COMMAND ${PN_COMPAT_SA_CMD} "${PN_COMPAT_SA_DIR}/assert_false.c"
        )
        set_tests_properties(
            test_core_compat_static_assert_false_${PN_STD}
            PROPERTIES PASS_REGULAR_EXPRESSION "negative|static assertion failed"
        )
    endforeach()
endif()

pubnub_add_unit_test(test_core_feature_registry_units SOURCES feature_registry_units.c LIBS pubnub)

# Clear-value sentinel: PN_IS_CLEAR_VALUE by-address identity contract.
# Links the aggregate library so the pn_core-defined marker object resolves;
# the distinct-identical-content case guards against linker/LTO data folding.
pubnub_add_unit_test(test_core_clear_value_units SOURCES clear_value_units.c LIBS pubnub)

# Response accessor unit tests: pubnub_response_error_message() routing
# coverage (status_code == 0 verbatim pass-through vs. service_error
# classifier for status_code != 0). Needs the full provider stack
# because the tests spin up a real pubnub_context_t to drive a
# hand-constructed slot.
pubnub_add_unit_test(test_core_response_units SOURCES response_units.c LIBS pubnub)

# Service-error classifier coverage: each of the seven recognised
# wire variants plus probe-ordering edge cases. Drives a real
# pubnub_context_t with the linked default serialization backend
# so the JSON walk runs end-to-end through the production vtable.
pubnub_add_unit_test(test_core_service_error_units SOURCES service_error_units.c LIBS pubnub)

# JSON helpers (PR5): exercised against the active serialization
# backend so the helpers' contract is validated against the same
# binary downstream consumers see (cJSON for hosted profiles, jsmn
# when overridden).
pubnub_add_unit_test(test_core_json_helpers_units SOURCES json_helpers_units.c LIBS pubnub)

# Future consumption (await/async/pending queue) unit tests.
pubnub_add_unit_test(
    test_core_future_consumption_units
    SOURCES future_consumption_units.c
    LIBS pubnub
)

# Pending-queue ring bookkeeping (head/tail/mid cancellation), pending-range
# future identity across promotion and ring wrap, and seed-bounded fuzzing of
# cancel/release/promote/complete orderings through a mock transport.
if(NOT PUBNUB_CFG_NO_HEAP)
    pubnub_add_unit_test(test_core_pending_queue_units SOURCES pending_queue_units.c LIBS pubnub)
endif()

# Completion-time eager body parsing: verifies the preparse_on_complete
# opt-in (set for every feature except subscribe, on both the direct and
# promotion dispatch paths) and that the parse cache is populated before any
# accessor runs, closing the socket Connection: close use-after-free. Uses
# the linked default serialization backend so the parse dereferences the body.
if(NOT PUBNUB_CFG_NO_HEAP)
    pubnub_add_unit_test(
        test_core_preparse_completion_units
        SOURCES preparse_completion_units.c
        LIBS pubnub
    )
endif()

# Failed-request transport handle ownership: HTTP 4xx, validator rejection and
# transport-error terminals must leave every handle (and the retry middleware
# slot wrapping it) cancelled exactly once after the future is released.
if(NOT PUBNUB_CFG_NO_HEAP)
    pubnub_add_unit_test(
        test_core_failure_handle_cancel_units
        SOURCES failure_handle_cancel_units.c
        LIBS pubnub
    )
endif()

# Context-level retry behaviour (per-attempt deadline budget, origin change)
# over a scripted mock transport and mock clock.
if(PUBNUB_ENABLE_RETRY AND NOT PUBNUB_CFG_NO_HEAP)
    pubnub_add_unit_test(test_core_retry_context_units SOURCES retry_context_units.c LIBS pubnub)
endif()

# Locked origin snapshot: consistent (host, generation) pair and no torn host
# while another thread switches the origin.
if(NOT PUBNUB_CFG_NO_HEAP)
    find_package(Threads REQUIRED)
    pubnub_add_unit_test(
        test_core_origin_snapshot_units
        SOURCES origin_snapshot_units.c
        LIBS pubnub Threads::Threads
    )
endif()

pubnub_add_unit_test(test_core_pn_string_units SOURCES pn_string_units.c LIBS pubnub)

# Prep-pool unit tests (prep acquire/release, feature-level lifecycle).
pubnub_add_unit_test(test_core_prep_pool_units SOURCES prep_pool_units.c LIBS pubnub)

# Cross-feature concurrent dispatch (publish + time on the same context).
pubnub_add_unit_test(
    test_core_cross_feature_dispatch_units
    SOURCES cross_feature_dispatch_units.c
    LIBS pubnub
)

# Real-thread stress for transport ownership: user threads release/cancel
# futures while the background thread owns the transport.
if(PUBNUB_CFG_THREAD_SAFETY AND PUBNUB_ENABLE_PUBLISH)
    find_package(Threads REQUIRED)
    pubnub_add_unit_test(
        test_core_future_release_thread_units
        SOURCES future_release_thread_units.c
        LIBS pubnub Threads::Threads
    )
endif()

# Feature-registry scan vs lazy registration under the context lock.
if(PUBNUB_CFG_THREAD_SAFETY)
    find_package(Threads REQUIRED)
    pubnub_add_unit_test(
        test_core_feature_registry_thread_units
        SOURCES feature_registry_thread_units.c
        LIBS pubnub Threads::Threads
    )
endif()

add_subdirectory(middleware)
add_subdirectory(pn_format)
add_subdirectory(protocol_common)
add_subdirectory(pipeline)
