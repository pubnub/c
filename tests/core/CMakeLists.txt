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

pubnub_add_unit_test(test_core_feature_registry_units SOURCES feature_registry_units.c LIBS pubnub)

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

# Completion-time eager body parsing: verifies the preparse_on_complete
# opt-in (set for every feature except subscribe, on both the direct and
# promotion dispatch paths) and that the parse cache is populated before any
# accessor runs, closing the socket Connection: close use-after-free. Uses
# the linked default serialization backend so the parse dereferences the body.
pubnub_add_unit_test(
    test_core_preparse_completion_units
    SOURCES preparse_completion_units.c
    LIBS pubnub
)

pubnub_add_unit_test(test_core_pn_string_units SOURCES pn_string_units.c LIBS pubnub)

# Prep-pool unit tests (prep acquire/release, feature-level lifecycle).
pubnub_add_unit_test(test_core_prep_pool_units SOURCES prep_pool_units.c LIBS pubnub)

# Cross-feature concurrent dispatch (publish + time on the same context).
pubnub_add_unit_test(
    test_core_cross_feature_dispatch_units
    SOURCES cross_feature_dispatch_units.c
    LIBS pubnub
)

add_subdirectory(middleware)
add_subdirectory(pn_format)
add_subdirectory(protocol_common)
add_subdirectory(pipeline)
