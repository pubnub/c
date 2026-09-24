# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# stdlib allocator -- always built against the selected allocator
# target (which maps to the stdlib implementation when
# PUBNUB_PROVIDER_ALLOCATOR=stdlib) rather than pulling the source
# directly.  That way the test exercises the same binary consumers
# will see.
if(PUBNUB_PROVIDER_ALLOCATOR STREQUAL "stdlib")
    pubnub_add_unit_test(
        test_provider_allocator_stdlib_units
        SOURCES stdlib_allocator_units.c
        LIBS pubnub
    )

    # OOM injection -- failure-injecting allocator wrapping malloc, used
    # to exercise feature error paths under allocation failure.  Built
    # only for the stdlib backend (the mock delegates to malloc).
    pubnub_add_unit_test(
        test_provider_allocator_oom_injection_units
        SOURCES oom_injection_units.c mock_oom_allocator.c
        LIBS pubnub
    )
endif()

# Arena allocator -- built when the arena provider is active.
if(PUBNUB_PROVIDER_ALLOCATOR STREQUAL "arena")
    pubnub_add_unit_test(
        test_provider_allocator_arena_units
        SOURCES arena_allocator_units.c
        LIBS pubnub
    )

    # Arena dispatch -- drives real feature operations (time, publish,
    # history, subscribe) through a caller-injected arena allocator to
    # prove per-request Zone A slots recycle across operations.
    pubnub_add_unit_test(
        test_provider_allocator_arena_dispatch_units
        SOURCES arena_dispatch_units.c
        LIBS pubnub
    )
endif()

# Non-selected backends can be compiled directly via their source
# when we need to test them regardless of the active profile:
# pubnub_add_unit_test(test_allocator_pool_units
#     SOURCES allocator_pool_units.c
#             ${PN_PROVIDERS_SRC_DIR}/allocator/pool/allocator_pool.c
# )
