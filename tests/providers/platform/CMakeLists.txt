# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# posix platform -- always built against the selected platform target
# (which maps to the posix implementation when
# PUBNUB_PROVIDER_PLATFORM=posix) rather than pulling the source
# directly.  That way the test exercises the same binary consumers
# will see.
if(PUBNUB_PROVIDER_PLATFORM STREQUAL "posix")
    pubnub_add_unit_test(
        test_provider_platform_posix_units
        SOURCES posix_platform_units.c
        LIBS pubnub
    )
endif()

# Non-selected backends can be compiled directly via their source
# when we need to test them regardless of the active profile:
# pubnub_add_unit_test(test_platform_freertos_units
#     SOURCES platform_freertos_units.c
#             ${PN_PROVIDERS_SRC_DIR}/platform/freertos/platform_freertos.c
# )
