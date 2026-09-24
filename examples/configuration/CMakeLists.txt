# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Examples for pubnub_config_t and the context lifecycle.
#
#   configuration.c -- one static function per configuration topic, each
#                      carrying its own doc snippet marker, driven from a
#                      single main() so the whole file is a compile gate.
#
# Not gated on a PUBNUB_ENABLE_* feature: pubnub/client.h, proxy.h, and
# tcp_keepalive.h are always declared. pubnub_time() is used to exercise
# the event loop, so the target is only added when TIME is enabled.

if(PUBNUB_ENABLE_TIME)
    add_executable(example_configuration configuration.c)
    target_link_libraries(example_configuration PRIVATE pubnub)
    set_target_properties(
        example_configuration
        PROPERTIES C_STANDARD ${PUBNUB_C_STANDARD} C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    pubnub_target_warnings(example_configuration)
    pubnub_target_sanitizers(example_configuration)
endif()
