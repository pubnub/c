# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Runnable example binaries. Each subdirectory holds one feature's
# demos, with filename naming the consumption style (cooperative.c,
# sync.c, async.c, etc.). Examples link against the aggregate
# `pubnub` target so they see whatever provider set the current
# build selected.
#
# Gated by PUBNUB_BUILD_EXAMPLES so test-only CI jobs can opt out
# of building demo executables.

# Feature-test macros required for POSIX APIs used by examples (usleep,
# nanosleep, clock_gettime). Must be set on the compiler command line
# before any system header is included. MSVC ignores these.
add_compile_definitions(
    _POSIX_C_SOURCE=200809L
    _DEFAULT_SOURCE
    $<$<PLATFORM_ID:Darwin>:_DARWIN_C_SOURCE>
)

if(PUBNUB_ENABLE_PAM)
    add_subdirectory(access)
endif()

if(PUBNUB_ENABLE_APP_CONTEXT)
    add_subdirectory(app_context)
endif()

if(PUBNUB_ENABLE_CHANNEL_GROUPS)
    add_subdirectory(channel_groups)
endif()

if(PUBNUB_ENABLE_CRYPTO)
    add_subdirectory(crypto)
endif()

if(PUBNUB_ENABLE_FILES)
    add_subdirectory(files)
endif()

if(PUBNUB_ENABLE_HISTORY)
    add_subdirectory(history)
endif()

if(PUBNUB_ENABLE_MESSAGE_ACTIONS)
    add_subdirectory(message_actions)
endif()

# Logging and configuration are not feature-gated: their headers are
# always declared.
add_subdirectory(configuration)
add_subdirectory(logging)

if(PUBNUB_ENABLE_PUBLISH AND PUBNUB_ENABLE_SUBSCRIBE)
    add_subdirectory(getting_started)
endif()

if(PUBNUB_ENABLE_PRESENCE)
    add_subdirectory(presence)
endif()

if(PUBNUB_ENABLE_PUBLISH)
    add_subdirectory(publish)
endif()

if(PUBNUB_ENABLE_PUSH_NOTIFICATIONS)
    add_subdirectory(push)
endif()

if(PUBNUB_ENABLE_SIGNAL)
    add_subdirectory(signal)
endif()

if(PUBNUB_ENABLE_TIME)
    add_subdirectory(time)
endif()

if(PUBNUB_ENABLE_SUBSCRIBE)
    add_subdirectory(subscribe)
endif()

if(PUBNUB_PROVIDER_ALLOCATOR STREQUAL "arena")
    add_subdirectory(arena_echo)
endif()
