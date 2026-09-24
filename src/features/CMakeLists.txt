# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

# Each feature is its own CMake target, conditionally included.

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
