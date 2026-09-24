# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# Thin ESP-IDF component wrapper ensuring the component name is always
# "pubnub" regardless of the SDK checkout directory name.

get_filename_component(PUBNUB_SDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

# Enable presence for this example so the device sends heartbeats.
# Remove or set to 0 to disable presence and save ~5KB of flash.
set(PUBNUB_ENABLE_PRESENCE 1)

include("${PUBNUB_SDK_DIR}/cmake/PubnubESP.cmake")
