# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.
#
# IoT kitchensink end-to-end test scaffold.
#
# The device/ subdirectory is a standalone ESP-IDF project built with
# idf.py -- it is NOT add_subdirectory'd into the host CMake tree.
#
# This file exists solely to let the top-level tests/CMakeLists.txt
# gate the option and print build instructions.

option(PUBNUB_BUILD_IOT_TESTS "Enable IoT kitchensink test scaffold (ESP-IDF only)" OFF)

if(NOT PUBNUB_BUILD_IOT_TESTS)
    return()
endif()

message(
    STATUS
    "[PubNub] IoT kitchensink scaffold enabled.\n"
    "  The device firmware is built with idf.py, not cmake --build:\n"
    "    cd tests/iot_kitchensink/device\n"
    "    idf.py set-target esp32s3   # or esp32\n"
    "    idf.py menuconfig           # set WiFi + PubNub keys\n"
    "    idf.py build\n"
    "    idf.py flash monitor\n"
    "  Start the companion on your workstation:\n"
    "    cd tests/iot_kitchensink/companion\n"
    "    npm install\n"
    "    node companion_iot.mjs --sub-key <key> --pub-key <key>"
)
