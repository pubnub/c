# Copyright (c) PubNub Inc.
# See LICENSE in the root directory of this source tree.

cmake_minimum_required(VERSION 3.16)

# Default target for ESP32-S3 DevKitC-1 (LX7 dual-core).
# Override by passing -DIDF_TARGET=<target> to idf.py if needed.
if(NOT DEFINED IDF_TARGET)
    set(IDF_TARGET esp32s3)
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(iot_kitchensink)
