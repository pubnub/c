# PubNub C SDK -- IoT Kitchensink End-to-End Test

Hardware-only manual test that exercises all SDK features on a real ESP32
device. There is no Linux host build and no CI automation path.

## Prerequisites

- **ESP-IDF v5.3+** installed and sourced (`$IDF_PATH` set)
- **Node.js 20+** (for the companion workstation script)
- A **PubNub keyset** (subscribe key + publish key)
- An **ESP32** board (ESP32-S3-DevKitC-1 recommended)

## Quick Start

### 1. Configure WiFi and PubNub keys

```bash
cd tests/iot_kitchensink/device
idf.py set-target esp32s3   # or esp32, esp32c3
idf.py menuconfig
```

Navigate to **PubNub Kitchensink Configuration**:
- **WiFi** -- set your SSID and password
- **PubNub Keys** -- set subscribe key and publish key
- **Features** -- toggle features on/off (all default ON)
- **Test Behavior** -- adjust timeouts if needed

### 2. Build and flash

```bash
idf.py build
idf.py flash monitor
```

The device will:
1. Connect to WiFi
2. Sync time via NTP
3. Attempt a companion handshake (optional)
4. Run all enabled tests sequentially
5. Print a summary to the serial monitor

### 3. Start the companion (optional)

The companion is a Node.js script that runs on your workstation. Tests
that require a companion (e.g. subscribe receive tests) are skipped
when the companion is not online.

```bash
cd tests/iot_kitchensink/companion
npm install
node companion_iot.mjs --sub-key <your-sub-key> --pub-key <your-pub-key>
```

Start the companion **before** flashing the device so it is ready to
respond to the handshake.

## Feature Variants

Disable features via `idf.py menuconfig` to create lighter builds:

- **Core variant**: disable FILES, APP_CONTEXT, MESSAGE_ACTIONS
- **Minimal variant**: disable everything except time/publish (always on)

## Interpreting Serial Output

Each test prints one line:

```
[KS] [PASS] time/basic (123 ms)
[KS] [FAIL] subscribe/receive_from_companion: timeout (10032 ms)
[KS] [SKIP] crypto/encrypt_decrypt: not yet implemented (0 ms)
```

The summary line:

```
[KS] === Summary: 7 pass, 0 fail, 15 skip (run a1b2c3d4) ===
```

## Directory Layout

```
tests/iot_kitchensink/
  CMakeLists.txt              # Host-side guard (prints instructions)
  README.md                   # This file
  device/                     # Standalone ESP-IDF project
    CMakeLists.txt            # ESP-IDF top-level
    sdkconfig.defaults        # Default sdkconfig overrides
    main/
      CMakeLists.txt          # idf_component_register
      Kconfig.projbuild       # Feature/WiFi/key configuration
      idf_component.yml       # IDF component dependencies
      kitchensink_main.c      # WiFi, NTP, task, runner
      ks_test_runner.h/.c     # Sequential test executor
      ks_protocol.h/.c        # Channel naming + JSON messages
      ks_tests.h              # Test table declarations
      ks_tests_time.c         # Time tests (implemented)
      ks_tests_publish.c      # Publish tests (implemented)
      ks_tests_*.c            # Stub files for remaining features
    components/pubnub/
      CMakeLists.txt          # SDK feature flags + PubnubESP.cmake
  companion/
    package.json
    companion_iot.mjs         # Node.js companion script
```
