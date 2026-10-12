<img width="1920" height="600" alt="PubNub C SDK header: a publish call sends Hello world! to the hello_world channel" src="https://github.com/user-attachments/assets/0971165c-96ab-47b2-836c-a83bdcbdcd2b" />

# PubNub C SDK

[![GitHub release](https://img.shields.io/github/v/release/pubnub/c)](https://github.com/pubnub/c/releases)

PubNub provides global infrastructure for real-time, interactive applications.

Publish and receive messages in C. Use this SDK for native and embedded C applications on Linux,
macOS, Windows, FreeRTOS, ESP-IDF, and Zephyr.

[Documentation](https://www.pubnub.com/docs/sdks/c) · [API reference](https://www.pubnub.com/docs/sdks/c/api-reference/publish-and-subscribe) · [Changelog](https://www.pubnub.com/docs/sdks/c/changelog) · [Support](https://support.pubnub.com/)

## Requirements

| Requirement                 | Supported version or setup                                                                                                                                         |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CMake and C compiler        | [CMake 3.16+ and a C11-capable compiler; C99 compatibility is available with `PUBNUB_CFG_C99_COMPAT=ON`](https://www.pubnub.com/docs/sdks/c)                       |
| Hosted and embedded targets | [Linux, macOS, Windows, FreeRTOS 10, ESP-IDF 5.2+, and Zephyr](https://www.pubnub.com/docs/sdks/c/platform-support)                                                |
| Hosted dependencies         | The full hosted profile uses `libcurl`, `OpenSSL`, and `cJSON`. CMake may fetch dependencies on first configure, so initial configuration requires network access. |

## Installation

Vendor the SDK source and add it as a CMake subdirectory:

```cmake
# Select a build profile (full | minimal | embedded) BEFORE adding the SDK. A profile only
# supplies defaults for features and providers; explicit -D options still win.
# See "Build profiles and presets": https://www.pubnub.com/docs/sdks/c/environment-setup
set(PUBNUB_PROFILE full CACHE STRING "")
add_subdirectory(third_party/pubnub-c)

add_executable(my_app main.c)
target_link_libraries(my_app PRIVATE pubnub)
```

For other installation methods,
see [environment setup](https://www.pubnub.com/docs/sdks/c/environment-setup).

## Quickstart

This example runs in the hosted `full` CMake profile. It subscribes to `hello_world`, publishes one
message, and prints the received text.

### Get your keys

1. Open the [PubNub Admin Portal](https://admin.pubnub.com/).
2. Create an app and a keyset for development, or select an existing development keyset.
3. Copy its publish key and subscribe key.

If Access Manager is enabled, obtain a token from your trusted backend and call
`pubnub_set_auth_token(ctx, token)`. Keep the secret key on the backend.

### Send and receive a message

Create `hello_world.c` and link it against the `pubnub` target from your `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(hello_world C)

# The full profile enables every feature and the hosted providers (libcurl, OpenSSL, cJSON).
# See "Build profiles and presets": https://www.pubnub.com/docs/sdks/c/environment-setup
set(PUBNUB_PROFILE full CACHE STRING "")
add_subdirectory(third_party/pubnub-c)

add_executable(hello_world hello_world.c)
target_link_libraries(hello_world PRIVATE pubnub)
```

The example below adds a listener, subscribes to `hello_world`, waits for the connection, publishes
one message, and waits for it to arrive.

Replace the key placeholders. Use a User ID that identifies the user or device in your app.

```c
#include <pubnub/pubnub.h>

#include <stdio.h>
#include <unistd.h>

static volatile int connected = 0;
static volatile int received  = 0;

static void on_status(const pubnub_subscribe_status_event_t* event, void* user_data)
{
    if (PUBNUB_SUBSCRIBE_STATUS_CONNECTED == event->status) {
        connected = 1;
    }
}

static void on_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    pubnub_context_t*                ctx = (pubnub_context_t*)user_data;
    pubnub_subscribe_message_event_t msg;
    size_t                           len = 0;

    pubnub_subscribe_event_message(ctx, event, &msg);

    const char* text = pubnub_serialization(ctx)->value_as_string(msg.message, &len);

    printf("%.*s\n", (int)len, text);
    received = 1;
}

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "YOUR_PUBLISH_KEY";
    cfg.subscribe_key   = "YOUR_SUBSCRIBE_KEY";
    cfg.user_id         = "hello-world-user";

    pubnub_context_t* ctx = pubnub_create(&cfg);

    pubnub_subscribe_listener_t listener = {
        .on_status  = on_status,
        .on_message = on_message,
        .user_data  = ctx,
    };
    pubnub_listener_handle_t handle = pubnub_add_listener(ctx, &listener);

    pubnub_entity_t       channel      = pubnub_channel(ctx, "hello_world");
    pubnub_subscription_t subscription = pubnub_subscription_create(channel, NULL);
    pubnub_entity_destroy(channel);
    pubnub_subscription_subscribe(subscription);

    while (!connected) {
        pubnub_process(ctx);
        usleep(10000);
    }

    pubnub_future_t publish = pubnub_publish(
        ctx,
        &(pubnub_publish_opts_t){
            .channel = "hello_world",
            .message = "\"Hello world\"",
        }
    );
    pubnub_await(publish);
    pubnub_future_release(publish);

    while (!received) {
        pubnub_process(ctx);
        usleep(10000);
    }

    pubnub_subscription_unsubscribe(subscription);
    pubnub_subscription_destroy(subscription);
    pubnub_remove_listener(ctx, handle);
    pubnub_destroy(ctx);

    return 0;
}
```

> [!NOTE]
> The example is shortened for readability:
>
> - It omits error checks. In production code, check every `pubnub_res_t` result and every
>   returned handle (`pubnub_create`, `pubnub_add_listener`, `pubnub_channel`,
>   `pubnub_subscription_create`), and bound the waiting loops with a timeout.
> - It targets Linux and macOS. `usleep()` comes from `<unistd.h>`; on Windows, include
>   `<windows.h>` and use `Sleep(10)` instead.
>
> For a complete version with error handling and cleanup on every path, see the
> [getting started example](https://github.com/pubnub/c/blob/master/examples/getting_started/getting_started.c).

### Run the example

```
cmake -B build
cmake --build build
./build/hello_world
```

The terminal should show:

```
Hello world
```

The SDK may also print its own log lines around this output.

Unsubscribe with `pubnub_subscription_unsubscribe()`, destroy the subscription with
`pubnub_subscription_destroy()`, remove the listener with `pubnub_remove_listener()`, destroy the
context with `pubnub_destroy()`, and release every returned `pubnub_future_t` exactly once with
`pubnub_future_release()`.

For a complete application, see the [getting started guide](https://www.pubnub.com/docs/sdks/c).

## Next steps

| Task                                 | Documentation                                                                                 |
|--------------------------------------|-----------------------------------------------------------------------------------------------|
| Configure the client                 | [Configuration](https://www.pubnub.com/docs/sdks/c/api-reference/configuration)               |
| Work with subscriptions and messages | [Publish & Subscribe](https://www.pubnub.com/docs/sdks/c/api-reference/publish-and-subscribe) |
| Check channel occupancy              | [Presence](https://www.pubnub.com/docs/sdks/c/api-reference/presence)                         |
| Read message history                 | [Message Persistence](https://www.pubnub.com/docs/sdks/c/api-reference/storage-and-playback)  |

## Build with an AI coding assistant

The [PubNub MCP server](https://www.pubnub.com/docs/ai/pubnub-mcp-server) gives an AI coding
assistant access to PubNub SDK documentation and PubNub APIs. Connect the assistant to the hosted
server at `https://mcp.pubnub.com`, or run `npx @pubnub/mcp@latest` locally.

The [server repository](https://github.com/pubnub/pubnub-mcp-server) has setup steps for VS Code,
Cursor, Claude Code, Claude Desktop, Codex, Gemini CLI, and OpenCode.

## Before production

Use [Access Manager](https://www.pubnub.com/docs/sdks/c/api-reference/access-manager) to grant each
client the permissions it needs. Keep the secret key on your backend. Never include it in a
distributed client.

Keep `pubnub_context_t` alive for the required client lifetime. Clean up subscriptions with
`pubnub_subscription_unsubscribe()` and `pubnub_subscription_destroy()`, remove listeners with
`pubnub_remove_listener()`, destroy the context with `pubnub_destroy()`, and release every future
exactly once with `pubnub_future_release()`.

Live delivery through PubNub SDKs is at-most-once. A subscriber can miss messages while disconnected
or if its buffer overflows. For longer-gap recovery,
see [Message Persistence](https://www.pubnub.com/docs/sdks/c/api-reference/storage-and-playback).

## Troubleshooting

| Symptom                                                           | Check                                                                                                                                                                                                                                  |
|-------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CMake cannot configure the SDK dependencies                       | Use CMake 3.16+ and satisfy the dependencies required by the selected build profile. The first configure may require network access for FetchContent. See [C Environment Setup](https://www.pubnub.com/docs/sdks/c/environment-setup). |
| A publish succeeds but no message appears                         | Check the message handler, subscription readiness, keyset, and channel name.                                                                                                                                                           |
| A hosted build fails to compile or link networking or TLS support | Verify the networking/TLS dependencies for the selected platform and profile. See [C Platform Support](https://www.pubnub.com/docs/sdks/c/platform-support) and [Troubleshooting](https://www.pubnub.com/docs/sdks/c/troubleshooting). |
| Extra clients or duplicate messages during development            | Do not create additional contexts, subscriptions, listeners, or futures without releasing their previous owners. Every subscription, listener, context, and future must follow its documented lifetime.                                |

For setup help, see [troubleshooting](https://www.pubnub.com/docs/sdks/c/troubleshooting).
Check [network status](https://status.pubnub.com/) for service incidents.

## Releases

Read the [changelog](https://www.pubnub.com/docs/sdks/c/changelog) before upgrading.

Applications migrating from C-Core v7 should
follow [Migrating from C-Core v7](https://www.pubnub.com/docs/sdks/c/migration-guides/migrating-from-c-core-v7).
The new C SDK is a full rewrite rather than an incremental version upgrade.

## Support and contributions

For setup or account help, contact [PubNub Support](https://support.pubnub.com/).

For a reproducible SDK bug, use [GitHub Issues](https://github.com/pubnub/c/issues). Include the SDK
version, runtime, and a small reproduction with credentials removed.

Build the affected CMake profile, run the repository test suite, and include tests for behavioral
changes before opening a pull request.

## License

See
the [PubNub Software Development Kit License Agreement](https://github.com/pubnub/c/blob/master/LICENSE).
