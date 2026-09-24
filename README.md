# PubNub C SDK

A next-generation C client for the [PubNub](https://www.pubnub.com/) real-time
network. The SDK is a **platform-neutral C11 core** (with a C99 compatibility
mode) that runs unchanged from cloud servers down to bare-metal
microcontrollers. Everything the core touches — HTTP transport, JSON
serialization, payload crypto, memory allocation, logging, and OS primitives —
is supplied by a **pluggable provider**, so the same application code targets
libcurl-on-Linux and a raw socket stack on an ESP32 without change.

Official documentation: https://www.pubnub.com/docs/sdks/c

## Highlights

- **Modular provider architecture** — six provider families (transport,
  serialization, crypto, allocator, logger, platform); pick a backend per family
  at build time, or supply your own.
- **One unified request flow, three completion modes** — every asynchronous
  operation returns a `pubnub_future_t` that you consume by **cooperative
  polling** (no threads), **blocking await**, or an **async callback**. No
  separate sync/async API surfaces.
- **Multi-context** — any number of independent client contexts in one process,
  with no static or global per-context state.
- **Runs where you run** — hosted heap model for servers/desktops, and a
  **no-heap embedded model** with a preallocated arena allocator for constrained
  devices.
- **Secure by default** — TLS is compiled in by default (OpenSSL or mbedTLS);
  plaintext requires an explicit opt-out.
- **Bounded and deterministic** — configurable in-flight concurrency, explicit
  backpressure, and a global → endpoint → per-request timeout hierarchy.
- **Full PubNub feature set** — Publish, Subscribe (event-engine), Presence,
  Message Persistence, Channel Groups, Message Actions, Signals, Files, App
  Context, Access Manager v3, Mobile Push, and payload encryption.

## Requirements

- A C11 compiler (GCC, Clang, MSVC) — or C99 with `PUBNUB_CFG_C99_COMPAT=ON`.
- CMake ≥ 3.16.
- Hosted builds: libcurl and OpenSSL (for the default transport and TLS).
- Embedded builds: a BSD-socket layer and mbedTLS (for the socket transport).

## Integrate into your project

The SDK is consumed as a CMake subproject. Linking the `pubnub` target pulls in
the public include path automatically, so `#include "pubnub/pubnub.h"` just
works.

### With `add_subdirectory`

Vendor this repository into your project (e.g. as a git submodule or a
copy), then point `add_subdirectory` at wherever you placed it — the path
below is only an example location:

```cmake
add_subdirectory(third_party/pubnub-c)     # path to your copy of this repo
target_link_libraries(my_app PRIVATE pubnub)
```

### With `FetchContent`

```cmake
include(FetchContent)
FetchContent_Declare(
    pubnub
    GIT_REPOSITORY https://github.com/pubnub/c.git
    GIT_TAG        1.0.0
)
FetchContent_MakeAvailable(pubnub)
target_link_libraries(my_app PRIVATE pubnub)
```

### Selecting features, providers, and a profile

Set cache variables **before** pulling the SDK in. Only Publish, Subscribe,
secure transport, and retry are enabled by default; every other feature is
opt-in.

```cmake
set(PUBNUB_PROFILE            full    CACHE STRING "")  # full | minimal | embedded
set(PUBNUB_PROVIDER_TRANSPORT curl    CACHE STRING "")  # curl | socket
set(PUBNUB_PROVIDER_PLATFORM  posix   CACHE STRING "")  # posix | windows | freertos | zephyr
set(PUBNUB_ENABLE_PRESENCE    ON      CACHE BOOL   "")
set(PUBNUB_ENABLE_HISTORY     ON      CACHE BOOL   "")
set(PUBNUB_ENABLE_CRYPTO      ON      CACHE BOOL   "")
```

### Building the SDK standalone

Configure/build presets are provided for the common profiles (`full`,
`minimal`, `embedded`, `dev`):

```sh
cmake --preset full
cmake --build --preset full
```

## Getting started

Create a context from a configuration, then issue requests against it.

```c
#include "pubnub/pubnub.h"

pubnub_config_t cfg = pubnub_config_defaults();
cfg.subscribe_key = "sub-c-...";
cfg.publish_key   = "pub-c-...";
cfg.user_id       = "my-user-id";

pubnub_context_t* ctx = pubnub_create(&cfg);   /* hosted heap model */
/* ... use ctx ... */
pubnub_destroy(ctx);
```

Two lifecycle models are available:

- **Hosted:** `pubnub_create()` / `pubnub_destroy()` — allocates the context for
  you and deep-copies config strings.
- **Caller-provided:** `pubnub_init()` / `pubnub_deinit()` — you provide a buffer
  of `pubnub_context_size()` bytes; config strings are borrowed. This is the only
  model available in the no-heap embedded profile (`PUBNUB_CFG_NO_HEAP=ON`).

## The unified request flow

Every asynchronous API call follows the same contract:

```
issue → wait / poll → check status → read result → release
```

The call returns a stack-allocated `pubnub_future_t`. You choose **one** of
three completion modes, then read typed results with
`pubnub_<feature>_result_*` accessors. **Release each future exactly once** with
`pubnub_future_release` — results are valid only until release, and on embedded
targets a leaked future exhausts the fixed slot pool.

### Cooperative polling (no threads, no sync primitives)

```c
pubnub_future_t fut = pubnub_publish(ctx, &(pubnub_publish_opts_t){
    .channel = "my-channel",
    .message = "\"hello world\"",
});
while (!pubnub_future_is_ready(fut)) {
    pubnub_process(ctx);               /* drive I/O one non-blocking tick */
}
if (PUBNUB_OK == pubnub_future_status(fut)) {
    pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
}
pubnub_future_release(fut);
```

### Blocking await (needs platform sync primitives)

```c
pubnub_future_t fut = pubnub_publish(ctx, &(pubnub_publish_opts_t){
    .channel = "my-channel", .message = "\"hello world\"" });

if (PUBNUB_OK == pubnub_await(fut)) {
    pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
}
pubnub_future_release(fut);
```

### Async callback

```c
static void on_publish(pubnub_future_t fut, pubnub_res_t status, void* ud)
{
    if (PUBNUB_OK == status) {
        pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
    }
    pubnub_future_release(fut);         /* safe to release inside the callback */
}

pubnub_future_t fut = pubnub_publish(ctx, &(pubnub_publish_opts_t){
    .channel = "my-channel", .message = "\"hello world\"" });
pubnub_async(fut, on_publish, NULL);
```

The same three modes apply to `pubnub_here_now`, `pubnub_fetch_messages`,
`pubnub_time`, and every other request-style API. In-flight requests can be
cancelled with `pubnub_future_cancel`.

## Subscribe

Subscribe delivers events through listener callbacks rather than a future.
Register a listener, create a subscription from an entity, and drive the event
loop (via `pubnub_process` cooperatively, or a background thread when
`PUBNUB_CFG_THREAD_SAFETY=ON`).

```c
static void on_message(const pubnub_subscribe_event_t* ev, void* ud)
{
    pubnub_context_t*          ctx = ud;
    pubnub_subscribe_message_t msg;
    if (PUBNUB_OK == pubnub_subscribe_event_message(ctx, ev, &msg)) {
        /* msg.channel is a string view; msg.payload is a parsed JSON tree
         * (see pubnub/json.h for value accessors). */
        printf("%.*s received a message\n", (int)msg.channel.len, msg.channel.ptr);
    }
}

pubnub_subscribe_listener_t listener = { .on_message = on_message, .user_data = ctx };
pubnub_add_listener(ctx, &listener);

pubnub_entity_t       entity = pubnub_channel(ctx, "my-channel");
pubnub_subscription_t sub    = pubnub_subscription_create(entity, NULL);
pubnub_subscription_subscribe(sub);

/* Cooperative mode (PUBNUB_CFG_THREAD_SAFETY=OFF): you must pump the context
 * to drive I/O and deliver events. When PUBNUB_CFG_THREAD_SAFETY=ON, a
 * background thread does this for you and this loop is not needed — just keep
 * the program alive and do your own work. */
for (;;) {
    pubnub_process(ctx);
}
```

A single listener struct can handle messages, signals, presence, message
actions, files, App Context changes, and connection-status events by setting the
relevant `on_*` callback.

## Capabilities

| Feature | API |
|---|---|
| Publish | `pubnub_publish` (sync/async, GET/POST, store+TTL, metadata, raw JSON, compression, file messages) |
| Subscribe | `pubnub_subscription_*`, listeners for message / signal / presence / message-action / file / App Context / status |
| Presence | here-now, where-now, get/set state, heartbeat |
| Message Persistence | fetch messages (with meta / actions / file / type / uuid), delete, message counts |
| Channel Groups | add / remove channels, list channels, remove group |
| Message Actions | add / get / remove reactions |
| Signal | `pubnub_signal` |
| Files | send / list / download / delete / URL / publish file message |
| App Context | UUID & channel metadata, memberships, channel members (Objects v2) |
| Access Manager | grant / parse / set / revoke v3 tokens |
| Mobile Push | add / remove / list device channels, remove device (APNS2, FCM) |
| Time | `pubnub_time` |
| Crypto | AES-256-CBC (random IV) and legacy cryptors; transparent payload encryption |

The machine-readable capability and platform matrix lives in
[`.pubnub.yml`](.pubnub.yml).

## Providers and profiles

Select exactly one backend per provider family via CMake:

| Family | Options | Default |
|---|---|---|
| transport | `curl`, `socket` | `curl` |
| serialization | `cjson`, `jsmn` | `cjson` |
| crypto | `openssl`, `mbedtls` | `openssl` |
| allocator | `stdlib`, `arena` | `stdlib` |
| platform | `posix`, `windows`, `freertos`, `zephyr` | *(set explicitly)* |
| logger | `stdout`, `none` | `none` |

Named profiles bundle sensible defaults and memory/latency budgets:

- **full** — all features, hosted providers.
- **minimal** — core messaging only.
- **embedded** — core features, arena allocator, no-heap mode, tight buffers.

TLS is **not** a provider — it is the compile-time toggle
`PUBNUB_ENABLE_SECURE_TRANSPORT` (ON by default), which controls whether the
selected transport compiles in its TLS stack.

## Memory model

- **Hosted (heap):** `stdlib` allocator, `pubnub_create`/`pubnub_destroy`.
- **Embedded (no-heap):** `arena` allocator with preallocated per-context/request
  pools, `pubnub_init`/`pubnub_deinit`, and `PUBNUB_CFG_NO_HEAP=ON`. The total
  per-context memory budget is deterministic at compile time and sized for
  `PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS` concurrent requests.

## Thread-safety

Separate contexts are always safe to use concurrently. Concurrent use of the
**same** context requires external synchronization, or enable
`PUBNUB_CFG_THREAD_SAFETY=ON` to run a background I/O thread with an internal
per-context lock (completion callbacks and `pubnub_await` are then driven by that
thread).

## Repository layout

```
include/pubnub/            Public API headers (pubnub/pubnub.h is the umbrella)
include/pubnub/providers/  Provider vtable contracts
src/core/                  Platform-neutral core: context, futures, pipeline
src/features/<feature>/    Feature modules (publish, subscribe, presence, ...)
src/providers/<family>/    Provider backends (curl, socket, cjson, arena, ...)
cmake/                     Profiles, feature/provider selection, toolchains
tests/ , examples/         Test suite and runnable examples
```

## Versioning and license

Releases follow [Semantic Versioning](https://semver.org/); tags carry no `v`
prefix (e.g. `1.0.0`). See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

This SDK is distributed under the PubNub Software Development Kit License
Agreement — see [`LICENSE`](LICENSE).

## Support

Direct all support questions to support@pubnub.com or visit the
[PubNub support portal](https://support.pubnub.com/).
