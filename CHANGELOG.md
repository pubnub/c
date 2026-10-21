## 1.1.0
October 21 2026

#### Added
- Pass `PUBNUB_CLEAR_VALUE` to a string or custom field to clear it. The SDK sends JSON null, so the stored value is gone.
- Tokens can now grant read access to all channel or UUID metadata at once, using `channels_category_permissions` and `uuids_category_permissions`.
- Context init now fails early if a provider is only half set up, for example a lock without its full set of functions, and logs why.
- Presence can be turned on per subscription, and wildcards match on their own. Handles are shared with sets, and listeners only get events while their subscription or set is active.

#### Fixed
- Windows reported pending connects as ready, so TLS started too early and failed. TLS now waits until the connection is really up.
- Some setups did not compile or link. Those were builds with logging turned off, Clang in C99 mode, or mbedTLS without `MBEDTLS_ERROR_C`. Strict C99 builds were broken too, and they all build now.

#### Modified
- The poll thread wakes much faster on Windows, so publish dispatch dropped from 52.6 ms to 0.1 ms. Connections stay open between requests, so 100 publishes need one TLS handshake instead of 100.
- Real-time events from subscribe REST API response with a type the SDK does not  know are skipped instead of being stored as-is. A debug log records them.
- Set `PUBNUB_OPENSSL_LIB_DIR` to point at a custom OpenSSL layout on MSVC. POSIX feature-test macros now apply only to non-Windows hosts, and no-heap builds reject more than 16 in-flight requests.
- The ESP32 example pins led_strip to 3.0.0. The nRF7002 example documents the net context limits it needs.
- New CI jobs cover TSan on sockets, the jsmn serializer, C99 syntax and the Windows shared library. Linux socket lanes now fail if pending-connect tests get skipped.
- Covers what happens to queued and in-flight futures on release, what an origin change does to retries and subscriptions, and the threading rules for transports.
- Rewrites the README around installation and a quickstart, with a new header image.
- Adds tests for subscribe, App Context, Files, Access, the pending queue, future release threads, the feature registry and retry context.

## 1.0.0
September 21 2026

#### Added
- Ground-up rewrite of the PubNub C SDK: a platform-neutral C11 core (with a C99 compatibility mode) built around six pluggable provider families — transport, serialization, crypto, allocator, logger, and platform.
- Multi-context architecture with no static or global per-context state; multiple independent client contexts operate concurrently in a single process.
- Pluggable HTTP transport providers: a libcurl-backed backend for hosted platforms and a native BSD-socket backend for constrained and embedded targets.
- Pluggable allocator providers supporting both a hosted heap-managed model and an embedded no-heap arena model with preallocated per-context/request pools sized for N concurrent in-flight requests.
- Three request-completion styles for every asynchronous operation: blocking await (sync), completion callback (async), and cooperative single-threaded polling via pubnub_process for no-thread event loops.
- Request/future handles with a three-level timeout hierarchy (global, endpoint, per-request), configurable in-flight concurrency, and explicit bounded-queue backpressure.
- Compile-time secure transport (PUBNUB_ENABLE_SECURE_TRANSPORT) with OpenSSL and mbedTLS TLS stacks selectable per transport backend; plaintext requires explicit opt-out.
- Named build profiles (full, minimal, embedded) with per-profile memory and latency budgets, plus explicit CMake feature toggles for every feature module.
- Payload crypto module with an AES-256-CBC cryptor using a random initialization vector (identifier ACRH) and a legacy cryptor, exposed through a pluggable crypto provider contract.
- Publish API: synchronous and asynchronous delivery, GET and POST transport, store flag with per-message TTL, stream-filter metadata, raw JSON value trees, optional body compression, and file-message publishing.
- Subscribe API (event-engine, PubSub v2): channels, channel groups, presence channels, wildcard subscriptions, stream-filter expressions, and timetoken cursor restore, with typed listeners for messages, signals, message actions, files, presence, and App Context objects.
- Presence API: here-now, where-now, get/set presence state, and heartbeat.
- Channel Groups API: add and remove channels, list channels in a group, and remove a group.
- Message Persistence (Storage) API: fetch messages with metadata, message actions, file, message-type and publisher-UUID includes, reverse ordering, count and start/end bounds, delete messages, and message counts.
- Message Actions API: add, get, and remove reactions on published messages.
- Signal API: lightweight signal publishing.
- Files API: send, list, download, delete, generate a file URL, and publish a file message.
- App Context (Objects v2) API: get/set/remove UUID and channel metadata, list all UUID and channel metadata, and manage memberships and channel members.
- Access Manager v3 API: grant, parse, set, and revoke resource tokens.
- Mobile Push API: add, remove, and list channels for a device and remove a device, for the APNS2 and FCM gateways.
- Time API: fetch the current PubNub network timetoken.
