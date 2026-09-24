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
