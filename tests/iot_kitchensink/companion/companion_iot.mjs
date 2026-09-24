#!/usr/bin/env node
/**
 * PubNub IoT Kitchensink Companion
 *
 * Runs on a workstation alongside the ESP32 device (or host-mode test
 * binary). Subscribes to the fixed `iot-ks-handshake` discovery channel and
 * presence at startup, buffers ALL incoming PubNub events in a
 * per-channel ring, and dispatches actions requested by the device
 * test runner.
 *
 * Supports two response styles:
 *   - One-shot: immediate action_done / action_fail reply.
 *   - Two-phase: READY reply first, then action_done / action_fail
 *     once the expected event arrives or times out.
 *
 * Usage:
 *   node companion_iot.mjs --sub-key <key> --pub-key <key> \
 *       [--cipher-key <key>]
 */

import PubNub from "pubnub";
// PubNub JS SDK is CommonJS — CryptoModule is a property on the constructor.
const { CryptoModule } = PubNub;

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === "--sub-key" && argv[i + 1]) {
            args.subKey = argv[++i];
        } else if (argv[i] === "--pub-key" && argv[i + 1]) {
            args.pubKey = argv[++i];
        } else if (argv[i] === "--cipher-key" && argv[i + 1]) {
            args.cipherKey = argv[++i];
        } else if (argv[i] === "--help" || argv[i] === "-h") {
            console.log(
                "Usage: node companion_iot.mjs " +
                    "--sub-key <key> --pub-key <key> [--cipher-key <key>]"
            );
            process.exit(0);
        }
    }
    if (!args.subKey || !args.pubKey) {
        console.error("Error: --sub-key and --pub-key are required");
        process.exit(1);
    }
    return args;
}

const args = parseArgs(process.argv);

// ---------------------------------------------------------------------------
// PubNub instances
// ---------------------------------------------------------------------------

const pubnub = new PubNub({
    subscribeKey: args.subKey,
    publishKey: args.pubKey,
    userId: "ks-companion-workstation",
    logVerbosity: true,
});

let acrhPubnub = null;
let legacyPubnub = null;

if (args.cipherKey) {
    acrhPubnub = new PubNub({
        subscribeKey: args.subKey,
        publishKey: args.pubKey,
        userId: "ks-companion-crypto-acrh",
        cryptoModule: CryptoModule.aesCbcCryptoModule({
            cipherKey: args.cipherKey,
        }),
    });

    legacyPubnub = new PubNub({
        subscribeKey: args.subKey,
        publishKey: args.pubKey,
        userId: "ks-companion-crypto-legacy",
        cryptoModule: CryptoModule.legacyCryptoModule({
            cipherKey: args.cipherKey,
        }),
    });
}

// ---------------------------------------------------------------------------
// Event buffer and expectation queue
// ---------------------------------------------------------------------------

/** channel -> [{type, channel, publisher, payload, ...}] */
const eventBuffer = new Map();

/** id -> {channel, eventType, filter, resolve, timer} */
const pendingExpectations = new Map();

let nextExpectationId = 1;

// ---------------------------------------------------------------------------
// Event normalizers
// ---------------------------------------------------------------------------

function normalizeMessageEvent(event) {
    return {
        type: "message",
        channel: event.channel,
        publisher: event.publisher || null,
        payload: event.message,
        timetoken: event.timetoken || null,
        customMessageType: event.customMessageType || null,
        // Unused fields set to null for uniform shape.
        presenceEvent: null,
        presenceUuid: null,
        presenceState: null,
        actionType: null,
        actionValue: null,
        actionEvent: null,
        messageTimetoken: null,
        objectType: null,
        objectId: null,
        fileId: null,
        fileName: null,
    };
}

function normalizeSignalEvent(event) {
    return {
        type: "signal",
        channel: event.channel,
        publisher: event.publisher || null,
        payload: event.message,
        timetoken: event.timetoken || null,
        customMessageType: null,
        presenceEvent: null,
        presenceUuid: null,
        presenceState: null,
        actionType: null,
        actionValue: null,
        actionEvent: null,
        messageTimetoken: null,
        objectType: null,
        objectId: null,
        fileId: null,
        fileName: null,
    };
}

function normalizePresenceEvent(event) {
    return {
        type: "presence",
        channel: event.channel,
        publisher: null,
        payload: null,
        timetoken: event.timetoken || null,
        customMessageType: null,
        presenceEvent: event.action || null,
        presenceUuid: event.uuid || null,
        presenceState: event.state || null,
        actionType: null,
        actionValue: null,
        actionEvent: null,
        messageTimetoken: null,
        objectType: null,
        objectId: null,
        fileId: null,
        fileName: null,
    };
}

function normalizeMessageActionEvent(event) {
    const data = event.data || {};
    return {
        type: "message_action",
        channel: event.channel,
        publisher: event.publisher || null,
        payload: null,
        timetoken: null,
        customMessageType: null,
        presenceEvent: null,
        presenceUuid: null,
        presenceState: null,
        actionType: data.type || null,
        actionValue: data.value || null,
        actionEvent: event.event || null, // 'added' or 'removed'
        messageTimetoken: data.messageTimetoken || null,
        objectType: null,
        objectId: null,
        fileId: null,
        fileName: null,
    };
}

function normalizeObjectEvent(event) {
    const msg = event.message || {};
    const data = msg.data || {};
    return {
        type: "object",
        channel: event.channel,
        publisher: null,
        payload: msg,
        timetoken: null,
        customMessageType: null,
        presenceEvent: null,
        presenceUuid: null,
        presenceState: null,
        actionType: null,
        actionValue: null,
        actionEvent: null,
        messageTimetoken: null,
        objectType: msg.type || null, // 'uuid', 'channel', 'membership'
        objectId: data.id || null,
        fileId: null,
        fileName: null,
    };
}

function normalizeFileEvent(event) {
    const file = event.file || {};
    return {
        type: "file",
        channel: event.channel,
        publisher: event.publisher || null,
        payload: event.message,
        timetoken: event.timetoken || null,
        customMessageType: null,
        presenceEvent: null,
        presenceUuid: null,
        presenceState: null,
        actionType: null,
        actionValue: null,
        actionEvent: null,
        messageTimetoken: null,
        objectType: null,
        objectId: null,
        fileId: file.id || null,
        fileName: file.name || null,
    };
}

// ---------------------------------------------------------------------------
// Expectation matching
// ---------------------------------------------------------------------------

function matchesExpectation(event, expectation) {
    if (event.channel !== expectation.channel) { return false; }
    if (event.type !== expectation.eventType) { return false; }
    if (expectation.filter && !expectation.filter(event)) { return false; }
    return true;
}

// ---------------------------------------------------------------------------
// Event buffer + expectation dispatch
// ---------------------------------------------------------------------------

function handleIncomingEvent(normalized) {
    const ch = normalized.channel;
    if (!eventBuffer.has(ch)) { eventBuffer.set(ch, []); }
    eventBuffer.get(ch).push(normalized);

    // Check if any pending expectation matches this event.
    for (const [id, exp] of pendingExpectations.entries()) {
        if (matchesExpectation(normalized, exp)) {
            clearTimeout(exp.timer);
            pendingExpectations.delete(id);
            exp.resolve({ pass: true, event: normalized });
            return;
        }
    }
}

/**
 * Register an expectation for a specific event type on a channel.
 * Checks the existing buffer first (resolves immediately if found),
 * otherwise waits up to `timeoutMs` for a matching live event.
 */
function registerExpectation(channel, eventType, filter, timeoutMs) {
    return new Promise((resolve) => {
        const id = nextExpectationId++;

        // Check buffer first -- maybe the event already arrived.
        const buffered = eventBuffer.get(channel) || [];
        const idx = buffered.findIndex((e) =>
            matchesExpectation(e, { channel, eventType, filter })
        );
        if (idx >= 0) {
            const matched = buffered.splice(idx, 1)[0];
            resolve({ pass: true, event: matched });
            return;
        }

        // Otherwise register a pending expectation.
        const timer = setTimeout(() => {
            pendingExpectations.delete(id);
            resolve({
                pass: false,
                detail: `timeout waiting for ${eventType} on ${channel}`,
            });
        }, timeoutMs);

        pendingExpectations.set(id, {
            channel,
            eventType,
            filter,
            resolve,
            timer,
        });
    });
}

// ---------------------------------------------------------------------------
// Reply helper
// ---------------------------------------------------------------------------

function reply(runId, message) {
    const resultChannel = `iot-ks-${runId}-result`;
    console.log(
        `[companion] reply → ${resultChannel}: type=${message.type} seq=${message.seq ?? "-"}`
    );
    pubnub
        .publish({ channel: resultChannel, message })
        .catch((err) =>
            console.error(`[companion] reply publish failed: ${err.status?.errorData?.message || err}`)
        );
}

// ---------------------------------------------------------------------------
// Run ID extraction from a channel name
// ---------------------------------------------------------------------------

function extractRunId(channelName) {
    // Matches dash-separated topology: iot-ks-{run_id}-*
    const match = (channelName || "").match(/^iot-ks-([0-9a-f]{8})-/);
    return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// Handshake handler
// ---------------------------------------------------------------------------

function handleHandshake(msg) {
    const runId = msg.run_id;
    if (!runId) { return; }

    console.log(
        `[companion] handshake from ${msg.device_id || "unknown"} ` +
            `(run ${runId})`
    );

    // Subscribe to the per-run control channel now that we know the run_id.
    pubnub.subscribe({
        channels: [`iot-ks-${runId}-control`],
        withPresence: true,
    });

    // Ack on the RESULT channel so the device picks it up.
    pubnub.publish({
        channel: `iot-ks-${runId}-result`,
        message: { type: "handshake_ack", run_id: runId },
    });
}

// ---------------------------------------------------------------------------
// Done handler
// ---------------------------------------------------------------------------

function handleDone(msg) {
    console.log(
        `[companion] run complete: ` +
            `${msg.pass} pass, ${msg.fail} fail, ${msg.skip} skip`
    );
    setTimeout(() => {
        console.log("[companion] exiting");
        process.exit(msg.fail > 0 ? 1 : 0);
    }, 2000);
}

// ---------------------------------------------------------------------------
// Request (action) handler
// ---------------------------------------------------------------------------

async function handleRequest(msg, runId) {
    const { test, action, channel, payload, seq } = msg;

    console.log(
        `[companion] request: test=${test} action=${action} seq=${seq}`
    );

    const send = (message) => reply(runId, message);

    try {
        switch (action) {
            // ----------------------------------------------------------
            // One-shot actions
            // ----------------------------------------------------------

            case "publish": {
                const pubOpts = {
                    channel,
                    message: payload || { from: "companion" },
                };
                if (msg.custom_message_type) {
                    pubOpts.customMessageType = msg.custom_message_type;
                }
                await pubnub.publish(pubOpts);
                send({ type: "action_done", seq });
                break;
            }

            case "signal": {
                await pubnub.signal({
                    channel,
                    message: payload || "companion-sig",
                });
                send({ type: "action_done", seq });
                break;
            }

            case "publish_cmt": {
                await pubnub.publish({
                    channel,
                    message: payload || "cmt payload",
                    customMessageType:
                        msg.custom_message_type || "test-cmt",
                });
                send({ type: "action_done", seq });
                break;
            }

            case "publish_encrypted": {
                if (!acrhPubnub) {
                    send({
                        type: "action_fail",
                        seq,
                        detail: "no cipher key",
                    });
                    break;
                }
                await acrhPubnub.publish({
                    channel,
                    message: payload || "encrypted from companion",
                });
                send({ type: "action_done", seq });
                break;
            }

            case "publish_legacy_encrypted": {
                if (!legacyPubnub) {
                    send({
                        type: "action_fail",
                        seq,
                        detail: "no cipher key",
                    });
                    break;
                }
                await legacyPubnub.publish({
                    channel,
                    message:
                        payload || "legacy encrypted from companion",
                });
                send({ type: "action_done", seq });
                break;
            }

            case "add_message_action": {
                await pubnub.addMessageAction({
                    channel,
                    messageTimetoken: payload.message_timetoken,
                    action: {
                        type: payload.action_type,
                        value: payload.action_value,
                    },
                });
                send({ type: "action_done", seq });
                break;
            }

            case "set_uuid_metadata": {
                await pubnub.objects.setUUIDMetadata({
                    uuid: payload.uuid,
                    data: {
                        name: payload.name,
                        ...(payload.custom
                            ? { custom: payload.custom }
                            : {}),
                    },
                });
                send({ type: "action_done", seq });
                break;
            }

            case "set_channel_metadata": {
                await pubnub.objects.setChannelMetadata({
                    channel: payload.channel_id || channel,
                    data: {
                        name: payload.name,
                        ...(payload.description
                            ? { description: payload.description }
                            : {}),
                    },
                });
                send({ type: "action_done", seq });
                break;
            }

            case "upload_file": {
                const result = await pubnub.sendFile({
                    channel,
                    file: {
                        data: Buffer.from(
                            payload.file_content || "companion file"
                        ),
                        name: payload.file_name || "companion.txt",
                    },
                    message: payload.file_message || undefined,
                });
                send({
                    type: "action_done",
                    seq,
                    detail: JSON.stringify({
                        file_id: result.id,
                        file_name: result.name,
                    }),
                });
                break;
            }

            case "download_and_verify": {
                const downloadInstance =
                    payload.decrypt && acrhPubnub ? acrhPubnub : pubnub;
                const dlResult = await downloadInstance.downloadFile({
                    channel,
                    id: payload.file_id,
                    name: payload.file_name,
                });
                const arrayBuf = await dlResult.toArrayBuffer();
                const content = Buffer.from(arrayBuf).toString("utf8");
                if (
                    payload.expected_content &&
                    content !== payload.expected_content
                ) {
                    send({
                        type: "action_fail",
                        seq,
                        detail: `content mismatch: got "${content.slice(0, 64)}"`,
                    });
                } else {
                    send({
                        type: "action_done",
                        seq,
                        detail: `size=${content.length}`,
                    });
                }
                break;
            }

            case "subscribe_to_channel": {
                // Subscribe with presence so we can confirm our own
                // join — proof that PubNub has registered our presence
                // before we signal the device.
                pubnub.subscribe({ channels: [channel], withPresence: true });

                // Wait for our own join event. Once we see it, the
                // presence event exists in PubNub's system and will
                // propagate to the device's -pnpres subscription.
                const ownJoin = await registerExpectation(
                    channel,
                    "presence",
                    (e) => e.presenceEvent === "join"
                        && e.presenceUuid === pubnub.getUUID(),
                    10000
                );

                if (ownJoin.pass) {
                    // Signal the device. The message arrival on the
                    // result channel forces a subscribe cycle, giving
                    // the device's next long-poll a chance to pick up
                    // the now-confirmed presence event.
                    send({ type: "action_done", seq });
                }
                break;
            }

            case "unsubscribe_from_channel": {
                pubnub.unsubscribe({ channels: [channel] });
                // We cannot see our own leave (already unsubscribed).
                // Give PubNub time to propagate the leave event, then
                // signal the device to trigger a subscribe cycle.
                await new Promise((r) => setTimeout(r, 1000));
                send({ type: "action_done", seq });
                break;
            }

            // ----------------------------------------------------------
            // Two-phase verification actions
            // ----------------------------------------------------------

            case "subscribe_and_verify": {
                const eventType = payload.event_type || "message";
                const timeoutMs = payload.timeout_ms || 10000;
                const filter = (e) => {
                    if (payload.expected_payload) {
                        const ps =
                            typeof e.payload === "string"
                                ? e.payload
                                : JSON.stringify(e.payload);
                        if (ps !== payload.expected_payload) {
                            return false;
                        }
                    }
                    if (
                        payload.expected_publisher &&
                        e.publisher !== payload.expected_publisher
                    ) {
                        return false;
                    }
                    if (
                        payload.expected_custom_message_type &&
                        e.customMessageType !==
                            payload.expected_custom_message_type
                    ) {
                        return false;
                    }
                    return true;
                };

                // Phase 1: subscribe to the test channel so events from
                // it land in the event buffer, then tell device we are ready.
                pubnub.subscribe({ channels: [channel], withPresence: false });
                // Brief settle to ensure the subscribe reaches the server
                // before device publishes — PubNub subscribe is async.
                await new Promise((r) => setTimeout(r, 500));
                send({ type: "ready", seq });

                // Phase 2: wait for the matching event.
                const svResult = await registerExpectation(
                    channel,
                    eventType,
                    filter,
                    timeoutMs
                );

                // Clean up: unsubscribe from the test channel.
                pubnub.unsubscribe({ channels: [channel] });
                if (svResult.pass) {
                    const ev = svResult.event;
                    send({
                        type: "action_done",
                        seq,
                        detail: JSON.stringify({
                            actual_event_type: ev.type,
                            actual_payload:
                                typeof ev.payload === "string"
                                    ? ev.payload
                                    : JSON.stringify(ev.payload),
                            actual_publisher: ev.publisher,
                        }),
                    });
                } else {
                    console.log(
                        `[companion] subscribe_and_verify FAIL seq=${seq}:`,
                        svResult.detail,
                        `| expected_payload=${payload.expected_payload}`,
                        `| expected_type=${eventType}`,
                        svResult.event
                            ? `| actual_payload=${typeof svResult.event.payload === "string" ? svResult.event.payload : JSON.stringify(svResult.event.payload)}`
                            : "| (no event received)"
                    );
                    send({
                        type: "action_fail",
                        seq,
                        detail: svResult.detail,
                    });
                }
                break;
            }

            case "subscribe_presence_and_verify": {
                const presTimeoutMs = payload.timeout_ms || 20000;
                const presFilter = (e) => {
                    if (
                        payload.presence_event &&
                        e.presenceEvent !== payload.presence_event
                    ) {
                        return false;
                    }
                    if (
                        payload.expected_uuid &&
                        e.presenceUuid !== payload.expected_uuid
                    ) {
                        return false;
                    }
                    return true;
                };

                pubnub.subscribe({ channels: [channel], withPresence: true });

                // For "join" verification the device subscribes AFTER we send
                // ready, so the 500 ms settle is sufficient — we just need the
                // subscription to be active before the device joins.
                //
                // For "leave" / "state-change" the device is already present
                // when this request arrives.  Sending ready immediately would
                // let the device unsubscribe / change state before our subscribe
                // cursor has advanced past the join event, causing the target
                // event to fall at or below the cursor on this POP.  Instead,
                // wait for the JOIN of the expected UUID first so our cursor is
                // guaranteed to be above it, then tell the device to proceed.
                if (
                    payload.presence_event &&
                    payload.presence_event !== "join" &&
                    payload.expected_uuid
                ) {
                    const joinFilter = (e) =>
                        e.presenceEvent === "join" &&
                        e.presenceUuid === payload.expected_uuid;
                    const joinResult = await registerExpectation(
                        channel,
                        "presence",
                        joinFilter,
                        presTimeoutMs
                    );
                    if (!joinResult.pass) {
                        pubnub.unsubscribe({ channels: [channel] });
                        send({
                            type: "action_fail",
                            seq,
                            detail: `timeout waiting for presence on ${channel}`,
                        });
                        break;
                    }
                } else {
                    await new Promise((r) => setTimeout(r, 500));
                }

                send({ type: "ready", seq });

                const presResult = await registerExpectation(
                    channel,
                    "presence",
                    presFilter,
                    presTimeoutMs
                );
                pubnub.unsubscribe({ channels: [channel] });
                if (presResult.pass) {
                    send({
                        type: "action_done",
                        seq,
                        detail: JSON.stringify({
                            actual_event: presResult.event.presenceEvent,
                            actual_uuid: presResult.event.presenceUuid,
                            actual_state: presResult.event.presenceState,
                        }),
                    });
                } else {
                    send({
                        type: "action_fail",
                        seq,
                        detail: presResult.detail,
                    });
                }
                break;
            }

            case "subscribe_object_and_verify": {
                const objTimeoutMs = payload.timeout_ms || 10000;
                const objFilter = (e) => {
                    if (
                        payload.object_type &&
                        e.objectType !== payload.object_type
                    ) {
                        return false;
                    }
                    if (
                        payload.expected_uuid &&
                        e.objectId !== payload.expected_uuid
                    ) {
                        return false;
                    }
                    return true;
                };

                pubnub.subscribe({ channels: [channel] });
                await new Promise((r) => setTimeout(r, 500));
                send({ type: "ready", seq });

                const objResult = await registerExpectation(
                    channel,
                    "object",
                    objFilter,
                    objTimeoutMs
                );
                pubnub.unsubscribe({ channels: [channel] });
                if (objResult.pass) {
                    send({
                        type: "action_done",
                        seq,
                        detail: JSON.stringify({
                            actual_object_type:
                                objResult.event.objectType,
                            actual_object_id: objResult.event.objectId,
                        }),
                    });
                } else {
                    send({
                        type: "action_fail",
                        seq,
                        detail: objResult.detail,
                    });
                }
                break;
            }

            case "subscribe_message_action_and_verify": {
                const maTimeoutMs = payload.timeout_ms || 10000;
                const maFilter = (e) => {
                    if (
                        payload.action_event &&
                        e.actionEvent !== payload.action_event
                    ) {
                        return false;
                    }
                    if (
                        payload.expected_type &&
                        e.actionType !== payload.expected_type
                    ) {
                        return false;
                    }
                    if (
                        payload.expected_value &&
                        e.actionValue !== payload.expected_value
                    ) {
                        return false;
                    }
                    return true;
                };

                pubnub.subscribe({ channels: [channel] });
                await new Promise((r) => setTimeout(r, 500));
                send({ type: "ready", seq });

                const maResult = await registerExpectation(
                    channel,
                    "message_action",
                    maFilter,
                    maTimeoutMs
                );
                pubnub.unsubscribe({ channels: [channel] });
                if (maResult.pass) {
                    send({
                        type: "action_done",
                        seq,
                        detail: JSON.stringify({
                            actual_action_type:
                                maResult.event.actionType,
                            actual_action_value:
                                maResult.event.actionValue,
                            actual_action_event:
                                maResult.event.actionEvent,
                        }),
                    });
                } else {
                    send({
                        type: "action_fail",
                        seq,
                        detail: maResult.detail,
                    });
                }
                break;
            }

            case "subscribe_file_and_verify": {
                const fileTimeoutMs = payload.timeout_ms || 15000;

                pubnub.subscribe({ channels: [channel] });
                await new Promise((r) => setTimeout(r, 500));
                send({ type: "ready", seq });

                const fileResult = await registerExpectation(
                    channel,
                    "file",
                    null,
                    fileTimeoutMs
                );
                pubnub.unsubscribe({ channels: [channel] });
                if (fileResult.pass) {
                    send({
                        type: "action_done",
                        seq,
                        detail: JSON.stringify({
                            actual_file_id: fileResult.event.fileId,
                            actual_file_name: fileResult.event.fileName,
                        }),
                    });
                } else {
                    send({
                        type: "action_fail",
                        seq,
                        detail: fileResult.detail,
                    });
                }
                break;
            }

            // ----------------------------------------------------------
            // Unknown action
            // ----------------------------------------------------------

            default: {
                send({
                    type: "action_fail",
                    seq,
                    detail: `unknown action: ${action}`,
                });
                break;
            }
        }
    } catch (err) {
        console.error(`[companion] action error: ${err.message}`);
        send({ type: "action_fail", seq, detail: err.message });
    }
}

// ---------------------------------------------------------------------------
// Incoming message router
// ---------------------------------------------------------------------------

function onMessage(event) {
    const msg = event.message;

    // Protocol messages from the device test runner.
    if (msg && msg.type) {
        if (msg.type === "handshake") {
            handleHandshake(msg);
            return;
        }
        if (msg.type === "request") {
            const runId = extractRunId(event.channel);
            if (runId) { handleRequest(msg, runId); }
            return;
        }
        if (msg.type === "done") {
            handleDone(msg);
            return;
        }
    }

    // Everything else goes to the event buffer for verification.
    handleIncomingEvent(normalizeMessageEvent(event));
}

// ---------------------------------------------------------------------------
// Listener setup
// ---------------------------------------------------------------------------

pubnub.addListener({
    message: onMessage,
    signal: (event) => handleIncomingEvent(normalizeSignalEvent(event)),
    presence: (event) =>
        handleIncomingEvent(normalizePresenceEvent(event)),
    messageAction: (event) =>
        handleIncomingEvent(normalizeMessageActionEvent(event)),
    objects: (event) =>
        handleIncomingEvent(normalizeObjectEvent(event)),
    file: (event) => handleIncomingEvent(normalizeFileEvent(event)),
    status: (event) => {
        if (event.category === "PNConnectedCategory") {
            console.log(
                "[companion] subscribed, waiting for device handshake..."
            );
        }
    },
});

// ---------------------------------------------------------------------------
// Subscribe — fixed discovery channel + presence.
// Dash-only names avoid PubNub's wildcard-depth restriction.
// ---------------------------------------------------------------------------

pubnub.subscribe({ channels: ["iot-ks-handshake"], withPresence: true });

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

console.log("[companion] PubNub IoT Kitchensink Companion started");
console.log(`[companion] sub-key: ${args.subKey.slice(0, 8)}...`);
console.log("[companion] listening for handshake on iot-ks-handshake");
if (args.cipherKey) {
    console.log("[companion] crypto: ACRH + legacy instances ready");
}
