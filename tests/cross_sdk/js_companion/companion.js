#!/usr/bin/env node
/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
/*
 * Headless JS companion CLI for C SDK cross-SDK parity tests.
 *
 * Usage:
 *   node companion.js \
 *     --sub-key <key> --pub-key <key> \
 *     --scenario <name> --channel <ch> \
 *     [--uuid <uuid>] [--content <str>] [--cipher <key>] [--output <path>]
 *
 * Exits 0 on pass, 1 on fail. Writes {"pass":bool,"detail":"..."} JSON to
 * --output path (or stdout when --output is absent).
 */

'use strict';

const fs = require('fs');

/* -------------------------------------------------------------------------- */
/* Argument parsing                                                            */
/* -------------------------------------------------------------------------- */

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; i++) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            continue;
        }
        const key = token.slice(2).replace(/-/g, '_');
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
            args[key] = next;
            i++;
        } else {
            args[key] = true;
        }
    }
    return args;
}

/* -------------------------------------------------------------------------- */
/* Result I/O                                                                  */
/* -------------------------------------------------------------------------- */

function writeResult(outputPath, pass, detail) {
    const payload = JSON.stringify({ pass, detail }) + '\n';
    if (outputPath && typeof outputPath === 'string') {
        fs.writeFileSync(outputPath, payload);
    } else {
        process.stdout.write(payload);
    }
}

/* -------------------------------------------------------------------------- */
/* PubNub initialisation                                                       */
/* -------------------------------------------------------------------------- */

function makePubNub(args) {
    /* Resolve exports for both CJS bundles and ESM-wrapped CJS. */
    const pkg = require('pubnub');
    const PubNub = pkg.default || pkg;
    const CryptoModule = pkg.CryptoModule || (PubNub && PubNub.CryptoModule);

    const opts = {
        publishKey: args.pub_key,
        subscribeKey: args.sub_key,
        userId: args.uuid || 'js-companion',
    };

    if (args.cipher && CryptoModule) {
        opts.cryptoModule = CryptoModule.aesCbcCryptoModule({
            cipherKey: args.cipher,
        });
    }

    return new PubNub(opts);
}

/* -------------------------------------------------------------------------- */
/* File download helper — handles Buffer/ArrayBuffer variants                  */
/* -------------------------------------------------------------------------- */

async function fileToString(fileObj) {
    if (typeof fileObj.toBuffer === 'function') {
        const buf = await fileObj.toBuffer();
        return buf.toString('utf8');
    }
    if (typeof fileObj.toArrayBuffer === 'function') {
        const ab = await fileObj.toArrayBuffer();
        return Buffer.from(ab).toString('utf8');
    }
    if (typeof fileObj.toString === 'function') {
        const s = fileObj.toString();
        if (s !== '[object Object]') {
            return s;
        }
    }
    return String(fileObj);
}

/* -------------------------------------------------------------------------- */
/* Scenario dispatch                                                           */
/* -------------------------------------------------------------------------- */

async function runScenario(args) {
    const pubnub = makePubNub(args);
    const { scenario, channel, content, uuid } = args;

    switch (scenario) {

        /* ------------------------------------------------------------------ */
        /* JS-produces                                                         */
        /* ------------------------------------------------------------------ */

        case 'js_publish': {
            const res = await pubnub.publish({ channel, message: content });
            return { pass: true, detail: `timetoken=${res.timetoken}` };
        }

        case 'js_publish_encrypted': {
            /* cryptoModule is wired at init when --cipher is present. */
            const res = await pubnub.publish({ channel, message: content });
            return { pass: true, detail: `timetoken=${res.timetoken}` };
        }

        case 'js_upload_file': {
            const buf = Buffer.from(content || '', 'utf-8');
            const res = await pubnub.sendFile({
                channel,
                file: { data: buf, name: 'companion-upload.txt', mimeType: 'text/plain' },
                /* message is a known value so the C side can verify the file
                 * notification message in channel history. */
                message: content,
            });
            return { pass: true, detail: `fileId=${res.fileId || res.id || 'ok'}` };
        }

        case 'js_set_uuid_metadata': {
            const targetUuid = uuid || 'js-companion';
            await pubnub.objects.setUUIDMetadata({
                uuid: targetUuid,
                data: { name: content },
            });
            return { pass: true, detail: `uuid=${targetUuid} name="${content}"` };
        }

        case 'js_json_publish': {
            const res = await pubnub.publish({
                channel,
                message: { from: 'js-sdk', value: 42 },
            });
            return { pass: true, detail: `timetoken=${res.timetoken}` };
        }

        case 'js_upload_encrypted_file': {
            /* cryptoModule is wired at init when --cipher is present. */
            const buf = Buffer.from(content || '', 'utf-8');
            const res = await pubnub.sendFile({
                channel,
                file: {
                    data: buf,
                    name: 'companion-upload-enc.txt',
                    mimeType: 'text/plain',
                },
                /* message is a known value so the C side can verify it. */
                message: content,
            });
            return { pass: true, detail: `fileId=${res.fileId || res.id || 'ok'}` };
        }

        case 'js_set_channel_metadata': {
            await pubnub.objects.setChannelMetadata({
                channel,
                data: { name: content },
            });
            return { pass: true, detail: `channel=${channel} name="${content}"` };
        }

        case 'js_add_message_action': {
            const pubRes = await pubnub.publish({
                channel,
                message: 'js-reaction-target',
            });
            const actionRes = await pubnub.addMessageAction({
                channel,
                messageTimetoken: pubRes.timetoken,
                action: { type: 'reaction', value: 'thumbsup' },
            });
            return {
                pass: true,
                detail: `actionTimetoken=${actionRes.data.actionTimetoken}`,
            };
        }

        /* ------------------------------------------------------------------ */
        /* C-produces / JS-verifies                                            */
        /* ------------------------------------------------------------------ */

        case 'c_publish_verify': {
            const res = await pubnub.fetchMessages({
                channels: [channel],
                count: 5,
            });
            const msgs = (res.channels && res.channels[channel]) || [];
            const found = msgs.some(
                (m) => typeof m.message === 'string' && m.message === content,
            );
            return found
                ? { pass: true, detail: `message exactly "${content}" found` }
                : {
                    pass: false,
                    detail: `exact message "${content}" not found in ${msgs.length} messages`,
                };
        }

        case 'c_json_verify': {
            const res = await pubnub.fetchMessages({
                channels: [channel],
                count: 5,
            });
            const msgs = (res.channels && res.channels[channel]) || [];
            const found = msgs.some((m) => {
                const msg = m.message;
                return (
                    msg !== null &&
                    typeof msg === 'object' &&
                    msg.from === 'c-sdk' &&
                    msg.value === 42
                );
            });
            return found
                ? { pass: true, detail: 'c-sdk JSON message with value=42 found' }
                : {
                    pass: false,
                    detail: `c-sdk JSON not found in last ${msgs.length} messages`,
                };
        }

        case 'c_encrypted_verify': {
            /* cryptoModule auto-decrypts during fetchMessages. A successful
             * decrypt yields a JS string; ciphertext appears as an object or
             * non-matching string, so exact-equality proves decryption worked. */
            const res = await pubnub.fetchMessages({
                channels: [channel],
                count: 5,
            });
            const msgs = (res.channels && res.channels[channel]) || [];
            const found = msgs.some(
                (m) => typeof m.message === 'string' && m.message === content,
            );
            return found
                ? { pass: true, detail: `decrypted message exactly "${content}" found` }
                : {
                    pass: false,
                    detail: `exact decrypted "${content}" not found in ${msgs.length} messages`,
                };
        }

        case 'c_file_verify': {
            const listRes = await pubnub.listFiles({ channel });
            const files = listRes.data || [];
            if (files.length === 0) {
                return { pass: false, detail: 'no files found on channel' };
            }
            const latest = files[files.length - 1];
            const dlRes = await pubnub.downloadFile({
                channel,
                id: latest.id,
                name: latest.name,
            });
            const text = await fileToString(dlRes);
            if (text !== content) {
                return {
                    pass: false,
                    detail: `file content mismatch: expected "${content}", got "${text.slice(0, 80)}"`,
                };
            }
            /* Also verify the file notification message in channel history.
             * C uploads with opts.message = JSON-encoded content, so the
             * file notification should carry message === content AND point
             * to this specific file. */
            const histRes = await pubnub.fetchMessages({ channels: [channel], count: 10 });
            const histMsgs = (histRes.channels && histRes.channels[channel]) || [];
            const notifOk = histMsgs.some(
                (m) =>
                    m.message &&
                    typeof m.message === 'object' &&
                    m.message.file &&
                    m.message.file.id === latest.id &&
                    m.message.message === content,
            );
            return notifOk
                ? {
                    pass: true,
                    detail: `file content and notification message both match "${content}"`,
                }
                : {
                    pass: false,
                    detail: `file content matches but notification message "${content}" not found for file ${latest.id}`,
                };
        }

        case 'c_encrypted_file_verify': {
            /* cryptoModule auto-decrypts on download. */
            const listRes = await pubnub.listFiles({ channel });
            const files = listRes.data || [];
            if (files.length === 0) {
                return { pass: false, detail: 'no files found on channel' };
            }
            const latest = files[files.length - 1];
            const dlRes = await pubnub.downloadFile({
                channel,
                id: latest.id,
                name: latest.name,
            });
            const text = await fileToString(dlRes);
            if (text !== content) {
                return {
                    pass: false,
                    detail: `decrypted content mismatch: expected "${content}", got "${text.slice(0, 80)}"`,
                };
            }
            const histRes = await pubnub.fetchMessages({ channels: [channel], count: 10 });
            const histMsgs = (histRes.channels && histRes.channels[channel]) || [];
            const notifOk = histMsgs.some(
                (m) =>
                    m.message &&
                    typeof m.message === 'object' &&
                    m.message.file &&
                    m.message.file.id === latest.id &&
                    m.message.message === content,
            );
            return notifOk
                ? {
                    pass: true,
                    detail: `decrypted file content and notification message both match "${content}"`,
                }
                : {
                    pass: false,
                    detail: `decrypted content matches but notification "${content}" not found for file ${latest.id}`,
                };
        }

        case 'c_metadata_verify': {
            const targetUuid = uuid || 'js-companion';
            const res = await pubnub.objects.getUUIDMetadata({
                uuid: targetUuid,
            });
            const name = res.data && res.data.name;
            return name === content
                ? { pass: true, detail: `UUID name="${name}"` }
                : {
                    pass: false,
                    detail: `expected name="${content}", got name="${name}"`,
                };
        }

        case 'c_channel_metadata_verify': {
            const res = await pubnub.objects.getChannelMetadata({ channel });
            const name = res.data && res.data.name;
            return name === content
                ? { pass: true, detail: `channel name="${name}"` }
                : {
                    pass: false,
                    detail: `expected name="${content}", got name="${name}"`,
                };
        }

        case 'c_message_action_verify': {
            const res = await pubnub.getMessageActions({ channel });
            const actions = res.data || [];
            const found = actions.some(
                (a) => a.type === 'reaction' && a.value === 'thumbsup',
            );
            return found
                ? { pass: true, detail: 'reaction:thumbsup action found' }
                : {
                    pass: false,
                    detail: `no reaction:thumbsup action; ${actions.length} actions total`,
                };
        }

        case 'c_presence_state_verify': {
            /* C set presence state on the channel; JS reads it via hereNow. */
            const targetUuid = uuid || 'xs-c-runner';
            const res = await pubnub.hereNow({
                channels: [channel],
                includeState: true,
                includeUUIDs: true,
            });
            const chData = res.channels && res.channels[channel];
            if (!chData || !chData.occupants) {
                return {
                    pass: false,
                    detail: `no occupants on channel ${channel}`,
                };
            }
            const occupant = chData.occupants.find((o) => o.uuid === targetUuid);
            if (!occupant) {
                const uuids = chData.occupants.map((o) => o.uuid).join(', ');
                return {
                    pass: false,
                    detail: `uuid ${targetUuid} not found; occupants: [${uuids}]`,
                };
            }
            const stateStr = JSON.stringify(occupant.state);
            const expected = content || '{"mood":"happy"}';
            if (stateStr === expected) {
                return { pass: true, detail: `state matches: ${stateStr}` };
            }
            return {
                pass: false,
                detail: `state mismatch: expected ${expected}, got ${stateStr}`,
            };
        }

        case 'c_channel_groups_verify': {
            /* C added 3 channels to a group named after the channel; JS lists them. */
            const res = await pubnub.channelGroups.listChannels({
                channelGroup: channel,
            });
            const channels_list = res.channels || [];
            const expected_a = `${channel}-a`;
            const expected_b = `${channel}-b`;
            const expected_c = `${channel}-c`;
            const has_a = channels_list.includes(expected_a);
            const has_b = channels_list.includes(expected_b);
            const has_c = channels_list.includes(expected_c);
            if (has_a && has_b && has_c) {
                return {
                    pass: true,
                    detail: `all 3 channels found in group: ${channels_list.join(', ')}`,
                };
            }
            return {
                pass: false,
                detail: `missing channels; expected [${expected_a},${expected_b},${expected_c}], got [${channels_list.join(', ')}]`,
            };
        }

        default:
            return { pass: false, detail: `unknown scenario: ${scenario}` };
    }
}

/* -------------------------------------------------------------------------- */
/* Entry point                                                                 */
/* -------------------------------------------------------------------------- */

async function main() {
    const args = parseArgs(process.argv);

    if (args.help || args.h) {
        process.stdout.write(
            'Scenarios: js_publish, js_publish_encrypted, js_upload_file,\n' +
                '           js_set_uuid_metadata, c_publish_verify, c_json_verify,\n' +
                '           c_encrypted_verify, c_file_verify, c_encrypted_file_verify,\n' +
                '           c_metadata_verify, c_channel_metadata_verify,\n' +
                '           c_message_action_verify\n',
        );
        process.exit(0);
    }

    if (!args.sub_key || !args.pub_key || !args.scenario) {
        process.stderr.write(
            'Usage: node companion.js --sub-key <key> --pub-key <key>\n' +
                '         --scenario <name> [--channel <ch>] [--uuid <uuid>]\n' +
                '         [--content <str>] [--cipher <key>] [--output <path>]\n',
        );
        process.exit(1);
    }

    let result;
    try {
        result = await runScenario(args);
    } catch (err) {
        result = { pass: false, detail: `error: ${err.message || String(err)}` };
    }

    writeResult(args.output, result.pass, result.detail);
    process.exit(result.pass ? 0 : 1);
}

main().catch((err) => {
    process.stderr.write(`Fatal: ${err.message || String(err)}\n`);
    process.exit(1);
});
