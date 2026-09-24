#!/usr/bin/env node
/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
/*
 * Headless orchestrator for C SDK cross-SDK parity tests.
 *
 * Reads environment variables, runs 12 scenarios (C-first and JS-first),
 * and exits 0 if all pass or 1 if any fail. Writes results.json alongside
 * this file for post-run inspection.
 *
 * Required env vars:
 *   PUBNUB_PUBLISH_KEY   — PubNub publish key
 *   PUBNUB_SUBSCRIBE_KEY — PubNub subscribe key
 *   CROSS_SDK_C_BINARY   — path to cross_sdk_c_runner executable
 *
 * Optional env vars:
 *   CROSS_SDK_C_PUB_KEY  — publish key for C runner (defaults to PUBNUB_PUBLISH_KEY)
 *   CROSS_SDK_C_SUB_KEY  — subscribe key for C runner (defaults to PUBNUB_SUBSCRIBE_KEY)
 */

'use strict';

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/* -------------------------------------------------------------------------- */
/* Environment                                                                  */
/* -------------------------------------------------------------------------- */

const PUB_KEY = process.env.PUBNUB_PUBLISH_KEY;
const SUB_KEY = process.env.PUBNUB_SUBSCRIBE_KEY;
const C_BINARY = process.env.CROSS_SDK_C_BINARY;
const C_PUB_KEY = process.env.CROSS_SDK_C_PUB_KEY || PUB_KEY;
const C_SUB_KEY = process.env.CROSS_SDK_C_SUB_KEY || SUB_KEY;

const COMPANION_JS = path.resolve(__dirname, '..', 'js_companion', 'companion.js');

/* -------------------------------------------------------------------------- */
/* Skip gate — exit 0 so CTest marks as "not run" rather than "failed"        */
/* -------------------------------------------------------------------------- */

if (!PUB_KEY || !SUB_KEY) {
    console.log('[cross-sdk] PUBNUB_PUBLISH_KEY or PUBNUB_SUBSCRIBE_KEY not set — skipping.');
    process.exit(0);
}

if (!C_BINARY) {
    console.log('[cross-sdk] CROSS_SDK_C_BINARY not set — skipping.');
    process.exit(0);
}

/* -------------------------------------------------------------------------- */
/* Scenario definitions                                                        */
/* -------------------------------------------------------------------------- */

const C_FIRST_SCENARIOS = [
    {
        name: 'c_publish_js_verifies',
        c_scenario: 'c_publish',
        js_scenario: 'c_publish_verify',
        channel_suffix: 'pub',
        content: 'c-hello-$$',
    },
    {
        name: 'c_compressed_publish_js_verifies',
        c_scenario: 'c_compressed_publish',
        js_scenario: 'c_publish_verify',
        channel_suffix: 'cpub',
        content: 'hello-compressed-xs',
    },
    {
        name: 'c_json_publish_js_verifies',
        c_scenario: 'c_json_publish',
        js_scenario: 'c_json_verify',
        channel_suffix: 'jpub',
    },
    {
        name: 'c_encrypted_publish_js_decrypts',
        c_scenario: 'c_encrypted_publish',
        js_scenario: 'c_encrypted_verify',
        channel_suffix: 'epub',
        cipher: 'enigma',
        content: 'c-encrypted-$$',
    },
    {
        name: 'c_upload_file_js_downloads',
        c_scenario: 'c_file_upload',
        js_scenario: 'c_file_verify',
        channel_suffix: 'file',
        content: 'Hello from C $$',
    },
    {
        name: 'c_upload_encrypted_file_js_downloads',
        c_scenario: 'c_encrypted_file_upload',
        js_scenario: 'c_encrypted_file_verify',
        channel_suffix: 'efile',
        cipher: 'enigma',
        content: 'Encrypted file $$',
    },
    {
        name: 'c_set_uuid_metadata_js_reads',
        c_scenario: 'c_set_uuid_metadata',
        js_scenario: 'c_metadata_verify',
        channel_suffix: 'umeta',
        content: 'C-SDK-$$',
    },
    {
        name: 'c_set_channel_metadata_js_reads',
        c_scenario: 'c_set_channel_metadata',
        js_scenario: 'c_channel_metadata_verify',
        channel_suffix: 'cmeta',
        content: 'C-Chan-$$',
    },
    {
        name: 'c_add_message_action_js_verifies',
        c_scenario: 'c_add_message_action',
        js_scenario: 'c_message_action_verify',
        channel_suffix: 'mact',
    },
    {
        name: 'c_presence_state_set_js_verifies',
        c_scenario: 'c_presence_state_set',
        js_scenario: 'c_presence_state_verify',
        channel_suffix: 'pstate',
        content: '{"mood":"happy"}',
    },
    {
        name: 'c_channel_groups_add_js_verifies',
        c_scenario: 'c_channel_groups_add',
        js_scenario: 'c_channel_groups_verify',
        channel_suffix: 'cgrp',
    },
];

const JS_FIRST_SCENARIOS = [
    {
        name: 'js_publish_c_verifies',
        js_scenario: 'js_publish',
        c_scenario: 'js_publish_verify',
        channel_suffix: 'jspub',
        content: 'js-hello-$$',
    },
    {
        name: 'js_publish_encrypted_c_decrypts',
        js_scenario: 'js_publish_encrypted',
        c_scenario: 'js_encrypted_verify',
        channel_suffix: 'jsepub',
        cipher: 'enigma',
        content: 'js-encrypted-$$',
    },
    {
        name: 'js_upload_file_c_downloads',
        js_scenario: 'js_upload_file',
        c_scenario: 'js_file_verify',
        channel_suffix: 'jsfile',
        content: 'Hello from JS $$',
    },
    {
        name: 'js_set_uuid_metadata_c_reads',
        js_scenario: 'js_set_uuid_metadata',
        c_scenario: 'js_metadata_verify',
        channel_suffix: 'jsmeta',
        content: 'JS-SDK-$$',
    },
    {
        name: 'js_json_publish_c_verifies',
        js_scenario: 'js_json_publish',
        c_scenario: 'js_json_verify',
        channel_suffix: 'jsjpub',
    },
    {
        name: 'js_upload_encrypted_file_c_downloads',
        js_scenario: 'js_upload_encrypted_file',
        c_scenario: 'js_encrypted_file_verify',
        channel_suffix: 'jsefile',
        cipher: 'enigma',
        content: 'Hello from JS encrypted $$',
    },
    {
        name: 'js_set_channel_metadata_c_reads',
        js_scenario: 'js_set_channel_metadata',
        c_scenario: 'js_channel_metadata_verify',
        channel_suffix: 'jscmeta',
        content: 'JS-Chan-$$',
    },
    {
        name: 'js_add_message_action_c_verifies',
        js_scenario: 'js_add_message_action',
        c_scenario: 'js_message_action_verify',
        channel_suffix: 'jsmact',
    },
];

/* -------------------------------------------------------------------------- */
/* Utilities                                                                   */
/* -------------------------------------------------------------------------- */

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomHex(bytes) {
    return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Run one side of a scenario synchronously.
 * Returns { pass: bool, detail: string }.
 *
 * @param {string}   cmd   Executable path (C binary) or 'node' (JS companion).
 * @param {string[]} args  Arguments to pass; --output is appended internally.
 */
function runSide(cmd, args) {
    const outputPath = `/tmp/xs_result_${randomHex(8)}.json`;
    const spawnResult = spawnSync(cmd, [...args, '--output', outputPath], {
        encoding: 'utf8',
        timeout: 30000,
    });

    let result;
    if (spawnResult.error) {
        result = { pass: false, detail: `spawn error: ${spawnResult.error.message}` };
    } else {
        try {
            const raw = fs.readFileSync(outputPath, 'utf8');
            const parsed = JSON.parse(raw.trim());
            result = { pass: !!parsed.pass, detail: String(parsed.detail || '') };
        } catch (_) {
            const stderr = (spawnResult.stderr || '').trim();
            result = {
                pass: false,
                detail:
                    `no output file; exit=${spawnResult.status}` +
                    (stderr ? `; ${stderr.slice(0, 200)}` : ''),
            };
        }
    }

    try { fs.unlinkSync(outputPath); } catch (_) { /* best effort */ }
    return result;
}

/**
 * Build argument list for a scenario side (C or JS).
 *
 * @param {string}          scenario  Scenario name.
 * @param {string}          channel   Channel name.
 * @param {string}          uuid      UUID for metadata scenarios.
 * @param {string}          pubKey    Publish key.
 * @param {string}          subKey    Subscribe key.
 * @param {string|undefined} content  Content string (may be undefined).
 * @param {string|undefined} cipher   Cipher key (may be undefined).
 * @returns {string[]}
 */
function buildArgs(scenario, channel, uuid, pubKey, subKey, content, cipher) {
    const args = [
        '--scenario', scenario,
        '--channel', channel,
        '--sub-key', subKey,
        '--pub-key', pubKey,
        '--uuid', uuid,
    ];
    if (content !== undefined) {
        args.push('--content', content);
    }
    if (cipher) {
        args.push('--cipher', cipher);
    }
    return args;
}

/**
 * Run the cleanup scenario (best effort — errors are ignored).
 *
 * @param {string} channel  Channel to clean up.
 * @param {string} uuid     UUID to clean up.
 */
function runCleanup(channel, uuid) {
    try {
        spawnSync(
            C_BINARY,
            [
                '--scenario', 'cleanup',
                '--channel', channel,
                '--sub-key', C_SUB_KEY,
                '--pub-key', C_PUB_KEY,
                '--uuid', uuid,
            ],
            { timeout: 10000 },
        );
    } catch (_) { /* best effort */ }
}

/* -------------------------------------------------------------------------- */
/* Per-scenario runners                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Run a C-first scenario: C publishes, JS verifies.
 *
 * @param {object} scenario  Scenario definition.
 * @returns {Promise<{name, pass, detail_a, detail_b}>}
 */
async function runCFirstScenario(scenario) {
    const hex = randomHex(4);
    const channel = `pn-xs-${hex}-${scenario.channel_suffix}`;
    const content = scenario.content ? scenario.content.replace('$$', hex) : undefined;
    const uuid = `xs-uuid-${hex}`;

    const resultA = runSide(
        C_BINARY,
        buildArgs(scenario.c_scenario, channel, uuid, C_PUB_KEY, C_SUB_KEY, content, scenario.cipher),
    );

    await sleep(2500);

    const resultB = runSide(
        'node',
        [COMPANION_JS,
         ...buildArgs(scenario.js_scenario, channel, uuid, PUB_KEY, SUB_KEY, content, scenario.cipher)],
    );

    runCleanup(channel, uuid);

    return {
        name: scenario.name,
        pass: resultA.pass && resultB.pass,
        detail_a: resultA.detail,
        detail_b: resultB.detail,
    };
}

/**
 * Run a JS-first scenario: JS publishes, C verifies.
 *
 * @param {object} scenario  Scenario definition.
 * @returns {Promise<{name, pass, detail_a, detail_b}>}
 */
async function runJsFirstScenario(scenario) {
    const hex = randomHex(4);
    const channel = `pn-xs-${hex}-${scenario.channel_suffix}`;
    const content = scenario.content ? scenario.content.replace('$$', hex) : undefined;
    const uuid = `xs-uuid-${hex}`;

    const resultA = runSide(
        'node',
        [COMPANION_JS,
         ...buildArgs(scenario.js_scenario, channel, uuid, PUB_KEY, SUB_KEY, content, scenario.cipher)],
    );

    await sleep(2500);

    const resultB = runSide(
        C_BINARY,
        buildArgs(scenario.c_scenario, channel, uuid, C_PUB_KEY, C_SUB_KEY, content, scenario.cipher),
    );

    runCleanup(channel, uuid);

    return {
        name: scenario.name,
        pass: resultA.pass && resultB.pass,
        detail_a: resultA.detail,
        detail_b: resultB.detail,
    };
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

async function main() {
    const total = C_FIRST_SCENARIOS.length + JS_FIRST_SCENARIOS.length;
    console.log(`[cross-sdk] Running ${total} scenarios...\n`);

    const results = [];

    for (const scenario of C_FIRST_SCENARIOS) {
        process.stdout.write(`  ${scenario.name} ... `);
        const result = await runCFirstScenario(scenario);
        results.push(result);
        if (result.pass) {
            console.log('PASS');
        } else {
            console.log('FAIL');
            console.log(`    side A (C): ${result.detail_a}`);
            console.log(`    side B (JS): ${result.detail_b}`);
        }
    }

    for (const scenario of JS_FIRST_SCENARIOS) {
        process.stdout.write(`  ${scenario.name} ... `);
        const result = await runJsFirstScenario(scenario);
        results.push(result);
        if (result.pass) {
            console.log('PASS');
        } else {
            console.log('FAIL');
            console.log(`    side A (JS): ${result.detail_a}`);
            console.log(`    side B (C): ${result.detail_b}`);
        }
    }

    const passCount = results.filter((r) => r.pass).length;
    const failCount = results.length - passCount;

    const outputData = {
        timestamp: new Date().toISOString(),
        scenarios: results,
        summary: { total: results.length, pass: passCount, fail: failCount },
    };

    const resultsPath = path.join(__dirname, 'results.json');
    fs.writeFileSync(resultsPath, JSON.stringify(outputData, null, 2) + '\n');

    console.log(`\n[cross-sdk] ${passCount}/${results.length} passed`);
    if (failCount > 0) {
        console.log(`[cross-sdk] ${failCount} failed`);
    }
    console.log(`[cross-sdk] Results written to ${resultsPath}`);

    process.exit(failCount === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('[cross-sdk] Fatal error:', err);
    process.exit(1);
});
