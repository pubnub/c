/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/cooperative.c
 * @brief Publish an encrypted message using cooperative polling.
 *
 * Demonstrates transparent payload encryption: set a crypto module on
 * the config and all publish/subscribe/history payloads are encrypted
 * automatically. Any completion style (polling, await, async) works.
 *
 * Build: cmake --build build/full --target example_crypto_cooperative
 * Run:   ./build/full/examples/crypto/example_crypto_cooperative
 */

// snippet.cryptoCooperative

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Create a crypto module (AES-256-CBC, random IV).
     * Pass NULL for allocator — uses compiled-in default. */
    pubnub_crypto_module_t* crypto =
        pubnub_crypto_module_aes_cbc("my-cipher-key", 1, NULL);
    if (NULL == crypto) {
        printf("Failed to create crypto module\n");
        return 1;
    }

    /* 2. Configure the client with crypto attached. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-crypto-cooperative";
    cfg.crypto_module   = crypto;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        pubnub_crypto_module_destroy(crypto);
        return 1;
    }

    /* 3. Publish — payload is encrypted transparently. */
    pubnub_future_t fut =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel = "crypto_demo",
                           .message = "{\"text\":\"Hello encrypted world!\"}",
                       });

    /* 4. Cooperative poll until ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 5. Check result. */
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        printf("Published (encrypted) OK, timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("Publish failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 6. Cleanup — context first, then module. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    pubnub_crypto_module_destroy(crypto);
    return 0;
}

// snippet.end
