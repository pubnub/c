/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/crypto/async.c
 * @brief Publish an encrypted message using async callback.
 *
 * Same transparent encryption as the cooperative example, but
 * completion is delivered via pubnub_async() callback.
 *
 * Build: cmake --build build/full --target example_crypto_async
 * Run:   ./build/full/examples/crypto/example_crypto_async
 */

// snippet.cryptoAsync

#include "pubnub/pubnub.h"

#include <stdio.h>

static volatile int s_done;

static void on_complete(pubnub_future_t future, pubnub_res_t status, void* user_data)
{
    (void)user_data;
    if (PUBNUB_OK == status) {
        pubnub_timetoken_t tt = pubnub_publish_result_timetoken(future);
        printf("Published (encrypted) OK, timetoken: %.*s\n", (int)tt.len, tt.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(future);
        printf("Publish failed: %.*s\n", (int)err.len, err.ptr);
    }
    pubnub_future_release(future);
    s_done = 1;
}

int main(void)
{
    /* 1. Create crypto module (NULL = compiled-in default allocator). */
    pubnub_crypto_module_t* crypto =
        pubnub_crypto_module_aes_cbc("my-cipher-key", 1, NULL);
    if (NULL == crypto) {
        printf("Failed to create crypto module\n");
        return 1;
    }

    /* 2. Configure and create context. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-crypto-async";
    cfg.crypto_module   = crypto;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        pubnub_crypto_module_destroy(crypto);
        return 1;
    }

    /* 3. Publish with async callback — encryption is transparent. */
    pubnub_future_t fut =
        pubnub_publish(ctx,
                       &(pubnub_publish_opts_t){
                           .channel = "crypto_demo",
                           .message = "{\"text\":\"Secret async message\"}",
                       });
    pubnub_async(fut, on_complete, NULL);

    /* 4. Drive I/O until callback fires. */
    while (!s_done) {
        pubnub_process(ctx);
    }

    /* 5. Cleanup. */
    pubnub_destroy(ctx);
    pubnub_crypto_module_destroy(crypto);
    return 0;
}

// snippet.end
