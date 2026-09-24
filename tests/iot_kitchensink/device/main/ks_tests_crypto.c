/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/features/crypto.h"
#include "pubnub/features/history.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator_arena.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern uint8_t*                 g_crypto_pool;
extern pubnub_arena_allocator_t g_crypto_arena;
extern uint8_t                  g_crypto_ctx_mem[];

static pubnub_context_t*            s_crypto_ctx    = NULL;
static pubnub_crypto_module_t*      s_crypto_module = NULL;
static pubnub_allocator_provider_t* s_crypto_alloc  = NULL;

/** Initialize g_crypto_arena once and return its allocator. */
static pubnub_allocator_provider_t* get_crypto_alloc(void)
{
    if (NULL == s_crypto_alloc) {
        if (NULL == g_crypto_pool) {
            return NULL;
        }
        s_crypto_alloc = pubnub_arena_allocator_init(
            &g_crypto_arena, g_crypto_pool, KS_CRYPTO_POOL_SIZE);
    }
    return s_crypto_alloc;
}

static pubnub_context_t* init_crypto_ctx(void)
{
    pubnub_allocator_provider_t* alloc;
    pubnub_config_t              cfg;
    pubnub_res_t                 rc;

    if (NULL != s_crypto_ctx) {
        return s_crypto_ctx;
    }
    if (NULL == g_crypto_pool) {
        return NULL;
    }
    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        return NULL;
    }

    alloc = get_crypto_alloc();
    if (NULL == alloc) {
        return NULL;
    }

    /* Use the crypto arena allocator — NULL would fall back to nothing on
     * embedded targets where there is no global heap. */
    s_crypto_module =
        pubnub_crypto_module_aes_cbc(CONFIG_PUBNUB_KS_CIPHER_KEY, 1, alloc);
    if (NULL == s_crypto_module) {
        return NULL;
    }

    cfg               = pubnub_config_defaults();
    cfg.subscribe_key = CONFIG_PUBNUB_KS_SUB_KEY;
    cfg.publish_key   = CONFIG_PUBNUB_KS_PUB_KEY;
    cfg.user_id       = CONFIG_PUBNUB_KS_USER_ID;
    cfg.allocator     = alloc;
    cfg.crypto_module = s_crypto_module;

    s_crypto_ctx = (pubnub_context_t*)g_crypto_ctx_mem;
    rc           = pubnub_init(s_crypto_ctx, &cfg);
    if (PUBNUB_OK != rc) {
        s_crypto_ctx = NULL;
        return NULL;
    }

    pubnub_set_log_level(s_crypto_ctx, PUBNUB_LOG_LEVEL_WARNING);
    return s_crypto_ctx;
}

static void cleanup_crypto_ctx(void)
{
    /* Destroy module BEFORE deinit: module + cryptors live in Zone B of
     * g_crypto_arena; arena_deinit rewinds Zone B, so destroying after
     * deinit would corrupt the free list. pubnub_deinit calls
     * pn_crypto_module_providers_deinit through a stale pointer — benign
     * because mbedTLS cryptor .deinit entries are NULL by design (DRBG
     * teardown is a module-lifetime operation in pubnub_cryptor_destroy,
     * not a context-lifetime operation). */
    if (NULL != s_crypto_module) {
        pubnub_crypto_module_destroy(s_crypto_module);
        s_crypto_module = NULL;
    }
    if (NULL != s_crypto_ctx) {
        pubnub_deinit(s_crypto_ctx);
        s_crypto_ctx = NULL;
    }
    s_crypto_alloc = NULL;
}

static void wait_sub_connected(pubnub_context_t* ctx, uint32_t timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(ctx)) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }
}

static void pump_until_flag(pubnub_context_t* ctx,
                            volatile uint8_t* flag,
                            uint32_t          timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (!*flag) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(ctx);
        vTaskDelay(1);
    }
}

static ks_result_t test_crypto_encrypt_decrypt(ks_runner_t* runner)
{
    pubnub_crypto_module_t* module;
    const char*             plaintext = "hello crypto";
    size_t                  pt_len    = strlen(plaintext);
    uint8_t                 enc_buf[256];
    uint8_t                 dec_buf[256];
    size_t                  enc_len = 0;
    size_t                  dec_len = 0;
    size_t                  needed;
    pubnub_res_t            rc;

    (void)runner;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    module = pubnub_crypto_module_aes_cbc(
        CONFIG_PUBNUB_KS_CIPHER_KEY, 1, get_crypto_alloc());
    if (NULL == module) {
        KS_RETURN_FAIL("failed to create crypto module");
    }

    needed = pubnub_crypto_module_encrypt_size(module, pt_len);
    if (0 == needed || needed > sizeof(enc_buf)) {
        pubnub_crypto_module_destroy(module);
        KS_RETURN_FAIL("encrypt size %u exceeds buffer", (unsigned)needed);
    }

    rc = pubnub_crypto_module_encrypt_buf(
        module, (const uint8_t*)plaintext, pt_len, enc_buf, sizeof(enc_buf), &enc_len);
    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(module);
        KS_RETURN_FAIL("encrypt failed: %s", pubnub_res_str(rc));
    }

    rc = pubnub_crypto_module_decrypt_buf(
        module, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    pubnub_crypto_module_destroy(module);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("decrypt failed: %s", pubnub_res_str(rc));
    }
    if (dec_len != pt_len || 0 != memcmp(dec_buf, plaintext, pt_len)) {
        KS_RETURN_FAIL("roundtrip mismatch");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_crypto_decrypt_from_base64(ks_runner_t* runner)
{
    pubnub_crypto_module_t* module;
    const char*             plaintext = "base64 test";
    size_t                  pt_len    = strlen(plaintext);
    char*                   b64_out   = NULL;
    size_t                  b64_len   = 0;
    uint8_t*                dec_out   = NULL;
    size_t                  dec_len   = 0;
    pubnub_res_t            rc;

    (void)runner;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    module = pubnub_crypto_module_aes_cbc(
        CONFIG_PUBNUB_KS_CIPHER_KEY, 1, get_crypto_alloc());
    if (NULL == module) {
        KS_RETURN_FAIL("failed to create crypto module");
    }

    rc = pubnub_crypto_module_encrypt_to_base64(
        module, (const uint8_t*)plaintext, pt_len, &b64_out, &b64_len);
    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(module);
        KS_RETURN_FAIL("encrypt_to_base64 failed: %s", pubnub_res_str(rc));
    }

    rc = pubnub_crypto_module_decrypt_from_base64(
        module, b64_out, b64_len, &dec_out, &dec_len);

    pubnub_crypto_module_free(module, b64_out);

    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(module);
        KS_RETURN_FAIL("decrypt_from_base64 failed: %s", pubnub_res_str(rc));
    }

    if (dec_len != pt_len || 0 != memcmp(dec_out, plaintext, pt_len)) {
        pubnub_crypto_module_free(module, dec_out);
        pubnub_crypto_module_destroy(module);
        KS_RETURN_FAIL("base64 roundtrip mismatch");
    }

    pubnub_crypto_module_free(module, dec_out);
    pubnub_crypto_module_destroy(module);
    KS_RETURN_PASS();
}

static ks_result_t test_crypto_publish_encrypted(ks_runner_t* runner)
{
    pubnub_context_t* cctx;
    char              ch[48] = {0};
    pubnub_future_t   fut;
    pubnub_res_t      rc;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    cctx = init_crypto_ctx();
    if (NULL == cctx) {
        KS_RETURN_FAIL("failed to init crypto context");
    }

    snprintf(ch, sizeof(ch), "iot-ks-%s-crypto-pub", runner->run_id);

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        opts.channel               = ch;
        opts.message               = "\"encrypted msg\"";

        fut = pubnub_publish(cctx, &opts);
        rc  = ks_pump_until_ready(cctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    }

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("encrypted publish failed: %s", pubnub_res_str(rc));
    }

    {
        pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
        pubnub_future_release(fut);

        if (NULL == tt.ptr || 0 == tt.len) {
            KS_RETURN_FAIL("no timetoken in encrypted publish response");
        }
    }

    KS_RETURN_PASS();
}

/** State shared between the subscribe_decrypt test and its listener. */
static volatile uint8_t s_sub_decrypt_received;
static char             s_sub_decrypt_payload[128];

static void sub_decrypt_on_message(const pubnub_subscribe_event_t* event,
                                   void*                           user_data)
{
    pubnub_serialization_provider_t* serial;
    size_t                           len = 0;

    (void)user_data;

    if (NULL == event || NULL == event->payload) {
        return;
    }

    serial = pubnub_serialization(s_crypto_ctx);
    if (NULL == serial || NULL == serial->serialize) {
        return;
    }

    memset(s_sub_decrypt_payload, 0, sizeof(s_sub_decrypt_payload));
    (void)serial->serialize(serial,
                            event->payload,
                            (uint8_t*)s_sub_decrypt_payload,
                            sizeof(s_sub_decrypt_payload) - 1,
                            &len);
    s_sub_decrypt_received = 1;
}

static ks_result_t test_crypto_subscribe_decrypt(ks_runner_t* runner)
{
    pubnub_context_t*        cctx;
    char                     ch[48] = {0};
    pubnub_entity_t          entity;
    pubnub_subscription_t    sub;
    pubnub_listener_handle_t handle;
    pubnub_res_t             rc;
    int64_t                  deadline;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    cctx = init_crypto_ctx();
    if (NULL == cctx) {
        KS_RETURN_FAIL("failed to init crypto context");
    }

    snprintf(ch, sizeof(ch), "iot-ks-%s-crypto-sub", runner->run_id);

    entity = pubnub_channel(cctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("failed to create entity");
    }

    {
        pubnub_subscription_opts_t sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
        sub = pubnub_subscription_create(entity, &sub_opts);
    }
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("failed to create subscription");
    }

    {
        pubnub_subscribe_listener_t listener = {0};
        listener.on_message                  = sub_decrypt_on_message;
        handle = pubnub_add_listener(cctx, &listener);
    }

    s_sub_decrypt_received   = 0;
    s_sub_decrypt_payload[0] = '\0';

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        pubnub_remove_listener(cctx, handle);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    /* Wait for connected. */
    deadline = esp_timer_get_time() + 15000LL * 1000;
    while (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(cctx)) {
        if (esp_timer_get_time() >= deadline) {
            pubnub_subscription_unsubscribe(sub);
            pubnub_subscription_destroy(sub);
            pubnub_entity_destroy(entity);
            pubnub_remove_listener(cctx, handle);
            KS_RETURN_FAIL("subscribe connect timed out");
        }
        pubnub_process(cctx);
        vTaskDelay(1);
    }

    /* Ask companion to publish encrypted on this channel. */
    if (!ks_ask_companion(runner,
                          "crypto/subscribe_decrypt",
                          "publish_encrypted",
                          ch,
                          NULL,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        pubnub_remove_listener(cctx, handle);
        KS_RETURN_FAIL("companion publish_encrypted failed");
    }

    /* Pump the crypto context until we receive the message. */
    deadline =
        esp_timer_get_time() + (int64_t)CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS * 1000;
    while (!s_sub_decrypt_received) {
        if (esp_timer_get_time() >= deadline) {
            break;
        }
        pubnub_process(cctx);
        vTaskDelay(1);
    }

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);
    pubnub_remove_listener(cctx, handle);

    if (!s_sub_decrypt_received) {
        KS_RETURN_FAIL("timed out waiting for decrypted message");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_crypto_legacy_compat(ks_runner_t* runner)
{
    pubnub_crypto_module_t* acrh_mod;
    pubnub_crypto_module_t* legacy_mod;
    const char*             plaintext = "legacy compat";
    size_t                  pt_len    = strlen(plaintext);
    uint8_t                 enc_buf[256];
    uint8_t                 dec_buf[256];
    size_t                  enc_len = 0;
    size_t                  dec_len = 0;
    pubnub_res_t            rc;

    (void)runner;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    acrh_mod = pubnub_crypto_module_aes_cbc(
        CONFIG_PUBNUB_KS_CIPHER_KEY, 1, get_crypto_alloc());
    legacy_mod = pubnub_crypto_module_legacy(
        CONFIG_PUBNUB_KS_CIPHER_KEY, 1, get_crypto_alloc());

    if (NULL == acrh_mod || NULL == legacy_mod) {
        if (NULL != acrh_mod) {
            pubnub_crypto_module_destroy(acrh_mod);
        }
        if (NULL != legacy_mod) {
            pubnub_crypto_module_destroy(legacy_mod);
        }
        KS_RETURN_FAIL("failed to create modules");
    }

    /* Encrypt with ACRH, decrypt with legacy module (has ACRH fallback). */
    rc = pubnub_crypto_module_encrypt_buf(
        acrh_mod, (const uint8_t*)plaintext, pt_len, enc_buf, sizeof(enc_buf), &enc_len);
    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(acrh_mod);
        pubnub_crypto_module_destroy(legacy_mod);
        KS_RETURN_FAIL("ACRH encrypt failed: %s", pubnub_res_str(rc));
    }

    rc = pubnub_crypto_module_decrypt_buf(
        legacy_mod, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(acrh_mod);
        pubnub_crypto_module_destroy(legacy_mod);
        KS_RETURN_FAIL("legacy decrypt of ACRH failed: %s", pubnub_res_str(rc));
    }
    if (dec_len != pt_len || 0 != memcmp(dec_buf, plaintext, pt_len)) {
        pubnub_crypto_module_destroy(acrh_mod);
        pubnub_crypto_module_destroy(legacy_mod);
        KS_RETURN_FAIL("ACRH->legacy roundtrip mismatch");
    }

    /* Encrypt with legacy, decrypt with ACRH module (has legacy fallback). */
    enc_len = 0;
    dec_len = 0;
    rc      = pubnub_crypto_module_encrypt_buf(
        legacy_mod, (const uint8_t*)plaintext, pt_len, enc_buf, sizeof(enc_buf), &enc_len);
    if (PUBNUB_OK != rc) {
        pubnub_crypto_module_destroy(acrh_mod);
        pubnub_crypto_module_destroy(legacy_mod);
        KS_RETURN_FAIL("legacy encrypt failed: %s", pubnub_res_str(rc));
    }

    rc = pubnub_crypto_module_decrypt_buf(
        acrh_mod, enc_buf, enc_len, dec_buf, sizeof(dec_buf), &dec_len);
    pubnub_crypto_module_destroy(acrh_mod);
    pubnub_crypto_module_destroy(legacy_mod);

    if (PUBNUB_OK != rc) {
        KS_RETURN_FAIL("ACRH decrypt of legacy failed: %s", pubnub_res_str(rc));
    }
    if (dec_len != pt_len || 0 != memcmp(dec_buf, plaintext, pt_len)) {
        KS_RETURN_FAIL("legacy->ACRH roundtrip mismatch");
    }

    KS_RETURN_PASS();
}

static ks_result_t test_crypto_history_decrypt(ks_runner_t* runner)
{
    pubnub_context_t* cctx;
    char              ch[48] = {0};
    pubnub_future_t   fut;
    pubnub_res_t      rc;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    cctx = init_crypto_ctx();
    if (NULL == cctx) {
        KS_RETURN_FAIL("failed to init crypto context");
    }

    snprintf(ch, sizeof(ch), "iot-ks-%s-crypto-hist", runner->run_id);

    /* Publish an encrypted message via the crypto context. */
    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        opts.channel               = ch;
        opts.message               = "\"history crypto\"";

        fut = pubnub_publish(cctx, &opts);
        rc  = ks_pump_until_ready(cctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            KS_RETURN_FAIL("encrypted publish failed: %s", pubnub_res_str(rc));
        }
    }

    /* Wait for message persistence. */
    vTaskDelay(pdMS_TO_TICKS(1500));

    /* Fetch via the same crypto context -- auto-decrypts. */
    {
        pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
        pubnub_fetch_messages_result_t result;

        opts.channels = ch;
        opts.count    = 1;

        fut = pubnub_fetch_messages(cctx, &opts);
        rc  = ks_pump_until_ready(cctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

        if (PUBNUB_OK != rc) {
            pubnub_future_release(fut);
            KS_RETURN_FAIL("fetch_messages failed: %s", pubnub_res_str(rc));
        }

        result = pubnub_fetch_messages_result(fut);
        pubnub_future_release(fut);

        if (0 == result.channel_count) {
            KS_RETURN_FAIL("no channels in fetch result");
        }
    }

    KS_RETURN_PASS();
}

static volatile uint8_t s_crypto_leg_received;

static void on_crypto_leg_message(const pubnub_subscribe_event_t* event,
                                  void*                           user_data)
{
    (void)user_data;
    if (NULL == event) {
        return;
    }
    s_crypto_leg_received = 1;
}

static ks_result_t test_crypto_legacy_from_companion(ks_runner_t* runner)
{
    pubnub_context_t*        cctx;
    char                     ch[48] = {0};
    pubnub_entity_t          entity;
    pubnub_subscription_t    sub;
    pubnub_listener_handle_t handle;
    pubnub_res_t             rc;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    cctx = init_crypto_ctx();
    if (NULL == cctx) {
        KS_RETURN_FAIL("failed to init crypto context");
    }

    snprintf(ch, sizeof(ch), "iot-ks-%s-crypto-leg", runner->run_id);

    entity = pubnub_channel(cctx, ch);
    if (NULL == entity) {
        KS_RETURN_FAIL("failed to create entity");
    }

    {
        pubnub_subscription_opts_t sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
        sub = pubnub_subscription_create(entity, &sub_opts);
    }
    if (NULL == sub) {
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("failed to create subscription");
    }

    {
        pubnub_subscribe_listener_t listener = {0};
        listener.on_message                  = on_crypto_leg_message;
        handle = pubnub_add_listener(cctx, &listener);
    }

    s_crypto_leg_received = 0;

    rc = pubnub_subscription_subscribe(sub);
    if (PUBNUB_OK != rc) {
        pubnub_remove_listener(cctx, handle);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
    }

    wait_sub_connected(cctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
    if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(cctx)) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        pubnub_remove_listener(cctx, handle);
        KS_RETURN_FAIL("subscribe connect timed out");
    }

    if (!ks_ask_companion(runner,
                          "crypto/legacy_from_companion",
                          "publish_legacy_encrypted",
                          ch,
                          NULL,
                          CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        pubnub_remove_listener(cctx, handle);
        KS_RETURN_FAIL("companion publish_legacy_encrypted failed");
    }

    pump_until_flag(cctx, &s_crypto_leg_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);
    pubnub_remove_listener(cctx, handle);

    if (!s_crypto_leg_received) {
        KS_RETURN_FAIL("timed out waiting for legacy-encrypted message");
    }

    KS_RETURN_PASS();
}

static volatile uint8_t s_crypto_xsdk_received;

static void on_crypto_xsdk_message(const pubnub_subscribe_event_t* event,
                                   void*                           user_data)
{
    (void)user_data;
    if (NULL == event) {
        return;
    }
    s_crypto_xsdk_received = 1;
}

static ks_result_t test_crypto_cross_sdk_bidirectional(ks_runner_t* runner)
{
    pubnub_context_t* cctx;
    char              ch_a[48] = {0};
    char              ch_b[48] = {0};
    pubnub_res_t      rc;

    if ('\0' == CONFIG_PUBNUB_KS_CIPHER_KEY[0]) {
        KS_RETURN_SKIP("cipher key not configured");
    }

    cctx = init_crypto_ctx();
    if (NULL == cctx) {
        KS_RETURN_FAIL("failed to init crypto context");
    }

    snprintf(ch_a, sizeof(ch_a), "iot-ks-%s-crypto-xsdk-a", runner->run_id);
    snprintf(ch_b, sizeof(ch_b), "iot-ks-%s-crypto-xsdk-b", runner->run_id);

    /* Phase A: device publishes encrypted, companion verifies. */
    if (!ks_companion_begin_verify(runner,
                                   "crypto/cross_sdk_bidirectional",
                                   "subscribe_and_verify",
                                   ch_a,
                                   "{\"event_type\":\"message\","
                                   "\"timeout_ms\":10000}",
                                   5000)) {
        cleanup_crypto_ctx();
        KS_RETURN_FAIL("companion begin_verify failed");
    }

    {
        pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
        pubnub_future_t       fut;

        opts.channel = ch_a;
        opts.message = "\"cross-sdk-test\"";

        fut = pubnub_publish(cctx, &opts);
        rc  = ks_pump_until_ready(cctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        pubnub_future_release(fut);

        if (PUBNUB_OK != rc) {
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("encrypted publish failed: %s", pubnub_res_str(rc));
        }
    }

    if (!ks_companion_end_verify(runner, 10000)) {
        cleanup_crypto_ctx();
        KS_RETURN_FAIL("companion end_verify phase A failed");
    }

    /* Phase B: companion publishes ACRH encrypted, device subscribes. */
    {
        pubnub_entity_t          entity;
        pubnub_subscription_t    sub;
        pubnub_listener_handle_t handle;

        entity = pubnub_channel(cctx, ch_b);
        if (NULL == entity) {
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("failed to create entity for phase B");
        }

        {
            pubnub_subscription_opts_t sub_opts = PUBNUB_SUBSCRIPTION_OPTS_INIT;
            sub = pubnub_subscription_create(entity, &sub_opts);
        }
        if (NULL == sub) {
            pubnub_entity_destroy(entity);
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("failed to create subscription for phase B");
        }

        {
            pubnub_subscribe_listener_t listener = {0};
            listener.on_message                  = on_crypto_xsdk_message;
            handle = pubnub_add_listener(cctx, &listener);
        }

        s_crypto_xsdk_received = 0;

        rc = pubnub_subscription_subscribe(sub);
        if (PUBNUB_OK != rc) {
            pubnub_remove_listener(cctx, handle);
            pubnub_subscription_destroy(sub);
            pubnub_entity_destroy(entity);
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("subscribe failed: %s", pubnub_res_str(rc));
        }

        wait_sub_connected(cctx, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);
        if (PUBNUB_SUBSCRIBE_CONNECTED != pubnub_subscribe_state(cctx)) {
            pubnub_subscription_unsubscribe(sub);
            pubnub_subscription_destroy(sub);
            pubnub_entity_destroy(entity);
            pubnub_remove_listener(cctx, handle);
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("subscribe connect timed out for phase B");
        }

        if (!ks_ask_companion(runner,
                              "crypto/cross_sdk_bidirectional",
                              "publish_encrypted",
                              ch_b,
                              NULL,
                              CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS)) {
            pubnub_subscription_unsubscribe(sub);
            pubnub_subscription_destroy(sub);
            pubnub_entity_destroy(entity);
            pubnub_remove_listener(cctx, handle);
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("companion publish_encrypted phase B failed");
        }

        pump_until_flag(
            cctx, &s_crypto_xsdk_received, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

        pubnub_subscription_unsubscribe(sub);
        pubnub_subscription_destroy(sub);
        pubnub_entity_destroy(entity);
        pubnub_remove_listener(cctx, handle);

        if (!s_crypto_xsdk_received) {
            cleanup_crypto_ctx();
            KS_RETURN_FAIL("timed out waiting for cross-SDK message");
        }
    }

    cleanup_crypto_ctx();
    KS_RETURN_PASS();
}

const ks_test_entry_t ks_crypto_tests[] = {
    {"crypto/encrypt_decrypt",         test_crypto_encrypt_decrypt,         0},
    {"crypto/decrypt_from_base64",     test_crypto_decrypt_from_base64,     0},
    {"crypto/publish_encrypted",       test_crypto_publish_encrypted,       1},
    {"crypto/subscribe_decrypt",       test_crypto_subscribe_decrypt,       1},
    {"crypto/legacy_compat",           test_crypto_legacy_compat,           0},
    {"crypto/history_decrypt",         test_crypto_history_decrypt,         0},
    {"crypto/legacy_from_companion",   test_crypto_legacy_from_companion,   1},
    {"crypto/cross_sdk_bidirectional", test_crypto_cross_sdk_bidirectional, 1},
};

const size_t ks_crypto_test_count =
    sizeof(ks_crypto_tests) / sizeof(ks_crypto_tests[0]);
