/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/error.h"

#if PUBNUB_ENABLE_CRYPTO
#include "pubnub/features/crypto.h"
#include "pubnub/future.h"
#endif

#if PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "it_bus.h"
#endif

#if PUBNUB_ENABLE_CRYPTO && PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/publish.h"
#include "pubnub/response.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

#if PUBNUB_ENABLE_SUBSCRIBE
static void on_message_cb(const pubnub_subscribe_event_t* ev, void* ud)
{
    it_bus_push_message((it_bus_t*)ud, ev);
}

static void on_status_cb(const pubnub_subscribe_status_event_t* ev, void* ud)
{
    it_bus_push_status((it_bus_t*)ud, ev->status);
}
#endif

static void encrypt_decrypt_round_trip_aes_cbc(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    static const char plaintext[] = "secret payload";
    uint8_t*          ciphertext  = NULL;
    size_t            cipher_len  = 0;
    uint8_t*          decrypted   = NULL;
    size_t            decrypt_len = 0;
    pubnub_res_t      rc;

    (void)state;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(module);

    rc = pubnub_crypto_module_encrypt(module,
                                      (const uint8_t*)plaintext,
                                      sizeof(plaintext) - 1U,
                                      &ciphertext,
                                      &cipher_len);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(ciphertext);
    assert_true(0U < cipher_len);

    rc = pubnub_crypto_module_decrypt(
        module, ciphertext, cipher_len, &decrypted, &decrypt_len);
    pubnub_crypto_module_free(module, ciphertext);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(decrypted);
    assert_int_equal(sizeof(plaintext) - 1U, decrypt_len);
    assert_memory_equal(plaintext, decrypted, decrypt_len);
    pubnub_crypto_module_free(module, decrypted);

    pubnub_crypto_module_destroy(module);
#else
    (void)state;
    skip();
#endif
}

static void encrypt_decrypt_round_trip_legacy(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    static const char plaintext[] = "secret payload";
    uint8_t*          ciphertext  = NULL;
    size_t            cipher_len  = 0;
    uint8_t*          decrypted   = NULL;
    size_t            decrypt_len = 0;
    pubnub_res_t      rc;

    (void)state;

    pubnub_crypto_module_t* module = pubnub_crypto_module_legacy("enigma", 1, NULL);
    assert_non_null(module);

    rc = pubnub_crypto_module_encrypt(module,
                                      (const uint8_t*)plaintext,
                                      sizeof(plaintext) - 1U,
                                      &ciphertext,
                                      &cipher_len);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(ciphertext);
    assert_true(0U < cipher_len);

    rc = pubnub_crypto_module_decrypt(
        module, ciphertext, cipher_len, &decrypted, &decrypt_len);
    pubnub_crypto_module_free(module, ciphertext);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(decrypted);
    assert_int_equal(sizeof(plaintext) - 1U, decrypt_len);
    assert_memory_equal(plaintext, decrypted, decrypt_len);
    pubnub_crypto_module_free(module, decrypted);

    pubnub_crypto_module_destroy(module);
#else
    (void)state;
    skip();
#endif
}

static void publish_encrypted_subscribe_receives_plaintext(void** state)
{
#if PUBNUB_ENABLE_CRYPTO && PUBNUB_ENABLE_SUBSCRIBE
    it_test_state_t*            s    = *state;
    pubnub_crypto_module_t*     cm   = NULL;
    pubnub_context_t*           cpub = NULL;
    pubnub_context_t*           csub = NULL;
    it_bus_t*                   bus  = NULL;
    char                        uid_sub[80];
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_res_t                st;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);

    cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    snprintf(uid_sub, sizeof(uid_sub), "%.70s-s", s->user_id);

    pubnub_config_t pub_cfg            = pubnub_config_defaults();
    pub_cfg.subscribe_key              = s->env->subscribe_key;
    pub_cfg.publish_key                = s->env->publish_key;
    pub_cfg.user_id                    = s->user_id;
    pub_cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    pub_cfg.crypto_module              = cm;

    pubnub_config_t sub_cfg            = pubnub_config_defaults();
    sub_cfg.subscribe_key              = s->env->subscribe_key;
    sub_cfg.publish_key                = s->env->publish_key;
    sub_cfg.user_id                    = uid_sub;
    sub_cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    sub_cfg.crypto_module              = cm;

    cpub = pubnub_create(&pub_cfg);
    if (NULL == cpub) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create publisher context");
    }

    csub = pubnub_create(&sub_cfg);
    if (NULL == csub) {
        pubnub_destroy(cpub);
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create subscriber context");
    }
    it_state_pump_ctx(s, csub);

    bus          = it_bus_create();
    l.on_message = on_message_cb;
    l.on_status  = on_status_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(csub, &l);

    entity = pubnub_channel(csub, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    fut = pubnub_publish(cpub,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"encrypted-test\"",
                         });
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("encrypted publish failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    pubnub_future_release(fut);
    assert_int_equal(PUBNUB_OK, st);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(csub, h);
    it_bus_destroy(bus);
    it_state_unpump_ctx(s, csub);
    pubnub_destroy(csub);
    pubnub_destroy(cpub);
    pubnub_crypto_module_destroy(cm);
#else
    (void)state;
    skip();
#endif
}

static void publish_encrypted_subscribe_without_crypto_sees_ciphertext(void** state)
{
#if PUBNUB_ENABLE_CRYPTO && PUBNUB_ENABLE_SUBSCRIBE
    it_test_state_t*            s    = *state;
    pubnub_crypto_module_t*     cm   = NULL;
    pubnub_context_t*           cpub = NULL;
    pubnub_context_t*           csub = NULL;
    it_bus_t*                   bus  = NULL;
    char                        uid_sub[80];
    pubnub_subscribe_listener_t l = {0};
    pubnub_listener_handle_t    h;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    pubnub_future_t             fut;
    pubnub_res_t                st;
    pubnub_subscribe_event_t    ev = {0};

    print_message("channel: %s", s->channel);

    cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    snprintf(uid_sub, sizeof(uid_sub), "%.70s-s", s->user_id);

    /* Publisher has crypto module configured. */
    pubnub_config_t pub_cfg            = pubnub_config_defaults();
    pub_cfg.subscribe_key              = s->env->subscribe_key;
    pub_cfg.publish_key                = s->env->publish_key;
    pub_cfg.user_id                    = s->user_id;
    pub_cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    pub_cfg.crypto_module              = cm;

    /* Subscriber has no crypto — receives the raw ciphertext blob. */
    pubnub_config_t sub_cfg            = pubnub_config_defaults();
    sub_cfg.subscribe_key              = s->env->subscribe_key;
    sub_cfg.publish_key                = s->env->publish_key;
    sub_cfg.user_id                    = uid_sub;
    sub_cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    cpub = pubnub_create(&pub_cfg);
    if (NULL == cpub) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create publisher context");
    }

    csub = pubnub_create(&sub_cfg);
    if (NULL == csub) {
        pubnub_destroy(cpub);
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create subscriber context");
    }
    it_state_pump_ctx(s, csub);

    bus          = it_bus_create();
    l.on_message = on_message_cb;
    l.on_status  = on_status_cb;
    l.user_data  = bus;
    h            = pubnub_add_listener(csub, &l);

    entity = pubnub_channel(csub, s->channel);
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    assert_int_not_equal(0,
                         it_bus_wait_status(bus,
                                            IT_SUBSCRIBE_CONNECT_MAX_MS,
                                            PUBNUB_SUBSCRIBE_STATUS_CONNECTED));

    fut = pubnub_publish(cpub,
                         &(pubnub_publish_opts_t){
                             .channel = s->channel,
                             .message = "\"encrypted-test\"",
                         });
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("encrypted publish failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    pubnub_future_release(fut);
    assert_int_equal(PUBNUB_OK, st);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    /* The subscriber receives the raw base64 ciphertext blob.  The
     * it_bus payload pointer is always NULL (JSON tree is not deep-
     * copied); channel routing confirms the encrypted message arrived
     * without error. */
    assert_int_not_equal(
        0, it_bus_wait_message(bus, IT_SUBSCRIBE_MESSAGE_MAX_MS, &ev));
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, (int)ev.type);
    assert_int_equal((int)strlen(s->channel), (int)ev.channel.len);
    assert_memory_equal(s->channel, ev.channel.ptr, ev.channel.len);

    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(csub, h);
    it_bus_destroy(bus);
    it_state_unpump_ctx(s, csub);
    pubnub_destroy(csub);
    pubnub_destroy(cpub);
    pubnub_crypto_module_destroy(cm);
#else
    (void)state;
    skip();
#endif
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(encrypt_decrypt_round_trip_aes_cbc),
        cmocka_unit_test(encrypt_decrypt_round_trip_legacy),
        cmocka_unit_test_setup_teardown(
            publish_encrypted_subscribe_receives_plaintext, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_encrypted_subscribe_without_crypto_sees_ciphertext, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
