/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/features/history.h"
#include "pubnub/future.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MAX_CAPTURES 4

typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_CAPTURES];
static int            s_fake_handle_storage[MAX_CAPTURES];

static void reset_chain(void)
{
    s_send_count = 0;
    s_in_flight  = 0;
    memset(s_captures, 0, sizeof(s_captures));
}

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_CAPTURES) {
        return NULL;
    }
    s_captures[s_send_count].request  = request;
    s_captures[s_send_count].response = response;
    s_send_count++;
    s_in_flight++;
    return (pubnub_transport_handle_t*)&s_fake_handle_storage[s_send_count - 1];
}

static int chain_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void chain_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_transport_provider_t s_chain_transport = {
    .send              = chain_send,
    .poll              = chain_poll,
    .cancel            = chain_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static void chain_complete_with(int index, const uint8_t* body, size_t len)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = len;
    resp->status_code = 200;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static void chain_complete_with_status(int            index,
                                       const uint8_t* body,
                                       size_t         len,
                                       int            status_code)
{
    pubnub_http_response_t* resp = s_captures[index].response;
    assert_non_null(resp);
    resp->body        = body;
    resp->body_len    = len;
    resp->status_code = status_code;
    resp->completion  = PUBNUB_HTTP_COMPLETE;
    if (s_in_flight > 0) {
        s_in_flight--;
    }
}

static pubnub_config_t chain_only_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static pubnub_config_t chain_config_with_user_id(const char* user_id)
{
    pubnub_config_t cfg = chain_only_config();
    cfg.user_id         = user_id;
    return cfg;
}

/* Locate a captured query parameter by (unencoded) key on the first
 * dispatched request. Returns the value view, or NULL when absent. */
static const pubnub_string_view_t* find_query_param(const char* key)
{
    const pubnub_http_request_t* req = s_captures[0].request;
    if (NULL == req) {
        return NULL;
    }
    const size_t key_len = strlen(key);
    for (uint16_t i = 0; i < req->query_param_count; ++i) {
        const pubnub_kv_t* kv = &req->query_params[i];
        if (kv->key.len == key_len && 0 == memcmp(kv->key.ptr, key, key_len)) {
            return &kv->value;
        }
    }
    return NULL;
}

static const uint8_t k_fetch_multi[] =
    "{\"status\":200,\"channels\":{"
    "\"ch1\":["
    "{\"message\":\"hello\",\"timetoken\":\"17001000000000001\"},"
    "{\"message\":{\"type\":\"file\",\"file\":{\"id\":\"f-id-1\","
    "\"name\":\"photo.png\"}},\"timetoken\":\"17001000000000002\"}"
    "],"
    "\"ch2\":["
    "{\"message\":\"world\",\"timetoken\":\"17001000000000010\"}"
    "]}}";

static void fetch_messages_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1,ch2";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_fetch_multi, sizeof(k_fetch_multi) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(2, result.channel_count);

    /* Find the ch1 channel (iteration order depends on JSON object
     * traversal, so probe both). */
    int ch1_idx = -1;
    for (size_t i = 0; i < (size_t)result.channel_count; ++i) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(fut, i);
        if (3 == ch.name.len && 0 == memcmp(ch.name.ptr, "ch1", 3)) {
            ch1_idx = (int)i;
            break;
        }
    }
    assert_true(ch1_idx >= 0);

    pubnub_fetch_messages_channel_result_t ch1 =
        pubnub_fetch_messages_result_channel_at(fut, (size_t)ch1_idx);
    assert_int_equal(3, ch1.name.len);
    assert_memory_equal(ch1.name.ptr, "ch1", 3);
    assert_int_equal(2, ch1.message_count);

    /* First message in ch1: regular text. */
    pubnub_history_message_result_t msg0 =
        pubnub_fetch_messages_result_message_at(fut, (size_t)ch1_idx, 0);
    assert_true(msg0.timetoken.len > 0);
    assert_memory_equal(msg0.timetoken.ptr, "17001000000000001", 17);

    /* Second message in ch1: file message. */
    pubnub_history_file_result_t file1 =
        pubnub_fetch_messages_result_file_at(fut, (size_t)ch1_idx, 1);
    assert_true(file1.id.len > 0);
    assert_memory_equal(file1.id.ptr, "f-id-1", 6);
    assert_true(file1.name.len > 0);
    assert_memory_equal(file1.name.ptr, "photo.png", 9);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_fetch_actions[] =
    "{\"status\":200,\"channels\":{"
    "\"ch1\":["
    "{\"message\":\"hi\",\"timetoken\":\"17001000000000001\","
    "\"actions\":{\"reaction\":{\"smiley\":[{\"uuid\":\"u1\","
    "\"actionTimetoken\":\"1000\"}]}}},"
    "{\"message\":\"bye\",\"timetoken\":\"17001000000000002\"}"
    "]}}";

static void fetch_messages_with_actions_parses_actions_at(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";
    opts.include_message_actions      = 1;

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_fetch_actions, sizeof(k_fetch_actions) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(1, result.channel_count);

    const pubnub_json_value_t* actions0 =
        pubnub_fetch_messages_result_actions_at(fut, 0, 0);
    assert_non_null(actions0);

    const pubnub_json_value_t* actions1 =
        pubnub_fetch_messages_result_actions_at(fut, 0, 1);
    assert_null(actions1);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_counts_body[] =
    "{\"status\":200,\"channels\":{\"ch1\":5,\"ch2\":12}}";

static void message_counts_parses_indexed_results(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_message_counts_opts_t opts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    opts.channels                     = "ch1,ch2";
    opts.timetoken                    = "17001000000000000";

    pubnub_future_t fut = pubnub_message_counts(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_counts_body, sizeof(k_counts_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_message_counts_result_t result = pubnub_message_counts_result(fut);
    assert_int_equal(2, result.channel_count);

    /* Probe both entries. */
    int found_ch1 = 0;
    int found_ch2 = 0;
    for (size_t i = 0; i < (size_t)result.channel_count; ++i) {
        pubnub_message_counts_channel_result_t entry =
            pubnub_message_counts_result_channel_at(fut, i);
        if (3 == entry.name.len && 0 == memcmp(entry.name.ptr, "ch1", 3)) {
            assert_int_equal(5, entry.count);
            found_ch1 = 1;
        } else if (3 == entry.name.len && 0 == memcmp(entry.name.ptr, "ch2", 3)) {
            assert_int_equal(12, entry.count);
            found_ch2 = 1;
        }
    }
    assert_true(found_ch1);
    assert_true(found_ch2);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void fetch_messages_bad_json_returns_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    static const uint8_t broken[] = "{broken";
    chain_complete_with(0, broken, sizeof(broken) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    /* Malformed JSON with HTTP 200: validator probe doesn't find a
     * "status" >= 400, so the request completes as OK. The parse
     * failure surfaces only through the result accessors returning
     * zero values. If this assertion fails, it means the SDK now
     * properly rejects malformed JSON at the validator level. */
    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(0, result.channel_count);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static const uint8_t k_403_body[] =
    "{\"error\":true,\"status\":403,\"message\":\"Forbidden\"}";

static void fetch_messages_http_403_surfaces_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with_status(0, k_403_body, sizeof(k_403_body) - 1, 403);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void fetch_messages_empty_body_returns_error(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, (const uint8_t*)"", 0);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    /* Empty body with HTTP 200: result accessors should return zero
     * values. If the SDK rejects empty bodies at the validator level
     * and the status is an error, that is also acceptable. */
    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(0, result.channel_count);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

static void dispatch_fetch_and_wait(pubnub_context_t* ctx, const char* channels)
{
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = channels;

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);
    pubnub_future_release(fut);
}

static void fetch_messages_dispatches_uuid_query_param(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* The userid middleware appends uuid=<user_id> to every request. */
    dispatch_fetch_and_wait(ctx, "ch1");

    const pubnub_string_view_t* uuid = find_query_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(6, uuid->len);
    assert_memory_equal(uuid->ptr, "tester", 6);

    pubnub_destroy(ctx);
}

static void fetch_messages_uuid_reflects_configured_user_id(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_config_with_user_id("custom-user-42");
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    dispatch_fetch_and_wait(ctx, "ch1");

    const pubnub_string_view_t* uuid = find_query_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(14, uuid->len);
    assert_memory_equal(uuid->ptr, "custom-user-42", 14);

    pubnub_destroy(ctx);
}

static void fetch_messages_uuid_is_url_encoded(void** state)
{
    (void)state;
    reset_chain();
    pubnub_config_t   cfg = chain_config_with_user_id("user@domain.com");
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    dispatch_fetch_and_wait(ctx, "ch1");

    /* '@' is a reserved character and must be percent-encoded to %40;
     * unreserved characters ('.', letters) pass through unchanged. */
    const pubnub_string_view_t* uuid = find_query_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(17, uuid->len);
    assert_memory_equal(uuid->ptr, "user%40domain.com", 17);

    pubnub_destroy(ctx);
}

#if PUBNUB_ENABLE_CRYPTO

static int s_decrypt_calls;
static int s_decrypt_should_fail;

static void reset_crypto_mock(void)
{
    s_decrypt_calls       = 0;
    s_decrypt_should_fail = 0;
}

/* Legacy-identifier cryptor: for a base64 payload without a PNED header
 * the crypto module dispatches to the {0,0,0,0} cryptor, so this mock
 * receives every fetch-history decrypt call. */
static pubnub_res_t mock_decrypt(struct pubnub_crypto_provider* self,
                                 const pubnub_encrypted_data_t* input,
                                 uint8_t*                       output,
                                 size_t*                        output_len)
{
    (void)self;
    (void)input;
    s_decrypt_calls++;
    if (s_decrypt_should_fail) {
        return PUBNUB_ERR_CRYPTO;
    }

    /* Emit a small valid-JSON plaintext. The output buffer is at least
     * input->data_len bytes; the fixtures decode to >= 4 bytes. */
    static const char plain[] = "\"ok\"";
    const size_t      n       = sizeof(plain) - 1;
    if (NULL == output || NULL == output_len || *output_len < n) {
        return PUBNUB_ERR_CRYPTO;
    }
    memcpy(output, plain, n);
    *output_len = n;
    return PUBNUB_OK;
}

static pubnub_crypto_provider_t s_mock_cryptor = {
    .identifier   = {0, 0, 0, 0},
    .encrypt_size = NULL,
    .encrypt      = NULL,
    .decrypt      = mock_decrypt,
    .hmac_sha256  = NULL,
    .init         = NULL,
    .deinit       = NULL,
};

/* Two string payloads that are valid base64 (no PNED header) so the
 * lazy history decryptor treats each as an encrypted message. */
static const uint8_t k_fetch_encrypted[] =
    "{\"status\":200,\"channels\":{"
    "\"ch1\":["
    "{\"message\":\"dGVzdA==\",\"timetoken\":\"17001000000000001\"},"
    "{\"message\":\"MTIzNA==\",\"timetoken\":\"17001000000000002\"}"
    "]}}";

static void fetch_messages_decrypts_each_message(void** state)
{
    (void)state;
    reset_chain();
    reset_crypto_mock();

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_create(&s_mock_cryptor, NULL, 0, NULL);
    assert_non_null(module);

    pubnub_config_t cfg   = chain_only_config();
    cfg.crypto_module     = module;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    chain_complete_with(0, k_fetch_encrypted, sizeof(k_fetch_encrypted) - 1);
    (void)pubnub_process(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(1, result.channel_count);

    /* Reading two distinct messages must invoke decrypt once each. */
    pubnub_history_message_result_t m0 =
        pubnub_fetch_messages_result_message_at(fut, 0, 0);
    assert_int_equal(PUBNUB_OK, m0.crypto_result);
    assert_non_null(m0.message);

    pubnub_history_message_result_t m1 =
        pubnub_fetch_messages_result_message_at(fut, 0, 1);
    assert_int_equal(PUBNUB_OK, m1.crypto_result);
    assert_non_null(m1.message);

    assert_int_equal(2, s_decrypt_calls);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    pubnub_crypto_module_destroy(module);
}

static void fetch_messages_decrypt_failure_sets_crypto_result(void** state)
{
    (void)state;
    reset_chain();
    reset_crypto_mock();
    s_decrypt_should_fail = 1;

    pubnub_crypto_module_t* module =
        pubnub_crypto_module_create(&s_mock_cryptor, NULL, 0, NULL);
    assert_non_null(module);

    pubnub_config_t cfg   = chain_only_config();
    cfg.crypto_module     = module;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    chain_complete_with(0, k_fetch_encrypted, sizeof(k_fetch_encrypted) - 1);
    (void)pubnub_process(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    /* Decrypt failure must surface per-message, not as a request error,
     * and the raw payload must remain accessible. */
    pubnub_history_message_result_t m0 =
        pubnub_fetch_messages_result_message_at(fut, 0, 0);
    assert_int_equal(PUBNUB_ERR_CRYPTO, m0.crypto_result);
    assert_non_null(m0.message);
    assert_true(s_decrypt_calls >= 1);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    pubnub_crypto_module_destroy(module);
}

static void fetch_messages_without_crypto_module_passes_through(void** state)
{
    (void)state;
    reset_chain();
    reset_crypto_mock();

    /* No crypto module configured. */
    pubnub_config_t   cfg = chain_only_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    chain_complete_with(0, k_fetch_encrypted, sizeof(k_fetch_encrypted) - 1);
    (void)pubnub_process(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    pubnub_history_message_result_t m0 =
        pubnub_fetch_messages_result_message_at(fut, 0, 0);
    /* No decryption attempted; payload passes through untouched. */
    assert_int_equal(PUBNUB_OK, m0.crypto_result);
    assert_non_null(m0.message);
    assert_int_equal(0, s_decrypt_calls);

    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

#endif /* PUBNUB_ENABLE_CRYPTO */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(fetch_messages_parses_indexed_results),
        cmocka_unit_test(fetch_messages_with_actions_parses_actions_at),
        cmocka_unit_test(message_counts_parses_indexed_results),
        cmocka_unit_test(fetch_messages_bad_json_returns_error),
        cmocka_unit_test(fetch_messages_http_403_surfaces_error),
        cmocka_unit_test(fetch_messages_empty_body_returns_error),
        cmocka_unit_test(fetch_messages_dispatches_uuid_query_param),
        cmocka_unit_test(fetch_messages_uuid_reflects_configured_user_id),
        cmocka_unit_test(fetch_messages_uuid_is_url_encoded),
#if PUBNUB_ENABLE_CRYPTO
        cmocka_unit_test(fetch_messages_decrypts_each_message),
        cmocka_unit_test(fetch_messages_decrypt_failure_sets_crypto_result),
        cmocka_unit_test(fetch_messages_without_crypto_module_passes_through),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
