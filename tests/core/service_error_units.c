/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file service_error_units.c
 * @brief Coverage of @ref pubnub_response_service_error and the
 *        seven-variant taxonomy.
 *
 * Each variant is exercised by injecting a synthetic response body
 * onto a hand-constructed slot in a terminal state and reading the
 * folded envelope back. Probe-ordering edge cases are covered with
 * dedicated cases (history flat carries both `error: bool` and
 * `error_message`; push string carries `error: <string>` and must
 * NOT route through the boolean-flag variant).
 */

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
#include "pubnub/future.h"
#include "pubnub/response.h"
#include "pubnub/service_error.h"
#include "pubnub/types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

/* Real default serialization provider (cjson or jsmn) wired through
 * the build. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* ======================================================================== */
/* Minimal provider stack -- only the methods the SDK touches at init       */
/* time and during slot lifecycle need to be non-NULL.                      */
/* ======================================================================== */

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return test_malloc(size);
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    test_free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    pubnub_buffer_t buf = {NULL, 0, 0, purpose};
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    (void)buf;
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc       = mock_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
    .buf_grow    = NULL,
};

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return NULL;
}

static int mock_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   h)
{
    (void)self;
    (void)h;
}

static pubnub_transport_provider_t s_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static pubnub_milliseconds_t mock_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static pubnub_milliseconds_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static void mock_sleep_ms(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int mock_random_bytes(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0, len);
    return 0;
}

static pubnub_platform_provider_t s_platform = {
    .monotonic_ms  = mock_monotonic_ms,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep_ms,
    .random_bytes  = mock_random_bytes,
};

static pubnub_res_t mock_encrypt(pubnub_crypto_provider_t* self,
                                 const uint8_t*            in,
                                 size_t                    in_len,
                                 pubnub_encrypted_data_t*  out)
{
    (void)self;
    (void)in;
    (void)in_len;
    (void)out;
    return PUBNUB_OK;
}

static pubnub_res_t mock_decrypt(pubnub_crypto_provider_t*      self,
                                 const pubnub_encrypted_data_t* in,
                                 uint8_t*                       out,
                                 size_t*                        out_len)
{
    (void)self;
    (void)in;
    (void)out;
    (void)out_len;
    return PUBNUB_OK;
}

static pubnub_res_t mock_hmac(pubnub_crypto_provider_t* self,
                              const uint8_t*            key,
                              size_t                    key_len,
                              const uint8_t*            data,
                              size_t                    data_len,
                              uint8_t*                  out,
                              size_t*                   out_len)
{
    (void)self;
    (void)key;
    (void)key_len;
    (void)data;
    (void)data_len;
    (void)out;
    (void)out_len;
    return PUBNUB_OK;
}

static pubnub_crypto_provider_t s_crypto = {
    .identifier   = {'T', 'E', 'S', 'T'},
    .encrypt_size = NULL,
    .encrypt      = mock_encrypt,
    .decrypt      = mock_decrypt,
    .hmac_sha256  = mock_hmac,
    .init         = NULL,
    .deinit       = NULL,
};

/* ======================================================================== */
/* Per-test fixture                                                          */
/* ======================================================================== */

typedef struct {
    pubnub_context_t* ctx;
    pubnub_future_t   future;
    pn_request_t*     slot;
} fixture_t;

static pubnub_config_t fixture_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-c-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_alloc;
    cfg.transport       = &s_transport;
    cfg.serialization   = pn_serialization_default();
    cfg.platform        = &s_platform;
    cfg.crypto_module   = NULL;
    cfg.logger          = NULL;
    return cfg;
}

static void fixture_init(fixture_t* fix)
{
    size_t sz = pubnub_context_size();
    fix->ctx  = (pubnub_context_t*)test_calloc(1, sz);
    assert_non_null(fix->ctx);

    pubnub_config_t cfg = fixture_config();
    assert_int_equal(pubnub_init(fix->ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pn_request_pool_acquire(
                         pn_context_request_pool(fix->ctx), fix->ctx, &fix->future),
                     PUBNUB_OK);

    fix->slot = pn_request_pool_get(pn_context_request_pool(fix->ctx),
                                    fix->future.slot_id);
    assert_non_null(fix->slot);

    /* Drive the slot into a terminal state so terminal_slot()
     * resolves it. */
    fix->slot->state = PN_REQUEST_IN_FLIGHT;
    pn_request_on_success(fix->slot, PUBNUB_OK);
}

static void fixture_teardown(fixture_t* fix)
{
    pn_request_pool_release(pn_context_request_pool(fix->ctx), fix->future.slot_id);
    pubnub_deinit(fix->ctx);
    test_free(fix->ctx);
}

static void fixture_set_body(fixture_t* fix, const char* body, int status_code)
{
    fix->slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    fix->slot->http_response.status_code = status_code;
    fix->slot->http_response.body        = (const uint8_t*)body;
    fix->slot->http_response.body_len    = strlen(body);
}

/* ======================================================================== */
/* Variant 1: ARRAY_PUBLISH                                                  */
/* ======================================================================== */

static void variant_array_publish_should_fold_failure(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Publish failure: array starts with 0; second element is the
     * human-readable message. */
    fixture_set_body(&fix, "[0,\"Forbidden\",\"\"]", 403);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.error_flag, 1);
    assert_int_equal(err.message.len, 9);
    assert_int_equal(0, memcmp(err.message.ptr, "Forbidden", 9));

    fixture_teardown(&fix);
}

static void variant_array_publish_success_should_not_classify_as_error(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Successful publish: first element is 1, not 0. The classifier
     * MUST NOT treat this as an array-publish error -- callers
     * should observe error_flag == 0 and an empty message view. */
    fixture_set_body(&fix, "[1,\"Sent\",\"17001234567890123\"]", 200);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.error_flag, 0);
    assert_null(err.message.ptr);
    assert_int_equal(err.message.len, 0);

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 2: OBJ_PUSH_STRING                                                */
/* ======================================================================== */

static void variant_push_string_should_fold_message(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Push management endpoints emit `{"error": "<reason>"}` on
     * failure. The classifier MUST surface that string as the
     * normalized message. */
    fixture_set_body(&fix, "{\"error\":\"Permission Denied\"}", 403);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.error_flag, 1);
    assert_int_equal(err.message.len, 17);
    assert_int_equal(0, memcmp(err.message.ptr, "Permission Denied", 17));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 3: OBJ_HISTORY_FLAT (probed BEFORE bool-error-flag)              */
/* ======================================================================== */

static void variant_history_flat_should_fold_message_and_status(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* History-style envelope: body carries both `error: true` (a
     * boolean) AND `error_message` (a string). The classifier MUST
     * dispatch this to the History variant -- otherwise the
     * boolean-flag variant catches it first and the message view
     * comes from the wrong key. */
    fixture_set_body(
        &fix, "{\"status\":400,\"error\":true,\"error_message\":\"bad ttl\"}", 400);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.status, 400);
    assert_int_equal(err.error_flag, 1);
    assert_int_equal(err.message.len, 7);
    assert_int_equal(0, memcmp(err.message.ptr, "bad ttl", 7));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 4: OBJ_PAM_DETAILS                                                */
/* ======================================================================== */

static void variant_pam_details_should_fold_message_source_service(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    fixture_set_body(
        &fix,
        "{\"status\":403,"
        "\"error\":{\"message\":\"Bad signature\",\"source\":\"balancer\"},"
        "\"service\":\"Access Manager\"}",
        403);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.status, 403);
    assert_int_equal(err.error_flag, 1);
    assert_int_equal(err.message.len, 13);
    assert_int_equal(0, memcmp(err.message.ptr, "Bad signature", 13));
    assert_int_equal(err.source.len, 8);
    assert_int_equal(0, memcmp(err.source.ptr, "balancer", 8));
    assert_int_equal(err.service.len, 14);
    assert_int_equal(0, memcmp(err.service.ptr, "Access Manager", 14));

    fixture_teardown(&fix);
}

static void variant_pam_details_should_expose_details_iterator(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    fixture_set_body(&fix,
                     "{\"status\":400,"
                     "\"error\":{"
                     "\"message\":\"Validation failed\","
                     "\"details\":["
                     "{\"message\":\"required\",\"location\":\"ttl\"},"
                     "{\"message\":\"too long\",\"location\":\"signature\"}"
                     "]"
                     "}}",
                     400);

    /* Two iterator entries reachable. */
    assert_int_equal(pubnub_service_error_detail_count(fix.future), 2);

    pubnub_service_error_detail_t d;
    assert_int_equal(pubnub_service_error_detail_at(fix.future, 0, &d), PUBNUB_OK);
    assert_int_equal(d.message.len, 8);
    assert_int_equal(0, memcmp(d.message.ptr, "required", 8));
    assert_int_equal(d.location.len, 3);
    assert_int_equal(0, memcmp(d.location.ptr, "ttl", 3));

    assert_int_equal(pubnub_service_error_detail_at(fix.future, 1, &d), PUBNUB_OK);
    assert_int_equal(d.message.len, 8);
    assert_int_equal(0, memcmp(d.message.ptr, "too long", 8));
    assert_int_equal(d.location.len, 9);
    assert_int_equal(0, memcmp(d.location.ptr, "signature", 9));

    /* Out-of-range index. */
    assert_int_equal(pubnub_service_error_detail_at(fix.future, 2, &d),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    fixture_teardown(&fix);
}

static void variant_pam_details_should_expose_files_code(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Files endpoint variant -- carries a numeric `error.code`
     * subclassifier alongside the message. */
    fixture_set_body(
        &fix,
        "{\"status\":400,"
        "\"error\":{\"message\":\"file too large\",\"source\":\"files\","
        "\"code\":1}}",
        400);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.code, 1);

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 5: OBJ_BOOL_ERROR_FLAG                                            */
/* ======================================================================== */

static void variant_bool_error_flag_should_fold_message(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    fixture_set_body(&fix,
                     "{\"status\":400,\"error\":true,"
                     "\"message\":\"Channel groups missing\","
                     "\"service\":\"Channel Groups\"}",
                     400);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.status, 400);
    assert_int_equal(err.error_flag, 1);
    assert_int_equal(err.message.len, 22);
    assert_int_equal(0, memcmp(err.message.ptr, "Channel groups missing", 22));
    assert_int_equal(err.service.len, 14);

    fixture_teardown(&fix);
}

static void variant_bool_error_flag_should_expose_payload_channels(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Subscribe channel-access-forbidden envelope with a list of
     * affected channels under payload.channels. */
    fixture_set_body(&fix,
                     "{\"status\":403,\"error\":true,\"message\":\"Forbidden\","
                     "\"service\":\"Access Manager\","
                     "\"payload\":{\"channels\":[\"ch1\",\"ch2\"]}}",
                     403);

    assert_int_equal(pubnub_service_error_channel_count(fix.future), 2);

    pubnub_string_view_t v0 = pubnub_service_error_channel_at(fix.future, 0);
    pubnub_string_view_t v1 = pubnub_service_error_channel_at(fix.future, 1);
    assert_int_equal(v0.len, 3);
    assert_int_equal(0, memcmp(v0.ptr, "ch1", 3));
    assert_int_equal(v1.len, 3);
    assert_int_equal(0, memcmp(v1.ptr, "ch2", 3));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 6: OBJ_GENERIC_HARVEST                                            */
/* ======================================================================== */

static void variant_generic_harvest_should_fold_message(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* Object body that does not match any of the more specific
     * shapes; the harvest path picks up `message` if present. */
    fixture_set_body(
        &fix, "{\"status\":500,\"message\":\"Internal Server Error\"}", 500);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.status, 500);
    assert_int_equal(err.message.len, 21);
    assert_int_equal(0, memcmp(err.message.ptr, "Internal Server Error", 21));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Variant 7: RAW_TEXT (parse failure)                                       */
/* ======================================================================== */

static void variant_raw_text_should_alias_response_body(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* S3 XML / non-JSON response: classifier falls through to
     * RAW_TEXT and folds the body bytes verbatim into the message
     * view. */
    static const char xml[] =
        "<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>";
    fixture_set_body(&fix, xml, 404);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.message.len, strlen(xml));
    assert_int_equal(0, memcmp(err.message.ptr, xml, strlen(xml)));
    /* The view aliases the raw RX buffer directly (variant-7
     * special case) -- not the parsed tree. */
    assert_ptr_equal(err.message.ptr, xml);

    fixture_teardown(&fix);
}

static void variant_raw_text_with_empty_body_returns_transport_error(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* No body -> nothing to surface. The server closed the connection
     * without sending a body; this is a transport-level failure, not
     * an uninitialized context. */
    fix.slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    fix.slot->http_response.status_code = 204;
    fix.slot->http_response.body        = NULL;
    fix.slot->http_response.body_len    = 0;

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err),
                     PUBNUB_ERR_TRANSPORT);

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Probe-ordering edge cases                                                 */
/* ======================================================================== */

static void push_string_should_not_misroute_to_bool_error_flag(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    /* `{"error": "<string>"}` carries an `error` key that is NOT a
     * boolean. The boolean-flag probe MUST NOT trigger here -- if
     * it did, the message view would come from the (missing) top-
     * level `message` key instead of the `error` string. */
    fixture_set_body(&fix, "{\"error\":\"Bad token\"}", 401);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);
    assert_int_equal(err.message.len, 9);
    assert_int_equal(0, memcmp(err.message.ptr, "Bad token", 9));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* shim parity                                                               */
/* ======================================================================== */

static void error_message_shim_should_match_service_error_message(void** state)
{
    (void)state;
    fixture_t fix;
    fixture_init(&fix);
    fixture_set_body(&fix, "[0,\"Forbidden\"]", 403);

    pubnub_string_view_t shim_view = pubnub_response_error_message(fix.future);

    pubnub_service_error_t err;
    assert_int_equal(pubnub_response_service_error(fix.future, &err), PUBNUB_OK);

    assert_int_equal(shim_view.len, err.message.len);
    assert_int_equal(0, memcmp(shim_view.ptr, err.message.ptr, shim_view.len));

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Test runner                                                               */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(variant_array_publish_should_fold_failure),
        cmocka_unit_test(variant_array_publish_success_should_not_classify_as_error),
        cmocka_unit_test(variant_push_string_should_fold_message),
        cmocka_unit_test(variant_history_flat_should_fold_message_and_status),
        cmocka_unit_test(variant_pam_details_should_fold_message_source_service),
        cmocka_unit_test(variant_pam_details_should_expose_details_iterator),
        cmocka_unit_test(variant_pam_details_should_expose_files_code),
        cmocka_unit_test(variant_bool_error_flag_should_fold_message),
        cmocka_unit_test(variant_bool_error_flag_should_expose_payload_channels),
        cmocka_unit_test(variant_generic_harvest_should_fold_message),
        cmocka_unit_test(variant_raw_text_should_alias_response_body),
        cmocka_unit_test(variant_raw_text_with_empty_body_returns_transport_error),
        cmocka_unit_test(push_string_should_not_misroute_to_bool_error_flag),
        cmocka_unit_test(error_message_shim_should_match_service_error_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
