/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file response_units.c
 * @brief Integration coverage of @ref pubnub_response_error_message
 *        routing through the folded service_error classifier.
 *
 * @c pubnub_response_error_message is a thin shim that calls
 * @c pubnub_response_service_error and returns its @c message view.
 * These tests drive the shim against hand-constructed slots in a
 * terminal state to confirm the routing each common shape lands on:
 *
 *   - Transport-level failure (`status_code == 0`) with a non-JSON
 *     diagnostic body falls into the variant-7 (RAW_TEXT) branch
 *     and aliases the body verbatim.
 *   - HTTP-200 publish-style failures route through the variant-1
 *     (ARRAY_PUBLISH) probe and surface the second array element.
 *   - Empty / NULL bodies on any HTTP code return @c {NULL, 0}.
 *
 * Variant-by-variant coverage of the classifier itself lives in
 * @c service_error_units.c; this file only exercises the legacy
 * accessor's compatibility surface.
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
#include "pubnub/types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

/* ======================================================================== */
/* Minimal provider stack mocks (mirrors client_units.c pattern).            */
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

/* The service_error classifier walks a parsed JSON tree. Point the
 * test fixture's `cfg.serialization` at the linked default provider
 * so the array-publish / object-shape probes exercise a real parse,
 * not a mocked NULL-returning shim. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

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
    .secure_zero   = NULL,
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

/* ----------------------------------------------------------------------- */
/* Per-test fixture: alloc context, init, acquire slot, drive to terminal. */
/* ----------------------------------------------------------------------- */

typedef struct {
    pubnub_context_t* ctx;
    pubnub_future_t   future;
    pn_request_t*     slot;
} response_fixture_t;

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

static void fixture_init(response_fixture_t* fix)
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

    /* Drive the slot into a terminal state so terminal_slot() in
     * response.c resolves it successfully. */
    fix->slot->state = PN_REQUEST_IN_FLIGHT;
    pn_request_on_success(fix->slot, PUBNUB_OK);
}

static void fixture_teardown(response_fixture_t* fix)
{
    pn_request_pool_release(pn_context_request_pool(fix->ctx), fix->future.slot_id);
    pubnub_deinit(fix->ctx);
    test_free(fix->ctx);
}

/* ======================================================================== */
/* Tests: pubnub_response_error_message routing                              */
/* ======================================================================== */

static void error_msg_status_zero_returns_body_verbatim(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    /* Transport-layer failure with diagnostic string from the
     * transport provider. The SDK returns it verbatim -- no
     * length cap, no character validation. */
    static const char diag[] =
        "TLS handshake failed: certificate verify failure";
    const size_t diag_len = sizeof(diag) - 1U;

    fix.slot->http_response.completion  = PUBNUB_HTTP_ERROR;
    fix.slot->http_response.status_code = 0;
    fix.slot->http_response.body        = (const uint8_t*)diag;
    fix.slot->http_response.body_len    = diag_len;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_non_null(view.ptr);
    assert_int_equal(diag_len, view.len);
    assert_int_equal(0, memcmp(view.ptr, diag, diag_len));

    fixture_teardown(&fix);
}

static void error_msg_status_zero_null_body_is_empty_view(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    /* Transport reported failure with no diagnostic. */
    fix.slot->http_response.completion  = PUBNUB_HTTP_ERROR;
    fix.slot->http_response.status_code = 0;
    fix.slot->http_response.body        = NULL;
    fix.slot->http_response.body_len    = 0;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_null(view.ptr);
    assert_int_equal(0, view.len);

    fixture_teardown(&fix);
}

static void error_msg_status_zero_zero_length_body_is_empty_view(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    /* Pointer present but zero length -- still treated as "no body". */
    static const uint8_t one_byte       = 'x';
    fix.slot->http_response.completion  = PUBNUB_HTTP_ERROR;
    fix.slot->http_response.status_code = 0;
    fix.slot->http_response.body        = &one_byte;
    fix.slot->http_response.body_len    = 0;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_null(view.ptr);
    assert_int_equal(0, view.len);

    fixture_teardown(&fix);
}

static void error_msg_runs_json_scanner_for_http_200(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    /* Server-error path: HTTP-200 with a publish-style array body
     * `[0,"foo","..."]` lands on the variant-1 (ARRAY_PUBLISH)
     * classifier branch; the second array element becomes the
     * normalized message view. */
    static const char body[]   = "[0,\"foo\",\"17142...\"]";
    const size_t      body_len = sizeof(body) - 1U;

    fix.slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    fix.slot->http_response.status_code = 200;
    fix.slot->http_response.body        = (const uint8_t*)body;
    fix.slot->http_response.body_len    = body_len;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_non_null(view.ptr);
    assert_int_equal(3, view.len);
    assert_int_equal(0, memcmp(view.ptr, "foo", 3));

    fixture_teardown(&fix);
}

static void error_msg_returns_empty_for_204_no_body(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    /* HTTP 204 No Content: status_code != 0 with body_len == 0.
     * The classifier returns PUBNUB_ERR_NOT_INITIALIZED, which the
     * shim collapses to {NULL, 0}. */
    fix.slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    fix.slot->http_response.status_code = 204;
    fix.slot->http_response.body        = NULL;
    fix.slot->http_response.body_len    = 0;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_null(view.ptr);
    assert_int_equal(0, view.len);

    fixture_teardown(&fix);
}

static void error_msg_returns_empty_for_304_no_body(void** state)
{
    (void)state;
    response_fixture_t fix;
    fixture_init(&fix);

    fix.slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    fix.slot->http_response.status_code = 304;
    fix.slot->http_response.body        = NULL;
    fix.slot->http_response.body_len    = 0;

    pubnub_string_view_t view = pubnub_response_error_message(fix.future);

    assert_null(view.ptr);
    assert_int_equal(0, view.len);

    fixture_teardown(&fix);
}

/* ======================================================================== */
/* Test runner                                                               */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(error_msg_status_zero_returns_body_verbatim),
        cmocka_unit_test(error_msg_status_zero_null_body_is_empty_view),
        cmocka_unit_test(error_msg_status_zero_zero_length_body_is_empty_view),
        cmocka_unit_test(error_msg_runs_json_scanner_for_http_200),
        cmocka_unit_test(error_msg_returns_empty_for_204_no_body),
        cmocka_unit_test(error_msg_returns_empty_for_304_no_body),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
