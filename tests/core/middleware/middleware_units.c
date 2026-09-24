/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file middleware_units.c
 * @brief Unit tests for the middleware chain.
 *
 * Uses a mock transport that records the final request it receives,
 * so tests can verify that middlewares enriched the request correctly.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/middleware/middleware_internal.h"
#include "pubnub/config.h"

/* URL-encoded form of PUBNUB_SDK_IDENTIFIER for test assertions.
 * Only '/' is reserved in the identifier; hyphens/dots/letters pass through. */
#define PN_TEST_PNSDK_ENCODED \
    PUBNUB_SDK_PLATFORM "-PubNub-C-core%2F" PUBNUB_SDK_VERSION

/* ======================================================================== */
/* Mock transport: records the request it receives                          */
/* ======================================================================== */

static pubnub_http_request_t s_captured_request;
static int                   s_send_called;
static int                   s_fake_handle;

/** Deep-copy buffer for query param key/value strings captured during send.
 *  Middlewares may free their heap-encoded buffers after send returns, so
 *  the captured views must point into this stable storage. */
static char   s_captured_param_buf[2048];
static size_t s_captured_param_buf_used;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)self;
    (void)response;
    s_captured_request        = *request;
    s_captured_param_buf_used = 0;
    s_send_called             = 1;

    /* Deep-copy all query param key/value views into stable storage. */
    for (unsigned int i = 0; i < request->query_param_count; i++) {
        pubnub_kv_t* kv = &s_captured_request.query_params[i];

        if (NULL != kv->key.ptr && kv->key.len > 0) {
            size_t needed = kv->key.len;
            if (s_captured_param_buf_used + needed <= sizeof(s_captured_param_buf)) {
                memcpy(s_captured_param_buf + s_captured_param_buf_used,
                       kv->key.ptr,
                       needed);
                kv->key.ptr = s_captured_param_buf + s_captured_param_buf_used;
                s_captured_param_buf_used += needed;
            }
        }

        if (NULL != kv->value.ptr && kv->value.len > 0) {
            size_t needed = kv->value.len;
            if (s_captured_param_buf_used + needed <= sizeof(s_captured_param_buf)) {
                memcpy(s_captured_param_buf + s_captured_param_buf_used,
                       kv->value.ptr,
                       needed);
                kv->value.ptr = s_captured_param_buf + s_captured_param_buf_used;
                s_captured_param_buf_used += needed;
            }
        }
    }

    return (pubnub_transport_handle_t*)&s_fake_handle;
}

static int mock_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   transport_handle)
{
    (void)self;
    (void)transport_handle;
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/* ======================================================================== */
/* Mock allocator (used only by _create tests)                              */
/* ======================================================================== */

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

/* ======================================================================== */
/* Test helpers                                                             */
/* ======================================================================== */

static int reset_test(void** state)
{
    (void)state;
    memset(&s_captured_request, 0, sizeof(s_captured_request));
    s_captured_param_buf_used = 0;
    s_send_called             = 0;
    return 0;
}

/**
 * @brief Find a query parameter by key in the captured request.
 *
 * @return Pointer to the value view, or NULL if not found.
 */
static const pubnub_string_view_t* find_query_param(const pubnub_http_request_t* req,
                                                    const char* key)
{
    size_t key_len = strlen(key);
    for (unsigned int i = 0; i < req->query_param_count; i++) {
        if (req->query_params[i].key.len == key_len
            && memcmp(req->query_params[i].key.ptr, key, key_len) == 0) {
            return &req->query_params[i].value;
        }
    }
    return NULL;
}

static int param_value_equals(const pubnub_string_view_t* view, const char* expected)
{
    if (view == NULL) {
        return 0;
    }
    size_t expected_len = strlen(expected);
    return view->len == expected_len
        && memcmp(view->ptr, expected, expected_len) == 0;
}

/* ======================================================================== */
/* Tests: pn_request_add_query_param                                        */
/* ======================================================================== */

static void add_param_should_append_to_request(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "foo", "bar", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_true(param_value_equals(&req.query_params[0].value, "bar"));
}

static void add_param_should_fail_when_params_full(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.query_param_count = PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS;

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "foo", "bar", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void add_param_should_fail_when_scratch_full(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "foo", "bar", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void add_param_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    assert_int_equal(pn_request_add_query_param(NULL, "k", "v", PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_request_add_query_param(&req, NULL, "v", PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_request_add_query_param(&req, "k", NULL, PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void add_param_should_roll_back_scratch_on_value_failure(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    /* Leave just enough room for the key "foo" but not the value. */
    req.scratch_used              = PUBNUB_CFG_HTTP_SCRATCH_SIZE - 3;
    const unsigned int saved_used = req.scratch_used;

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "foo", "bar", PN_ENCODE_FULL);

    assert_int_not_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
    /* scratch_used must be restored to the pre-call value. */
    assert_int_equal(req.scratch_used, saved_used);
}

/* ======================================================================== */
/* Tests: pnsdk middleware                                                  */
/* ======================================================================== */

static void pnsdk_should_add_pnsdk_param(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, NULL, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    /* "/" is reserved and gets percent-encoded. */
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED));
}

static void pnsdk_should_delegate_poll_to_next(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, NULL, &s_mock_transport);

    int rc = mw.base.poll(&mw.base, 100);

    assert_int_equal(rc, 0);
}

static void pnsdk_should_delegate_cancel_to_next(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, NULL, &s_mock_transport);

    /* Should not crash -- just delegates. */
    mw.base.cancel(&mw.base, (pubnub_transport_handle_t*)&s_fake_handle);
}

static void pnsdk_should_append_suffix_when_set(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, "Chat/1.0", &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED "%20Chat%2F1.0"));
}

static void pnsdk_should_skip_suffix_when_null(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, NULL, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED));
}

static void pnsdk_should_handle_empty_suffix(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, "", &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    /* Empty suffix treated same as NULL -- no trailing space. */
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED));
}

static void pnsdk_override_should_replace_base(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, "Unreal-PubNub/5.4", NULL, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, "Unreal-PubNub%2F5.4"));
}

static void pnsdk_override_plus_suffix(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, "Unreal-PubNub/5.4", "UE5", &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, "Unreal-PubNub%2F5.4%20UE5"));
}

static void pnsdk_empty_override_should_fall_back_to_default(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, "", NULL, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED));
}

static void pnsdk_null_override_with_suffix_regression(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, "Chat/1.0", &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(val);
    assert_true(param_value_equals(val, PN_TEST_PNSDK_ENCODED "%20Chat%2F1.0"));
}

/* ======================================================================== */
/* Tests: userid middleware                                                 */
/* ======================================================================== */

static void userid_should_add_uuid_param(void** state)
{
    (void)state;
    const char*             user_id = "test-user-123";
    pn_middleware_user_id_t mw;
    pn_middleware_userid_init(&mw, &user_id, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "uuid");
    assert_non_null(val);
    assert_true(param_value_equals(val, "test-user-123"));
}

static void user_id_should_see_runtime_id_change(void** state)
{
    (void)state;
    const char*             user_id = "first-user";
    pn_middleware_user_id_t mw;
    pn_middleware_userid_init(&mw, &user_id, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* First send: original user_id. */
    mw.base.send(&mw.base, &req, &resp);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "uuid");
    assert_non_null(val);
    assert_true(param_value_equals(val, "first-user"));

    /* Simulate pubnub_set_user_id() rotating the id. */
    user_id       = "second-user";
    s_send_called = 0;
    memset(&req, 0, sizeof(req));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    val = find_query_param(&s_captured_request, "uuid");
    assert_non_null(val);
    assert_true(param_value_equals(val, "second-user"));
}

/* ======================================================================== */
/* Tests: auth middleware                                                   */
/* ======================================================================== */

static void auth_should_add_auth_param_when_token_set(void** state)
{
    (void)state;
    const char*          token = "my-secret-token";
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "auth");
    assert_non_null(val);
    assert_true(param_value_equals(val, "my-secret-token"));

    pn_middleware_auth_deinit(&mw);
}

static void auth_should_skip_when_token_is_null(void** state)
{
    (void)state;
    const char*          token = NULL;
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "auth");
    assert_null(val);
}

static void auth_should_skip_when_token_ptr_is_null(void** state)
{
    (void)state;
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, NULL, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "auth");
    assert_null(val);
}

static void auth_should_see_runtime_token_change(void** state)
{
    (void)state;
    const char*          token = NULL;
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* First send: no auth. */
    mw.base.send(&mw.base, &req, &resp);
    assert_null(find_query_param(&s_captured_request, "auth"));

    /* Simulate runtime change. */
    token         = "new-token";
    s_send_called = 0;
    memset(&req, 0, sizeof(req));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "auth");
    assert_non_null(val);
    assert_true(param_value_equals(val, "new-token"));

    pn_middleware_auth_deinit(&mw);
}

/* ======================================================================== */
/* Tests: init argument validation                                          */
/*                                                                          */
/* Contract asymmetry:                                                      */
/*   - pnsdk_init and userid_init reject NULL mw/next/string                */
/*   - auth_init rejects NULL mw/next but ACCEPTS NULL auth_token           */
/*     (a NULL token pointer means "no auth configured")                    */
/* ======================================================================== */

static void pnsdk_init_should_be_safe_with_null_mw(void** state)
{
    (void)state;
    /* Must not crash. */
    pn_middleware_pnsdk_init(NULL, NULL, NULL, &s_mock_transport);
}

static void pnsdk_init_should_leave_struct_unmodified_on_null_next(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_pnsdk_init(&sut, NULL, NULL, NULL);

    assert_null(sut.base.send);
    assert_null(sut.next);
    assert_null(sut.suffix);
}

static void pnsdk_init_should_succeed_with_null_suffix(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_pnsdk_init(&sut, NULL, NULL, &s_mock_transport);

    assert_non_null(sut.base.send);
    assert_ptr_equal(sut.next, &s_mock_transport);
    assert_null(sut.suffix);
}

static void userid_init_should_be_safe_with_null_mw(void** state)
{
    (void)state;

    const char* uid = "u";
    pn_middleware_userid_init(NULL, &uid, &s_mock_transport);
}

static void userid_init_should_leave_struct_unmodified_on_null_next(void** state)
{
    (void)state;
    const char*             uid = "u";
    pn_middleware_user_id_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_userid_init(&sut, &uid, NULL);

    assert_null(sut.base.send);
}

static void userid_init_should_reject_null_user_id(void** state)
{
    (void)state;
    pn_middleware_user_id_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_userid_init(&sut, NULL, &s_mock_transport);

    /* Contract: userid middleware requires a non-NULL user_id;
     * rejection leaves the struct unpopulated. */
    assert_null(sut.base.send);
    assert_null(sut.user_id);
}

static void auth_init_should_be_safe_with_null_mw(void** state)
{
    (void)state;
    const char* token = "t";

    pn_middleware_auth_init(NULL, &token, &s_mock_transport, &s_mock_allocator);
}

static void auth_init_should_leave_struct_unmodified_on_null_next(void** state)
{
    (void)state;
    const char*          token = "t";
    pn_middleware_auth_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_auth_init(&sut, &token, NULL, &s_mock_allocator);

    assert_null(sut.base.send);
}

static void auth_init_should_reject_null_allocator(void** state)
{
    (void)state;
    const char*          token = "t";
    pn_middleware_auth_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_auth_init(&sut, &token, &s_mock_transport, NULL);

    assert_null(sut.base.send);
}

static void auth_init_should_accept_null_auth_token(void** state)
{
    (void)state;
    pn_middleware_auth_t sut;
    memset(&sut, 0, sizeof(sut));

    pn_middleware_auth_init(&sut, NULL, &s_mock_transport, &s_mock_allocator);

    /* Contract asymmetry: auth middleware ACCEPTS a NULL
     * auth_token pointer (meaning "no auth configured"). The
     * struct must be fully populated and usable. */
    assert_non_null(sut.base.send);
    assert_ptr_equal(sut.next, &s_mock_transport);
    assert_null(sut.auth_token);
}

/* ======================================================================== */
/* Tests: _create() argument validation                                      */
/*                                                                          */
/* _create() factories allocate via the allocator provider. They must     */
/* reject NULL allocator, NULL next, and (for non-auth variants) NULL      */
/* state without allocating anything and without dereferencing.            */
/* ======================================================================== */

static void pnsdk_create_should_reject_null_next(void** state)
{
    (void)state;

    pubnub_transport_provider_t* layer =
        pn_middleware_pnsdk_create(NULL, NULL, NULL, &s_mock_allocator);

    assert_null(layer);
}

static void pnsdk_create_should_reject_null_allocator(void** state)
{
    (void)state;

    pubnub_transport_provider_t* layer =
        pn_middleware_pnsdk_create(NULL, NULL, &s_mock_transport, NULL);

    assert_null(layer);
}

static void userid_create_should_reject_null_user_id(void** state)
{
    (void)state;

    pubnub_transport_provider_t* layer =
        pn_middleware_userid_create(NULL, &s_mock_transport, &s_mock_allocator);

    assert_null(layer);
}

static void userid_create_should_reject_null_next(void** state)
{
    (void)state;
    const char* uid = "u";

    pubnub_transport_provider_t* layer =
        pn_middleware_userid_create(&uid, NULL, &s_mock_allocator);

    assert_null(layer);
}

static void userid_create_should_reject_null_allocator(void** state)
{
    (void)state;
    const char* uid = "u";

    pubnub_transport_provider_t* layer =
        pn_middleware_userid_create(&uid, &s_mock_transport, NULL);

    assert_null(layer);
}

static void auth_create_should_accept_null_auth_token(void** state)
{
    (void)state;

    pubnub_transport_provider_t* layer =
        pn_middleware_auth_create(NULL, &s_mock_transport, &s_mock_allocator, NULL);

    /* Contract asymmetry: NULL auth_token means "no auth configured"
     * and is a valid operating mode. */
    assert_non_null(layer);
    s_mock_allocator.free(&s_mock_allocator, layer);
}

static void auth_create_should_reject_null_next(void** state)
{
    (void)state;
    const char* token = "tok";

    pubnub_transport_provider_t* layer =
        pn_middleware_auth_create(&token, NULL, &s_mock_allocator, NULL);

    assert_null(layer);
}

static void auth_create_should_reject_null_allocator(void** state)
{
    (void)state;
    const char* token = "tok";

    pubnub_transport_provider_t* layer =
        pn_middleware_auth_create(&token, &s_mock_transport, NULL, NULL);

    assert_null(layer);
}

/* ======================================================================== */
/* Tests: defensive checks for a broken chain (mw->next == NULL)            */
/*                                                                          */
/* In a correctly built chain mw->next is always set by init. A            */
/* corrupted or partially constructed chain (e.g. zero-initialised          */
/* middleware fed into the chain) must not crash -- it should fail          */
/* the request cleanly and return an error to the caller.                   */
/* ======================================================================== */

static void send_should_fail_when_next_is_null(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t sut;
    pn_middleware_pnsdk_init(&sut, NULL, NULL, &s_mock_transport);
    sut.next = NULL; /* Simulate a broken chain. */
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = sut.base.send(&sut.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);
}

static void poll_should_return_error_when_next_is_null(void** state)
{
    (void)state;
    const char*             uid = "u";
    pn_middleware_user_id_t sut;
    pn_middleware_userid_init(&sut, &uid, &s_mock_transport);
    sut.next = NULL;

    int rc = sut.base.poll(&sut.base, 100);

    assert_int_equal(rc, -1);
}

static void cancel_should_be_safe_when_next_is_null(void** state)
{
    (void)state;
    const char*          token = "t";
    pn_middleware_auth_t sut;
    pn_middleware_auth_init(&sut, &token, &s_mock_transport, &s_mock_allocator);
    sut.next = NULL;

    /* Must not crash. */
    sut.base.cancel(&sut.base, (pubnub_transport_handle_t*)&s_fake_handle);
}

/* ======================================================================== */
/* Tests: chain composition                                                 */
/* ======================================================================== */

static void chain_should_compose_all_params(void** state)
{
    (void)state;
    const char* token = "tok-123";

    /* Build chain: auth -> userid -> pnsdk -> mock_transport
     * Outermost is auth, executed first. */
    pn_middleware_pnsdk_t   mw_pnsdk;
    pn_middleware_user_id_t mw_userid;
    pn_middleware_auth_t    mw_auth;

    const char* uid = "user-456";
    pn_middleware_pnsdk_init(&mw_pnsdk, NULL, NULL, &s_mock_transport);
    pn_middleware_userid_init(&mw_userid, &uid, &mw_pnsdk.base);
    pn_middleware_auth_init(&mw_auth, &token, &mw_userid.base, &s_mock_allocator);

    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* Send through the outermost middleware. */
    mw_auth.base.send(&mw_auth.base, &req, &resp);

    assert_true(s_send_called);
    assert_int_equal(s_captured_request.query_param_count, 3);

    const pubnub_string_view_t* auth_val =
        find_query_param(&s_captured_request, "auth");
    assert_non_null(auth_val);
    assert_true(param_value_equals(auth_val, "tok-123"));

    const pubnub_string_view_t* uuid_val =
        find_query_param(&s_captured_request, "uuid");
    assert_non_null(uuid_val);
    assert_true(param_value_equals(uuid_val, "user-456"));

    const pubnub_string_view_t* pnsdk_val =
        find_query_param(&s_captured_request, "pnsdk");
    assert_non_null(pnsdk_val);
    assert_true(param_value_equals(pnsdk_val, PN_TEST_PNSDK_ENCODED));

    pn_middleware_auth_deinit(&mw_auth);
}

static void chain_should_work_without_auth(void** state)
{
    (void)state;
    const char* token = NULL;

    pn_middleware_pnsdk_t   mw_pnsdk;
    pn_middleware_user_id_t mw_userid;
    pn_middleware_auth_t    mw_auth;

    const char* uid = "user-789";
    pn_middleware_pnsdk_init(&mw_pnsdk, NULL, NULL, &s_mock_transport);
    pn_middleware_userid_init(&mw_userid, &uid, &mw_pnsdk.base);
    pn_middleware_auth_init(&mw_auth, &token, &mw_userid.base, &s_mock_allocator);

    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw_auth.base.send(&mw_auth.base, &req, &resp);

    assert_true(s_send_called);
    assert_int_equal(s_captured_request.query_param_count, 2);

    assert_null(find_query_param(&s_captured_request, "auth"));
    assert_non_null(find_query_param(&s_captured_request, "uuid"));
    assert_non_null(find_query_param(&s_captured_request, "pnsdk"));
}

/* ======================================================================== */
/* Tests: URL encoding of values                                            */
/* ======================================================================== */

static void add_param_should_percent_encode_reserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "auth", "tok+abc/def==", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_true(param_value_equals(&req.query_params[0].value,
                                   "tok%2Babc%2Fdef%3D%3D"));
}

static void add_param_should_encode_space_as_percent_20(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    /* Space encoding differs between standards: RFC 3986 percent-encoding
     * uses %20, but application/x-www-form-urlencoded uses '+'. PubNub
     * query strings follow RFC 3986 -- pin the contract so the encoder
     * doesn't drift to '+' (some languages, e.g. Dart, default to '+'). */
    pubnub_res_t rc =
        pn_request_add_query_param(&req, "x", "hello world", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_true(param_value_equals(&req.query_params[0].value, "hello%20world"));
}

static void add_param_should_preserve_unreserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    /* Unreserved per RFC 3986: letters, digits, -_.~ */
    pubnub_res_t rc =
        pn_request_add_query_param(&req, "x", "Ab1-_.~", PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(param_value_equals(&req.query_params[0].value, "Ab1-_.~"));
}

static void add_param_should_copy_verbatim_with_encode_none(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "tt", "16230000000000000", PN_ENCODE_NONE);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(param_value_equals(&req.query_params[0].value, "16230000000000000"));
}

static void add_param_encode_none_should_preserve_reserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc =
        pn_request_add_query_param(&req, "sig", "v2.abc/def+x==", PN_ENCODE_NONE);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(param_value_equals(&req.query_params[0].value, "v2.abc/def+x=="));
}

static void add_param_keep_commas_should_encode_reserved_but_not_commas(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc = pn_request_add_query_param(
        &req, "channel-group", "group-a,group b,group/c", PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(param_value_equals(&req.query_params[0].value,
                                   "group-a,group%20b,group%2Fc"));
}

static void add_param_keep_commas_should_pass_simple_names(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    pubnub_res_t rc = pn_request_add_query_param(
        &req, "channel-group", "alpha,beta,gamma", PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(param_value_equals(&req.query_params[0].value, "alpha,beta,gamma"));
}

static void auth_should_percent_encode_slash_in_token(void** state)
{
    (void)state;
    const char*          token = "a/b+c";
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    const pubnub_string_view_t* val = find_query_param(&s_captured_request, "auth");
    assert_non_null(val);
    assert_true(param_value_equals(val, "a%2Fb%2Bc"));

    pn_middleware_auth_deinit(&mw);
}

/* ======================================================================== */
/* Tests: pn_request_scratch_encode                                    */
/* ======================================================================== */

static void scratch_encode_should_encode_reserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_string_view_t out;

    pubnub_res_t rc =
        pn_request_scratch_encode(&req, "my/channel", &out, PN_ENCODE_FULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.len, 12); /* my%2Fchannel */
    assert_memory_equal(out.ptr, "my%2Fchannel", 12);
}

static void scratch_encode_should_preserve_commas(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_string_view_t out;

    pubnub_res_t rc = pn_request_scratch_encode(
        &req, "chan a,chan/b,chan-c", &out, PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_memory_equal(out.ptr, "chan%20a,chan%2Fb,chan-c", out.len);
}

static void scratch_encode_should_pass_unreserved(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_string_view_t out;

    pubnub_res_t rc = pn_request_scratch_encode(
        &req, "alpha,beta,gamma", &out, PN_ENCODE_KEEP_COMMAS);

    assert_int_equal(rc, PUBNUB_OK);
    assert_memory_equal(out.ptr, "alpha,beta,gamma", out.len);
}

static void scratch_encode_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_string_view_t out;

    assert_int_equal(pn_request_scratch_encode(NULL, "x", &out, PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_request_scratch_encode(&req, NULL, &out, PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_request_scratch_encode(&req, "x", NULL, PN_ENCODE_FULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

static void scratch_encode_should_fail_when_scratch_full(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    pubnub_string_view_t out;

    pubnub_res_t rc = pn_request_scratch_encode(&req, "x", &out, PN_ENCODE_FULL);

    assert_int_not_equal(rc, PUBNUB_OK);
}

/* ======================================================================== */
/* Tests: scratch exhaustion -- middleware must short-circuit               */
/* ======================================================================== */

static void pnsdk_should_fail_when_scratch_exhausted(void** state)
{
    (void)state;
    pn_middleware_pnsdk_t mw;
    pn_middleware_pnsdk_init(&mw, NULL, NULL, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);
}

static void userid_should_fail_when_scratch_exhausted(void** state)
{
    (void)state;
    const char*             uid = "user-123";
    pn_middleware_user_id_t mw;
    pn_middleware_userid_init(&mw, &uid, &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);
}

static void auth_should_fail_when_scratch_exhausted(void** state)
{
    (void)state;
    const char*          token = "tok";
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);

    pn_middleware_auth_deinit(&mw);
}

static void auth_should_not_fail_on_scratch_exhaustion_when_no_token(void** state)
{
    (void)state;
    const char*          token = NULL;
    pn_middleware_auth_t mw;
    pn_middleware_auth_init(&mw, &token, &s_mock_transport, &s_mock_allocator);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.scratch_used = PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    /* No token -> nothing to encode -> delegates normally. */
    assert_true(s_send_called);
    assert_int_not_equal(resp.completion, PUBNUB_HTTP_ERROR);
}

#if PUBNUB_ENABLE_PAM
/* ======================================================================== */
/* Mock crypto provider (signature middleware tests)                        */
/* ======================================================================== */

static int     s_hmac_called;
static uint8_t s_hmac_last_data[512];
static size_t  s_hmac_last_data_len;
static uint8_t s_hmac_last_key[64];
static size_t  s_hmac_last_key_len;
static int     s_hmac_force_error;

static pubnub_res_t mock_hmac_sha256(pubnub_crypto_provider_t* self,
                                     const uint8_t*            key,
                                     size_t                    key_len,
                                     const uint8_t*            data,
                                     size_t                    data_len,
                                     uint8_t*                  output,
                                     size_t*                   output_len)
{
    (void)self;
    s_hmac_called = 1;
    if (key_len <= sizeof(s_hmac_last_key)) {
        memcpy(s_hmac_last_key, key, key_len);
        s_hmac_last_key_len = key_len;
    }
    if (data_len <= sizeof(s_hmac_last_data)) {
        memcpy(s_hmac_last_data, data, data_len);
        s_hmac_last_data_len = data_len;
    }
    if (s_hmac_force_error) {
        return PUBNUB_ERR_CRYPTO;
    }
    for (size_t i = 0; i < 32; i++) {
        output[i] = (uint8_t)(0xC0 + (i & 0x0F));
    }
    *output_len = 32;
    return PUBNUB_OK;
}

static pubnub_crypto_provider_t s_mock_crypto = {
    .identifier   = {0, 0, 0, 0},
    .encrypt_size = NULL,
    .encrypt      = NULL,
    .decrypt      = NULL,
    .hmac_sha256  = mock_hmac_sha256,
    .init         = NULL,
    .deinit       = NULL,
};

/* ======================================================================== */
/* Mock platform -- wall_clock_ms returns a fixed Unix-epoch value so       */
/* signature tests can compare against deterministic canonical strings.     */
/* ======================================================================== */

#define PN_TEST_FIXED_TIMESTAMP_MS UINT64_C(1700000000000)
#define PN_TEST_FIXED_TIMESTAMP_S  UINT64_C(1700000000)

static pubnub_milliseconds_t mock_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return PN_TEST_FIXED_TIMESTAMP_MS;
}

static pubnub_milliseconds_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return PN_TEST_FIXED_TIMESTAMP_MS;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic_ms,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = NULL,
    .random_bytes  = NULL,
    .secure_zero   = NULL,
};

/* ======================================================================== */
/* Mock allocator that can be forced to fail                                 */
/* ======================================================================== */

static int s_failing_alloc_calls;

static void* failing_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)size;
    (void)align;
    s_failing_alloc_calls++;
    return NULL;
}

static pubnub_allocator_provider_t s_failing_allocator = {
    .alloc       = failing_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

/* ======================================================================== */
/* Signature middleware: setup helper                                        */
/* ======================================================================== */

/**
 * @brief Reset per-test state for signature tests.
 *
 * The base reset_test() only touches request/send state; signature
 * tests additionally track HMAC invocations and alloc-failure
 * behavior.
 */
static int reset_signature_test(void** state)
{
    reset_test(state);
    s_hmac_called         = 0;
    s_hmac_last_data_len  = 0;
    s_hmac_last_key_len   = 0;
    s_hmac_force_error    = 0;
    s_failing_alloc_calls = 0;
    memset(s_hmac_last_data, 0, sizeof(s_hmac_last_data));
    memset(s_hmac_last_key, 0, sizeof(s_hmac_last_key));
    return 0;
}

/* ======================================================================== */
/* Tests: signature middleware                                               */
/* ======================================================================== */

static void signature_should_passthrough_when_secret_null(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = NULL;
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    assert_false(s_hmac_called);
    assert_null(find_query_param(&s_captured_request, "signature"));
}

static void signature_should_passthrough_when_publish_key_null(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk-42";
    pn_middleware_signature_init(&mw,
                                 /*publish_key=*/NULL,
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    assert_false(s_hmac_called);
    assert_null(find_query_param(&s_captured_request, "signature"));
}

static void signature_should_passthrough_when_crypto_null(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk-42";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 /*crypto=*/NULL,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_send_called);
    assert_false(s_hmac_called);
    assert_null(find_query_param(&s_captured_request, "signature"));
}

static void signature_should_append_signature_param_when_signing(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "my-secret";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_non_null(handle);
    assert_true(s_hmac_called);

    /* HMAC key is the raw secret. */
    assert_int_equal(s_hmac_last_key_len, strlen(secret));
    assert_memory_equal(s_hmac_last_key, secret, s_hmac_last_key_len);

    /* Canonical signing string for a zeroed GET request with no
     * params/body and empty publish_key path -- the middleware adds
     * the mandatory PAMv3 timestamp query param (derived from the
     * mock platform's pinned wall_clock_ms) before signing, so the
     * canonical string's query section is
     * "timestamp=<fixed-test-value>":
     *   "GET\npub_k\n/\ntimestamp=1700000000\n" */
    const char* expected = "GET\npub_k\n/\ntimestamp=1700000000\n";
    assert_int_equal(s_hmac_last_data_len, strlen(expected));
    assert_memory_equal(s_hmac_last_data, expected, s_hmac_last_data_len);

    /* Signature param added, `v2.` prefix present. */
    const pubnub_string_view_t* sig =
        find_query_param(&s_captured_request, "signature");
    assert_non_null(sig);
    assert_true(sig->len > 3);
    assert_memory_equal(sig->ptr, "v2.", 3);
}

static void signature_should_sort_query_params_before_signing(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "my-secret";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    /* Insert in reverse-alphabetical order to prove sorting. */
    assert_int_equal(pn_request_add_query_param(&req, "uuid", "u1", PN_ENCODE_FULL),
                     PUBNUB_OK);
    assert_int_equal(pn_request_add_query_param(&req, "pnsdk", "s", PN_ENCODE_FULL),
                     PUBNUB_OK);
    assert_int_equal(pn_request_add_query_param(&req, "auth", "t", PN_ENCODE_FULL),
                     PUBNUB_OK);
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_hmac_called);
    /* Expected order after sort: auth, pnsdk, timestamp, uuid, signature.
     * (The middleware inserts the PAMv3 timestamp before sorting, so it
     * participates in the alphabetical ordering; the signature param is
     * always last since it is appended post-sort.) */
    assert_int_equal(s_captured_request.query_param_count, 5);
    const char* expected_order[] = {"auth", "pnsdk", "timestamp", "uuid", "signature"};
    for (size_t i = 0; i < sizeof(expected_order) / sizeof(expected_order[0]); i++) {
        size_t exp_len = strlen(expected_order[i]);
        assert_int_equal(s_captured_request.query_params[i].key.len, exp_len);
        assert_memory_equal(s_captured_request.query_params[i].key.ptr,
                            expected_order[i],
                            exp_len);
    }
}

static void signature_should_include_body_in_canonical_string(void** state)
{
    reset_signature_test(state);
    /* Non-publish POST/PATCH endpoints include the body in the
     * canonical signing string (matches JS/Go/Kotlin/Python SDKs). */
    pn_middleware_signature_t mw;
    const char*               secret = "sk";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method           = PUBNUB_HTTP_POST;
    const uint8_t body[] = {'{', '"', 'a', '"', ':', '1', '}'};
    req.body             = body;
    req.body_len         = sizeof(body);
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_hmac_called);
    /* The canonical string must end with the body bytes (after the
     * query-section trailing LF). */
    assert_true(s_hmac_last_data_len >= sizeof(body));
    assert_memory_equal(s_hmac_last_data + s_hmac_last_data_len - sizeof(body),
                        body,
                        sizeof(body));
}

static void signature_should_observe_runtime_secret_change(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = NULL;
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* First send: secret not set -> passthrough. */
    mw.base.send(&mw.base, &req, &resp);
    assert_false(s_hmac_called);

    /* Rotate secret and send again. */
    secret        = "late-secret";
    s_send_called = 0;
    memset(&req, 0, sizeof(req));

    mw.base.send(&mw.base, &req, &resp);

    assert_true(s_hmac_called);
    assert_non_null(find_query_param(&s_captured_request, "signature"));
}

static void signature_should_fail_when_hmac_returns_error(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));
    s_hmac_force_error = 1;

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);
}

static void signature_should_fail_when_allocator_returns_null(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_failing_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    pubnub_http_response_t resp;
    memset(&resp, 0, sizeof(resp));

    pubnub_transport_handle_t* handle = mw.base.send(&mw.base, &req, &resp);

    assert_null(handle);
    assert_false(s_send_called);
    assert_int_equal(resp.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(s_failing_alloc_calls, 1);
}

static void signature_should_delegate_poll_to_next(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);

    int rc = mw.base.poll(&mw.base, 100);

    assert_int_equal(rc, 0);
}

static void signature_should_delegate_cancel_to_next(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    const char*               secret = "sk";
    pn_middleware_signature_init(&mw,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);

    /* Should not crash -- just delegates. */
    mw.base.cancel(&mw.base, (pubnub_transport_handle_t*)&s_fake_handle);
}

static void signature_init_should_be_safe_with_null_mw(void** state)
{
    reset_signature_test(state);
    const char* secret = "sk";

    /* Must not crash. */
    pn_middleware_signature_init(NULL,
                                 "pub_k",
                                 &secret,
                                 &s_mock_crypto,
                                 &s_mock_allocator,
                                 &s_mock_platform,
                                 &s_mock_transport);
}

static void signature_init_should_leave_struct_unmodified_on_null_next(void** state)
{
    reset_signature_test(state);
    pn_middleware_signature_t mw;
    memset(&mw, 0, sizeof(mw));
    const char* secret = "sk";

    pn_middleware_signature_init(
        &mw, "pub_k", &secret, &s_mock_crypto, &s_mock_allocator, &s_mock_platform, NULL);

    /* next==NULL is a hard error; struct must not be partially init. */
    assert_null(mw.base.send);
    assert_null(mw.next);
}

static void signature_create_should_reject_null_next(void** state)
{
    reset_signature_test(state);
    const char* secret = "sk";

    pubnub_transport_provider_t* tp = pn_middleware_signature_create(
        "pub_k", &secret, &s_mock_crypto, NULL, &s_mock_allocator, &s_mock_platform, NULL);

    assert_null(tp);
}

static void signature_create_should_reject_null_allocator(void** state)
{
    reset_signature_test(state);
    const char* secret = "sk";

    pubnub_transport_provider_t* tp = pn_middleware_signature_create(
        "pub_k", &secret, &s_mock_crypto, &s_mock_transport, NULL, &s_mock_platform, NULL);

    assert_null(tp);
}
#endif /* PUBNUB_ENABLE_PAM */

/* ======================================================================== */
/* Test runner                                                              */
/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* query param helper */
        cmocka_unit_test_setup(add_param_should_append_to_request, reset_test),
        cmocka_unit_test_setup(add_param_should_fail_when_params_full, reset_test),
        cmocka_unit_test_setup(add_param_should_fail_when_scratch_full, reset_test),
        cmocka_unit_test_setup(add_param_should_reject_null_args, reset_test),
        cmocka_unit_test_setup(
            add_param_should_roll_back_scratch_on_value_failure, reset_test),
        cmocka_unit_test_setup(add_param_should_percent_encode_reserved_chars,
                               reset_test),
        cmocka_unit_test_setup(add_param_should_encode_space_as_percent_20,
                               reset_test),
        cmocka_unit_test_setup(add_param_should_preserve_unreserved_chars, reset_test),
        cmocka_unit_test_setup(add_param_should_copy_verbatim_with_encode_none,
                               reset_test),
        cmocka_unit_test_setup(
            add_param_encode_none_should_preserve_reserved_chars, reset_test),
        cmocka_unit_test_setup(
            add_param_keep_commas_should_encode_reserved_but_not_commas, reset_test),
        cmocka_unit_test_setup(add_param_keep_commas_should_pass_simple_names,
                               reset_test),

        /* scratch encode */
        cmocka_unit_test_setup(scratch_encode_should_encode_reserved_chars,
                               reset_test),
        cmocka_unit_test_setup(scratch_encode_should_preserve_commas, reset_test),
        cmocka_unit_test_setup(scratch_encode_should_pass_unreserved, reset_test),
        cmocka_unit_test_setup(scratch_encode_should_reject_null_args, reset_test),
        cmocka_unit_test_setup(scratch_encode_should_fail_when_scratch_full,
                               reset_test),

        /* pnsdk */
        cmocka_unit_test_setup(pnsdk_should_add_pnsdk_param, reset_test),
        cmocka_unit_test_setup(pnsdk_should_delegate_poll_to_next, reset_test),
        cmocka_unit_test_setup(pnsdk_should_delegate_cancel_to_next, reset_test),
        cmocka_unit_test_setup(pnsdk_should_append_suffix_when_set, reset_test),
        cmocka_unit_test_setup(pnsdk_should_skip_suffix_when_null, reset_test),
        cmocka_unit_test_setup(pnsdk_should_handle_empty_suffix, reset_test),
        cmocka_unit_test_setup(pnsdk_override_should_replace_base, reset_test),
        cmocka_unit_test_setup(pnsdk_override_plus_suffix, reset_test),
        cmocka_unit_test_setup(pnsdk_empty_override_should_fall_back_to_default,
                               reset_test),
        cmocka_unit_test_setup(pnsdk_null_override_with_suffix_regression, reset_test),

        /* userid */
        cmocka_unit_test_setup(userid_should_add_uuid_param, reset_test),
        cmocka_unit_test_setup(user_id_should_see_runtime_id_change, reset_test),

        /* auth */
        cmocka_unit_test_setup(auth_should_add_auth_param_when_token_set, reset_test),
        cmocka_unit_test_setup(auth_should_skip_when_token_is_null, reset_test),
        cmocka_unit_test_setup(auth_should_skip_when_token_ptr_is_null, reset_test),
        cmocka_unit_test_setup(auth_should_see_runtime_token_change, reset_test),
        cmocka_unit_test_setup(auth_should_percent_encode_slash_in_token, reset_test),

#if PUBNUB_ENABLE_PAM
        /* signature */
        cmocka_unit_test_setup(signature_should_passthrough_when_secret_null,
                               reset_test),
        cmocka_unit_test_setup(signature_should_passthrough_when_publish_key_null,
                               reset_test),
        cmocka_unit_test_setup(signature_should_passthrough_when_crypto_null,
                               reset_test),
        cmocka_unit_test_setup(
            signature_should_append_signature_param_when_signing, reset_test),
        cmocka_unit_test_setup(signature_should_sort_query_params_before_signing,
                               reset_test),
        cmocka_unit_test_setup(signature_should_include_body_in_canonical_string,
                               reset_test),
        cmocka_unit_test_setup(signature_should_observe_runtime_secret_change,
                               reset_test),
        cmocka_unit_test_setup(signature_should_fail_when_hmac_returns_error,
                               reset_test),
        cmocka_unit_test_setup(signature_should_fail_when_allocator_returns_null,
                               reset_test),
        cmocka_unit_test_setup(signature_should_delegate_poll_to_next, reset_test),
        cmocka_unit_test_setup(signature_should_delegate_cancel_to_next, reset_test),
#endif

        /* init argument validation */
        cmocka_unit_test_setup(pnsdk_init_should_be_safe_with_null_mw, reset_test),
        cmocka_unit_test_setup(
            pnsdk_init_should_leave_struct_unmodified_on_null_next, reset_test),
        cmocka_unit_test_setup(pnsdk_init_should_succeed_with_null_suffix, reset_test),
        cmocka_unit_test_setup(userid_init_should_be_safe_with_null_mw, reset_test),
        cmocka_unit_test_setup(
            userid_init_should_leave_struct_unmodified_on_null_next, reset_test),
        cmocka_unit_test_setup(userid_init_should_reject_null_user_id, reset_test),
        cmocka_unit_test_setup(auth_init_should_be_safe_with_null_mw, reset_test),
        cmocka_unit_test_setup(
            auth_init_should_leave_struct_unmodified_on_null_next, reset_test),
        cmocka_unit_test_setup(auth_init_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(auth_init_should_accept_null_auth_token, reset_test),
#if PUBNUB_ENABLE_PAM
        cmocka_unit_test_setup(signature_init_should_be_safe_with_null_mw, reset_test),
        cmocka_unit_test_setup(
            signature_init_should_leave_struct_unmodified_on_null_next, reset_test),
#endif

        /* _create() argument validation */
        cmocka_unit_test_setup(pnsdk_create_should_reject_null_next, reset_test),
        cmocka_unit_test_setup(pnsdk_create_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(userid_create_should_reject_null_user_id, reset_test),
        cmocka_unit_test_setup(userid_create_should_reject_null_next, reset_test),
        cmocka_unit_test_setup(userid_create_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(auth_create_should_accept_null_auth_token, reset_test),
        cmocka_unit_test_setup(auth_create_should_reject_null_next, reset_test),
        cmocka_unit_test_setup(auth_create_should_reject_null_allocator, reset_test),
#if PUBNUB_ENABLE_PAM
        cmocka_unit_test_setup(signature_create_should_reject_null_next, reset_test),
        cmocka_unit_test_setup(signature_create_should_reject_null_allocator,
                               reset_test),
#endif

        /* defensive: broken chain (mw->next == NULL) */
        cmocka_unit_test_setup(send_should_fail_when_next_is_null, reset_test),
        cmocka_unit_test_setup(poll_should_return_error_when_next_is_null, reset_test),
        cmocka_unit_test_setup(cancel_should_be_safe_when_next_is_null, reset_test),

        /* scratch exhaustion */
        cmocka_unit_test_setup(pnsdk_should_fail_when_scratch_exhausted, reset_test),
        cmocka_unit_test_setup(userid_should_fail_when_scratch_exhausted, reset_test),
        cmocka_unit_test_setup(auth_should_fail_when_scratch_exhausted, reset_test),
        cmocka_unit_test_setup(
            auth_should_not_fail_on_scratch_exhaustion_when_no_token, reset_test),

        /* chain composition */
        cmocka_unit_test_setup(chain_should_compose_all_params, reset_test),
        cmocka_unit_test_setup(chain_should_work_without_auth, reset_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
