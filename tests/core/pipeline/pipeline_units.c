/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pipeline_units.c
 * @brief Unit tests for pn_pipeline_t,
 * pn_pipeline_prepare_pubnub_middlewares(), and pn_request_dispatch().
 *
 * Tests use a mock transport and a tracking allocator to verify:
 *   - pn_pipeline_prepare_pubnub_middlewares() wraps the SDK's four canonical
 *     middlewares (signature, userid, pnsdk, auth) and delegates
 *     to pn_pipeline_init().
 *   - pn_pipeline_init() is a pure container: it stores a pre-built
 *     chain and never imports a middleware type. Input-validation
 *     branches are covered at this layer.
 *   - pn_request_dispatch() routes pre-built requests through the
 *     chain head to the mock transport.
 *   - All enrichment is applied before the transport sees the
 *     request (pnsdk, uuid, auth, and -- when secret_key is set --
 *     signature query params all present).
 *   - Immediate-failure paths transition the request to FAILED and
 *     invoke the callback.
 *   - pn_pipeline_deinit() frees every owned middleware via the
 *     allocator.
 *   - Allocation failure during build_default is rolled back cleanly.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/pipeline_internal.h"

/* ======================================================================== */
/* Tracking allocator mock                                                  */
/* ======================================================================== */

static int s_alloc_count;
static int s_free_count;
static int s_alloc_fail_after; /* <= 0 disables; N succeeds N times then fails */

static void* tracking_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    if (s_alloc_fail_after > 0) {
        if (s_alloc_count >= s_alloc_fail_after) {
            return NULL;
        }
    }
    void* p = malloc(size);
    if (NULL != p) {
        s_alloc_count++;
    }
    return p;
}

static void tracking_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    if (NULL != ptr) {
        s_free_count++;
        free(ptr);
    }
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = tracking_alloc,
    .realloc     = NULL,
    .free        = tracking_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

/* No-op destroy used by tests that pass fake (stack-allocated) layer
 * pointers and therefore must not be freed. */
static void noop_destroy(pubnub_transport_provider_t* mw,
                         pubnub_allocator_provider_t* allocator)
{
    (void)mw;
    (void)allocator;
}

/* ======================================================================== */
/* Mock transport: records the request and returns a canned handle          */
/* ======================================================================== */

static pubnub_http_request_t s_captured_request;
static int                   s_send_called;
static int                   s_send_fake_success;
static int                   s_fake_handle_storage;

/** Deep-copy buffer for query param views captured during mock_send.
 *  Middlewares may free heap-encoded buffers after send returns. */
static char   s_captured_param_buf[2048];
static size_t s_captured_param_buf_used;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)self;
    s_send_called             = 1;
    s_captured_request        = *request;
    s_captured_param_buf_used = 0;

    /* Deep-copy query param views into stable storage. */
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

    if (!s_send_fake_success) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }
    return (pubnub_transport_handle_t*)&s_fake_handle_storage;
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
/* Mock crypto provider (records hmac_sha256 inputs, returns canned digest) */
/* ======================================================================== */

static int     s_hmac_called;
static uint8_t s_hmac_last_data[512];
static size_t  s_hmac_last_data_len;
static uint8_t s_hmac_last_key[64];
static size_t  s_hmac_last_key_len;

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
    /* Canned 32-byte digest, deterministic for assertions. */
    for (size_t i = 0; i < 32; i++) {
        output[i] = (uint8_t)(0xA0 + (i & 0x0F));
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

/* Mock platform: monotonic_ms returns a boot-relative value for
 * timeouts; wall_clock_ms returns a fixed Unix-epoch-anchored value
 * for PAM signing determinism.  1700000000000 ms == 1700000000 s. */
static pubnub_milliseconds_t mock_monotonic_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return UINT64_C(1700000000000);
}

static pubnub_milliseconds_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return UINT64_C(1700000000000);
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic_ms,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = NULL,
    .random_bytes  = NULL,
    .secure_zero   = NULL,
};

/* ======================================================================== */
/* Completion callback tracking                                              */
/* ======================================================================== */

static int          s_cb_invoked;
static pubnub_res_t s_cb_status;

static void completion_cb(pn_request_t* request, pubnub_res_t status, void* user_data)
{
    (void)request;
    (void)user_data;
    s_cb_invoked = 1;
    s_cb_status  = status;
}

/* ======================================================================== */
/* Test fixture                                                              */
/* ======================================================================== */

static int reset_test(void** state)
{
    (void)state;
    memset(&s_captured_request, 0, sizeof(s_captured_request));
    s_send_called        = 0;
    s_send_fake_success  = 1;
    s_cb_invoked         = 0;
    s_cb_status          = PUBNUB_OK;
    s_alloc_count        = 0;
    s_free_count         = 0;
    s_alloc_fail_after   = 0;
    s_hmac_called        = 0;
    s_hmac_last_data_len = 0;
    s_hmac_last_key_len  = 0;
    memset(s_hmac_last_data, 0, sizeof(s_hmac_last_data));
    memset(s_hmac_last_key, 0, sizeof(s_hmac_last_key));
    return 0;
}

/**
 * @brief Initialize the pipeline with signing disabled (no secret_key).
 *
 * Most pre-signature tests exercise the pipeline without signing; the
 * signature layer is still added to the chain but stays in
 * passthrough mode.
 */
static pubnub_res_t init_default_pipeline(pn_pipeline_t*     pipeline,
                                          const char* const* auth_token)
{
    static const char* user_id = "user-42";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &user_id,
        .auth_token   = auth_token,
        .pnsdk_suffix = NULL,
        .publish_key  = NULL,
        .secret_key   = NULL,
        .crypto       = NULL,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    return pn_pipeline_prepare_pubnub_middlewares(pipeline, &opts);
}

/**
 * @brief Build a PENDING request with a completion callback.
 */
static void build_pending_request(pn_request_t* req, void* user_data)
{
    pn_request_init(req, 0);
    req->on_complete = completion_cb;
    req->user_data   = user_data;
    pn_request_enqueue(req);
}

/**
 * @brief Find a query parameter by key in the captured request.
 */
static const pubnub_string_view_t* find_query_param(const char* key)
{
    size_t key_len = strlen(key);
    for (unsigned int i = 0; i < s_captured_request.query_param_count; i++) {
        if (s_captured_request.query_params[i].key.len == key_len
            && memcmp(s_captured_request.query_params[i].key.ptr, key, key_len)
                   == 0) {
            return &s_captured_request.query_params[i].value;
        }
    }
    return NULL;
}

/* ======================================================================== */
/* Tests: pn_pipeline_prepare_pubnub_middlewares */
/*                                                                           */
/* This is the convenience builder that wraps the SDK's four canonical       */
/* middlewares and then delegates to pn_pipeline_init(). The lower-level    */
/* pn_pipeline_init() tests are in their own section below.                  */
/* ======================================================================== */

static void prepare_pubnub_middlewares_should_allocate_three_without_secret(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";

    pubnub_res_t rc = init_default_pipeline(&sut, &token);

    int expected = 3 + PUBNUB_ENABLE_REQUEST_COMPRESSION;

    assert_int_equal(rc, PUBNUB_OK);
    /* auth + pnsdk + userid + [compression] (no signature — secret_key is NULL) */
    assert_int_equal(s_alloc_count, expected);
    assert_int_equal(sut.owned_count, expected);
    assert_non_null(sut.chain_head);
    assert_ptr_equal(sut.allocator, &s_mock_allocator);

    /* chain_head is the outermost (last) owned entry. */
    assert_ptr_equal(sut.chain_head, sut.owned[expected - 1].layer);

    pn_pipeline_deinit(&sut);
}

#if PUBNUB_ENABLE_PAM
static void prepare_pubnub_middlewares_should_allocate_four_with_secret(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token  = "tok";
    const char*   uid    = "u";
    const char*   secret = "s";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &uid,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = "p",
        .secret_key   = &secret,
        .crypto       = &s_mock_crypto,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);

    int expected = 4 + PUBNUB_ENABLE_REQUEST_COMPRESSION;

    assert_int_equal(rc, PUBNUB_OK);
    /* auth + pnsdk + userid + signature + [compression] */
    assert_int_equal(s_alloc_count, expected);
    assert_int_equal(sut.owned_count, expected);
    assert_non_null(sut.chain_head);

    /* chain_head is the outermost (last) owned entry. */
    assert_ptr_equal(sut.chain_head, sut.owned[expected - 1].layer);

    pn_pipeline_deinit(&sut);
}
#endif /* PUBNUB_ENABLE_PAM */

static void prepare_pubnub_middlewares_should_reject_null_pipeline(void** state)
{
    (void)state;
    const char* token = "tok";

    pubnub_res_t rc = init_default_pipeline(NULL, &token);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void prepare_pubnub_middlewares_should_reject_null_user_id(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = NULL,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = NULL,
        .secret_key   = NULL,
        .crypto       = NULL,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(s_alloc_count, 0);
}

static void prepare_pubnub_middlewares_should_reject_null_allocator(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token   = "tok";
    const char*   user_id = "user-42";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &user_id,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = NULL,
        .secret_key   = NULL,
        .crypto       = NULL,
        .allocator    = NULL,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void prepare_pubnub_middlewares_should_reject_null_transport(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token   = "tok";
    const char*   user_id = "user-42";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &user_id,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = NULL,
        .secret_key   = NULL,
        .crypto       = NULL,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = NULL,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void prepare_pubnub_middlewares_should_accept_null_auth_token(void** state)
{
    (void)state;
    pn_pipeline_t sut;

    pubnub_res_t rc = init_default_pipeline(&sut, NULL);

    /* Auth token is optional (means "no auth configured"). */
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(sut.chain_head);

    pn_pipeline_deinit(&sut);
}

static void prepare_pubnub_middlewares_should_rollback_on_allocation_failure(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";
    /* userid + pnsdk succeed; auth allocation fails (no signature
     * because secret_key is NULL in init_default_pipeline). */
    s_alloc_fail_after = 2;

    pubnub_res_t rc = init_default_pipeline(&sut, &token);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    /* Two successful allocations must be rolled back. */
    assert_int_equal(s_alloc_count, 2);
    assert_int_equal(s_free_count, 2);
}

/* ======================================================================== */
/* Tests: pn_pipeline_init (low-level container)                             */
/*                                                                           */
/* Stores a pre-built chain; does not touch any middleware type. These      */
/* tests build the chain manually to prove the decoupling and to cover the   */
/* input-validation branches that can only be triggered at this layer.      */
/* ======================================================================== */

static void init_should_store_prebuilt_chain(void** state)
{
    (void)state;
    /* Three fake layers -- identity pointers, we only need to check
     * that the pipeline stores them and frees them in reverse. */
    int                          fake_a, fake_b, fake_c;
    pubnub_transport_provider_t* layers[3] = {
        (pubnub_transport_provider_t*)&fake_a,
        (pubnub_transport_provider_t*)&fake_b,
        (pubnub_transport_provider_t*)&fake_c,
    };
    pn_middleware_destroy_fn_t destroys[3] = {
        noop_destroy,
        noop_destroy,
        noop_destroy,
    };
    pn_pipeline_t sut;
    memset(&sut, 0, sizeof(sut));

    pubnub_res_t rc =
        pn_pipeline_init(&sut, layers[2], layers, destroys, 3, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_OK);
    assert_ptr_equal(sut.chain_head, layers[2]);
    assert_int_equal(sut.owned_count, 3);
    assert_ptr_equal(sut.owned[0].layer, layers[0]);
    assert_ptr_equal(sut.owned[1].layer, layers[1]);
    assert_ptr_equal(sut.owned[2].layer, layers[2]);
    /* pn_pipeline_init itself must not allocate. */
    assert_int_equal(s_alloc_count, 0);
}

static void init_should_reject_null_pipeline(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};

    pubnub_res_t rc =
        pn_pipeline_init(NULL, layers[0], layers, destroys, 1, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_chain_head(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc =
        pn_pipeline_init(&sut, NULL, layers, destroys, 1, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_layers(void** state)
{
    (void)state;
    int                        fake;
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc = pn_pipeline_init(
        &sut, (pubnub_transport_provider_t*)&fake, NULL, destroys, 1, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_destroys(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_pipeline_t sut;

    pubnub_res_t rc =
        pn_pipeline_init(&sut, layers[0], layers, NULL, 1, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_allocator(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc = pn_pipeline_init(&sut, layers[0], layers, destroys, 1, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_zero_layer_count(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc =
        pn_pipeline_init(&sut, layers[0], layers, destroys, 0, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_layer_count_over_max(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[1] = {
        (pubnub_transport_provider_t*)&fake,
    };
    pn_middleware_destroy_fn_t destroys[1] = {noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc = pn_pipeline_init(&sut,
                                       layers[0],
                                       layers,
                                       destroys,
                                       PUBNUB_CFG_PIPELINE_MAX_MIDDLEWARES + 1,
                                       &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_entry_in_layers(void** state)
{
    (void)state;
    int                          fake;
    pubnub_transport_provider_t* layers[2] = {
        (pubnub_transport_provider_t*)&fake,
        NULL,
    };
    pn_middleware_destroy_fn_t destroys[2] = {noop_destroy, noop_destroy};
    pn_pipeline_t              sut;

    pubnub_res_t rc =
        pn_pipeline_init(&sut, layers[0], layers, destroys, 2, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_entry_in_destroys(void** state)
{
    (void)state;
    int                          fake_a, fake_b;
    pubnub_transport_provider_t* layers[2] = {
        (pubnub_transport_provider_t*)&fake_a,
        (pubnub_transport_provider_t*)&fake_b,
    };
    pn_middleware_destroy_fn_t destroys[2] = {noop_destroy, NULL};
    pn_pipeline_t              sut;

    pubnub_res_t rc =
        pn_pipeline_init(&sut, layers[0], layers, destroys, 2, &s_mock_allocator);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* Tests: pn_pipeline_deinit                                                 */
/* ======================================================================== */

static void deinit_should_free_every_owned_middleware(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token    = "tok";
    int           expected = 3 + PUBNUB_ENABLE_REQUEST_COMPRESSION;

    init_default_pipeline(&sut, &token);
    assert_int_equal(s_alloc_count, expected);

    pn_pipeline_deinit(&sut);

    assert_int_equal(s_free_count, expected);
    assert_null(sut.chain_head);
    assert_int_equal(sut.owned_count, 0);
}

static void deinit_should_be_safe_on_zero_initialized_pipeline(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    memset(&sut, 0, sizeof(sut));

    /* Must not crash. */
    pn_pipeline_deinit(&sut);
}

static void deinit_should_be_safe_on_null(void** state)
{
    (void)state;

    pn_pipeline_deinit(NULL);
}

/* ======================================================================== */
/* Tests: pn_request_dispatch -- happy path                                  */
/* ======================================================================== */

static void dispatch_should_run_full_chain_with_auth(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok-abc";
    init_default_pipeline(&sut, &token);

    pn_request_t req;
    build_pending_request(&req, NULL);

    pubnub_res_t rc = pn_request_dispatch(&sut, &req, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.state, PN_REQUEST_IN_FLIGHT);
    assert_true(s_send_called);

    /* All enrichment middlewares touched the request before
     * transport. No signature — secret_key is NULL. */
    assert_non_null(find_query_param("pnsdk"));
    assert_non_null(find_query_param("uuid"));
    assert_non_null(find_query_param("auth"));
    assert_null(find_query_param("signature"));

    pn_pipeline_deinit(&sut);
}

static void dispatch_should_skip_auth_when_token_absent(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    init_default_pipeline(&sut, NULL);

    pn_request_t req;
    build_pending_request(&req, NULL);

    pubnub_res_t rc = pn_request_dispatch(&sut, &req, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(s_send_called);

    assert_non_null(find_query_param("pnsdk"));
    assert_non_null(find_query_param("uuid"));
    assert_null(find_query_param("auth"));

    pn_pipeline_deinit(&sut);
}

static void dispatch_should_observe_runtime_auth_token_change(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = NULL;
    init_default_pipeline(&sut, &token);

    pn_request_t req1;
    build_pending_request(&req1, NULL);
    pn_request_dispatch(&sut, &req1, NULL);
    assert_null(find_query_param("auth"));

    /* Runtime swap. */
    token = "late-token";
    reset_test(NULL);
    pn_request_t req2;
    build_pending_request(&req2, NULL);
    pn_request_dispatch(&sut, &req2, NULL);

    const pubnub_string_view_t* auth_val = find_query_param("auth");
    assert_non_null(auth_val);
    assert_int_equal(auth_val->len, strlen("late-token"));
    assert_memory_equal(auth_val->ptr, "late-token", auth_val->len);

    pn_pipeline_deinit(&sut);
}

#if PUBNUB_ENABLE_PAM
/* ======================================================================== */
/* Tests: pn_request_dispatch -- signing                                     */
/* ======================================================================== */

static void dispatch_should_append_signature_when_secret_key_set(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    /* Short token/secret/user keep us under the default 96-byte
     * scratch when the chain emits auth, pnsdk, uuid, and the 46-
     * byte signature=v2.<base64url-43> value. */
    const char* uid    = "u";
    const char* token  = "t";
    const char* secret = "s";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &uid,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = "p",
        .secret_key   = &secret,
        .crypto       = &s_mock_crypto,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t req;
    build_pending_request(&req, NULL);

    rc = pn_request_dispatch(&sut, &req, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(s_hmac_called);

    /* HMAC key must be the secret string (verbatim). */
    assert_int_equal(s_hmac_last_key_len, strlen(secret));
    assert_memory_equal(s_hmac_last_key, secret, s_hmac_last_key_len);

    /* Canonical string starts with "GET\np\n" for the default
     * PUBNUB_HTTP_GET method and publish_key="p"; proves the
     * signing middleware picked up the publish_key we passed in. */
    const char* expected_prefix = "GET\np\n";
    assert_true(s_hmac_last_data_len >= strlen(expected_prefix));
    assert_memory_equal(s_hmac_last_data, expected_prefix, strlen(expected_prefix));

    /* The middleware must append `signature=v2.<...>` as a query param.
     * Exact length: 3 (`v2.`) + 43 (base64url of a 32-byte HMAC with
     * no padding) = 46 bytes. Pinning the length catches a regression
     * in either the canonical string length or the encoder. */
    const pubnub_string_view_t* sig = find_query_param("signature");
    assert_non_null(sig);
    assert_int_equal(sig->len, 46);
    assert_memory_equal(sig->ptr, "v2.", 3);

    pn_pipeline_deinit(&sut);
}

static void dispatch_should_sort_query_params_before_signing(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   uid    = "u";
    const char*   token  = "t";
    const char*   secret = "s";

    const pn_pipeline_prepare_opts_t opts = {
        .user_id      = &uid,
        .auth_token   = &token,
        .pnsdk_suffix = NULL,
        .publish_key  = "p",
        .secret_key   = &secret,
        .crypto       = &s_mock_crypto,
        .allocator    = &s_mock_allocator,
        .platform     = &s_mock_platform,
        .transport    = &s_mock_transport,
        .retry_config = NULL,
    };
    pubnub_res_t rc = pn_pipeline_prepare_pubnub_middlewares(&sut, &opts);
    assert_int_equal(rc, PUBNUB_OK);

    pn_request_t req;
    build_pending_request(&req, NULL);

    pn_request_dispatch(&sut, &req, NULL);

    /* After sorting, query order must be alphabetical: auth, pnsdk,
     * timestamp, uuid (the signature param itself is appended last
     * and is NOT included in the pre-signing sort; timestamp is
     * inserted by the signature middleware before sort and therefore
     * participates in the alphabetical ordering). */
    assert_true(s_captured_request.query_param_count >= 5);
    const char* expected_order[] = {"auth", "pnsdk", "timestamp", "uuid", "signature"};
    for (size_t i = 0; i < sizeof(expected_order) / sizeof(expected_order[0]); i++) {
        size_t exp_len = strlen(expected_order[i]);
        assert_int_equal(s_captured_request.query_params[i].key.len, exp_len);
        assert_memory_equal(s_captured_request.query_params[i].key.ptr,
                            expected_order[i],
                            exp_len);
    }

    pn_pipeline_deinit(&sut);
}
#endif /* PUBNUB_ENABLE_PAM */

/* ======================================================================== */
/* Tests: pn_request_dispatch -- argument validation                         */
/* ======================================================================== */

static void dispatch_should_reject_null_pipeline(void** state)
{
    (void)state;
    pn_request_t req;
    build_pending_request(&req, NULL);

    pubnub_res_t rc = pn_request_dispatch(NULL, &req, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(req.state, PN_REQUEST_PENDING);
}

static void dispatch_should_reject_null_request(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";
    init_default_pipeline(&sut, &token);

    pubnub_res_t rc = pn_request_dispatch(&sut, NULL, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);

    pn_pipeline_deinit(&sut);
}

static void dispatch_should_reject_idle_request(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";
    init_default_pipeline(&sut, &token);
    pn_request_t req;
    pn_request_init(&req, 0); /* IDLE, not PENDING */

    pubnub_res_t rc = pn_request_dispatch(&sut, &req, NULL);

    assert_int_equal(rc, PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(req.state, PN_REQUEST_IDLE);
    assert_false(s_send_called);

    pn_pipeline_deinit(&sut);
}

/* ======================================================================== */
/* Tests: pn_request_dispatch -- failure paths                               */
/* ======================================================================== */

static void dispatch_should_transition_to_failed_on_transport_reject(void** state)
{
    (void)state;
    pn_pipeline_t sut;
    const char*   token = "tok";
    init_default_pipeline(&sut, &token);
    pn_request_t req;
    build_pending_request(&req, NULL);
    s_send_fake_success = 0; /* Transport returns NULL. */

    pubnub_res_t rc = pn_request_dispatch(&sut, &req, NULL);

    assert_int_equal(rc, PUBNUB_ERR_TRANSPORT);
    /* Slot enters COMPLETING (callback pending delivery outside lock). */
    assert_int_equal(req.state, PN_REQUEST_COMPLETING);
    assert_int_equal(req.result, PUBNUB_ERR_TRANSPORT);
    assert_false(s_cb_invoked);
    assert_null(req.transport_handle);

    /* Deliver the notification (normally done by pubnub_process). */
    pn_request_deliver_notification(&req);

    assert_int_equal(req.state, PN_REQUEST_FAILED);
    assert_true(s_cb_invoked);
    assert_int_equal(s_cb_status, PUBNUB_ERR_TRANSPORT);

    pn_pipeline_deinit(&sut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* pn_pipeline_prepare_pubnub_middlewares */
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_allocate_three_without_secret,
            reset_test),
#if PUBNUB_ENABLE_PAM
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_allocate_four_with_secret, reset_test),
#endif
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_reject_null_pipeline, reset_test),
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_reject_null_user_id, reset_test),
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_reject_null_transport, reset_test),
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_accept_null_auth_token, reset_test),
        cmocka_unit_test_setup(
            prepare_pubnub_middlewares_should_rollback_on_allocation_failure,
            reset_test),

        /* pn_pipeline_init (low-level container) */
        cmocka_unit_test_setup(init_should_store_prebuilt_chain, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_pipeline, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_chain_head, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_layers, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_destroys, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_allocator, reset_test),
        cmocka_unit_test_setup(init_should_reject_zero_layer_count, reset_test),
        cmocka_unit_test_setup(init_should_reject_layer_count_over_max, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_entry_in_layers, reset_test),
        cmocka_unit_test_setup(init_should_reject_null_entry_in_destroys, reset_test),

        /* deinit */
        cmocka_unit_test_setup(deinit_should_free_every_owned_middleware, reset_test),
        cmocka_unit_test_setup(deinit_should_be_safe_on_zero_initialized_pipeline,
                               reset_test),
        cmocka_unit_test_setup(deinit_should_be_safe_on_null, reset_test),

        /* dispatch: happy path */
        cmocka_unit_test_setup(dispatch_should_run_full_chain_with_auth, reset_test),
        cmocka_unit_test_setup(dispatch_should_skip_auth_when_token_absent,
                               reset_test),
        cmocka_unit_test_setup(dispatch_should_observe_runtime_auth_token_change,
                               reset_test),

#if PUBNUB_ENABLE_PAM
        /* dispatch: signing */
        cmocka_unit_test_setup(
            dispatch_should_append_signature_when_secret_key_set, reset_test),
        cmocka_unit_test_setup(dispatch_should_sort_query_params_before_signing,
                               reset_test),
#endif

        /* dispatch: arg validation */
        cmocka_unit_test_setup(dispatch_should_reject_null_pipeline, reset_test),
        cmocka_unit_test_setup(dispatch_should_reject_null_request, reset_test),
        cmocka_unit_test_setup(dispatch_should_reject_idle_request, reset_test),

        /* dispatch: failure propagation */
        cmocka_unit_test_setup(
            dispatch_should_transition_to_failed_on_transport_reject, reset_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
