/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file client_units.c
 * @brief Unit tests for client lifecycle: create/destroy, init/deinit,
 *        config validation, provider resolution, provider init rollback,
 *        cooperative loop, and error string mapping.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/capabilities.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/time.h"
#include "pubnub/future.h"
#include "pubnub/types.h"
#include "config_internal.h"
#include "core/core_internal.h"
#include "core/pn_crypto_module.h"
#include "core/runtime/pending_queue_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "pubnub/future.h"

/* ======================================================================== */
/* Forward declarations: mock providers, helpers, tracking callbacks         */
/*                                                                          */
/* Implementations are at the bottom of this file.                          */
/* ======================================================================== */

/* Mock provider instances (valid no-op implementations). */
static pubnub_allocator_provider_t     s_mock_allocator;
static pubnub_transport_provider_t     s_mock_transport;
static pubnub_transport_provider_t     s_chain_transport;
static pubnub_allocator_provider_t     s_oom_allocator;
static pubnub_serialization_provider_t s_mock_serialization;
static pubnub_platform_provider_t      s_mock_platform;
static pubnub_crypto_provider_t        s_mock_crypto;

/* Chain-tracking transport capture state (defined below). */
static pubnub_http_request_t s_chain_captured_request;
static int                   s_chain_send_called;
static int                   s_chain_complete_in_send;
static int                   s_chain_error_in_send;
static int                   s_chain_send_returns_null;
static int                   s_chain_poll_called;
static int                   s_chain_poll_last_timeout;

/* OOM-after-N allocator state (defined below). */
static int s_oom_alloc_count;
static int s_oom_alloc_fail_after;

/* Deinit sequence tracking. */
static int s_deinit_sequence;
static int s_transport_deinit_seq;
static int s_serial_deinit_seq;
static int s_crypto_deinit_seq;

static void tracking_transport_deinit(pubnub_transport_provider_t* self);
static void tracking_serial_deinit(pubnub_serialization_provider_t* self);
static void tracking_crypto_deinit(pubnub_crypto_provider_t* self);
static int  reset_tracking(void** state);

/* Failing init callbacks for rollback tests. */
static int failing_transport_init(pubnub_transport_provider_t*  self,
                                  const pubnub_provider_deps_t* deps);
static int failing_serial_init(pubnub_serialization_provider_t* self,
                               const pubnub_provider_deps_t*    deps);
#if PUBNUB_ENABLE_CRYPTO
static int failing_cryptor_init(pubnub_crypto_provider_t*     self,
                                const pubnub_provider_deps_t* deps);

/* Tracking init/deinit callbacks for cryptor lifecycle tests. */
static int  s_cryptor_init_count;
static int  s_cryptor_deinit_count;
static int  tracking_cryptor_init(pubnub_crypto_provider_t*     self,
                                  const pubnub_provider_deps_t* deps);
static void tracking_cryptor_deinit_count(pubnub_crypto_provider_t* self);
#endif

/* Failing allocator for OOM tests. */
static void* failing_alloc(pubnub_allocator_provider_t* self,
                           size_t                       size,
                           size_t                       align);

/* Test helpers. */
static pubnub_config_t   valid_config(void);
static pubnub_context_t* alloc_test_context(void);
static void              free_test_context(pubnub_context_t* ctx);

/* Pipeline-integration tracking transport helpers (defined below). */
static void                        reset_chain_capture(void);
static const pubnub_string_view_t* find_captured_param(const char* key);
static void                        chain_mark_complete(int status_code);
static pubnub_config_t             valid_config_with_chain_transport(void);
static void                        chain_mark_error(void);
static pubnub_config_t             valid_config_with_chain_transport(void);

/* ======================================================================== */
/* Tests: pubnub_config_defaults()                                           */
/* ======================================================================== */

static void config_default_should_have_null_keys_and_valid_tunables(void** state)
{
    (void)state;
    pubnub_config_t cfg = pubnub_config_defaults();

    assert_null(cfg.subscribe_key);
    assert_null(cfg.publish_key);
    assert_null(cfg.secret_key);
    assert_null(cfg.user_id);
    assert_null(cfg.auth_token);
    assert_null(cfg.origin);
    assert_int_equal(cfg.transaction_timeout_ms, PUBNUB_CFG_TRANSACTION_TIMEOUT_MS);
#ifdef PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS
    assert_int_equal(cfg.non_transaction_timeout_ms,
                     PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS);
#else
    assert_int_equal(cfg.non_transaction_timeout_ms, 0);
#endif
    assert_null(cfg.allocator);
    assert_null(cfg.transport);
    assert_null(cfg.serialization);
    assert_null(cfg.platform);
    assert_null(cfg.crypto_module);
    assert_null(cfg.logger);
}

/* ======================================================================== */
/* Tests: pubnub_context_size()                                             */
/* ======================================================================== */

static void context_size_should_return_nonzero(void** state)
{
    (void)state;
    size_t sz = pubnub_context_size();
    assert_true(sz > 0);
    assert_true(sz >= sizeof(void*));
}

/* ======================================================================== */
/* Tests: config validation (via pubnub_init)                               */
/* ======================================================================== */

static void init_should_reject_null_context(void** state)
{
    (void)state;
    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(NULL, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void init_should_reject_null_config(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    assert_int_equal(pubnub_init(ctx, NULL), PUBNUB_ERR_INVALID_ARGUMENT);

    free_test_context(ctx);
}

static void init_should_reject_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.subscribe_key   = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);

    free_test_context(ctx);
}

static void init_should_reject_empty_subscribe_key(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.subscribe_key   = "";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);

    free_test_context(ctx);
}

static void init_should_reject_null_user_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.user_id         = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);

    free_test_context(ctx);
}

static void init_should_reject_empty_user_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.user_id         = "";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);

    free_test_context(ctx);
}

static void init_should_apply_default_when_timeouts_are_zero(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg            = valid_config();
    cfg.transaction_timeout_ms     = 0;
    cfg.non_transaction_timeout_ms = 0;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* After init, zero-valued timeouts must be replaced by the
     * compile-time defaults. */
    const pubnub_config_t* resolved = pn_context_config(ctx);
    assert_non_null(resolved);
    assert_int_equal(resolved->transaction_timeout_ms,
                     PUBNUB_CFG_TRANSACTION_TIMEOUT_MS);
#ifdef PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS
    assert_int_equal(resolved->non_transaction_timeout_ms,
                     PUBNUB_CFG_NON_TRANSACTION_TIMEOUT_MS);
#else
    assert_int_equal(resolved->non_transaction_timeout_ms, 0);
#endif

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_accept_optional_publish_key(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.publish_key     = "pub-c-test";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_accept_optional_secret_key(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.secret_key      = "sec-c-test";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: origin resolution                                                  */
/* ======================================================================== */

static void init_should_resolve_null_origin_to_compile_time_default(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.origin          = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Value compare only: the macro expands to a string literal,
     * but linker-level merging of literals across translation
     * units is not guaranteed, so asserting pointer identity
     * would be brittle across compilers/platforms. */
    assert_non_null(ctx_cfg->origin);
    assert_string_equal(ctx_cfg->origin, PUBNUB_CFG_ORIGIN);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_resolve_empty_origin_to_compile_time_default(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.origin          = "";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    assert_non_null(ctx_cfg->origin);
    assert_string_equal(ctx_cfg->origin, PUBNUB_CFG_ORIGIN);
    /* Extra guard against the "still points at caller's ''" bug:
     * the resolved string must be non-empty. */
    assert_true(ctx_cfg->origin[0] != '\0');

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_honour_custom_origin(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    const char*     custom = "enterprise.example.pubnub.com";
    pubnub_config_t cfg    = valid_config();
    cfg.origin             = custom;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Origin is always copied into the context's internal buffer. */
    assert_string_equal(ctx_cfg->origin, custom);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pubnub_init() / pubnub_deinit() lifecycle                         */
/* ======================================================================== */

static void init_should_succeed_with_valid_config(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void deinit_should_accept_null_context(void** state)
{
    (void)state;

    pubnub_deinit(NULL);
}

static void deinit_should_accept_uninitialized_context(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_reject_double_init_without_deinit(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INVALID_ARGUMENT);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_succeed_after_deinit(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pubnub_create() / pubnub_destroy() (heap lifecycle)               */
/* ======================================================================== */

#if !PUBNUB_CFG_NO_HEAP

static void create_should_return_context_with_valid_config(void** state)
{
    (void)state;
    pubnub_config_t   cfg = valid_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_destroy(ctx);
}

static void create_should_return_null_for_null_config(void** state)
{
    (void)state;
    assert_null(pubnub_create(NULL));
}

static void create_should_return_null_for_invalid_config(void** state)
{
    (void)state;
    pubnub_config_t cfg = valid_config();
    cfg.subscribe_key   = NULL;
    assert_null(pubnub_create(&cfg));
}

static void destroy_should_accept_null_context(void** state)
{
    (void)state;

    pubnub_destroy(NULL);
}

static void create_should_return_null_when_allocation_fails(void** state)
{
    (void)state;
    pubnub_config_t             cfg       = valid_config();
    pubnub_allocator_provider_t oom_alloc = s_mock_allocator;
    oom_alloc.alloc                       = failing_alloc;
    cfg.allocator                         = &oom_alloc;
    assert_null(pubnub_create(&cfg));
}

static void create_should_deep_copy_custom_origin(void** state)
{
    (void)state;
    /* Mirrors the deep-copy contract for subscribe_key / publish_key
     * etc.: the caller must be free to overwrite or free the
     * original buffer after pubnub_create() returns without
     * corrupting the context's view of the config. */
    char caller_buf[64];
    strncpy(caller_buf, "enterprise.example.pubnub.com", sizeof(caller_buf) - 1);
    caller_buf[sizeof(caller_buf) - 1] = '\0';

    pubnub_config_t cfg = valid_config();
    cfg.origin          = caller_buf;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Pointer must have been dup'd, not aliased. */
    assert_ptr_not_equal(ctx_cfg->origin, caller_buf);
    assert_string_equal(ctx_cfg->origin, "enterprise.example.pubnub.com");

    /* Overwrite the caller's buffer; the context keeps its own copy. */
    memset(caller_buf, 'X', sizeof(caller_buf));
    assert_string_equal(ctx_cfg->origin, "enterprise.example.pubnub.com");

    pubnub_destroy(ctx);
}

static void create_should_deep_copy_filter_expression(void** state)
{
    (void)state;
    /* filter_expression is read at subscribe time (subscribe_effects),
     * long after pubnub_create() returns. The caller's string is heap
     * allocated and freed immediately after create: if pubnub_create
     * aliased it instead of dup'ing, the context would hold a dangling
     * pointer and the reads below would be a genuine use-after-free that
     * ASan flags on the freed heap region. */
    const char* const expected = "uuid == 'abc-123'";
    char*             caller   = malloc(strlen(expected) + 1);
    assert_non_null(caller);
    memcpy(caller, expected, strlen(expected) + 1);

    pubnub_config_t cfg   = valid_config();
    cfg.filter_expression = caller;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Simulate a caller freeing its config strings after create. */
    free(caller);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Pointer must have been dup'd, not aliased at the freed buffer. */
    assert_ptr_not_equal(ctx_cfg->filter_expression, caller);
    assert_string_equal(ctx_cfg->filter_expression, expected);

    pubnub_destroy(ctx);
}

static void init_should_borrow_filter_expression(void** state)
{
    (void)state;
    /* pubnub_init() is the caller-provided-lifetime path: config strings
     * are borrowed, not copied. The stored pointer must alias the
     * caller's buffer so that ownership stays with the caller. */
    pubnub_context_t* ctx = alloc_test_context();

    char caller_buf[64];
    strncpy(caller_buf, "channel == 'news'", sizeof(caller_buf) - 1);
    caller_buf[sizeof(caller_buf) - 1] = '\0';

    pubnub_config_t cfg   = valid_config();
    cfg.filter_expression = caller_buf;

    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Borrowed, not dup'd: pointer identity must be preserved. */
    assert_ptr_equal(ctx_cfg->filter_expression, caller_buf);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void create_should_deep_copy_resolved_default_origin(void** state)
{
    (void)state;
    /* NULL / empty origin is resolved to PUBNUB_CFG_ORIGIN
     * during init_common, and the resolved value is then dup'd so
     * pubnub_destroy can free every owns_config string uniformly
     * without ownership branching. */
    pubnub_config_t cfg = valid_config();
    cfg.origin          = NULL;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    const pubnub_config_t* ctx_cfg = pn_context_config(ctx);
    assert_non_null(ctx_cfg);
    /* Dup'd pointer -- NOT the macro's static literal. */
    assert_ptr_not_equal(ctx_cfg->origin, PUBNUB_CFG_ORIGIN);
    assert_string_equal(ctx_cfg->origin, PUBNUB_CFG_ORIGIN);

    pubnub_destroy(ctx);
}

static void create_should_deep_copy_user_id(void** state)
{
    (void)state;
    char caller_buf[64];
    strncpy(caller_buf, "my-user-id-to-copy", sizeof(caller_buf) - 1);
    caller_buf[sizeof(caller_buf) - 1] = '\0';

    pubnub_config_t cfg = valid_config_with_chain_transport();
    cfg.user_id         = caller_buf;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Clobber the caller's buffer to simulate freeing it. */
    memset(caller_buf, 'X', sizeof(caller_buf));

    /* Dispatch and verify the context still knows the original user_id. */
    reset_chain_capture();
    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* uuid = find_captured_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(uuid->len, strlen("my-user-id-to-copy"));
    assert_memory_equal(uuid->ptr, "my-user-id-to-copy", uuid->len);

    pubnub_destroy(ctx);
}

/* Fill @p buf with @p len printable characters plus a NUL terminator.
 * Caller must size @p buf to at least @p len + 1 bytes. */
static void fill_user_id(char* buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (char)('a' + (int)(i % 26));
    }
    buf[len] = '\0';
}

static void set_user_id_should_accept_224_char_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    char id[1001];
    fill_user_id(id, 224);
    assert_int_equal(PUBNUB_OK, pubnub_set_user_id(ctx, id));
    assert_string_equal(id, pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_should_accept_500_char_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    char id[1001];
    fill_user_id(id, 500);
    assert_int_equal(PUBNUB_OK, pubnub_set_user_id(ctx, id));
    assert_string_equal(id, pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_should_accept_1000_char_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    char id[1001];
    fill_user_id(id, 1000);
    /* There is no client-side length cap on user_id. */
    assert_int_equal(PUBNUB_OK, pubnub_set_user_id(ctx, id));
    assert_string_equal(id, pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_should_accept_single_char_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_user_id(ctx, "x"));
    assert_string_equal("x", pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_should_reject_null(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_set_user_id(ctx, NULL));
    /* The prior user_id must survive a rejected update. */
    assert_string_equal("test-user", pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_accept_long_user_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    char id[1001];
    fill_user_id(id, 500);
    pubnub_config_t cfg = valid_config();
    cfg.user_id         = id;
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));
    assert_string_equal(id, pubnub_get_user_id(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void create_should_deep_copy_long_user_id(void** state)
{
    (void)state;
    char id[1001];
    char expected[1001];
    fill_user_id(id, 1000);
    memcpy(expected, id, sizeof(id));

    pubnub_config_t cfg = valid_config_with_chain_transport();
    cfg.user_id         = id;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Clobber the caller buffer: a deep copy must have been made. */
    memset(id, 'X', sizeof(id));

    assert_string_equal(expected, pubnub_get_user_id(ctx));

    pubnub_destroy(ctx);
}

static void create_should_deep_copy_auth_token(void** state)
{
    (void)state;
    char caller_buf[64];
    strncpy(caller_buf, "my-secret-token", sizeof(caller_buf) - 1);
    caller_buf[sizeof(caller_buf) - 1] = '\0';

    pubnub_config_t cfg = valid_config_with_chain_transport();
    cfg.auth_token      = caller_buf;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Clobber the caller's buffer. */
    memset(caller_buf, 'X', sizeof(caller_buf));

    /* Dispatch and verify auth param still contains original token. */
    reset_chain_capture();
    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* auth = find_captured_param("auth");
    assert_non_null(auth);
    assert_int_equal(auth->len, strlen("my-secret-token"));
    assert_memory_equal(auth->ptr, "my-secret-token", auth->len);

    pubnub_destroy(ctx);
}

static void create_should_free_context_when_provider_init_fails(void** state)
{
    (void)state;
    pubnub_config_t             cfg     = valid_config();
    pubnub_transport_provider_t failing = s_mock_transport;
    failing.init                        = failing_transport_init;
    cfg.transport                       = &failing;
    /* Config is valid, allocation succeeds, but transport init fails.
     * pubnub_create must free the allocated context.  cmocka's
     * test_malloc/test_free tracking will detect a leak if it doesn't. */
    assert_null(pubnub_create(&cfg));
}

#endif /* !PUBNUB_CFG_NO_HEAP */

/* ======================================================================== */
/* Tests: provider struct pointer validation                                */
/* ======================================================================== */

/* --- Allocator --------------------------------------------------------- */

static void provider_should_reject_allocator_with_null_alloc(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_allocator_provider_t bad = s_mock_allocator;
    bad.alloc                       = NULL;
    cfg.allocator                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_allocator_with_null_free(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_allocator_provider_t bad = s_mock_allocator;
    bad.free                        = NULL;
    cfg.allocator                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_allocator_with_null_buf_acquire(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_allocator_provider_t bad = s_mock_allocator;
    bad.buf_acquire                 = NULL;
    cfg.allocator                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_allocator_with_null_buf_release(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_allocator_provider_t bad = s_mock_allocator;
    bad.buf_release                 = NULL;
    cfg.allocator                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

/* --- Transport --------------------------------------------------------- */

static void provider_should_reject_transport_with_null_send(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_transport_provider_t bad = s_mock_transport;
    bad.send                        = NULL;
    cfg.transport                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_transport_with_null_poll(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_transport_provider_t bad = s_mock_transport;
    bad.poll                        = NULL;
    cfg.transport                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_transport_with_null_cancel(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t             cfg = valid_config();
    pubnub_transport_provider_t bad = s_mock_transport;
    bad.cancel                      = NULL;
    cfg.transport                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

/* --- Serialization ----------------------------------------------------- */

static void provider_should_reject_serialization_with_null_parse(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t                 cfg = valid_config();
    pubnub_serialization_provider_t bad = s_mock_serialization;
    bad.parse                           = NULL;
    cfg.serialization                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_serialization_with_null_serialize(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t                 cfg = valid_config();
    pubnub_serialization_provider_t bad = s_mock_serialization;
    bad.serialize                       = NULL;
    cfg.serialization                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_serialization_with_null_value_destroy(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t                 cfg = valid_config();
    pubnub_serialization_provider_t bad = s_mock_serialization;
    bad.value_destroy                   = NULL;
    cfg.serialization                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

/* --- Platform ---------------------------------------------------------- */

static void provider_should_reject_platform_with_null_monotonic_ms(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t            cfg = valid_config();
    pubnub_platform_provider_t bad = s_mock_platform;
    bad.monotonic_ms               = NULL;
    cfg.platform                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_platform_with_null_sleep_ms(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t            cfg = valid_config();
    pubnub_platform_provider_t bad = s_mock_platform;
    bad.sleep_ms                   = NULL;
    cfg.platform                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

static void provider_should_reject_platform_with_null_random_bytes(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t            cfg = valid_config();
    pubnub_platform_provider_t bad = s_mock_platform;
    bad.random_bytes               = NULL;
    cfg.platform                   = &bad;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_PROVIDER_MISSING);

    free_test_context(ctx);
}

/* --- Crypto ------------------------------------------------------------ */

static void provider_should_treat_null_crypto_config_as_disabled(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.crypto_module   = NULL;

    /* NULL crypto in the config means "no crypto provider" --
     * the SDK deliberately does NOT fall back to the compiled-in
     * default for crypto, because the stub's all-NULL callbacks
     * are indistinguishable from "disabled" and would otherwise
     * trip the validation block that flags partially-populated
     * crypto vtables as malformed. Init must succeed and leave
     * the context with crypto turned off. */
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_allow_null_logger(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    cfg.logger          = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void noop_log(struct pubnub_logger_provider* self,
                     const pubnub_log_entry_t*      entry)
{
    (void)self;
    (void)entry;
}

static void provider_should_tolerate_logger_with_null_log_callback(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_logger_provider_t partial = {.log = NULL, .set_level = NULL};
    pubnub_config_t          cfg     = valid_config();
    cfg.logger                       = &partial;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_tolerate_logger_with_null_set_level_callback(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_logger_provider_t partial = {.log = noop_log, .set_level = NULL};
    pubnub_config_t          cfg     = valid_config();
    cfg.logger                       = &partial;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_logger_add_should_reject_null_provider(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_logger_add(ctx, NULL), PUBNUB_ERR_INVALID_ARGUMENT);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_logger_remove_should_reject_unknown_provider(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_logger_provider_t unknown = {.log = noop_log, .set_level = NULL};
    assert_int_equal(pubnub_logger_remove(ctx, &unknown),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_accept_crypto_with_null_encrypt(void** state)
{
    (void)state;
    /* Crypto ops are opt-in per capability: a caller that only
     * needs PAMv3 signing (hmac_sha256) can wire a crypto provider
     * without encrypt/decrypt. */
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t          cfg     = valid_config();
    pubnub_crypto_provider_t partial = s_mock_crypto;
    partial.encrypt                  = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_accept_crypto_with_null_decrypt(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t          cfg     = valid_config();
    pubnub_crypto_provider_t partial = s_mock_crypto;
    partial.decrypt                  = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_accept_crypto_with_null_hmac(void** state)
{
    (void)state;
    /* A caller that only needs message encryption (not PAMv3) can
     * wire crypto without hmac_sha256. Features that need HMAC
     * pass through at dispatch time. */
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t          cfg     = valid_config();
    pubnub_crypto_provider_t partial = s_mock_crypto;
    partial.hmac_sha256              = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void provider_should_accept_valid_crypto(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: provider init() failure triggers rollback                         */
/* ======================================================================== */

static void init_should_fail_when_transport_init_fails(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_transport_provider_t failing = s_mock_transport;
    failing.init                        = failing_transport_init;

    pubnub_config_t cfg = valid_config();
    cfg.transport       = &failing;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INTERNAL);

    free_test_context(ctx);
}

static void init_should_rollback_transport_when_serialization_init_fails(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    /* Tracking globals — reset by setup, verified after init failure. */
    assert_int_equal(s_transport_deinit_seq, 0);

    pubnub_transport_provider_t tracked_transport = s_mock_transport;
    tracked_transport.deinit                      = tracking_transport_deinit;

    pubnub_serialization_provider_t failing = s_mock_serialization;
    failing.init                            = failing_serial_init;

    pubnub_config_t cfg = valid_config();
    cfg.transport       = &tracked_transport;
    cfg.serialization   = &failing;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INTERNAL);
    assert_int_equal(s_transport_deinit_seq, 1);

    free_test_context(ctx);
}

#if PUBNUB_ENABLE_CRYPTO
/* ======================================================================== */
/* Tests: crypto_module init/deinit integration                             */
/* ======================================================================== */

static void init_should_store_crypto_module_pointer(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    /* Real module struct with all-NULL cryptors so init/deinit
     * iteration is a no-op. */
    pubnub_crypto_module_t dummy_module = {0};

    pubnub_config_t cfg = valid_config();
    cfg.crypto_module   = &dummy_module;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_ptr_equal(pn_context_crypto_module(ctx), &dummy_module);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void
deinit_should_call_serial_and_transport_deinit_when_crypto_module_is_set(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    assert_int_equal(s_transport_deinit_seq, 0);
    assert_int_equal(s_serial_deinit_seq, 0);

    pubnub_transport_provider_t tracked_transport = s_mock_transport;
    tracked_transport.deinit                      = tracking_transport_deinit;

    pubnub_serialization_provider_t tracked_serial = s_mock_serialization;
    tracked_serial.deinit                          = tracking_serial_deinit;

    /* Real module struct with all-NULL cryptors so the crypto
     * init/deinit iteration is a no-op. Verifies the deinit path
     * is not disturbed by the module pointer being set. */
    pubnub_crypto_module_t dummy_module = {0};

    pubnub_config_t cfg = valid_config();
    cfg.transport       = &tracked_transport;
    cfg.serialization   = &tracked_serial;
    cfg.crypto_module   = &dummy_module;

    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);

    /* Reverse init order: serialization=1, transport=2. */
    assert_int_equal(s_serial_deinit_seq, 1);
    assert_int_equal(s_transport_deinit_seq, 2);
    assert_true(s_serial_deinit_seq < s_transport_deinit_seq);

    free_test_context(ctx);
}

static void init_should_rollback_serial_and_transport_when_crypto_init_fails(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    assert_int_equal(s_transport_deinit_seq, 0);
    assert_int_equal(s_serial_deinit_seq, 0);

    pubnub_transport_provider_t tracked_transport = s_mock_transport;
    tracked_transport.deinit                      = tracking_transport_deinit;

    pubnub_serialization_provider_t tracked_serial = s_mock_serialization;
    tracked_serial.deinit                          = tracking_serial_deinit;

    /* Module whose default cryptor init fails. */
    pubnub_crypto_provider_t failing_cryptor = {0};
    failing_cryptor.init                     = failing_cryptor_init;
    pubnub_crypto_module_t failing_module    = {0};
    failing_module.default_cryptor           = &failing_cryptor;

    pubnub_config_t cfg = valid_config();
    cfg.transport       = &tracked_transport;
    cfg.serialization   = &tracked_serial;
    cfg.crypto_module   = &failing_module;

    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_ERR_INTERNAL);

    /* Rollback: serialization deinit called before transport deinit. */
    assert_int_equal(s_serial_deinit_seq, 1);
    assert_int_equal(s_transport_deinit_seq, 2);
    assert_true(s_serial_deinit_seq < s_transport_deinit_seq);

    free_test_context(ctx);
}

static void init_deinit_should_call_cryptor_init_and_deinit(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    assert_int_equal(s_cryptor_init_count, 0);
    assert_int_equal(s_cryptor_deinit_count, 0);

    pubnub_crypto_provider_t tracked_cryptor = {0};
    tracked_cryptor.init                     = tracking_cryptor_init;
    tracked_cryptor.deinit                   = tracking_cryptor_deinit_count;

    pubnub_crypto_module_t module = {0};
    module.default_cryptor        = &tracked_cryptor;

    pubnub_config_t cfg = valid_config();
    cfg.crypto_module   = &module;

    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    assert_int_equal(s_cryptor_init_count, 1);
    assert_int_equal(s_cryptor_deinit_count, 0);

    pubnub_deinit(ctx);
    assert_int_equal(s_cryptor_deinit_count, 1);

    free_test_context(ctx);
}
#endif /* PUBNUB_ENABLE_CRYPTO */

/* ======================================================================== */
/* Tests: deinit should call provider deinit callbacks                      */
/* ======================================================================== */

static void deinit_should_call_provider_deinit_callbacks(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    assert_int_equal(s_transport_deinit_seq, 0);
    assert_int_equal(s_serial_deinit_seq, 0);

    pubnub_transport_provider_t tracked_transport = s_mock_transport;
    tracked_transport.deinit                      = tracking_transport_deinit;

    pubnub_serialization_provider_t tracked_serial = s_mock_serialization;
    tracked_serial.deinit                          = tracking_serial_deinit;

    pubnub_config_t cfg = valid_config();
    cfg.transport       = &tracked_transport;
    cfg.serialization   = &tracked_serial;

    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);

    /* serialization=1, transport=2 (reverse init order). */
    assert_int_equal(s_serial_deinit_seq, 1);
    assert_int_equal(s_transport_deinit_seq, 2);
    assert_true(s_serial_deinit_seq < s_transport_deinit_seq);

    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pubnub_process()                                                  */
/* ======================================================================== */

static void process_should_reject_null_context(void** state)
{
    (void)state;
    assert_int_equal(pubnub_process(NULL), PUBNUB_ERR_NOT_INITIALIZED);
}

static void process_should_reject_uninitialized_context(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    assert_int_equal(pubnub_process(ctx), PUBNUB_ERR_NOT_INITIALIZED);

    free_test_context(ctx);
}

static void process_should_return_ok_after_init(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    /* Fresh context: no slots acquired, pool is quiescent -- process
     * reports OK (everything's done, nothing to cook). Richer
     * behaviour is exercised by the pubnub_process +
     * pubnub_future_release tests below. */
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_reject_deinitialized_context(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    pubnub_config_t cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    assert_int_equal(pubnub_process(ctx), PUBNUB_ERR_NOT_INITIALIZED);

    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pipeline wiring                                                    */
/*                                                                           */
/* These tests verify that pubnub_init()/pubnub_create() build the           */
/* canonical middleware chain inside the context and that features can       */
/* reach it through pn_context_pipeline(). They use s_chain_transport       */
/* (capturing) rather than s_mock_transport (null-returning) because         */
/* the chain must actually dispatch a request to prove wiring.              */
/* ======================================================================== */

static pubnub_config_t valid_config_with_chain_transport(void)
{
    pubnub_config_t cfg = valid_config();
    cfg.transport       = &s_chain_transport;
    return cfg;
}

static void context_pipeline_should_return_null_when_ctx_is_null(void** state)
{
    (void)state;

    assert_null(pn_context_pipeline(NULL));
}

static void context_pipeline_should_return_null_for_uninitialized(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    /* Context memory allocated but pubnub_init() not called. */
    assert_null(pn_context_pipeline(ctx));

    free_test_context(ctx);
}

static void context_pipeline_should_return_valid_pointer_after_init(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pn_pipeline_t* pipe = pn_context_pipeline(ctx);

    assert_non_null(pipe);
    /* base 3 (auth + pnsdk + userid) + retry + compression when enabled. */
    assert_int_equal(pipe->owned_count,
                     3 + PUBNUB_ENABLE_RETRY + PUBNUB_ENABLE_REQUEST_COMPRESSION);
    assert_non_null(pipe->chain_head);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void deinit_should_tear_down_pipeline(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pn_pipeline_t* pipe = pn_context_pipeline(ctx);
    assert_int_equal(pipe->owned_count,
                     3 + PUBNUB_ENABLE_RETRY + PUBNUB_ENABLE_REQUEST_COMPRESSION);

    pubnub_deinit(ctx);

    /* The accessor rejects a deinited context by checking the
     * initialized sentinel. */
    assert_null(pn_context_pipeline(ctx));

    /* The embedded pn_pipeline_t is zeroed in place, so a caller
     * who cached the pointer during init observes the cleared
     * state. This is the contract that makes pn_request_dispatch()
     * on a stale cached pointer fail via its chain_head NULL check. */
    assert_null(pipe->chain_head);
    assert_int_equal(pipe->owned_count, 0);

    free_test_context(ctx);
}

static void dispatch_through_context_should_reach_transport(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.auth_token        = "tok";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);

    pubnub_res_t rc = pn_request_dispatch(
        pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(s_chain_send_called);
    /* All three enrichment middlewares contributed params before
     * the transport saw the request. No secret_key is configured,
     * so signature is a passthrough. */
    assert_non_null(find_captured_param("pnsdk"));
    assert_non_null(find_captured_param("uuid"));
    assert_non_null(find_captured_param("auth"));
    assert_null(find_captured_param("signature"));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_should_propagate_to_middleware(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* Rotate user_id after the chain is built; userid middleware
     * dereferences a pointer-to-pointer into ctx->user_id, so the
     * update must be visible on the next dispatch without any
     * rebuild. */
    const char* new_uid = "rotated-user";
    assert_int_equal(pubnub_set_user_id(ctx, new_uid), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* uuid = find_captured_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(uuid->len, strlen(new_uid));
    assert_memory_equal(uuid->ptr, new_uid, uuid->len);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_auth_token_should_propagate_to_middleware(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    /* Start without a token. */
    cfg.auth_token = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* First dispatch: no token. */
    reset_chain_capture();
    pn_request_t req1;
    pn_request_init(&req1, 0);
    pn_request_enqueue(&req1);
    pn_request_dispatch(pn_context_pipeline(ctx), &req1, pn_context_platform(ctx));
    assert_null(find_captured_param("auth"));

    /* Rotate to a real token. */
    const char* new_tok = "late-token";
    assert_int_equal(pubnub_set_auth_token(ctx, new_tok), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req2;
    pn_request_init(&req2, 0);
    pn_request_enqueue(&req2);
    pn_request_dispatch(pn_context_pipeline(ctx), &req2, pn_context_platform(ctx));

    const pubnub_string_view_t* auth = find_captured_param("auth");
    assert_non_null(auth);
    assert_int_equal(auth->len, strlen(new_tok));
    assert_memory_equal(auth->ptr, new_tok, auth->len);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_user_id_empty_should_be_rejected(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* Empty user_id must be rejected. */
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_set_user_id(ctx, ""));

    /* Original user_id must be preserved after rejection. */
    reset_chain_capture();
    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* uuid = find_captured_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(uuid->len, strlen("test-user"));
    assert_memory_equal(uuid->ptr, "test-user", uuid->len);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_auth_token_empty_string_then_clear(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.auth_token        = NULL;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* Set token to empty string — middleware should still add an
     * "auth" param (empty string is a valid token value). */
    assert_int_equal(pubnub_set_auth_token(ctx, ""), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req1;
    pn_request_init(&req1, 0);
    pn_request_enqueue(&req1);
    pn_request_dispatch(pn_context_pipeline(ctx), &req1, pn_context_platform(ctx));

    const pubnub_string_view_t* auth = find_captured_param("auth");
    /* Empty-string token: middleware may add an empty auth param or
     * skip it. Either behavior is defensible. This assertion tests
     * that the SDK doesn't crash and that clearing afterward works. */

    /* Clear token by setting NULL. */
    assert_int_equal(pubnub_set_auth_token(ctx, NULL), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req2;
    pn_request_init(&req2, 0);
    pn_request_enqueue(&req2);
    pn_request_dispatch(pn_context_pipeline(ctx), &req2, pn_context_platform(ctx));

    /* After clearing, "auth" param must be absent. */
    assert_null(find_captured_param("auth"));

    (void)auth; /* Suppress unused warning if we removed the assertion. */
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

#if !PUBNUB_CFG_NO_HEAP

static void dispatch_through_owned_context_should_reach_transport(void** state)
{
    (void)state;
    pubnub_config_t cfg = valid_config_with_chain_transport();
    cfg.auth_token      = "tok";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);

    pubnub_res_t rc = pn_request_dispatch(
        pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(s_chain_send_called);
    /* pubnub_create deep-copies config strings before building the
     * pipeline, so middleware pointers must refer to context-owned
     * storage -- not the transient cfg on this test's stack. If the
     * order were wrong the uuid/auth views would dangle. */
    assert_non_null(find_captured_param("pnsdk"));
    assert_non_null(find_captured_param("uuid"));
    assert_non_null(find_captured_param("auth"));
    assert_null(find_captured_param("signature"));

    pubnub_destroy(ctx);
}

static void set_user_id_should_propagate_on_owned_context(void** state)
{
    (void)state;
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Owned-config path: pubnub_set_user_id() deep-copies via
     * pn_strdup() and frees the previous pointer. The middleware
     * holds &ctx->user_id (pointer-to-pointer), so the swap must
     * propagate without rebuilding the chain. */
    const char* new_uid = "rotated-owned-user";
    assert_int_equal(pubnub_set_user_id(ctx, new_uid), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* uuid = find_captured_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(uuid->len, strlen(new_uid));
    assert_memory_equal(uuid->ptr, new_uid, uuid->len);

    pubnub_destroy(ctx);
}

static void set_auth_token_should_propagate_on_owned_context(void** state)
{
    (void)state;
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* No token at create time; rotate in a token afterwards. On an
     * owned context this path goes through pn_strdup + pn_strfree
     * and must still update the pointer the auth middleware holds. */
    const char* new_tok = "owned-late-token";
    assert_int_equal(pubnub_set_auth_token(ctx, new_tok), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* auth = find_captured_param("auth");
    assert_non_null(auth);
    assert_int_equal(auth->len, strlen(new_tok));
    assert_memory_equal(auth->ptr, new_tok, auth->len);

    pubnub_destroy(ctx);
}

/* --- TLS setter capture helpers ----------------------------------------- */

static const char* s_captured_ca_bundle;
static int         s_captured_ca_bundle_calls;
static uint8_t     s_captured_skip_verify;
static int         s_captured_skip_verify_calls;

static void capturing_set_tls_ca_bundle(struct pubnub_transport_provider* self,
                                        const char* ca_pem)
{
    (void)self;
    s_captured_ca_bundle = ca_pem;
    ++s_captured_ca_bundle_calls;
}

static void capturing_set_tls_verify(struct pubnub_transport_provider* self,
                                     uint8_t skip_verify)
{
    (void)self;
    s_captured_skip_verify = skip_verify;
    ++s_captured_skip_verify_calls;
}

static void reset_tls_captures(void)
{
    s_captured_ca_bundle         = NULL;
    s_captured_ca_bundle_calls   = 0;
    s_captured_skip_verify       = 0;
    s_captured_skip_verify_calls = 0;
}

static void set_tls_ca_bundle_should_delegate_to_transport(void** state)
{
    (void)state;
    reset_tls_captures();

    pubnub_transport_provider_t capturing = s_mock_transport;
    capturing.set_tls_ca_bundle           = capturing_set_tls_ca_bundle;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.transport         = &capturing;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_set_tls_ca_bundle(ctx, "-----BEGIN CERTIFICATE-----\n"),
                     PUBNUB_OK);
    assert_int_equal(s_captured_ca_bundle_calls, 1);
    assert_string_equal(s_captured_ca_bundle, "-----BEGIN CERTIFICATE-----\n");

    /* NULL reverts to system certs — setter must accept it. */
    assert_int_equal(pubnub_set_tls_ca_bundle(ctx, NULL), PUBNUB_OK);
    assert_int_equal(s_captured_ca_bundle_calls, 2);
    assert_null(s_captured_ca_bundle);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_tls_verify_should_delegate_to_transport(void** state)
{
    (void)state;
    reset_tls_captures();

    pubnub_transport_provider_t capturing = s_mock_transport;
    capturing.set_tls_verify              = capturing_set_tls_verify;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.transport         = &capturing;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_set_tls_skip_verify(ctx, 1), PUBNUB_OK);
    assert_int_equal(s_captured_skip_verify_calls, 1);
    assert_int_equal(s_captured_skip_verify, 1);

    assert_int_equal(pubnub_set_tls_skip_verify(ctx, 0), PUBNUB_OK);
    assert_int_equal(s_captured_skip_verify_calls, 2);
    assert_int_equal(s_captured_skip_verify, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void deprecated_tls_verify_alias_should_delegate(void** state)
{
    (void)state;
    reset_tls_captures();

    pubnub_transport_provider_t capturing = s_mock_transport;
    capturing.set_tls_verify              = capturing_set_tls_verify;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.transport         = &capturing;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_set_tls_skip_verify(ctx, 1), PUBNUB_OK);
    assert_int_equal(s_captured_skip_verify_calls, 1);
    assert_int_equal(s_captured_skip_verify, 1);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void
set_tls_ca_bundle_should_return_not_supported_when_transport_lacks_setter(void** state)
{
    (void)state;
    /* s_mock_transport has set_tls_ca_bundle = NULL. */
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_set_tls_ca_bundle(ctx, "pem"), PUBNUB_ERR_NOT_SUPPORTED);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void
set_tls_verify_should_return_not_supported_when_transport_lacks_setter(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    assert_int_equal(pubnub_set_tls_skip_verify(ctx, 1), PUBNUB_ERR_NOT_SUPPORTED);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_tls_ca_bundle_should_return_not_initialized_on_null_ctx(void** state)
{
    (void)state;
    assert_int_equal(pubnub_set_tls_ca_bundle(NULL, "pem"),
                     PUBNUB_ERR_NOT_INITIALIZED);
}

static void set_tls_verify_should_return_not_initialized_on_null_ctx(void** state)
{
    (void)state;
    assert_int_equal(pubnub_set_tls_skip_verify(NULL, 1),
                     PUBNUB_ERR_NOT_INITIALIZED);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

static void init_should_rollback_when_pool_init_fails(void** state)
{
    (void)state;
    s_oom_alloc_count      = 0;
    s_oom_alloc_fail_after = 0; /* Fail on the very first alloc. */

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.allocator         = &s_oom_allocator;

    /* Mock providers perform no allocations during init(), so the
     * first alloc() to hit the allocator is pn_request_pool_init()
     * inside pn_context_init_common. With fail_after = 0 it
     * returns NULL immediately, which exercises the rollback path
     * that tears down providers and leaves the context reusable. */
    pubnub_res_t rc = pubnub_init(ctx, &cfg);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    /* Rollback must clear the initialized sentinel; the accessor
     * reports the context as uninitialized. */
    assert_null(pn_context_pipeline(ctx));
    assert_null(pn_context_request_pool(ctx));
    assert_int_equal(pubnub_process(ctx), PUBNUB_ERR_NOT_INITIALIZED);
    /* The same context memory must be reusable with a working
     * allocator -- proves the rollback is complete. */
    cfg.allocator = &s_mock_allocator;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_rollback_when_pending_queue_init_fails(void** state)
{
    (void)state;
    s_oom_alloc_count = 0;
    /* One alloc succeeds (the request pool's slots[] array), then the
     * next fails (pending queue entries).  pn_context_init_common()
     * must roll back the pool and leave the context reusable.
     * cmocka's test_malloc/test_free tracking detects any leak. */
    s_oom_alloc_fail_after = 1;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.allocator         = &s_oom_allocator;

    pubnub_res_t rc = pubnub_init(ctx, &cfg);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    assert_null(pn_context_pipeline(ctx));
    assert_null(pn_context_request_pool(ctx));
    assert_int_equal(pubnub_process(ctx), PUBNUB_ERR_NOT_INITIALIZED);
    /* Reusability check. */
    cfg.allocator = &s_mock_allocator;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_rollback_when_pipeline_build_fails(void** state)
{
    (void)state;
    s_oom_alloc_count = 0;
    /* Three allocs in pn_context_init_common() succeed:
     *   [0] request pool slots array
     *   [1] pending queue entries array
     *   [2] pending slot map
     * The fourth alloc is the first middleware struct inside
     * pn_context_build_pipeline() — it fails, returning
     * PUBNUB_ERR_OUT_OF_MEMORY.
     *
     * The fix under test: pubnub_init() must free all three
     * allocations made by pn_context_init_common(), not just the
     * pool.  cmocka's test_malloc/test_free tracking detects any
     * unreleased allocation. */
    s_oom_alloc_fail_after = 3;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.allocator         = &s_oom_allocator;

    pubnub_res_t rc = pubnub_init(ctx, &cfg);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    /* Context must be uninitialized so accessors safely return NULL/error
     * and the same memory can be reused. */
    assert_null(pn_context_pipeline(ctx));
    assert_null(pn_context_request_pool(ctx));
    assert_int_equal(pubnub_process(ctx), PUBNUB_ERR_NOT_INITIALIZED);
    /* Reusability check: must succeed with a working allocator. */
    cfg.allocator = &s_mock_allocator;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ========================================================================
 * Tests: request pool wiring                                                *
 *                                                                           *
 * Exercises pubnub_context_t's embedded pn_request_pool_t: accessor         *
 * contract, init/deinit lifecycle, and the pubnub_future_t public API       *
 * bound to it.                                                              *
 * ======================================================================== */

static void context_request_pool_should_return_null_when_ctx_is_null(void** state)
{
    (void)state;

    assert_null(pn_context_request_pool(NULL));
}

static void context_request_pool_should_return_null_for_uninitialized(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();

    assert_null(pn_context_request_pool(ctx));

    free_test_context(ctx);
}

static void context_request_pool_should_size_at_compile_time_constant(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);

    assert_non_null(pool);
    assert_int_equal(pool->capacity, PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS);
    assert_int_equal(pool->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void deinit_should_tear_down_request_pool(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool->slots);

    pubnub_deinit(ctx);

    /* Accessor rejects a deinited context; the embedded pool's
     * slots array has been freed and the capacity cleared. */
    assert_null(pn_context_request_pool(ctx));
    assert_null(pool->slots);
    assert_int_equal(pool->capacity, 0);

    free_test_context(ctx);
}

static void future_ready_should_return_true_for_invalid_sentinel(void** state)
{
    (void)state;

    pubnub_future_t fut = PUBNUB_FUTURE_INVALID;

    assert_true(pubnub_future_is_ready(fut));
}

static void future_status_should_return_invalid_argument_for_sentinel(void** state)
{
    (void)state;

    pubnub_future_t fut = PUBNUB_FUTURE_INVALID;

    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void future_ready_should_return_false_for_in_progress_slot(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pubnub_future_t fut;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);

    /* Slot is PENDING (acquired but not dispatched); not ready. */
    assert_false(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_IN_PROGRESS);

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_status_should_return_slot_result_when_terminal(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pubnub_future_t fut;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);

    /* Drive the slot to a terminal state directly (no pipeline /
     * transport -- that's the job of later sub-PRs). This test
     * only pins the future query path. */
    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    slot->state = PN_REQUEST_IN_FLIGHT;
    pn_request_on_success(slot, PUBNUB_OK);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_status_should_return_not_initialized_for_deinited_ctx(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pubnub_future_t fut;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);

    /* Deinit the ctx while holding the future: pool goes away,
     * future becomes stale. */
    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_NOT_INITIALIZED);

    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pubnub_process + pubnub_future_release                             */
/*                                                                           */
/* These tests drive the cooperative polling loop end-to-end with the        */
/* chain-tracking transport mock controlling when (and how) a request        */
/* completes. Between them they cover:                                      */
/*   - dispatch of PENDING slots into the chain on the first tick            */
/*   - routing of transport COMPLETE / ERROR back into the slot's            */
/*     terminal state on subsequent ticks                                    */
/*   - the "return IN_PROGRESS when nothing to do" contract                  */
/*   - pubnub_future_release semantics (invalid sentinel, live terminal      */
/*     slot, double release)                                                 */
/* ======================================================================== */

/* Small helper: acquire a slot and minimally populate the request so
 * the pipeline/transport contract is satisfied (host and a path
 * segment). Returns the future. */
static pubnub_future_t acquire_and_populate(pubnub_context_t* ctx)
{
    pubnub_future_t fut;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);
    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    slot->http_request.method             = PUBNUB_HTTP_GET;
    slot->http_request.host               = "ps.pndsn.com";
    slot->http_request.path_segments[0]   = (pubnub_string_view_t){"v2", 2};
    slot->http_request.path_segment_count = 1;
    return fut;
}

static void process_should_dispatch_pending_slot_to_in_flight(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    pubnub_future_t fut = acquire_and_populate(ctx);

    pubnub_res_t rc = pubnub_process(ctx);

    /* process dispatched the PENDING slot: the mock transport saw
     * send() and the slot is now IN_FLIGHT. Nothing in the
     * transport has completed it yet, so the pool is still active
     * and the future is not ready. */
    assert_int_equal(rc, PUBNUB_IN_PROGRESS);
    assert_true(s_chain_send_called);
    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_int_equal(slot->state, PN_REQUEST_IN_FLIGHT);
    assert_false(pubnub_future_is_ready(fut));

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_route_sync_completion_to_slot_complete(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    /* Mock finishes the request synchronously inside send(). */
    s_chain_complete_in_send = 1;
    pubnub_future_t fut      = acquire_and_populate(ctx);

    /* One tick: dispatch (slot is briefly IN_FLIGHT with
     * completion already marked) and then routing transitions the
     * slot to COMPLETE on the same pass. */
    pubnub_res_t rc = pubnub_process(ctx);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_route_sync_error_to_slot_failed(void** state)
{
    (void)state;
    pubnub_context_t* ctx          = alloc_test_context();
    pubnub_config_t   cfg          = valid_config_with_chain_transport();
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    s_chain_error_in_send = 1;
    pubnub_future_t fut   = acquire_and_populate(ctx);

    pubnub_res_t rc = pubnub_process(ctx);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_TRANSPORT);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_route_async_completion_on_next_tick(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    pubnub_future_t fut = acquire_and_populate(ctx);

    /* First tick: PENDING -> IN_FLIGHT. Transport has not
     * "completed" anything yet so the pool is still active and the
     * future is not ready. */
    assert_int_equal(pubnub_process(ctx), PUBNUB_IN_PROGRESS);
    assert_false(pubnub_future_is_ready(fut));

    /* Simulate the transport finishing the request between ticks. */
    chain_mark_complete(200);

    /* Second tick: routing picks up the completion and terminates
     * the slot. Pool is now quiescent (one COMPLETE slot, nothing
     * active). */
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_route_async_error_on_next_tick(void** state)
{
    (void)state;
    pubnub_context_t* ctx          = alloc_test_context();
    pubnub_config_t   cfg          = valid_config_with_chain_transport();
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    pubnub_future_t fut = acquire_and_populate(ctx);

    assert_int_equal(pubnub_process(ctx), PUBNUB_IN_PROGRESS);
    assert_false(pubnub_future_is_ready(fut));

    chain_mark_error();

    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_TRANSPORT);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_return_ok_when_pool_is_idle(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* No slots in use -- pool is quiescent, process reports OK. */
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_return_ok_when_only_terminal_slots(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    s_chain_complete_in_send = 1;
    pubnub_future_t fut      = acquire_and_populate(ctx);
    /* First tick dispatches + transitions to COMPLETE. The pool
     * is now quiescent (COMPLETE slots don't count as active), so
     * even this transitioning tick reports OK. */
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));

    /* Second tick: slot is terminal, still quiescent. */
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_release_should_return_slot_to_pool(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    s_chain_complete_in_send = 1;
    pubnub_future_t fut      = acquire_and_populate(ctx);
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_int_equal(pool->in_use_count, 1);

    pubnub_future_release(fut);

    /* The slot is back in FREE; next acquire hands it out again. */
    assert_int_equal(pool->in_use_count, 0);
    assert_true(pn_request_is_idle(pn_request_pool_get(pool, fut.slot_id)));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_release_should_be_safe_on_invalid_sentinel(void** state)
{
    (void)state;

    /* Must not crash on a sentinel that was never bound to a ctx. */
    pubnub_future_release(PUBNUB_FUTURE_INVALID);
}

static void future_release_should_be_safe_on_immediate_failure_future(void** state)
{
    (void)state;
    /* Futures returned by queue-full or other immediate errors
     * carry a non-IN_PROGRESS status and were never bound to a
     * slot; release must be a no-op. */
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = {
        .ctx     = ctx,
        .slot_id = PUBNUB_SLOT_ID_INVALID,
        .status  = PUBNUB_ERR_QUEUE_FULL,
    };

    pubnub_future_release(fut);
    /* No slot was ever claimed; in_use_count stays at 0. */
    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_release_should_be_idempotent_on_already_idle_slot(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    s_chain_complete_in_send = 1;
    pubnub_future_t fut      = acquire_and_populate(ctx);
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);

    /* First release returns the slot; the second should be a no-op
     * rather than decrementing in_use_count below zero or otherwise
     * corrupting the pool. */
    pubnub_future_release(fut);
    pubnub_future_release(fut);

    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void cooperative_loop_should_complete_a_request_end_to_end(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    pubnub_future_t fut = acquire_and_populate(ctx);

    /* Simulate the async-I/O caller loop: drive process until the
     * future is ready, with the transport completing mid-loop. */
    int ticks = 0;
    while (!pubnub_future_is_ready(fut)) {
        if (ticks == 2) {
            /* On the third tick, the "async transport" finishes. */
            chain_mark_complete(200);
        }
        assert_int_not_equal(ticks, 10); /* liveness guard */
        pubnub_process(ctx);
        ticks++;
    }

    assert_int_equal(pubnub_future_status(fut), PUBNUB_OK);
    pubnub_future_release(fut);
    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void process_should_route_dispatch_failure_to_slot_failed(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    /* Mock transport refuses the request outright (send -> NULL).
     * pn_request_dispatch must route that into slot FAILED so the
     * future observes PUBNUB_ERR_TRANSPORT, closing the Phase-1-
     * fails path entirely through pubnub_process. */
    s_chain_send_returns_null = 1;
    pubnub_future_t fut       = acquire_and_populate(ctx);

    pubnub_res_t rc = pubnub_process(ctx);

    assert_int_equal(rc, PUBNUB_OK);
    assert_true(s_chain_send_called);
    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_int_equal(slot->state, PN_REQUEST_FAILED);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_TRANSPORT);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void future_release_should_be_safe_after_ctx_deinit(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    pubnub_future_t fut;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);

    /* Tear down the context while the caller still holds the future.
     * The pool is gone; pn_context_request_pool() returns NULL and
     * pubnub_future_release must bail cleanly rather than
     * dereference stale memory. */
    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);

    pubnub_future_release(fut); /* must not crash */

    free_test_context(ctx);
}

static void process_should_call_transport_poll_with_zero_timeout(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();

    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);

    /* Phase 2 of pubnub_process must give the transport a non-blocking
     * slice -- timeout_ms = 0 is the contract for cooperative mode.
     * Anything else would block the caller's main loop. */
    assert_true(s_chain_poll_called);
    assert_int_equal(s_chain_poll_last_timeout, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/* ======================================================================== */
/* Tests: pubnub_res_str()                                                  */
/* ======================================================================== */

/* The full set of committed pubnub_res_t values, range-coded. Range gaps
 * (e.g. value 5, 35, 47) are intentional growth slack and MUST NOT be
 * iterated as if they were valid values -- the old loop test used a
 * dense PUBNUB_ERR__COUNT sentinel which no longer exists. */
static const pubnub_res_t pn_committed_res_values[] = {PUBNUB_OK,
                                                       PUBNUB_IN_PROGRESS,
                                                       PUBNUB_ERR_CANCELLED,
                                                       PUBNUB_ERR_INVALID_ARGUMENT,
                                                       PUBNUB_ERR_NOT_INITIALIZED,
                                                       PUBNUB_ERR_PROVIDER_MISSING,
                                                       PUBNUB_ERR_NOT_SUPPORTED,
                                                       PUBNUB_ERR_OUT_OF_MEMORY,
                                                       PUBNUB_ERR_BUFFER_TOO_SMALL,
                                                       PUBNUB_ERR_QUEUE_FULL,
                                                       PUBNUB_ERR_TIMEOUT,
                                                       PUBNUB_ERR_TRANSPORT,
                                                       PUBNUB_ERR_SERVER,
                                                       PUBNUB_ERR_SERIALIZATION,
                                                       PUBNUB_ERR_CRYPTO,
                                                       PUBNUB_ERR_INTERNAL};

/* Replacement for the old dense-loop test: iterate the explicit valid-
 * value list and verify the function never returns NULL. When labels
 * are compiled in, the result is a non-empty, non-"Unknown error"
 * string; when compiled out, every value returns the empty string. */
static void res_str_should_return_non_null_for_all_committed_codes(void** state)
{
    (void)state;
    const size_t n =
        sizeof(pn_committed_res_values) / sizeof(pn_committed_res_values[0]);
    for (size_t i = 0; i < n; i++) {
        const char* s = pubnub_res_str(pn_committed_res_values[i]);
        assert_non_null(s);
#if PUBNUB_CFG_RES_STR
        assert_true(s[0] != '\0');
        assert_string_not_equal(s, "Unknown error");
#else
        assert_string_equal(s, "");
#endif
    }
}

/* Range-gap values fall between the committed class buckets and must
 * resolve to the fallback. Picks one value from each populated gap. */
static void res_str_should_return_unknown_for_gap_values(void** state)
{
    (void)state;
    const pubnub_res_t gaps[] = {
        (pubnub_res_t)5,  /* gap 3..15 between completion class and arg class */
        (pubnub_res_t)25, /* gap 20..31 inside arg/lifecycle class */
        (pubnub_res_t)45, /* gap 35..47 inside memory/capacity class */
        (pubnub_res_t)100, /* gap 98..111 inside payload class */
        (pubnub_res_t)200 /* gap 112..239 between payload and invariant classes */
    };
    const size_t n = sizeof(gaps) / sizeof(gaps[0]);
    for (size_t i = 0; i < n; i++) {
        const char* s = pubnub_res_str(gaps[i]);
        assert_non_null(s);
#if PUBNUB_CFG_RES_STR
        assert_string_equal(s, "Unknown error");
#else
        assert_string_equal(s, "");
#endif
    }
}

#if PUBNUB_CFG_RES_STR
static void res_str_should_return_label_for_pubnub_ok(void** state)
{
    (void)state;
    const char* s = pubnub_res_str(PUBNUB_OK);
    assert_non_null(s);
    assert_string_equal(s, "Success");
}
#endif

static void res_str_should_return_fallback_for_out_of_range(void** state)
{
    (void)state;
    const char* s = pubnub_res_str((pubnub_res_t)0x7FFE);
    assert_non_null(s);
#if PUBNUB_CFG_RES_STR
    assert_string_equal(s, "Unknown error");
#else
    assert_string_equal(s, "");
#endif
}

static void res_str_should_return_fallback_for_negative(void** state)
{
    (void)state;
    const char* s = pubnub_res_str((pubnub_res_t)-1);
    assert_non_null(s);
#if PUBNUB_CFG_RES_STR
    assert_string_equal(s, "Unknown error");
#else
    assert_string_equal(s, "");
#endif
}

/* Replacement for the old _COUNT sentinel test: pick a value just past
 * the highest committed enumerator (PUBNUB_ERR_INTERNAL = 240) and
 * verify the bound check. */
static void res_str_should_return_fallback_past_highest_committed(void** state)
{
    (void)state;
    const char* s = pubnub_res_str((pubnub_res_t)(PUBNUB_ERR_INTERNAL + 1));
    assert_non_null(s);
#if PUBNUB_CFG_RES_STR
    assert_string_equal(s, "Unknown error");
#else
    assert_string_equal(s, "");
#endif
}

#if PUBNUB_CFG_RES_STR
static void res_str_should_return_correct_strings_for_known_codes(void** state)
{
    (void)state;
    assert_string_equal(pubnub_res_str(PUBNUB_ERR_PROVIDER_MISSING),
                        "Required provider missing");
    assert_string_equal(pubnub_res_str(PUBNUB_ERR_TIMEOUT), "Operation timed out");
    assert_string_equal(pubnub_res_str(PUBNUB_IN_PROGRESS), "Operation in progress");
}
#endif

#if !PUBNUB_CFG_RES_STR
static void res_str_should_return_empty_when_disabled(void** state)
{
    (void)state;
    const char* s = pubnub_res_str(PUBNUB_OK);
    assert_non_null(s);
    assert_string_equal(s, "");
}
#endif

static void init_with_log_level_none_sets_silent_level(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.log_level         = PUBNUB_LOG_LEVEL_NONE;

    pubnub_res_t rc = pubnub_init(ctx, &cfg);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_log_level_t level = pubnub_logger_log_level(ctx);
    assert_int_equal(PUBNUB_LOG_LEVEL_NONE, level);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/**
 * Mock allocator to fail on the prep_entries allocation specifically.
 * The prep_entries alloc is the 4th alloc during init_common:
 *   [0] request pool slots
 *   [1] pending queue entries
 *   [2] pending slot map
 *   [3] prep_entries  <-- fail here
 */
static void init_should_rollback_when_prep_pool_alloc_fails(void** state)
{
    (void)state;
    s_oom_alloc_count      = 0;
    s_oom_alloc_fail_after = 3;

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.allocator         = &s_oom_allocator;

    pubnub_res_t rc = pubnub_init(ctx, &cfg);

    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);
    assert_null(pn_context_pipeline(ctx));
    assert_null(pn_context_request_pool(ctx));

    /* Reusability: must succeed with a working allocator. */
    cfg.allocator = &s_mock_allocator;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/**
 * Init a context, verify prep_entries was allocated (by successfully
 * acquiring), then deinit. Valgrind/cmocka leak tracking catches leaks.
 */
static void deinit_should_free_prep_pool(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* Verify prep_entries is functional. */
    pn_pending_entry_t* entry = pn_prep_acquire(ctx);
    assert_non_null(entry);
    pn_prep_release(ctx, entry);

    pubnub_deinit(ctx);
    /* Implicit: Valgrind/cmocka leak tracking detects leaked prep_entries. */
    free_test_context(ctx);
}

/**
 * Dispatch via chain transport that rejects send() (returns NULL).
 * Verify the prep entry is released and not leaked.
 */
static void dispatch_failure_releases_prep_entry(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    s_chain_send_returns_null = 1;

    pubnub_future_t fut = acquire_and_populate(ctx);
    assert_int_equal(pubnub_process(ctx), PUBNUB_OK);
    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_TRANSPORT);
    pubnub_future_release(fut);

    /* Verify the pool slot was released (can re-acquire all). */
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    assert_int_equal(pool->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

/**
 * Fill pool, enqueue with query params, complete a slot, process()
 * promotes. Verify promoted slot's query param pointers land inside
 * the slot's own scratch, not the prep entry's.
 */
static void process_promote_pending_relocates_scratch_correctly(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();
    /* Inline-complete all dispatched slots so they reach terminal
     * state on the first process tick. */
    s_chain_complete_in_send = 1;

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    const uint16_t capacity = pool->capacity;

    /* Fill all pool slots via direct acquire + dispatch. */
    pubnub_future_t futs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (uint16_t i = 0; i < capacity; i++) {
        futs[i] = acquire_and_populate(ctx);
    }
    /* Dispatch all pending slots (chain completes them inline). */
    (void)pubnub_process(ctx);
    assert_true(s_chain_send_called);

    /* Build a pending entry with query params pointing into scratch. */
    pn_pending_queue_t* queue = pn_context_pending_queue(ctx);
    assert_non_null(queue);

    pn_pending_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.http_request.method             = PUBNUB_HTTP_GET;
    entry.http_request.host               = "ps.pndsn.com";
    entry.http_request.path_segments[0]   = (pubnub_string_view_t){"v2", 2};
    entry.http_request.path_segment_count = 1;

    /* Write key and value into the entry's scratch buffer. */
    memcpy(entry.http_request.scratch, "testkey", 7);
    memcpy(entry.http_request.scratch + 7, "testval", 7);
    entry.http_request.query_params[0].key =
        (pubnub_string_view_t){(const char*)entry.http_request.scratch, 7};
    entry.http_request.query_params[0].value =
        (pubnub_string_view_t){(const char*)entry.http_request.scratch + 7, 7};
    entry.http_request.query_param_count = 1;

    pubnub_res_t rc = pn_pending_queue_enqueue(queue, &entry);
    assert_int_equal(rc, PUBNUB_OK);

    /* Release slot 0 (already completed inline). */
    pubnub_future_release(futs[0]);

    /* Process to promote the pending entry and dispatch it. */
    (void)pubnub_process(ctx);

    /* The promoted slot should have query params pointing into its own
     * scratch, not the original entry's. Find the promoted slot. */
    pn_request_t* promoted_slot = NULL;
    for (uint16_t i = 0; i < capacity; i++) {
        pn_request_t* s = pn_request_pool_get(pool, i);
        if (NULL != s && s->http_request.query_param_count > 0
            && PN_REQUEST_IDLE != s->state) {
            promoted_slot = s;
            break;
        }
    }
    /* Promotion must have happened; if not, the test fails here. */
    assert_non_null(promoted_slot);

    /* Verify the key pointer lands inside this slot's scratch. */
    const uintptr_t scratch_lo = (uintptr_t)promoted_slot->http_request.scratch;
    const uintptr_t scratch_hi = scratch_lo + PUBNUB_CFG_HTTP_SCRATCH_SIZE;
    const uintptr_t key_addr =
        (uintptr_t)promoted_slot->http_request.query_params[0].key.ptr;
    assert_true(key_addr >= scratch_lo && key_addr < scratch_hi);

    /* Clean up remaining slots (already completed inline). */
    for (uint16_t i = 1; i < capacity; i++) {
        pubnub_future_release(futs[i]);
    }
    /* Drain the promoted slot. */
    for (int pass = 0; pass < 3; pass++) {
        (void)pubnub_process(ctx);
    }

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void dispatch_uuid_value_matches_configured_user_id(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.user_id           = "specific-test-uid-42";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    const pubnub_string_view_t* uuid = find_captured_param("uuid");
    assert_non_null(uuid);
    assert_int_equal(uuid->len, strlen("specific-test-uid-42"));
    assert_memory_equal(uuid->ptr, "specific-test-uid-42", uuid->len);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void dispatch_auth_empty_string_omits_auth_param(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    cfg.auth_token        = "";
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);
    reset_chain_capture();

    pn_request_t req;
    pn_request_init(&req, 0);
    pn_request_enqueue(&req);
    pn_request_dispatch(pn_context_pipeline(ctx), &req, pn_context_platform(ctx));

    /* An empty-string auth token should either omit the auth param
     * entirely or propagate it as an empty value. If the SDK treats
     * empty-string the same as NULL, auth should be absent. If it
     * propagates the empty string, that may be a bug that leaks
     * credentials logic. Either way, this test documents the behavior. */
    const pubnub_string_view_t* auth = find_captured_param("auth");
    if (NULL != auth) {
        /* If auth IS present, it must be the empty string we set. */
        assert_int_equal(0, auth->len);
    }

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

#if PUBNUB_ENABLE_TIME
static void has_feature_time_returns_nonzero_when_enabled(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();

    pubnub_res_t rc = pubnub_init(ctx, &cfg);
    assert_int_equal(PUBNUB_OK, rc);

    int has = pubnub_has_feature(ctx, PUBNUB_FEATURE_TIME);
    assert_int_not_equal(0, has);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}
#endif /* PUBNUB_ENABLE_TIME */

/* ======================================================================== */
/* Tests: pubnub_set_origin / pubnub_get_origin                             */
/* ======================================================================== */

static void set_origin_should_reject_null_ctx(void** state)
{
    (void)state;
    assert_int_equal(PUBNUB_ERR_NOT_INITIALIZED, pubnub_set_origin(NULL, "x"));
}

static void get_origin_should_return_null_for_null_ctx(void** state)
{
    (void)state;
    assert_null(pubnub_get_origin(NULL));
}

static void set_origin_should_accept_custom_host(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "custom.example.com"));
    assert_string_equal("custom.example.com", pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_null_should_reset_to_default(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "custom.host"));
    assert_string_equal("custom.host", pubnub_get_origin(ctx));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, NULL));
    assert_string_equal(PUBNUB_CFG_ORIGIN, pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_empty_should_reset_to_default(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "custom.host"));
    assert_string_equal("custom.host", pubnub_get_origin(ctx));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, ""));
    assert_string_equal(PUBNUB_CFG_ORIGIN, pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_max_length_should_succeed(void** state)
{
    (void)state;
    char maxstr[PUBNUB_CFG_MAX_HOSTNAME_LEN];
    memset(maxstr, 'a', PUBNUB_CFG_MAX_HOSTNAME_LEN - 1);
    maxstr[PUBNUB_CFG_MAX_HOSTNAME_LEN - 1] = '\0';

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, maxstr));
    assert_string_equal(maxstr, pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_overlength_should_be_rejected(void** state)
{
    (void)state;
    char bigstr[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1];
    memset(bigstr, 'b', PUBNUB_CFG_MAX_HOSTNAME_LEN);
    bigstr[PUBNUB_CFG_MAX_HOSTNAME_LEN] = '\0';

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_set_origin(ctx, bigstr));
    assert_string_equal(PUBNUB_CFG_ORIGIN, pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_failure_should_preserve_old_value(void** state)
{
    (void)state;
    char bigstr[PUBNUB_CFG_MAX_HOSTNAME_LEN + 1];
    memset(bigstr, 'c', PUBNUB_CFG_MAX_HOSTNAME_LEN);
    bigstr[PUBNUB_CFG_MAX_HOSTNAME_LEN] = '\0';

    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "good.host.com"));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_set_origin(ctx, bigstr));
    assert_string_equal("good.host.com", pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_should_reject_header_injection(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "good.host.com"));

    /* CR, LF, and space would let an attacker smuggle extra headers into
     * the outbound Host: line; each must be rejected. */
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_set_origin(ctx, "ps.pndsn.com\r\nX-Evil: hdr"));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_set_origin(ctx, "ps.pndsn.com\rX"));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_set_origin(ctx, "ps.pndsn.com\nX"));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_set_origin(ctx, "ps.pndsn.com evil"));

    /* Every rejection must leave the previously accepted origin intact. */
    assert_string_equal("good.host.com", pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void init_should_reject_header_injection_origin(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.origin            = "ps.pndsn.com\r\nX-Evil: hdr";

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_init(ctx, &cfg));

    free_test_context(ctx);
}

static void set_origin_init_lifecycle(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "lifecycle.test"));
    assert_string_equal("lifecycle.test", pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

#if !PUBNUB_CFG_NO_HEAP
static void set_origin_create_lifecycle(void** state)
{
    (void)state;
    pubnub_config_t   cfg = valid_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.host"));
    assert_string_equal("new.host", pubnub_get_origin(ctx));

    pubnub_destroy(ctx);
}

static void set_origin_create_buffer_independent(void** state)
{
    (void)state;
    char* heap_origin = (char*)test_malloc(32);
    assert_non_null(heap_origin);
    strncpy(heap_origin, "heap.host.com", 31);
    heap_origin[31] = '\0';

    pubnub_config_t cfg   = valid_config();
    cfg.origin            = heap_origin;
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    test_free(heap_origin);
    assert_string_equal("heap.host.com", pubnub_get_origin(ctx));

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

static void set_origin_repeated_sets(void** state)
{
    (void)state;
    char              buf[64];
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    for (int i = 0; i < 20; i++) {
        snprintf(buf, sizeof(buf), "origin-%d.example.com", i);
        assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, buf));
    }
    assert_string_equal("origin-19.example.com", pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_after_deinit_should_fail(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    pubnub_deinit(ctx);

    assert_int_equal(PUBNUB_ERR_NOT_INITIALIZED,
                     pubnub_set_origin(ctx, "late.host"));

    free_test_context(ctx);
}

static void get_origin_should_return_default_after_init(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_string_equal(PUBNUB_CFG_ORIGIN, pubnub_get_origin(ctx));

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

#if PUBNUB_ENABLE_TIME
static void set_origin_should_propagate_to_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "new.api.com"));
    reset_chain_capture();
    s_chain_complete_in_send = 1;

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut.status);

    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal("new.api.com", s_chain_captured_request.host);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void default_origin_should_propagate_to_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    /* No pubnub_set_origin call: the compile-time default origin must
     * reach the request Host. */
    reset_chain_capture();
    s_chain_complete_in_send = 1;

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut.status);

    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal(PUBNUB_CFG_ORIGIN, s_chain_captured_request.host);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_null_should_reset_to_default_in_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    /* Move away from the default, then reset with NULL. */
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "custom.host.com"));
    /* NOTE: pubnub_set_origin(NULL) resets to the compile-time default
     * origin rather than rejecting the call. */
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, NULL));

    reset_chain_capture();
    s_chain_complete_in_send = 1;

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut.status);

    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal(PUBNUB_CFG_ORIGIN, s_chain_captured_request.host);

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_empty_should_reset_to_default_in_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "custom.host.com"));
    /* NOTE: pubnub_set_origin("") resets to the compile-time default
     * origin rather than storing an empty host. */
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, ""));

    reset_chain_capture();
    s_chain_complete_in_send = 1;

    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut.status);

    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal(PUBNUB_CFG_ORIGIN, s_chain_captured_request.host);
    assert_true(s_chain_captured_request.host[0] != '\0');

    pubnub_future_release(fut);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void set_origin_change_should_affect_subsequent_requests(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config_with_chain_transport();
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    /* First origin. */
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "origin-a.example.com"));
    reset_chain_capture();
    s_chain_complete_in_send = 1;
    pubnub_future_t fut_a    = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut_a.status);
    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal("origin-a.example.com", s_chain_captured_request.host);
    pubnub_future_release(fut_a);

    /* Change origin: the next request must observe the new host. */
    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "origin-b.example.com"));
    reset_chain_capture();
    s_chain_complete_in_send = 1;
    pubnub_future_t fut_b    = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, fut_b.status);
    pubnub_process(ctx);
    assert_true(s_chain_send_called);
    assert_string_equal("origin-b.example.com", s_chain_captured_request.host);
    pubnub_future_release(fut_b);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}
#endif /* PUBNUB_ENABLE_TIME */

static struct {
    int          count;
    int          canceled;
    int          failed;
    pubnub_res_t result;
    uint16_t     slot_id;
} s_abort_log_cap;

static void abort_capture_log(struct pubnub_logger_provider* self,
                              const pubnub_log_entry_t*      entry)
{
    const pubnub_log_entry_net_request_t* req;
    (void)self;
    if (NULL == entry || PUBNUB_LOG_ENTRY_NET_REQ != entry->type) {
        return;
    }
    req = (const pubnub_log_entry_net_request_t*)entry;
    s_abort_log_cap.count++;
    s_abort_log_cap.canceled = req->canceled;
    s_abort_log_cap.failed   = req->failed;
    s_abort_log_cap.result   = req->result;
    s_abort_log_cap.slot_id  = req->slot_id;
}

static pubnub_future_t abort_acquire_pending(pubnub_context_t* ctx)
{
    pubnub_future_t fut;
    pn_request_t*   slot;
    assert_int_equal(pn_request_pool_acquire(pn_context_request_pool(ctx), ctx, &fut),
                     PUBNUB_OK);
    slot = pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_non_null(slot);
    slot->http_request.method = PUBNUB_HTTP_GET;
    slot->http_request.host   = "example.com";
    return fut;
}

static void abort_cancelled_should_emit_debug_cancel_log(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = abort_capture_log, .set_level = NULL};
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.logger            = &logger;
    /* Cancel logs at DEBUG; the default runtime level (INFO) suppresses
     * it so routine deinit cancels stay quiet. Opt into DEBUG to observe. */
    cfg.log_level = PUBNUB_LOG_LEVEL_DEBUG;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);
    memset(&s_abort_log_cap, 0, sizeof(s_abort_log_cap));

    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 0);
#if PUBNUB_LOG_ENABLED(DEBUG)
    assert_int_equal(s_abort_log_cap.count, 1);
    assert_int_equal(s_abort_log_cap.canceled, 1);
    assert_int_equal(s_abort_log_cap.failed, 0);
    assert_int_equal(s_abort_log_cap.result, PUBNUB_ERR_CANCELLED);
    assert_int_equal(s_abort_log_cap.slot_id, fut.slot_id);
#else
    assert_int_equal(s_abort_log_cap.count, 0);
#endif

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void abort_timeout_should_emit_error_fail_log(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = abort_capture_log, .set_level = NULL};
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.logger            = &logger;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);
    memset(&s_abort_log_cap, 0, sizeof(s_abort_log_cap));

    /* Timeout/transport aborts log at ERROR; ERROR passes the default
     * runtime level (INFO), so no log_level override is needed here. */
    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_TIMEOUT, 0);
#if PUBNUB_LOG_ENABLED(ERROR)
    assert_int_equal(s_abort_log_cap.count, 1);
    assert_int_equal(s_abort_log_cap.canceled, 0);
    assert_int_equal(s_abort_log_cap.failed, 1);
    assert_int_equal(s_abort_log_cap.result, PUBNUB_ERR_TIMEOUT);
    assert_int_equal(s_abort_log_cap.slot_id, fut.slot_id);
#else
    assert_int_equal(s_abort_log_cap.count, 0);
#endif

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void abort_noop_on_terminal_slot_should_not_emit(void** state)
{
    (void)state;
    pubnub_logger_provider_t logger = {.log = abort_capture_log, .set_level = NULL};
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    cfg.logger            = &logger;
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);
    pn_request_t*   slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    slot->state = PN_REQUEST_IN_FLIGHT;
    pn_request_on_success(slot, PUBNUB_OK);

    memset(&s_abort_log_cap, 0, sizeof(s_abort_log_cap));
    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 0);
    assert_int_equal(s_abort_log_cap.count, 0);

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static pubnub_future_t s_abort_release_future;
static int             s_abort_release_cb_fired;

static void abort_release_self_cb(pn_request_t* request,
                                  pubnub_res_t  status,
                                  void*         user_data)
{
    (void)request;
    (void)status;
    (void)user_data;
    s_abort_release_cb_fired = 1;
    /* Fires from Phase 3 of pn_request_abort while the slot is held in
     * COMPLETING. This stands in for a concurrent user-thread
     * pubnub_future_release racing the bg-thread abort: the release
     * must observe COMPLETING and defer rather than recycle the slot. */
    pubnub_future_release(s_abort_release_future);
}

static void abort_release_during_completing_should_defer_and_finalize(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);
    pn_request_t*   slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_non_null(slot);
    slot->on_complete = abort_release_self_cb;
    slot->user_data   = ctx;

    s_abort_release_future   = fut;
    s_abort_release_cb_fired = 0;

    /* The nested release defers (slot is COMPLETING); abort's Phase 4
     * finalize then honors the deferred release and recycles the slot
     * to IDLE exactly once -- no OOB read, no double release. */
    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_TIMEOUT, 0);

    assert_int_equal(s_abort_release_cb_fired, 1);
    assert_int_equal(slot->state, PN_REQUEST_IDLE);
    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void abort_timeout_should_preserve_result_over_cancelled_state(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);

    /* Abort with a non-cancel reason: the slot lands in CANCELLED but
     * result must stay PUBNUB_ERR_TIMEOUT. A completed-future status
     * read returns slot->result, not a state-derived code. */
    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_TIMEOUT, 0);

    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_non_null(slot);
    assert_int_equal(slot->state, PN_REQUEST_CANCELLED);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_TIMEOUT);

    pn_request_pool_release(pn_context_request_pool(ctx), fut.slot_id);
    pubnub_deinit(ctx);
    free_test_context(ctx);
}

static void abort_then_release_without_defer_should_recycle_to_idle(void** state)
{
    (void)state;
    pubnub_context_t* ctx = alloc_test_context();
    pubnub_config_t   cfg = valid_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    pubnub_future_t fut = abort_acquire_pending(ctx);

    /* No on_complete callback: abort finalizes to CANCELLED with
     * release_deferred == 0. The subsequent release is the sole
     * reclaim path -- complementary to the deferred-release finalize. */
    pn_request_abort(ctx, fut.slot_id, PN_GENERATION_ANY, PUBNUB_ERR_CANCELLED, 0);

    pn_request_t* slot =
        pn_request_pool_get(pn_context_request_pool(ctx), fut.slot_id);
    assert_non_null(slot);
    assert_int_equal(slot->state, PN_REQUEST_CANCELLED);
    assert_int_equal(slot->release_deferred, 0);
    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 1);

    pubnub_future_release(fut);

    assert_int_equal(slot->state, PN_REQUEST_IDLE);
    assert_int_equal(pn_context_request_pool(ctx)->in_use_count, 0);

    pubnub_deinit(ctx);
    free_test_context(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* config defaults */
        cmocka_unit_test(config_default_should_have_null_keys_and_valid_tunables),

        /* context size */
        cmocka_unit_test(context_size_should_return_nonzero),

        /* config validation */
        cmocka_unit_test(init_should_reject_null_context),
        cmocka_unit_test(init_should_reject_null_config),
        cmocka_unit_test(init_should_reject_null_subscribe_key),
        cmocka_unit_test(init_should_reject_empty_subscribe_key),
        cmocka_unit_test(init_should_reject_null_user_id),
        cmocka_unit_test(init_should_reject_empty_user_id),
        cmocka_unit_test(init_should_apply_default_when_timeouts_are_zero),
        cmocka_unit_test(init_should_accept_optional_publish_key),
        cmocka_unit_test(init_should_accept_optional_secret_key),

        /* origin resolution */
        cmocka_unit_test(init_should_resolve_null_origin_to_compile_time_default),
        cmocka_unit_test(init_should_resolve_empty_origin_to_compile_time_default),
        cmocka_unit_test(init_should_honour_custom_origin),
        cmocka_unit_test(init_should_reject_header_injection_origin),

        /* init/deinit lifecycle */
        cmocka_unit_test(init_should_succeed_with_valid_config),
        cmocka_unit_test(deinit_should_accept_null_context),
        cmocka_unit_test(deinit_should_accept_uninitialized_context),
        cmocka_unit_test(init_should_reject_double_init_without_deinit),
        cmocka_unit_test(init_should_succeed_after_deinit),

    /* create/destroy (heap) */
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(create_should_return_context_with_valid_config),
        cmocka_unit_test(create_should_return_null_for_null_config),
        cmocka_unit_test(create_should_return_null_for_invalid_config),
        cmocka_unit_test(destroy_should_accept_null_context),
        cmocka_unit_test(create_should_return_null_when_allocation_fails),
        cmocka_unit_test(create_should_free_context_when_provider_init_fails),
        cmocka_unit_test(create_should_deep_copy_custom_origin),
        cmocka_unit_test(create_should_deep_copy_filter_expression),
        cmocka_unit_test(init_should_borrow_filter_expression),
        cmocka_unit_test(create_should_deep_copy_resolved_default_origin),
        cmocka_unit_test(create_should_deep_copy_user_id),
        cmocka_unit_test(create_should_deep_copy_auth_token),
#endif

        /* provider validation — allocator */
        cmocka_unit_test(provider_should_reject_allocator_with_null_alloc),
        cmocka_unit_test(provider_should_reject_allocator_with_null_free),
        cmocka_unit_test(provider_should_reject_allocator_with_null_buf_acquire),
        cmocka_unit_test(provider_should_reject_allocator_with_null_buf_release),
        /* provider validation — transport */
        cmocka_unit_test(provider_should_reject_transport_with_null_send),
        cmocka_unit_test(provider_should_reject_transport_with_null_poll),
        cmocka_unit_test(provider_should_reject_transport_with_null_cancel),
        /* provider validation — serialization */
        cmocka_unit_test(provider_should_reject_serialization_with_null_parse),
        cmocka_unit_test(provider_should_reject_serialization_with_null_serialize),
        cmocka_unit_test(provider_should_reject_serialization_with_null_value_destroy),
        /* provider validation — platform */
        cmocka_unit_test(provider_should_reject_platform_with_null_monotonic_ms),
        cmocka_unit_test(provider_should_reject_platform_with_null_sleep_ms),
        cmocka_unit_test(provider_should_reject_platform_with_null_random_bytes),
        /* provider validation — optional */
        cmocka_unit_test(provider_should_treat_null_crypto_config_as_disabled),
        cmocka_unit_test(provider_should_allow_null_logger),
        /* provider validation — logger vtable */
        cmocka_unit_test(provider_should_tolerate_logger_with_null_log_callback),
        cmocka_unit_test(provider_should_tolerate_logger_with_null_set_level_callback),
        cmocka_unit_test(provider_logger_add_should_reject_null_provider),
        cmocka_unit_test(provider_logger_remove_should_reject_unknown_provider),
        /* provider validation — crypto fn ptrs */
        cmocka_unit_test(provider_should_accept_crypto_with_null_encrypt),
        cmocka_unit_test(provider_should_accept_crypto_with_null_decrypt),
        cmocka_unit_test(provider_should_accept_crypto_with_null_hmac),
        cmocka_unit_test(provider_should_accept_valid_crypto),

        /* provider init rollback (use setup to reset tracking globals) */
        cmocka_unit_test_setup(init_should_fail_when_transport_init_fails,
                               reset_tracking),
        cmocka_unit_test_setup(init_should_rollback_transport_when_serialization_init_fails,
                               reset_tracking),
#if PUBNUB_ENABLE_CRYPTO
        /* crypto_module init/deinit integration */
        cmocka_unit_test(init_should_store_crypto_module_pointer),
        cmocka_unit_test_setup(
            deinit_should_call_serial_and_transport_deinit_when_crypto_module_is_set,
            reset_tracking),
        cmocka_unit_test_setup(
            init_should_rollback_serial_and_transport_when_crypto_init_fails,
            reset_tracking),
        cmocka_unit_test_setup(init_deinit_should_call_cryptor_init_and_deinit,
                               reset_tracking),
#endif
        /* deinit provider callbacks */
        cmocka_unit_test_setup(deinit_should_call_provider_deinit_callbacks,
                               reset_tracking),

        /* pubnub_process */
        cmocka_unit_test(process_should_reject_null_context),
        cmocka_unit_test(process_should_reject_uninitialized_context),
        cmocka_unit_test(process_should_return_ok_after_init),
        cmocka_unit_test(process_should_reject_deinitialized_context),

        /* pipeline wiring */
        cmocka_unit_test(context_pipeline_should_return_null_when_ctx_is_null),
        cmocka_unit_test(context_pipeline_should_return_null_for_uninitialized),
        cmocka_unit_test(context_pipeline_should_return_valid_pointer_after_init),
        cmocka_unit_test(deinit_should_tear_down_pipeline),
        cmocka_unit_test(dispatch_through_context_should_reach_transport),
        cmocka_unit_test(set_user_id_should_propagate_to_middleware),
        cmocka_unit_test(set_auth_token_should_propagate_to_middleware),
        cmocka_unit_test(set_user_id_empty_should_be_rejected),
        cmocka_unit_test(set_user_id_should_reject_null),
        cmocka_unit_test(set_user_id_should_accept_single_char_id),
        cmocka_unit_test(set_user_id_should_accept_224_char_id),
        cmocka_unit_test(set_user_id_should_accept_500_char_id),
        cmocka_unit_test(set_user_id_should_accept_1000_char_id),
        cmocka_unit_test(init_should_accept_long_user_id),
        cmocka_unit_test(create_should_deep_copy_long_user_id),
        cmocka_unit_test(set_auth_token_empty_string_then_clear),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(dispatch_through_owned_context_should_reach_transport),
        cmocka_unit_test(set_user_id_should_propagate_on_owned_context),
        cmocka_unit_test(set_auth_token_should_propagate_on_owned_context),
        cmocka_unit_test(set_tls_ca_bundle_should_delegate_to_transport),
        cmocka_unit_test(set_tls_verify_should_delegate_to_transport),
        cmocka_unit_test(deprecated_tls_verify_alias_should_delegate),
        cmocka_unit_test(
            set_tls_ca_bundle_should_return_not_supported_when_transport_lacks_setter),
        cmocka_unit_test(
            set_tls_verify_should_return_not_supported_when_transport_lacks_setter),
        cmocka_unit_test(set_tls_ca_bundle_should_return_not_initialized_on_null_ctx),
        cmocka_unit_test(set_tls_verify_should_return_not_initialized_on_null_ctx),
#endif
        cmocka_unit_test(init_should_rollback_when_pool_init_fails),
        cmocka_unit_test(init_should_rollback_when_pending_queue_init_fails),
        cmocka_unit_test(init_should_rollback_when_pipeline_build_fails),

        /* request pool wiring */
        cmocka_unit_test(context_request_pool_should_return_null_when_ctx_is_null),
        cmocka_unit_test(context_request_pool_should_return_null_for_uninitialized),
        cmocka_unit_test(context_request_pool_should_size_at_compile_time_constant),
        cmocka_unit_test(deinit_should_tear_down_request_pool),
        cmocka_unit_test(future_ready_should_return_true_for_invalid_sentinel),
        cmocka_unit_test(future_status_should_return_invalid_argument_for_sentinel),
        cmocka_unit_test(future_ready_should_return_false_for_in_progress_slot),
        cmocka_unit_test(future_status_should_return_slot_result_when_terminal),
        cmocka_unit_test(future_status_should_return_not_initialized_for_deinited_ctx),

        /* pubnub_process + pubnub_future_release */
        cmocka_unit_test(process_should_dispatch_pending_slot_to_in_flight),
        cmocka_unit_test(process_should_route_sync_completion_to_slot_complete),
        cmocka_unit_test(process_should_route_sync_error_to_slot_failed),
        cmocka_unit_test(process_should_route_async_completion_on_next_tick),
        cmocka_unit_test(process_should_route_async_error_on_next_tick),
        cmocka_unit_test(process_should_return_ok_when_pool_is_idle),
        cmocka_unit_test(process_should_return_ok_when_only_terminal_slots),
        cmocka_unit_test(future_release_should_return_slot_to_pool),
        cmocka_unit_test(future_release_should_be_safe_on_invalid_sentinel),
        cmocka_unit_test(future_release_should_be_safe_on_immediate_failure_future),
        cmocka_unit_test(future_release_should_be_idempotent_on_already_idle_slot),
        cmocka_unit_test(cooperative_loop_should_complete_a_request_end_to_end),
        cmocka_unit_test(process_should_route_dispatch_failure_to_slot_failed),
        cmocka_unit_test(future_release_should_be_safe_after_ctx_deinit),
        cmocka_unit_test(process_should_call_transport_poll_with_zero_timeout),

        /* pubnub_res_str */
        cmocka_unit_test(res_str_should_return_non_null_for_all_committed_codes),
        cmocka_unit_test(res_str_should_return_unknown_for_gap_values),
        cmocka_unit_test(res_str_should_return_fallback_for_out_of_range),
        cmocka_unit_test(res_str_should_return_fallback_for_negative),
        cmocka_unit_test(res_str_should_return_fallback_past_highest_committed),
#if PUBNUB_CFG_RES_STR
        cmocka_unit_test(res_str_should_return_label_for_pubnub_ok),
        cmocka_unit_test(res_str_should_return_correct_strings_for_known_codes),
#else
        cmocka_unit_test(res_str_should_return_empty_when_disabled),
#endif

        /* log level */
        cmocka_unit_test(init_with_log_level_none_sets_silent_level),

        /* prep pool */
        cmocka_unit_test(init_should_rollback_when_prep_pool_alloc_fails),
        cmocka_unit_test(deinit_should_free_prep_pool),
        cmocka_unit_test(dispatch_failure_releases_prep_entry),
        cmocka_unit_test(process_promote_pending_relocates_scratch_correctly),

    /* feature capabilities */
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test(has_feature_time_returns_nonzero_when_enabled),
#endif

        /* dispatch edge cases */
        cmocka_unit_test(dispatch_uuid_value_matches_configured_user_id),
        cmocka_unit_test(dispatch_auth_empty_string_omits_auth_param),

        /* origin setter/getter */
        cmocka_unit_test(set_origin_should_reject_null_ctx),
        cmocka_unit_test(get_origin_should_return_null_for_null_ctx),
        cmocka_unit_test(set_origin_should_accept_custom_host),
        cmocka_unit_test(set_origin_null_should_reset_to_default),
        cmocka_unit_test(set_origin_empty_should_reset_to_default),
        cmocka_unit_test(set_origin_max_length_should_succeed),
        cmocka_unit_test(set_origin_overlength_should_be_rejected),
        cmocka_unit_test(set_origin_should_reject_header_injection),
        cmocka_unit_test(set_origin_failure_should_preserve_old_value),
        cmocka_unit_test(set_origin_init_lifecycle),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(set_origin_create_lifecycle),
        cmocka_unit_test(set_origin_create_buffer_independent),
#endif
        cmocka_unit_test(set_origin_repeated_sets),
        cmocka_unit_test(set_origin_after_deinit_should_fail),
        cmocka_unit_test(get_origin_should_return_default_after_init),
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test(set_origin_should_propagate_to_request),
        cmocka_unit_test(default_origin_should_propagate_to_request),
        cmocka_unit_test(set_origin_null_should_reset_to_default_in_request),
        cmocka_unit_test(set_origin_empty_should_reset_to_default_in_request),
        cmocka_unit_test(set_origin_change_should_affect_subsequent_requests),
#endif
        cmocka_unit_test(abort_cancelled_should_emit_debug_cancel_log),
        cmocka_unit_test(abort_timeout_should_emit_error_fail_log),
        cmocka_unit_test(abort_noop_on_terminal_slot_should_not_emit),
        cmocka_unit_test(abort_release_during_completing_should_defer_and_finalize),
        cmocka_unit_test(abort_timeout_should_preserve_result_over_cancelled_state),
        cmocka_unit_test(abort_then_release_without_defer_should_recycle_to_idle),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ======================================================================== */
/* Implementation: mock provider callbacks                                  */
/* ======================================================================== */

/* --- Allocator --------------------------------------------------------- */

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
    (void)purpose;
    pubnub_buffer_t buf = {NULL, 0, 0, purpose};
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    (void)buf;
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
    .buf_grow    = NULL,
};

/* --- OOM-after-N counting allocator --------------------------------------
 *
 * Used by init_should_rollback_when_pipeline_build_fails. Counts
 * successful alloc() calls and starts returning NULL after
 * s_oom_alloc_fail_after have succeeded (0 = fail on the first call,
 * -1 = never fail). All other callbacks mirror s_mock_allocator so
 * any layers that did succeed can still be freed during rollback. */

static void* oom_counting_alloc(pubnub_allocator_provider_t* self,
                                size_t                       size,
                                size_t                       align)
{
    (void)self;
    (void)align;
    if (s_oom_alloc_fail_after >= 0 && s_oom_alloc_count >= s_oom_alloc_fail_after) {
        return NULL;
    }
    void* p = test_malloc(size);
    if (p != NULL) {
        s_oom_alloc_count++;
    }
    return p;
}

static pubnub_allocator_provider_t s_oom_allocator = {
    .alloc       = oom_counting_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
    .buf_grow    = NULL,
};

/* --- Transport --------------------------------------------------------- */

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

/* --- Tracking transport used by the pipeline-integration tests.          -
 *
 * Captures the request it receives so tests can assert which query
 * params the middleware chain added, and returns a canned handle so
 * dispatch counts as "sent". Kept separate from s_mock_transport
 * (which returns NULL) to avoid perturbing the lifecycle tests. */

static pubnub_http_request_t   s_chain_captured_request;
static int                     s_chain_send_called;
static int                     s_chain_fake_handle_storage;
static pubnub_http_response_t* s_chain_last_response;
static int                     s_chain_complete_in_send;
static int                     s_chain_error_in_send;

/** Deep-copy buffer for query param views captured during chain_send.
 *  Middlewares may free heap-encoded buffers after send returns. */
static char   s_chain_param_buf[2048];
static size_t s_chain_param_buf_used;

static pubnub_transport_handle_t* chain_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    s_chain_send_called      = 1;
    s_chain_captured_request = *request;
    s_chain_param_buf_used   = 0;
    s_chain_last_response    = response;

    /* Deep-copy query param views into stable storage. */
    for (unsigned int i = 0; i < request->query_param_count; i++) {
        pubnub_kv_t* kv = &s_chain_captured_request.query_params[i];

        if (NULL != kv->key.ptr && kv->key.len > 0) {
            size_t needed = kv->key.len;
            if (s_chain_param_buf_used + needed <= sizeof(s_chain_param_buf)) {
                memcpy(s_chain_param_buf + s_chain_param_buf_used, kv->key.ptr, needed);
                kv->key.ptr = s_chain_param_buf + s_chain_param_buf_used;
                s_chain_param_buf_used += needed;
            }
        }

        if (NULL != kv->value.ptr && kv->value.len > 0) {
            size_t needed = kv->value.len;
            if (s_chain_param_buf_used + needed <= sizeof(s_chain_param_buf)) {
                memcpy(s_chain_param_buf + s_chain_param_buf_used,
                       kv->value.ptr,
                       needed);
                kv->value.ptr = s_chain_param_buf + s_chain_param_buf_used;
                s_chain_param_buf_used += needed;
            }
        }
    }

    if (s_chain_send_returns_null) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }
    if (s_chain_complete_in_send) {
        response->completion  = PUBNUB_HTTP_COMPLETE;
        response->status_code = 200;
    } else if (s_chain_error_in_send) {
        response->completion = PUBNUB_HTTP_ERROR;
    }
    return (pubnub_transport_handle_t*)&s_chain_fake_handle_storage;
}

static int chain_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    s_chain_poll_called       = 1;
    s_chain_poll_last_timeout = (int)timeout_ms;
    return 0;
}

static pubnub_transport_provider_t s_chain_transport = {
    .send              = chain_send,
    .poll              = chain_poll,
    .cancel            = mock_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

static void reset_chain_capture(void)
{
    memset(&s_chain_captured_request, 0, sizeof(s_chain_captured_request));
    s_chain_send_called       = 0;
    s_chain_last_response     = NULL;
    s_chain_complete_in_send  = 0;
    s_chain_error_in_send     = 0;
    s_chain_send_returns_null = 0;
    s_chain_poll_called       = 0;
    s_chain_poll_last_timeout = -1;
}

/* Helpers for tests that need to simulate async transport completion
 * between pubnub_process() ticks -- call after the first process
 * tick has dispatched the request and captured s_chain_last_response. */
static void chain_mark_complete(int status_code)
{
    if (s_chain_last_response != NULL) {
        s_chain_last_response->completion  = PUBNUB_HTTP_COMPLETE;
        s_chain_last_response->status_code = status_code;
    }
}

static void chain_mark_error(void)
{
    if (s_chain_last_response != NULL) {
        s_chain_last_response->completion = PUBNUB_HTTP_ERROR;
    }
}

static const pubnub_string_view_t* find_captured_param(const char* key)
{
    size_t key_len = strlen(key);
    for (unsigned int i = 0; i < s_chain_captured_request.query_param_count; i++) {
        if (s_chain_captured_request.query_params[i].key.len == key_len
            && memcmp(s_chain_captured_request.query_params[i].key.ptr, key, key_len)
                   == 0) {
            return &s_chain_captured_request.query_params[i].value;
        }
    }
    return NULL;
}

/* --- Serialization ----------------------------------------------------- */

static pubnub_json_value_t* mock_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return NULL;
}

static pubnub_res_t mock_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       val,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)val;
    (void)buf;
    (void)buf_len;
    (void)out_len;
    return PUBNUB_OK;
}

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             val)
{
    (void)self;
    (void)val;
}

static pubnub_serialization_provider_t s_mock_serialization = {
    .parse         = mock_parse,
    .serialize     = mock_serialize,
    .value_destroy = mock_value_destroy,
    .init          = NULL,
    .deinit        = NULL,
};

/* --- Platform ---------------------------------------------------------- */

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

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic_ms,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep_ms,
    .random_bytes  = mock_random_bytes,
    .secure_zero   = NULL,
};

/* --- Crypto ------------------------------------------------------------ */

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

static pubnub_crypto_provider_t s_mock_crypto = {
    .identifier   = {'T', 'E', 'S', 'T'},
    .encrypt_size = NULL,
    .encrypt      = mock_encrypt,
    .decrypt      = mock_decrypt,
    .hmac_sha256  = mock_hmac,
    .init         = NULL,
    .deinit       = NULL,
};

/* ======================================================================== */
/* Implementation: tracking callbacks and setup                             */
/* ======================================================================== */

static void tracking_transport_deinit(pubnub_transport_provider_t* self)
{
    (void)self;
    s_transport_deinit_seq = ++s_deinit_sequence;
}

static void tracking_serial_deinit(pubnub_serialization_provider_t* self)
{
    (void)self;
    s_serial_deinit_seq = ++s_deinit_sequence;
}

static void tracking_crypto_deinit(pubnub_crypto_provider_t* self)
{
    (void)self;
    s_crypto_deinit_seq = ++s_deinit_sequence;
}

static int reset_tracking(void** state)
{
    (void)state;
    s_deinit_sequence      = 0;
    s_transport_deinit_seq = 0;
    s_serial_deinit_seq    = 0;
    s_crypto_deinit_seq    = 0;
#if PUBNUB_ENABLE_CRYPTO
    s_cryptor_init_count   = 0;
    s_cryptor_deinit_count = 0;
#endif
    return 0;
}

/* ======================================================================== */
/* Implementation: failing init callbacks for rollback tests                */
/* ======================================================================== */

static int failing_transport_init(pubnub_transport_provider_t*  self,
                                  const pubnub_provider_deps_t* deps)
{
    (void)self;
    (void)deps;
    return -1;
}

static int failing_serial_init(pubnub_serialization_provider_t* self,
                               const pubnub_provider_deps_t*    deps)
{
    (void)self;
    (void)deps;
    return -1;
}

#if PUBNUB_ENABLE_CRYPTO
static int failing_cryptor_init(pubnub_crypto_provider_t*     self,
                                const pubnub_provider_deps_t* deps)
{
    (void)self;
    (void)deps;
    return -1;
}

static int tracking_cryptor_init(pubnub_crypto_provider_t*     self,
                                 const pubnub_provider_deps_t* deps)
{
    (void)self;
    (void)deps;
    ++s_cryptor_init_count;
    return 0;
}

static void tracking_cryptor_deinit_count(pubnub_crypto_provider_t* self)
{
    (void)self;
    ++s_cryptor_deinit_count;
}
#endif /* PUBNUB_ENABLE_CRYPTO */

static void* failing_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)size;
    (void)align;
    return NULL;
}

/* ======================================================================== */
/* Implementation: test helpers                                             */
/* ======================================================================== */

/**
 * Return a minimal valid config with all required providers set.
 *
 * Crypto is explicitly set to a valid mock because when
 * PUBNUB_HAS_DEFAULT_CRYPTO == 1 the stub backend resolves NULL to a
 * provider with NULL function pointers, which then fails validation.
 * Logger is left NULL — the stub logger default is valid (log==NULL
 * is acceptable since logger is optional).
 */
static pubnub_config_t valid_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-c-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_mock_allocator;
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = &s_mock_serialization;
    cfg.platform        = &s_mock_platform;
    cfg.logger          = NULL;
    return cfg;
}

static pubnub_context_t* alloc_test_context(void)
{
    size_t sz  = pubnub_context_size();
    void*  buf = test_calloc(1, sz);
    assert_non_null(buf);
    return (pubnub_context_t*)buf;
}

static void free_test_context(pubnub_context_t* ctx)
{
    test_free(ctx);
}
