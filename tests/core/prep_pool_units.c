/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file prep_pool_units.c
 * @brief Unit tests for the prep-pool mechanism (pn_prep_acquire,
 *        pn_prep_release, pn_feature_prepare, pn_feature_prep_release).
 *
 * The prep pool is the only pool in the codebase without its own
 * dedicated test file.  These tests exercise acquire/release semantics,
 * OOM rollback, double-release safety, and feature-level lifecycle.
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
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "core/core_internal.h"
#include "core/runtime/pending_queue_internal.h"

/* OOM-after-N counting allocator. */
static int s_alloc_count;
static int s_alloc_fail_after; /* -1 = never fail. */

static void* oom_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    if (s_alloc_fail_after >= 0 && s_alloc_count >= s_alloc_fail_after) {
        return NULL;
    }
    void* p = malloc(size);
    if (NULL != p) {
        s_alloc_count++;
    }
    return p;
}

static void* stdlib_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* stdlib_realloc(pubnub_allocator_provider_t* self,
                            void*                        ptr,
                            size_t                       old_size,
                            size_t                       new_size,
                            size_t                       align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return realloc(ptr, new_size);
}

static void stdlib_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t stdlib_buf_acquire(pubnub_allocator_provider_t* self,
                                          pubnub_buf_purpose_t         purpose)
{
    pubnub_buffer_t buf = {0};
    (void)self;
    buf.data    = (uint8_t*)malloc(4096);
    buf.cap     = buf.data ? 4096 : 0;
    buf.len     = 0;
    buf.purpose = purpose;
    return buf;
}

static void stdlib_buf_release(pubnub_allocator_provider_t* self,
                               pubnub_buffer_t*             buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->cap  = 0;
    }
}

static int stdlib_buf_grow(pubnub_allocator_provider_t* self,
                           pubnub_buffer_t*             buf,
                           size_t                       new_cap)
{
    uint8_t* grown;
    (void)self;
    if (NULL == buf || new_cap <= buf->cap) {
        return -1;
    }
    grown = (uint8_t*)realloc(buf->data, new_cap);
    if (NULL == grown) {
        return -1;
    }
    buf->data = grown;
    buf->cap  = new_cap;
    return 0;
}

static pubnub_allocator_provider_t s_allocator = {
    .alloc       = stdlib_alloc,
    .realloc     = stdlib_realloc,
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
    .buf_grow    = stdlib_buf_grow,
};

static pubnub_allocator_provider_t s_oom_allocator = {
    .alloc       = oom_alloc,
    .realloc     = NULL,
    .free        = stdlib_free,
    .buf_acquire = stdlib_buf_acquire,
    .buf_release = stdlib_buf_release,
    .buf_grow    = NULL,
};

/* Transport: no-op stubs. */
static pubnub_transport_handle_t* stub_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return NULL;
}

static int stub_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void stub_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   h)
{
    (void)self;
    (void)h;
}

static pubnub_transport_provider_t s_stub_transport = {
    .send              = stub_send,
    .poll              = stub_poll,
    .cancel            = stub_cancel,
    .init              = NULL,
    .deinit            = NULL,
    .set_dns_servers   = NULL,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/* Serialization: minimal stubs. */
static int s_stub_tree_backing;

static pubnub_json_value_t* stub_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return (pubnub_json_value_t*)&s_stub_tree_backing;
}

static pubnub_res_t stub_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    *out_len = 0;
    return PUBNUB_OK;
}

static void stub_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_stub_serialization = {
    .parse         = stub_parse,
    .serialize     = stub_serialize,
    .value_destroy = stub_value_destroy,
};

/* Platform: minimal stubs. */
static pubnub_milliseconds_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static pubnub_milliseconds_t mock_wall_clock(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static void mock_sleep(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int mock_random(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0, len);
    return 0;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
    .secure_zero   = NULL,
    .lock_size     = NULL,
    .lock_init     = NULL,
    .lock_destroy  = NULL,
    .lock_acquire  = NULL,
    .lock_release  = NULL,
    .thread_create = NULL,
    .thread_join   = NULL,
};

static pubnub_config_t test_config(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "prep-pool-tester";
    cfg.allocator       = &s_allocator;
    cfg.transport       = &s_stub_transport;
    cfg.serialization   = &s_stub_serialization;
    cfg.platform        = &s_mock_platform;
    return cfg;
}

static int reset_test(void** state)
{
    (void)state;
    s_alloc_count      = 0;
    s_alloc_fail_after = -1;
    return 0;
}

/* Cleanup stub for feature state. */
static int s_cleanup_called;

static void mock_cleanup(void* fstate, pubnub_allocator_provider_t* alloc)
{
    s_cleanup_called++;
    if (NULL != alloc && NULL != fstate) {
        PN_FREE(alloc, fstate);
    }
}

/* Dummy response validator that always succeeds. */
static pubnub_res_t mock_validator(const uint8_t* body, size_t len, int status_code)
{
    (void)body;
    (void)len;
    (void)status_code;
    return PUBNUB_OK;
}

#if PUBNUB_CFG_NO_HEAP
static void tests_require_hosted_heap_allocation(void** state)
{
    (void)state;
}
#endif

#if !PUBNUB_CFG_NO_HEAP

/**
 * Acquire all N prep entries, verify next acquire returns NULL.
 */
static void acquire_all_n_returns_null_on_overflow(void** state)
{
    (void)state;
    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }

    /* Pool is full; next acquire must return NULL. */
    pn_pending_entry_t* overflow = pn_prep_acquire(ctx);
    assert_null(overflow);

    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * Acquire all, release one, re-acquire succeeds.
 */
static void release_then_reacquire_succeeds(void** state)
{
    (void)state;
    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }

    /* Release the first entry and re-acquire. */
    pn_prep_release(ctx, entries[0]);
    pn_pending_entry_t* recycled = pn_prep_acquire(ctx);
    assert_non_null(recycled);

    /* Clean up all. */
    pn_prep_release(ctx, recycled);
    for (int i = 1; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * pn_feature_prepare + pn_feature_prep_release frees both state and slot.
 */
static void feature_prep_release_frees_state_and_slot(void** state)
{
    (void)state;
    s_cleanup_called = 0;

    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_feature_prep_t prep = {0};
    pubnub_res_t      rc   = pn_feature_prepare(ctx,
                                         1,  /* feature_id */
                                         64, /* state_size */
                                         mock_cleanup,
                                         mock_validator,
                                         PUBNUB_HTTP_GET,
                                         0, /* timeout_ms */
                                         &prep);
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(prep.entry);
    assert_non_null(prep.state);

    /* Release the prep entry manually (simulating error path). */
    pn_feature_prep_release(ctx, &prep);
    assert_int_equal(s_cleanup_called, 1);
    assert_null(prep.entry);

    /* Verify all N slots are available again. */
    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * When allocator fails on state alloc inside pn_feature_prepare, the
 * prep slot is released so all N entries remain acquirable.
 */
static void feature_prepare_oom_releases_slot(void** state)
{
    (void)state;

    pubnub_config_t cfg = test_config();
    cfg.allocator       = &s_oom_allocator;
    s_alloc_count       = 0;
    /* Let the context creation / init succeed (needs many allocs),
     * then fail specifically during pn_feature_prepare's state alloc.
     * Use a very high threshold first so create/init succeeds. */
    s_alloc_fail_after = -1;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Now set OOM to trigger on the very next alloc. This will fail
     * the feature-state allocation inside pn_feature_prepare. */
    s_alloc_fail_after = s_alloc_count;

    pn_feature_prep_t prep = {0};
    pubnub_res_t      rc   = pn_feature_prepare(
        ctx, 1, 64, mock_cleanup, mock_validator, PUBNUB_HTTP_GET, 0, &prep);
    assert_int_equal(rc, PUBNUB_ERR_OUT_OF_MEMORY);

    /* The prep slot should have been released. Verify all N are free. */
    s_alloc_fail_after = -1; /* Allow alloc again for cleanup. */
    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * Releasing the same entry twice must not crash or corrupt state.
 */
static void double_release_is_safe(void** state)
{
    (void)state;
    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pn_pending_entry_t* entry = pn_prep_acquire(ctx);
    assert_non_null(entry);

    pn_prep_release(ctx, entry);
    /* Second release: pointer is within the prep_entries array range,
     * but the slot is already marked free. Must not crash. */
    pn_prep_release(ctx, entry);

    pubnub_destroy(ctx);
}

/**
 * pn_prep_release(ctx, NULL) and pn_feature_prep_release(ctx, NULL)
 * must be no-ops.
 */
static void release_null_entry_is_safe(void** state)
{
    (void)state;
    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Direct NULL release. */
    pn_prep_release(ctx, NULL);

    /* Feature-level NULL release. */
    pn_feature_prep_release(ctx, NULL);

    /* Also test with zeroed prep struct (entry is NULL). */
    pn_feature_prep_t prep = {0};
    pn_feature_prep_release(ctx, &prep);

    pubnub_destroy(ctx);
}

/**
 * Loop 100 times: acquire, release. Verify all N still acquirable.
 */
static void acquire_release_cycle_100x_no_leak(void** state)
{
    (void)state;
    pubnub_config_t   cfg = test_config();
    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    for (int cycle = 0; cycle < 100; cycle++) {
        pn_pending_entry_t* entry = pn_prep_acquire(ctx);
        assert_non_null(entry);
        pn_prep_release(ctx, entry);
    }

    /* Verify all N slots are still free. */
    pn_pending_entry_t* entries[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        entries[i] = pn_prep_acquire(ctx);
        assert_non_null(entries[i]);
    }
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; i++) {
        pn_prep_release(ctx, entries[i]);
    }
    pubnub_destroy(ctx);
}

/**
 * After pubnub_deinit, pn_prep_acquire returns NULL because the
 * context is no longer initialized.
 */
static void acquire_after_deinit_returns_null(void** state)
{
    (void)state;
    size_t sz  = pubnub_context_size();
    void*  buf = calloc(1, sz);
    assert_non_null(buf);
    pubnub_context_t* ctx = (pubnub_context_t*)buf;

    pubnub_config_t cfg = test_config();
    assert_int_equal(pubnub_init(ctx, &cfg), PUBNUB_OK);

    /* Verify acquire works while initialized. */
    pn_pending_entry_t* entry = pn_prep_acquire(ctx);
    assert_non_null(entry);
    pn_prep_release(ctx, entry);

    pubnub_deinit(ctx);

    /* After deinit, acquire must return NULL. */
    pn_pending_entry_t* after_deinit = pn_prep_acquire(ctx);
    assert_null(after_deinit);

    free(buf);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test_setup(acquire_all_n_returns_null_on_overflow, reset_test),
        cmocka_unit_test_setup(release_then_reacquire_succeeds, reset_test),
        cmocka_unit_test_setup(feature_prep_release_frees_state_and_slot, reset_test),
        cmocka_unit_test_setup(feature_prepare_oom_releases_slot, reset_test),
        cmocka_unit_test_setup(double_release_is_safe, reset_test),
        cmocka_unit_test_setup(release_null_entry_is_safe, reset_test),
        cmocka_unit_test_setup(acquire_release_cycle_100x_no_leak, reset_test),
        cmocka_unit_test_setup(acquire_after_deinit_returns_null, reset_test),
#else
        cmocka_unit_test(tests_require_hosted_heap_allocation),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
