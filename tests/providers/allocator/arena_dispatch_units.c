/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file providers/allocator/arena_dispatch_units.c
 * @brief End-to-end feature dispatch under the arena allocator.
 *
 * The feature unit tests run against the stdlib allocator. This binary
 * re-exercises representative operations (time, publish GET/POST,
 * history, subscribe) with a caller-owned arena allocator injected via
 * @c pubnub_config_t::allocator, driving each through a capturing mock
 * transport. It catches allocator-tier misuse that only surfaces on the
 * arena backend: a feature that acquires per-request working memory
 * through the general @c alloc tier (bump pointer, never reclaimed until
 * rotation) instead of the purpose-tagged @c buf_acquire tier (Zone A
 * slots, released per request) would leak Zone A / Zone B here even
 * though it looks correct against stdlib malloc.
 *
 * The binary is built only when @c PUBNUB_PROVIDER_ALLOCATOR=arena, which
 * on this SDK implies the embedded profile and @c PUBNUB_CFG_NO_HEAP=1 —
 * hence the caller-provided @c pubnub_init / @c pubnub_deinit lifecycle
 * and a static context buffer.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/pubnub_compat.h"
#include "pubnub/providers/allocator_arena.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "pubnub/features/publish.h"
#include "pubnub/features/subscribe.h"
#if PUBNUB_ENABLE_HISTORY
#include "pubnub/features/history.h"
#endif
#if PUBNUB_ENABLE_TIME
#include "pubnub/features/time.h"
#endif

#include "core/core_internal.h"
#include "core/runtime/request_pool_internal.h"

#define MAX_CAPTURES 8

typedef struct send_capture {
    pubnub_http_request_t*  request;
    pubnub_http_response_t* response;
} send_capture_t;

static int            s_send_count;
static int            s_in_flight;
static send_capture_t s_captures[MAX_CAPTURES];
static int            s_fake_handle_storage[MAX_CAPTURES];

static pubnub_arena_allocator_t s_arena;
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_pool[PUBNUB_CFG_ARENA_POOL_SIZE];
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

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

/**
 * @brief Assert every Zone A slot (RX, OBJ, SCRATCH) is free.
 *
 * Fresh per-request working memory lives in Zone A and MUST be released
 * once a request completes. A non-free slot here means a feature either
 * failed to release a @c buf_acquire buffer or routed per-request memory
 * through the wrong tier.
 */
static void assert_arena_zone_a_free(void)
{
    size_t i;
    for (i = 0; i < (size_t)PUBNUB_ARENA_RX_SLOTS; ++i) {
        assert_int_equal(0, s_arena.rx_in_use[i]);
    }
    for (i = 0; i < (size_t)PUBNUB_ARENA_OBJ_SLOTS; ++i) {
        assert_int_equal(0, s_arena.obj_in_use[i]);
    }
    for (i = 0; i < (size_t)PUBNUB_ARENA_SCRATCH_SLOTS; ++i) {
        assert_int_equal(0, s_arena.scratch_in_use[i]);
    }
}

static uint16_t pool_in_use(pubnub_context_t* ctx)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);
    return pool->in_use_count;
}

/**
 * @brief Initialize a context backed by a freshly reset arena allocator.
 *
 * Re-initializing the arena on every call discards any prior allocations,
 * so each test starts from a clean Zone A / Zone B.
 */
static pubnub_context_t* arena_ctx_init(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.publish_key     = "pub-test";
    cfg.user_id         = "tester";
    cfg.transport       = &s_chain_transport;
    cfg.allocator = pubnub_arena_allocator_init(&s_arena, s_pool, sizeof(s_pool));
    assert_non_null(cfg.allocator);

    assert_true(pubnub_context_size() <= sizeof(s_ctx_mem));
    pubnub_context_t* ctx = (pubnub_context_t*)s_ctx_mem;
    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));
    return ctx;
}

static pubnub_publish_opts_t publish_opts(void)
{
    pubnub_publish_opts_t opts = PUBNUB_PUBLISH_OPTS_INIT;
    opts.channel               = "ch";
    opts.message               = "\"hello\"";
    return opts;
}

static void drive_publish_cycle(pubnub_context_t* ctx)
{
    static const uint8_t  k_pub_body[] = "[1,\"Sent\",\"17001000000000001\"]";
    pubnub_publish_opts_t opts         = publish_opts();

    reset_chain();
    pubnub_future_t fut = pubnub_publish(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_pub_body, sizeof(k_pub_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));
    pubnub_future_release(fut);
}

#if PUBNUB_ENABLE_TIME
static void drive_time_cycle(pubnub_context_t* ctx)
{
    static const uint8_t k_time_body[] = "[17001000000000001]";

    reset_chain();
    pubnub_future_t fut = pubnub_time(ctx);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_time_body, sizeof(k_time_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));
    pubnub_future_release(fut);
}

static void test_arena_time_dispatch(void** state)
{
    (void)state;
    pubnub_context_t* ctx = arena_ctx_init();

    drive_time_cycle(ctx);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}
#endif /* PUBNUB_ENABLE_TIME */

static void test_arena_publish_get_dispatch(void** state)
{
    (void)state;
    pubnub_context_t* ctx = arena_ctx_init();

    drive_publish_cycle(ctx);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}

static void test_arena_publish_post_dispatch(void** state)
{
    (void)state;
    static const uint8_t k_pub_body[] = "[1,\"Sent\",\"17001000000000001\"]";
    pubnub_context_t*    ctx          = arena_ctx_init();

    /* POST exercises the OBJ buffer tier (request body) that a GET does
     * not; a mis-tiered body buffer would strand an OBJ slot here. */
    pubnub_publish_opts_t opts = publish_opts();
    opts.method                = PUBNUB_PUBLISH_METHOD_POST;

    reset_chain();
    pubnub_future_t fut = pubnub_publish(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_pub_body, sizeof(k_pub_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));
    pubnub_future_release(fut);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}

#if PUBNUB_ENABLE_HISTORY
static void test_arena_history_dispatch(void** state)
{
    (void)state;
    static const uint8_t k_fetch_body[] =
        "{\"status\":200,\"channels\":{\"ch1\":["
        "{\"message\":\"hi\",\"timetoken\":\"17001000000000001\"}]}}";
    pubnub_context_t* ctx = arena_ctx_init();

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = "ch1";

    reset_chain();
    pubnub_future_t fut = pubnub_fetch_messages(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);

    chain_complete_with(0, k_fetch_body, sizeof(k_fetch_body) - 1);
    (void)pubnub_process(ctx);

    assert_true(pubnub_future_is_ready(fut));
    assert_int_equal(PUBNUB_OK, pubnub_future_status(fut));

    /* Result views alias arena memory; read before release. */
    pubnub_fetch_messages_result_t result = pubnub_fetch_messages_result(fut);
    assert_int_equal(1, result.channel_count);
    pubnub_future_release(fut);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}
#endif /* PUBNUB_ENABLE_HISTORY */

static void test_arena_subscribe_one_cycle(void** state)
{
    (void)state;
    static const uint8_t k_handshake[] =
        "{\"t\":{\"t\":\"17009999999999999\",\"r\":7},\"m\":[]}";
    pubnub_context_t* ctx = arena_ctx_init();

    pubnub_entity_t entity = pubnub_channel(ctx, "ch");
    assert_non_null(entity);
    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    assert_non_null(sub);

    reset_chain();
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub));

    /* Drive the handshake request out to the transport. */
    (void)pubnub_process(ctx);
    assert_true(s_send_count >= 1);

    /* Complete the handshake; the arena served the subscribe request's
     * working buffers without exhaustion. */
    chain_complete_with(0, k_handshake, sizeof(k_handshake) - 1);
    (void)pubnub_process(ctx);

    /* Stop the subscribe loop and cancel any in-flight receive so Zone A
     * can drain, then verify the slots recycled. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub));
    (void)pubnub_process(ctx);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}

/**
 * @brief Subscribe long-poll RX buffers must recycle across receive cycles.
 *
 * The original smoking gun for the slot-release ordering fix: a completed
 * long-poll's pool slot is reaped on the NEXT receive re-dispatch, not on
 * completion. If the slot is released before its transport handle is
 * cancelled, the retry lookup misses (generation already bumped) and the
 * inner handle plus its RX buffer are stranded. After PUBNUB_ARENA_RX_SLOTS
 * (== MAX_IN_FLIGHT == 2) leaked cycles, every RX slot is exhausted and no
 * further receive can acquire working memory. Driving >2 receive cycles and
 * asserting a free RX slot each time — plus a live buf_acquire(RX) after
 * cycle 3+ — fails pre-fix and passes post-fix.
 */
static void test_arena_subscribe_rx_recycles_across_cycles(void** state)
{
    (void)state;
    static const uint8_t k_handshake[] =
        "{\"t\":{\"t\":\"17009999999999999\",\"r\":7},\"m\":[]}";
    static const uint8_t k_receive[] =
        "{\"t\":{\"t\":\"17010000000000000\",\"r\":7},\"m\":[]}";
    pubnub_context_t* ctx = arena_ctx_init();
    int               cycle;
    int               sends_before_loop;

    pubnub_entity_t entity = pubnub_channel(ctx, "ch");
    assert_non_null(entity);
    pubnub_subscription_t sub = pubnub_subscription_create(entity, NULL);
    assert_non_null(sub);

    reset_chain();
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub));

    /* Handshake out, then completed; the first receive re-dispatches. */
    (void)pubnub_process(ctx);
    assert_true(s_send_count >= 1);
    chain_complete_with(0, k_handshake, sizeof(k_handshake) - 1);
    (void)pubnub_process(ctx);
    sends_before_loop = s_send_count;

    for (cycle = 0; cycle < 4; ++cycle) {
        int    free_rx = 0;
        size_t i;

        /* Complete the current in-flight receive; the next process reaps its
         * slot + RX and re-dispatches the successor long-poll. */
        chain_complete_with(s_send_count - 1, k_receive, sizeof(k_receive) - 1);
        (void)pubnub_process(ctx);

        for (i = 0; i < (size_t)PUBNUB_ARENA_RX_SLOTS; ++i) {
            if (0 == s_arena.rx_in_use[i]) {
                free_rx = 1;
            }
        }
        assert_int_equal(1, free_rx);
    }

    /* Guard against a stalled EE masking the recycle check: each cycle must
     * have re-dispatched a fresh receive. */
    assert_true(s_send_count >= sends_before_loop + 4);

    /* Smoking gun: a fresh RX acquisition still succeeds after cycle 3+. */
    pubnub_allocator_provider_t* alloc = pn_context_allocator(ctx);
    assert_non_null(alloc);
    pubnub_buffer_t rx = alloc->buf_acquire(alloc, PUBNUB_BUF_RX);
    assert_non_null(rx.data);
    alloc->buf_release(alloc, &rx);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub));
    (void)pubnub_process(ctx);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(entity);

    assert_int_equal(0, pool_in_use(ctx));
    assert_arena_zone_a_free();

    pubnub_deinit(ctx);
}

#if PUBNUB_ENABLE_TIME
static void test_arena_multi_op_sequence_recycles(void** state)
{
    (void)state;
    pubnub_context_t* ctx = arena_ctx_init();

    /* time -> publish -> time -> publish on one context. Each cycle
     * completes and releases; if any op stranded a slot, a later op would
     * find Zone A partially occupied and eventually fail to acquire. */
    drive_time_cycle(ctx);
    assert_arena_zone_a_free();

    drive_publish_cycle(ctx);
    assert_arena_zone_a_free();

    drive_time_cycle(ctx);
    assert_arena_zone_a_free();

    drive_publish_cycle(ctx);
    assert_arena_zone_a_free();

    assert_int_equal(0, pool_in_use(ctx));

    pubnub_deinit(ctx);
}
#endif /* PUBNUB_ENABLE_TIME */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test(test_arena_time_dispatch),
#endif
        cmocka_unit_test(test_arena_publish_get_dispatch),
        cmocka_unit_test(test_arena_publish_post_dispatch),
#if PUBNUB_ENABLE_HISTORY
        cmocka_unit_test(test_arena_history_dispatch),
#endif
        cmocka_unit_test(test_arena_subscribe_one_cycle),
        cmocka_unit_test(test_arena_subscribe_rx_recycles_across_cycles),
#if PUBNUB_ENABLE_TIME
        cmocka_unit_test(test_arena_multi_op_sequence_recycles),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
