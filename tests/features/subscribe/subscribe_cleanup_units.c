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

#include "features/subscribe/subscribe_manager_internal.h"
#if PUBNUB_ENABLE_PRESENCE
#include "features/presence/presence_manager.h"
#endif
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "pubnub/client.h"
#include "pubnub/features/subscribe.h"

/* Live-allocation counter: a portable leak check independent of sanitizer
 * leak detection (unavailable on some hosts). Must reach zero after teardown. */
static int s_live_allocs;

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    void* ptr;

    (void)self;
    (void)align;
    ptr = malloc(size);
    if (NULL != ptr) {
        s_live_allocs++;
    }
    return ptr;
}

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    if (NULL != ptr) {
        s_live_allocs--;
    }
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    (void)purpose;
    pubnub_buffer_t buf = {0};
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    (void)buf;
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
};

static uint64_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static uint64_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
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
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
};

static int s_cancel_called;

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
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
    s_cancel_called = 1;
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

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
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    if (NULL != out_len) {
        *out_len = 0;
    }
    return PUBNUB_OK;
}

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_mock_serialization = {
    .parse         = mock_parse,
    .serialize     = mock_serialize,
    .value_destroy = mock_value_destroy,
};

#if !PUBNUB_CFG_NO_HEAP
static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    /* Reset so the post-destroy assertion covers the whole lifecycle. */
    s_live_allocs     = 0;
    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_mock_platform;
    return pubnub_create(&cfg);
}

/* Cleanup with no active request does not crash. */
static void test_cleanup_no_active_request(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_SLOT_ID_INVALID, mgr->active_slot_id);
    assert_int_equal(0, mgr->draining);

    pn_subscribe_manager_cleanup(mgr, &s_mock_allocator);
    pubnub_destroy(ctx);
}

/* Cleanup sets draining=1 and cancels pending slots. */
static void test_cleanup_sets_draining(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, &s_mock_allocator);
    assert_non_null(mgr);

    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    assert_non_null(pool);

    pubnub_future_t future = {0};
    pubnub_res_t    rc     = pn_request_pool_acquire(pool, ctx, &future);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_not_equal(PUBNUB_SLOT_ID_INVALID, future.slot_id);

    mgr->active_slot_id = future.slot_id;

    s_cancel_called = 0;
    pn_subscribe_manager_cleanup(mgr, &s_mock_allocator);

    /* PENDING slot is aborted, not transport-cancelled (cancel is
     * IN_FLIGHT-only). */
    assert_int_equal(0, s_cancel_called);

    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

/* Cleanup handles NULL state gracefully. */
static void test_cleanup_null_state(void** state)
{
    (void)state;
    pn_subscribe_manager_cleanup(NULL, &s_mock_allocator);
    pn_subscribe_manager_cleanup((void*)0x1, NULL);
}

#if !PUBNUB_CFG_NO_HEAP
static void unsubscribe_all_on_idle_context_returns_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_res_t rc = pubnub_subscribe_unsubscribe_all(ctx);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_destroy(ctx);
}

static void subscription_unsubscribe_before_subscribe_returns_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t sub = pubnub_subscription_create(e, NULL);
    assert_non_null(sub);

    pubnub_res_t rc = pubnub_subscription_unsubscribe(sub);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}

static void subscription_set_add_subscription_before_subscribe_ok(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);

    pubnub_res_t rc = pubnub_subscription_set_add_subscription(set, sub);
    assert_int_equal(PUBNUB_OK, rc);

    pubnub_subscription_destroy(sub);
    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}

/* restore saves the cursor; event processing in UNSUBSCRIBED state does
 * not clear it. */
static void subscription_restore_then_subscribe_preserves_timetoken(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    /* Creating an entity triggers lazy manager registration. */
    pubnub_entity_t       e   = pubnub_channel(ctx, "ch");
    pubnub_subscription_t sub = pubnub_subscription_create(e, NULL);
    assert_non_null(sub);

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    assert_int_equal(PN_SUBSCRIBE_STATE_UNSUBSCRIBED, mgr->ee_state);

    /* Restore with a known timetoken. */
    pubnub_timetoken_t tt = {.ptr = "17000000000000001", .len = 17};
    pubnub_res_t       rc = pubnub_subscribe_restore(ctx, tt);
    assert_int_equal(PUBNUB_OK, rc);

    /* Cursor stored immediately. */
    assert_int_equal(1, mgr->restore_cursor_valid);
    assert_int_equal(17, mgr->cursor.timetoken_len);
    assert_memory_equal("17000000000000001", mgr->cursor.timetoken, 17);

    /* Drive the cooperative loop to process the queued
     * SUBSCRIPTION_RESTORED event (stays in UNSUBSCRIBED because
     * subscription_subscribe was not called). */
    pubnub_process(ctx);

    /* Cursor must survive — old code cleared it here. */
    assert_int_equal(1, mgr->restore_cursor_valid);
    assert_memory_equal("17000000000000001", mgr->cursor.timetoken, 17);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
}

/* A destroyed subscription that is still a set member stays alive and is
 * returned by the member getter until the set releases it. */
static void subscription_handle_alive_in_set_after_destroy(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "ch-alive");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));

    pubnub_subscription_destroy(sub);

    pubnub_subscription_t members[4] = {0};
    size_t                n          = 0;
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_subscriptions(set, members, 4, &n));
    assert_int_equal(1, n);
    assert_non_null(members[0]);

    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* The member getter returns only the set's real members, not unrelated
 * standalone subscriptions resolving to other entries. */
static void subscription_set_getter_returns_only_members(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ea  = pubnub_channel(ctx, "a");
    pubnub_entity_t           eb  = pubnub_channel(ctx, "b");
    pubnub_entity_t           ec  = pubnub_channel(ctx, "c");
    pubnub_subscription_t     s1  = pubnub_subscription_create(ea, NULL);
    pubnub_subscription_t     s2  = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_t     s3  = pubnub_subscription_create(ec, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(s1);
    assert_non_null(s2);
    assert_non_null(s3);
    assert_non_null(set);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s1));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s2));

    pubnub_subscription_t members[8] = {0};
    size_t                n          = 0;
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_subscriptions(set, members, 8, &n));
    assert_int_equal(2, n);

    size_t i;
    for (i = 0; i < n; ++i) {
        assert_ptr_not_equal(members[i], s3);
    }

    pubnub_subscription_destroy(s1);
    pubnub_subscription_destroy(s2);
    pubnub_subscription_destroy(s3);
    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_entity_destroy(ec);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* The member getter reports the full count and PUBNUB_ERR_BUFFER_TOO_SMALL
 * when the buffer cannot hold every member. */
static void subscription_set_getter_buffer_too_small(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ea  = pubnub_channel(ctx, "a");
    pubnub_entity_t           eb  = pubnub_channel(ctx, "b");
    pubnub_subscription_t     s1  = pubnub_subscription_create(ea, NULL);
    pubnub_subscription_t     s2  = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s1));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s2));

    pubnub_subscription_t members[1] = {0};
    size_t                n          = 0;
    assert_int_equal(PUBNUB_ERR_BUFFER_TOO_SMALL,
                     pubnub_subscription_set_subscriptions(set, members, 1, &n));
    assert_int_equal(2, n);

    pubnub_subscription_destroy(s1);
    pubnub_subscription_destroy(s2);
    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* Two handles resolving to the same entry contribute only one active share
 * for that entry in a subscribed set. */
static void subscription_set_active_share_once_per_entry(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e  = pubnub_channel(ctx, "dup");
    pubnub_subscription_t s1 = pubnub_subscription_create(e, NULL);
    pubnub_subscription_t s2 = pubnub_subscription_create(e, NULL);
    assert_non_null(s1);
    assert_non_null(s2);
    assert_int_equal(s1->entry_index, s2->entry_index);

    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s1));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s2));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    assert_int_equal(1, mgr->entries[s1->entry_index].active_count);

    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(s1);
    pubnub_subscription_destroy(s2);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* Adding the same handle twice is a no-op (membership dedup is by handle,
 * not by entry). */
static void subscription_set_duplicate_handle_add_is_noop(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "ch-dup");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    uint16_t count_before = mgr->sets[set->set_index].count;

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));
    assert_int_equal(count_before, mgr->sets[set->set_index].count);

    pubnub_subscription_destroy(sub);
    pubnub_subscription_set_destroy(set);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* A handle shared by two sets survives removal from one set; the other set
 * still owns and returns it. */
static void subscription_shared_handle_survives_single_remove(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e     = pubnub_channel(ctx, "shared");
    pubnub_subscription_t     sub   = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set_a = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t set_b = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set_a, sub));
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set_b, sub));

    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_remove_subscription(set_a, sub));

    pubnub_subscription_t members[4] = {0};
    size_t                n          = 0;
    assert_int_equal(
        PUBNUB_OK, pubnub_subscription_set_subscriptions(set_b, members, 4, &n));
    assert_int_equal(1, n);

    n = 0;
    assert_int_equal(
        PUBNUB_OK, pubnub_subscription_set_subscriptions(set_a, members, 4, &n));
    assert_int_equal(0, n);

    pubnub_subscription_destroy(sub);
    pubnub_subscription_set_destroy(set_a);
    pubnub_subscription_set_destroy(set_b);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* Context teardown releases subscriptions and sets still allocated at
 * destroy time without leaks (live-allocation counter returns to zero). */
static void context_teardown_releases_live_handles_and_sets(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e1  = pubnub_channel(ctx, "t1");
    pubnub_entity_t           e2  = pubnub_channel(ctx, "t2");
    pubnub_subscription_t     s1  = pubnub_subscription_create(e1, NULL);
    pubnub_subscription_t     s2  = pubnub_subscription_create(e2, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(s1);
    assert_non_null(s2);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, s1));

    /* Intentionally skip destroy of s1, s2, and set — the context teardown
     * cascade must free every live handle and set exactly once. */
    pubnub_entity_destroy(e1);
    pubnub_entity_destroy(e2);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* The slot table tolerates holes: a freed middle slot is reused by a later
 * create and introspection still enumerates every live subscription. */
static void subscriptions_getter_handles_slot_holes(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e1 = pubnub_channel(ctx, "h1");
    pubnub_entity_t       e2 = pubnub_channel(ctx, "h2");
    pubnub_entity_t       e3 = pubnub_channel(ctx, "h3");
    pubnub_entity_t       e4 = pubnub_channel(ctx, "h4");
    pubnub_subscription_t s1 = pubnub_subscription_create(e1, NULL);
    pubnub_subscription_t s2 = pubnub_subscription_create(e2, NULL);
    pubnub_subscription_t s3 = pubnub_subscription_create(e3, NULL);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s1));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s2));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s3));

    pubnub_subscription_destroy(s2);

    pubnub_subscription_t s4 = pubnub_subscription_create(e4, NULL);
    assert_non_null(s4);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(s4));

    pubnub_subscription_t out[8] = {0};
    size_t                n      = 0;
    assert_int_equal(PUBNUB_OK, pubnub_subscriptions(ctx, out, 8, &n));
    assert_int_equal(3, n);

    pubnub_subscription_destroy(s1);
    pubnub_subscription_destroy(s3);
    pubnub_subscription_destroy(s4);
    pubnub_entity_destroy(e1);
    pubnub_entity_destroy(e2);
    pubnub_entity_destroy(e3);
    pubnub_entity_destroy(e4);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* A merge that cannot complete (saturated source handle) is rejected whole:
 * target, reference counts and subscription state unchanged, no event queued. */
static void merge_does_not_fit_leaves_target_untouched_unsubscribed(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           et     = pubnub_channel(ctx, "t-a");
    pubnub_entity_t           eb     = pubnub_channel(ctx, "o-b");
    pubnub_entity_t           ec     = pubnub_channel(ctx, "o-c");
    pubnub_subscription_t     ta     = pubnub_subscription_create(et, NULL);
    pubnub_subscription_t     ob     = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_t     oc     = pubnub_subscription_create(ec, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    assert_non_null(ta);
    assert_non_null(ob);
    assert_non_null(oc);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, ta));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, ob));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, oc));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pn_subscription_set_data_t* ts = &mgr->sets[target->set_index];
    pn_subscription_set_data_t* os = &mgr->sets[other->set_index];

    uint16_t ts_count_before = ts->count;
    uint16_t ts_slots_before[PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET];
    memcpy(ts_slots_before, ts->member_slots, sizeof(ts_slots_before));
    uint16_t os_count_before = os->count;
    uint16_t ta_ref_before   = ta->ref_count;
    uint16_t ob_ref_before   = ob->ref_count;
    uint8_t  queue_before    = mgr->event_queue.count;

    char wire_before[256] = {0};
    pn_subscribe_build_channel_string(mgr, wire_before, sizeof(wire_before));

    /* Saturate a NEW source handle so the whole merge must be refused. */
    uint16_t oc_ref_real = oc->ref_count;
    oc->ref_count        = UINT16_MAX;

    assert_int_equal(PUBNUB_ERR_QUEUE_FULL,
                     pubnub_subscription_set_add_subscription_set(target, other));

    assert_int_equal(ts_count_before, ts->count);
    assert_memory_equal(ts_slots_before, ts->member_slots, sizeof(ts_slots_before));
    assert_int_equal(ta_ref_before, ta->ref_count);
    assert_int_equal(queue_before, mgr->event_queue.count);

    char wire_after[256] = {0};
    pn_subscribe_build_channel_string(mgr, wire_after, sizeof(wire_after));
    assert_string_equal(wire_before, wire_after);

    assert_int_equal(os_count_before, os->count);
    assert_int_equal(ob_ref_before, ob->ref_count);

    /* Restore the clobbered reference count so teardown frees the handle. */
    oc->ref_count = oc_ref_real;

    pubnub_subscription_destroy(ta);
    pubnub_subscription_destroy(ob);
    pubnub_subscription_destroy(oc);
    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_entity_destroy(et);
    pubnub_entity_destroy(eb);
    pubnub_entity_destroy(ec);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* All-or-nothing merge with the target subscribed: a failed merge bumps no
 * entry's active_count and queues no SUBSCRIPTION_CHANGED event. */
static void merge_does_not_fit_leaves_target_untouched_subscribed(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           et     = pubnub_channel(ctx, "ts-a");
    pubnub_entity_t           eb     = pubnub_channel(ctx, "os-b");
    pubnub_subscription_t     ta     = pubnub_subscription_create(et, NULL);
    pubnub_subscription_t     ob     = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, ta));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, ob));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(target));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pn_subscription_set_data_t* ts = &mgr->sets[target->set_index];

    uint16_t ts_count_before  = ts->count;
    uint16_t ta_active_before = mgr->entries[ta->entry_index].active_count;
    uint8_t  queue_before     = mgr->event_queue.count;

    uint16_t ob_ref_real = ob->ref_count;
    ob->ref_count        = UINT16_MAX;

    assert_int_equal(PUBNUB_ERR_QUEUE_FULL,
                     pubnub_subscription_set_add_subscription_set(target, other));

    assert_int_equal(ts_count_before, ts->count);
    assert_int_equal(ta_active_before, mgr->entries[ta->entry_index].active_count);
    assert_int_equal(queue_before, mgr->event_queue.count);

    ob->ref_count = ob_ref_real;

    pubnub_subscription_destroy(ta);
    pubnub_subscription_destroy(ob);
    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_entity_destroy(et);
    pubnub_entity_destroy(eb);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* A merge that fits succeeds and the target gains every distinct new member. */
static void merge_exactly_fits_succeeds(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ea     = pubnub_channel(ctx, "f-a");
    pubnub_entity_t           eb     = pubnub_channel(ctx, "f-b");
    pubnub_entity_t           ecc    = pubnub_channel(ctx, "f-c");
    pubnub_subscription_t     sa     = pubnub_subscription_create(ea, NULL);
    pubnub_subscription_t     sb     = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_t     sc     = pubnub_subscription_create(ecc, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sa));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sb));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sc));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription_set(target, other));
    assert_int_equal(3, mgr->sets[target->set_index].count);

    pubnub_subscription_destroy(sa);
    pubnub_subscription_destroy(sb);
    pubnub_subscription_destroy(sc);
    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_entity_destroy(ecc);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* A handle shared by both sets is counted once: the target grows by the
 * distinct new members, not by the raw source count. */
static void merge_duplicate_members_counted_correctly(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ea     = pubnub_channel(ctx, "d-a");
    pubnub_entity_t           eb     = pubnub_channel(ctx, "d-b");
    pubnub_entity_t           ecc    = pubnub_channel(ctx, "d-c");
    pubnub_subscription_t     sa     = pubnub_subscription_create(ea, NULL);
    pubnub_subscription_t     sb     = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_t     sc     = pubnub_subscription_create(ecc, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    /* target = {A, B}; other = {B, C}. B is shared. */
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sa));
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sb));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sb));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sc));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);

    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription_set(target, other));
    /* Only C is new; B was already a member. */
    assert_int_equal(3, mgr->sets[target->set_index].count);

    pubnub_subscription_destroy(sa);
    pubnub_subscription_destroy(sb);
    pubnub_subscription_destroy(sc);
    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_entity_destroy(ecc);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* A saturated source handle that is not the first new member still fails the
 * whole merge: earlier fitting members are not added (the pre-check completes
 * before any mutation) and the source set is unchanged. */
static void merge_saturated_source_handle_fails_atomically(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           et     = pubnub_channel(ctx, "a-t");
    pubnub_entity_t           ex     = pubnub_channel(ctx, "a-x");
    pubnub_entity_t           ey     = pubnub_channel(ctx, "a-y");
    pubnub_entity_t           ez     = pubnub_channel(ctx, "a-z");
    pubnub_subscription_t     ta     = pubnub_subscription_create(et, NULL);
    pubnub_subscription_t     sx     = pubnub_subscription_create(ex, NULL);
    pubnub_subscription_t     sy     = pubnub_subscription_create(ey, NULL);
    pubnub_subscription_t     sz     = pubnub_subscription_create(ez, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, ta));
    /* other = {X, Y, Z}; Y (the middle member) is the saturated one. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sx));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sy));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sz));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pn_subscription_set_data_t* ts = &mgr->sets[target->set_index];
    pn_subscription_set_data_t* os = &mgr->sets[other->set_index];

    uint16_t ts_count_before = ts->count;
    uint16_t os_count_before = os->count;
    uint16_t sx_ref_before   = sx->ref_count;
    uint16_t sz_ref_before   = sz->ref_count;

    uint16_t sy_ref_real = sy->ref_count;
    sy->ref_count        = UINT16_MAX;

    assert_int_equal(PUBNUB_ERR_QUEUE_FULL,
                     pubnub_subscription_set_add_subscription_set(target, other));

    /* X and Z would have fit but must NOT have been added. */
    assert_int_equal(ts_count_before, ts->count);
    assert_int_equal(sx_ref_before, sx->ref_count);
    assert_int_equal(sz_ref_before, sz->ref_count);
    assert_int_equal(os_count_before, os->count);

    sy->ref_count = sy_ref_real;

    pubnub_subscription_destroy(ta);
    pubnub_subscription_destroy(sx);
    pubnub_subscription_destroy(sy);
    pubnub_subscription_destroy(sz);
    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_entity_destroy(et);
    pubnub_entity_destroy(ex);
    pubnub_entity_destroy(ey);
    pubnub_entity_destroy(ez);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

#if PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIPTIONS \
    && PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
/* A merge that would push the target past PER_SET is rejected whole. Reachable
 * only when PER_SET is below both the handle and entity caps; the guard above
 * compiles it out otherwise. */
static void merge_capacity_overflow_leaves_target_untouched(void** state)
{
    (void)state;

    enum { FILL = PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET };

    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ents[FILL + 1];
    pubnub_subscription_t     subs[FILL + 1];
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    uint16_t                  i;
    assert_true(PUBNUB_SUBSCRIPTION_SET_INVALID != target);
    assert_true(PUBNUB_SUBSCRIPTION_SET_INVALID != other);

    /* target gets PER_SET members; other adds one more, needing PER_SET+1. */
    for (i = 0; i < FILL + 1; ++i) {
        char name[16] = {0};
        snprintf(name, sizeof(name), "ov-%u", (unsigned)i);
        ents[i] = pubnub_channel(ctx, name);
        subs[i] = pubnub_subscription_create(ents[i], NULL);
        assert_non_null(subs[i]);
        if (i < FILL) {
            assert_int_equal(
                PUBNUB_OK,
                pubnub_subscription_set_add_subscription(target, subs[i]));
        }
    }
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(other, subs[FILL]));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pn_subscription_set_data_t* ts = &mgr->sets[target->set_index];

    uint16_t ts_count_before = ts->count;
    uint16_t slots_before[PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET];
    memcpy(slots_before, ts->member_slots, sizeof(slots_before));
    uint8_t queue_before = mgr->event_queue.count;

    assert_int_equal(PUBNUB_ERR_LIMIT_REACHED,
                     pubnub_subscription_set_add_subscription_set(target, other));

    assert_int_equal(ts_count_before, ts->count);
    assert_memory_equal(slots_before, ts->member_slots, sizeof(slots_before));
    assert_int_equal(queue_before, mgr->event_queue.count);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    for (i = 0; i < FILL + 1; ++i) {
        pubnub_subscription_destroy(subs[i]);
        pubnub_entity_destroy(ents[i]);
    }
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}
#endif

/* The handle table caps at MAX_SUBSCRIPTIONS independent of the entity cap:
 * all handles target one entity, yet introspection reports MAX_SUBSCRIPTIONS;
 * one past the cap fails. */
static void handle_table_fills_independent_of_entity(void** state)
{
    (void)state;

    enum { CAP = PUBNUB_CFG_MAX_SUBSCRIPTIONS };

    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e = pubnub_channel(ctx, "shared");
    pubnub_subscription_t subs[CAP];
    uint16_t              i;
    assert_non_null(e);

    for (i = 0; i < CAP; ++i) {
        subs[i] = pubnub_subscription_create(e, NULL);
        assert_non_null(subs[i]);
        assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(subs[i]));
    }
    assert_null(pubnub_subscription_create(e, NULL));

    pubnub_subscription_t out[CAP];
    size_t                count = 0;
    assert_int_equal(PUBNUB_OK, pubnub_subscriptions(ctx, out, CAP, &count));
    assert_int_equal((size_t)CAP, count);

    for (i = 0; i < CAP; ++i) {
        pubnub_subscription_destroy(subs[i]);
    }
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* The set table caps at PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; one more create
 * returns PUBNUB_SUBSCRIPTION_SET_INVALID. */
static void set_table_fills_to_max_subscription_sets(void** state)
{
    (void)state;

    enum { CAP = PUBNUB_CFG_MAX_SUBSCRIPTION_SETS };

    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_subscription_set_t sets[CAP];
    uint16_t                  i;
    for (i = 0; i < CAP; ++i) {
        sets[i] = pubnub_subscription_set_create(ctx);
        assert_non_null(sets[i]);
    }
    assert_null(pubnub_subscription_set_create(ctx));

    for (i = 0; i < CAP; ++i) {
        pubnub_subscription_set_destroy(sets[i]);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

#if PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIPTIONS
/* A set caps membership at PER_SET; one more distinct handle is rejected
 * with PUBNUB_ERR_LIMIT_REACHED. Reachable only when PER_SET is smaller than
 * the handle cap. */
static void set_rejects_member_beyond_per_set(void** state)
{
    (void)state;

    enum { CAP = PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET };

    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e = pubnub_channel(ctx, "pset");
    pubnub_subscription_t     subs[CAP + 1];
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    uint16_t                  i;
    assert_non_null(e);
    assert_non_null(set);

    for (i = 0; i < CAP + 1; ++i) {
        subs[i] = pubnub_subscription_create(e, NULL);
        assert_non_null(subs[i]);
    }
    for (i = 0; i < CAP; ++i) {
        assert_int_equal(PUBNUB_OK,
                         pubnub_subscription_set_add_subscription(set, subs[i]));
    }
    assert_int_equal(PUBNUB_ERR_LIMIT_REACHED,
                     pubnub_subscription_set_add_subscription(set, subs[CAP]));

    pubnub_subscription_set_destroy(set);
    for (i = 0; i < CAP + 1; ++i) {
        pubnub_subscription_destroy(subs[i]);
    }
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}
#endif

/** Callback context for the destroy-from-within-callback tests. */
typedef struct destroy_cb_ctx {
    /** Subscription handle destroyed from inside the message callback. */
    pubnub_subscription_t sub;
    /** Subscription set destroyed from inside the message callback. */
    pubnub_subscription_set_t set;
    /** Number of times the self-destroying callback has fired. */
    int self_calls;
    /** Number of times the independent global listener has fired. */
    int other_calls;
} destroy_cb_ctx_t;

/** Destroys its own bound subscription from inside the delivery callback. */
static void on_message_destroy_sub(const pubnub_subscribe_event_t* event,
                                   void*                           user_data)
{
    destroy_cb_ctx_t* c = (destroy_cb_ctx_t*)user_data;
    (void)event;
    c->self_calls++;
    pubnub_subscription_destroy(c->sub);
}

/** Destroys its own bound subscription set from inside the callback. */
static void on_message_destroy_set(const pubnub_subscribe_event_t* event,
                                   void*                           user_data)
{
    destroy_cb_ctx_t* c = (destroy_cb_ctx_t*)user_data;
    (void)event;
    c->self_calls++;
    pubnub_subscription_set_destroy(c->set);
}

/** Independent global listener that just counts its invocations. */
static void on_message_count_other(const pubnub_subscribe_event_t* event,
                                   void*                           user_data)
{
    destroy_cb_ctx_t* c = (destroy_cb_ctx_t*)user_data;
    (void)event;
    c->other_calls++;
}

/** Build a MESSAGE event for @p channel (subscription match == channel). */
static pubnub_subscribe_event_t make_message_event(const char* channel)
{
    pubnub_subscribe_event_t ev = {0};
    ev.type                     = PUBNUB_SUBSCRIBE_MESSAGE;
    ev.channel.ptr              = channel;
    ev.channel.len              = strlen(channel);
    ev.subscription.ptr         = channel;
    ev.subscription.len         = strlen(channel);
    ev.timetoken.ptr            = "17000000000000000";
    ev.timetoken.len            = 17;
    return ev;
}

/* Destroying a subscription from inside its own delivery callback mid-emit
 * is safe: no use-after-free, no re-fire, an independent listener still runs,
 * the slot is reclaimed, and allocations return to zero. */
static void subscription_destroy_from_within_callback(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t       e   = pubnub_channel(ctx, "cb-chan");
    pubnub_subscription_t sub = pubnub_subscription_create(e, NULL);
    assert_non_null(sub);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    uint16_t slot = sub->slot_index;

    destroy_cb_ctx_t cbctx = {0};
    cbctx.sub              = sub;

    pubnub_subscribe_listener_t self_listener = {0};
    self_listener.on_message                  = on_message_destroy_sub;
    self_listener.user_data                   = &cbctx;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &self_listener));

    pubnub_subscribe_listener_t other_listener = {0};
    other_listener.on_message                  = on_message_count_other;
    other_listener.user_data                   = &cbctx;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_add_listener(ctx, &other_listener));

    pubnub_subscribe_event_t ev = make_message_event("cb-chan");
    pn_subscribe_emit_message(mgr, &ev);

    assert_int_equal(1, cbctx.self_calls);
    assert_int_equal(1, cbctx.other_calls);
    /* Handle freed by the in-callback destroy; its slot is a NULL hole. */
    assert_null(mgr->tracked_subs[slot]);

    /* A second emit must not re-invoke the destroyed subscription's
     * listener. */
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, cbctx.self_calls);
    assert_int_equal(2, cbctx.other_calls);

    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/* Destroying a subscription SET from inside a per-set listener callback
 * mid-emit is safe: the set is torn down, no re-fire, an independent
 * listener still runs, and allocations return to zero. */
static void set_destroy_from_within_set_listener_callback(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "sc-a");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    uint16_t set_index = set->set_index;

    destroy_cb_ctx_t cbctx = {0};
    cbctx.set              = set;

    pubnub_subscribe_listener_t self_listener = {0};
    self_listener.on_message                  = on_message_destroy_set;
    self_listener.user_data                   = &cbctx;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_set_add_listener(set, &self_listener));

    pubnub_subscribe_listener_t other_listener = {0};
    other_listener.on_message                  = on_message_count_other;
    other_listener.user_data                   = &cbctx;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_add_listener(ctx, &other_listener));

    pubnub_subscribe_event_t ev = make_message_event("sc-a");
    pn_subscribe_emit_message(mgr, &ev);

    assert_int_equal(1, cbctx.self_calls);
    assert_int_equal(1, cbctx.other_calls);
    /* Set slot released by the in-callback destroy. */
    assert_int_equal(0, mgr->sets[set_index].active);

    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, cbctx.self_calls);
    assert_int_equal(2, cbctx.other_calls);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);

    assert_int_equal(0, s_live_allocs);
}

/** Bumps the int pointed to by user_data (shared by message/presence tests). */
static void on_event_count(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)event;
    (*(int*)user_data)++;
}

/** Build a PRESENCE event for @p channel (base name, with -pnpres subscription). */
static pubnub_subscribe_event_t make_presence_event(const char* channel,
                                                    const char* pnpres)
{
    pubnub_subscribe_event_t ev = {0};
    ev.type                     = PUBNUB_SUBSCRIBE_PRESENCE;
    ev.channel.ptr              = channel;
    ev.channel.len              = strlen(channel);
    ev.subscription.ptr         = pnpres;
    ev.subscription.len         = strlen(pnpres);
    ev.timetoken.ptr            = "17000000000000000";
    ev.timetoken.len            = 17;
    return ev;
}

/* A per-handle listener on a never-directly-subscribed member fires only while
 * a containing set is subscribed; the set grant/revoke toggles its share. */
static void member_listener_fires_via_subscribed_set(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "m-ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("m-ch");

    /* Member added but set not subscribed: no delivery share, silent. */
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(0, count);

    /* Subscribing the set grants one share; the member listener fires. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(1, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Unsubscribing the set revokes the share; silent again. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set));
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Resubscribe restores delivery. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(1, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    /* Destroying the subscribed set revokes the surviving member's share. */
    pubnub_subscription_set_destroy(set);
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* A handle subscribed directly AND in a subscribed set fires exactly once per
 * event; it keeps firing after the set unsubscribes and goes silent only once
 * its own direct subscribe is also dropped. */
static void member_direct_and_set_fires_once(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "d-ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("d-ch");

    /* Both direct and set-share active: one listener slot fires once. */
    assert_int_equal(1, sub->subscribed_set_refs);
    assert_int_equal(1, sub->subscribed);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Set unsubscribes: direct subscribe keeps delivery alive. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set));
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    /* Direct unsubscribe too: now silent. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub));
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Adding a handle into an already-subscribed set grants its listener an
 * immediate delivery share; removing it from the set revokes the share. */
static void add_into_subscribed_set_activates_member(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "a-ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("a-ch");

    /* Not yet a member: silent. */
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(0, count);

    /* Join the subscribed set: immediate share, fires. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));
    assert_int_equal(1, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Leave the set: share revoked, silent. */
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_remove_subscription(set, sub));
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* A handle shared by two sets accumulates one share per subscribed set and
 * delivers while any one of them is still subscribed. */
static void member_in_two_sets_shares_accumulate(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e     = pubnub_channel(ctx, "two-ch");
    pubnub_subscription_t     sub   = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set_a = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t set_b = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set_a);
    assert_non_null(set_b);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set_a, sub));
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set_b, sub));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("two-ch");

    /* Both subscribed: two shares, still one listener slot fires once. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set_a));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set_b));
    assert_int_equal(2, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* One set unsubscribed: the other keeps delivery alive. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set_a));
    assert_int_equal(1, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    /* Both unsubscribed: silent. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set_b));
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(2, count);

    pubnub_subscription_set_destroy(set_a);
    pubnub_subscription_set_destroy(set_b);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Merging a set into a subscribed target activates the new members' listeners;
 * the inverse merge-remove deactivates them. */
static void merge_into_subscribed_target_activates_members(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           ea     = pubnub_channel(ctx, "mg-a");
    pubnub_entity_t           eb     = pubnub_channel(ctx, "mg-b");
    pubnub_subscription_t     sa     = pubnub_subscription_create(ea, NULL);
    pubnub_subscription_t     sb     = pubnub_subscription_create(eb, NULL);
    pubnub_subscription_set_t target = pubnub_subscription_set_create(ctx);
    pubnub_subscription_set_t other  = pubnub_subscription_set_create(ctx);
    assert_non_null(sa);
    assert_non_null(sb);
    assert_non_null(target);
    assert_non_null(other);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sa));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sb));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(target));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sb, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("mg-b");

    /* B not yet in the subscribed target: silent. */
    assert_int_equal(0, sb->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(0, count);

    /* Merge other into subscribed target: B gains a share and fires. */
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription_set(target, other));
    assert_int_equal(1, sb->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Merge-remove other from target: B loses the share and goes silent. */
    assert_int_equal(
        PUBNUB_OK, pubnub_subscription_set_remove_subscription_set(target, other));
    assert_int_equal(0, sb->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_subscription_destroy(sa);
    pubnub_subscription_destroy(sb);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Destroying a subscribed set silences its members' listeners; the caller-owned
 * handle survives and can still be destroyed, with allocations back to zero. */
static void destroy_subscribed_set_silences_member(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_entity_t           e   = pubnub_channel(ctx, "ds-ch");
    pubnub_subscription_t     sub = pubnub_subscription_create(e, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sub);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sub));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));

    int                         count = 0;
    pubnub_subscribe_listener_t l     = {0};
    l.on_message                      = on_event_count;
    l.user_data                       = &count;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sub, &l));

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    pubnub_subscribe_event_t ev = make_message_event("ds-ch");

    assert_int_equal(1, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    /* Set destroyed while subscribed: the surviving member loses its share. */
    pubnub_subscription_set_destroy(set);
    assert_int_equal(0, sub->subscribed_set_refs);
    pn_subscribe_emit_message(mgr, &ev);
    assert_int_equal(1, count);

    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Presence routing follows the member handle's own presence flag: a
 * presence-requesting member activated only through a set receives a PRESENCE
 * event; a non-presence member on the same set does not. */
static void set_member_presence_follows_handle_flag(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pubnub_subscription_opts_t pres_opts = {0};
    pres_opts.with_presence              = 1;

    pubnub_entity_t           ep  = pubnub_channel(ctx, "roomP");
    pubnub_entity_t           en  = pubnub_channel(ctx, "roomN");
    pubnub_subscription_t     sp  = pubnub_subscription_create(ep, &pres_opts);
    pubnub_subscription_t     sn  = pubnub_subscription_create(en, NULL);
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(sp);
    assert_non_null(sn);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sp));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sn));

    int                         pcount = 0;
    int                         ncount = 0;
    pubnub_subscribe_listener_t lp     = {0};
    lp.on_presence                     = on_event_count;
    lp.user_data                       = &pcount;
    pubnub_subscribe_listener_t ln     = {0};
    ln.on_presence                     = on_event_count;
    ln.user_data                       = &ncount;
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sp, &lp));
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_add_listener(sn, &ln));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(1, sp->subscribed_set_refs);
    assert_int_equal(1, sn->subscribed_set_refs);

    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);

    /* Presence on the presence-requesting member's channel fires only its
     * listener. */
    pubnub_subscribe_event_t evp = make_presence_event("roomP", "roomP-pnpres");
    pn_subscribe_emit_message(mgr, &evp);
    assert_int_equal(1, pcount);
    assert_int_equal(0, ncount);

    /* Presence on the non-presence member's channel reaches no one. */
    pubnub_subscribe_event_t evn = make_presence_event("roomN", "roomN-pnpres");
    pn_subscribe_emit_message(mgr, &evn);
    assert_int_equal(1, pcount);
    assert_int_equal(0, ncount);

    pubnub_subscription_set_destroy(set);
    assert_int_equal(0, sp->subscribed_set_refs);
    assert_int_equal(0, sn->subscribed_set_refs);
    pubnub_subscription_destroy(sp);
    pubnub_subscription_destroy(sn);
    pubnub_entity_destroy(ep);
    pubnub_entity_destroy(en);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* NULL on either side is rejected before anything is touched. */
static void merge_null_arguments_returns_invalid_and_leaves_target_untouched(void** state)
{
    (void)state;
    pubnub_context_t*           ctx = create_ctx();
    pubnub_entity_t             et;
    pubnub_entity_t             eo;
    pubnub_subscription_t       st;
    pubnub_subscription_t       so;
    pubnub_subscription_set_t   target;
    pubnub_subscription_set_t   other;
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* ts;
    pn_subscription_set_data_t* os;
    uint16_t                    ts_count_before;
    uint16_t                    os_count_before;
    uint16_t                    st_active_before;
    uint8_t                     queue_before;

    assert_non_null(ctx);

    et     = pubnub_channel(ctx, "na-t");
    eo     = pubnub_channel(ctx, "na-o");
    st     = pubnub_subscription_create(et, NULL);
    so     = pubnub_subscription_create(eo, NULL);
    target = pubnub_subscription_set_create(ctx);
    other  = pubnub_subscription_set_create(ctx);
    assert_non_null(st);
    assert_non_null(so);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, st));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, so));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(target));

    mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    ts = &mgr->sets[target->set_index];
    os = &mgr->sets[other->set_index];

    ts_count_before  = ts->count;
    os_count_before  = os->count;
    st_active_before = mgr->entries[st->entry_index].active_count;
    queue_before     = mgr->event_queue.count;

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_subscription_set_add_subscription_set(NULL, other));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_subscription_set_add_subscription_set(target, NULL));

    assert_int_equal(ts_count_before, ts->count);
    assert_int_equal(os_count_before, os->count);
    assert_int_equal(1, target->subscribed);
    assert_int_equal(st_active_before, mgr->entries[st->entry_index].active_count);
    assert_int_equal(queue_before, mgr->event_queue.count);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_subscription_destroy(st);
    pubnub_subscription_destroy(so);
    pubnub_entity_destroy(et);
    pubnub_entity_destroy(eo);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Merging a set into itself succeeds without touching members or queuing a
 * SUBSCRIPTION_CHANGED event. */
static void merge_self_is_noop_no_event(void** state)
{
    (void)state;
    pubnub_context_t*           ctx = create_ctx();
    pubnub_entity_t             ea;
    pubnub_entity_t             eb;
    pubnub_subscription_t       sa;
    pubnub_subscription_t       sb;
    pubnub_subscription_set_t   target;
    pn_subscribe_manager_t*     mgr;
    pn_subscription_set_data_t* ts;
    uint16_t                    ts_count_before;
    uint16_t                    sa_ref_before;
    uint16_t                    sa_active_before;
    uint8_t                     queue_before;
    uint32_t                    gen_before;

    assert_non_null(ctx);

    ea     = pubnub_channel(ctx, "sf-a");
    eb     = pubnub_channel(ctx, "sf-b");
    sa     = pubnub_subscription_create(ea, NULL);
    sb     = pubnub_subscription_create(eb, NULL);
    target = pubnub_subscription_set_create(ctx);
    assert_non_null(sa);
    assert_non_null(sb);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sa));
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sb));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(target));

    mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    ts = &mgr->sets[target->set_index];

    ts_count_before  = ts->count;
    sa_ref_before    = sa->ref_count;
    sa_active_before = mgr->entries[sa->entry_index].active_count;
    queue_before     = mgr->event_queue.count;
    gen_before       = mgr->subscription_generation;

    assert_int_equal(
        PUBNUB_OK, pubnub_subscription_set_add_subscription_set(target, target));

    assert_int_equal(2, ts->count);
    assert_int_equal(ts_count_before, ts->count);
    assert_int_equal(sa_ref_before, sa->ref_count);
    assert_int_equal(sa_active_before, mgr->entries[sa->entry_index].active_count);
    assert_int_equal(queue_before, mgr->event_queue.count);
    assert_int_equal(gen_before, mgr->subscription_generation);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_destroy(sa);
    pubnub_subscription_destroy(sb);
    pubnub_entity_destroy(ea);
    pubnub_entity_destroy(eb);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}

/* Sets owned by different contexts cannot be merged; neither side changes. */
static void merge_across_contexts_returns_invalid_and_leaves_target_untouched(void** state)
{
    (void)state;
    pubnub_context_t*           ctx_a = create_ctx();
    pubnub_context_t*           ctx_b;
    pubnub_entity_t             ea;
    pubnub_entity_t             eb;
    pubnub_subscription_t       sa;
    pubnub_subscription_t       sb;
    pubnub_subscription_set_t   target;
    pubnub_subscription_set_t   other;
    pn_subscribe_manager_t*     mgr_a;
    pn_subscribe_manager_t*     mgr_b;
    pn_subscription_set_data_t* ts;
    pn_subscription_set_data_t* os;
    int                         ctx_a_allocs;
    uint16_t                    ts_count_before;
    uint16_t                    os_count_before;
    uint16_t                    sa_ref_before;
    uint16_t                    sb_ref_before;
    uint8_t                     queue_a_before;
    uint8_t                     queue_b_before;

    assert_non_null(ctx_a);

    ea     = pubnub_channel(ctx_a, "xc-a");
    sa     = pubnub_subscription_create(ea, NULL);
    target = pubnub_subscription_set_create(ctx_a);
    assert_non_null(sa);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, sa));

    /* create_ctx() resets the leak counter; carry ctx A's live allocations
     * across so the final zero check covers both contexts. */
    ctx_a_allocs = s_live_allocs;
    ctx_b        = create_ctx();
    assert_non_null(ctx_b);
    s_live_allocs += ctx_a_allocs;

    eb    = pubnub_channel(ctx_b, "xc-b");
    sb    = pubnub_subscription_create(eb, NULL);
    other = pubnub_subscription_set_create(ctx_b);
    assert_non_null(sb);
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(other, sb));

    mgr_a = pn_subscribe_manager_from_ctx(ctx_a);
    mgr_b = pn_subscribe_manager_from_ctx(ctx_b);
    assert_non_null(mgr_a);
    assert_non_null(mgr_b);
    ts = &mgr_a->sets[target->set_index];
    os = &mgr_b->sets[other->set_index];

    ts_count_before = ts->count;
    os_count_before = os->count;
    sa_ref_before   = sa->ref_count;
    sb_ref_before   = sb->ref_count;
    queue_a_before  = mgr_a->event_queue.count;
    queue_b_before  = mgr_b->event_queue.count;

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_subscription_set_add_subscription_set(target, other));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pubnub_subscription_set_add_subscription_set(other, target));

    assert_int_equal(ts_count_before, ts->count);
    assert_int_equal(os_count_before, os->count);
    assert_int_equal(sa_ref_before, sa->ref_count);
    assert_int_equal(sb_ref_before, sb->ref_count);
    assert_int_equal(queue_a_before, mgr_a->event_queue.count);
    assert_int_equal(queue_b_before, mgr_b->event_queue.count);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_destroy(sa);
    pubnub_entity_destroy(ea);
    pubnub_destroy(ctx_a);

    pubnub_subscription_set_destroy(other);
    pubnub_subscription_destroy(sb);
    pubnub_entity_destroy(eb);
    pubnub_destroy(ctx_b);

    assert_int_equal(0, s_live_allocs);
}

/* The target already covers the channel through a non-presence handle, so
 * merging in a presence handle for it flips only the -pnpres share: one
 * SUBSCRIPTION_CHANGED, no new activation. The merge calls
 * pn_notify_presence_joined only when an entry was activated, so a
 * presence-only flip drives no join. That is asserted through the presence
 * manager: a join would rewrite its channel/group lists and enqueue an
 * event, so those must be identical before and after the merge. */
static void merge_presence_member_into_subscribed_target_queues_change(void** state)
{
    (void)state;
    pubnub_context_t*           ctx       = create_ctx();
    pubnub_subscription_opts_t  pres_opts = {0};
    pubnub_entity_t             e;
    pubnub_subscription_t       plain;
    pubnub_subscription_t       pres;
    pubnub_subscription_set_t   target;
    pubnub_subscription_set_t   other;
    pn_subscribe_manager_t*     mgr;
    pn_subscription_entry_t*    entry;
    pn_subscription_set_data_t* ts;
    uint16_t                    active_before;
    uint8_t                     queue_before;
    uint32_t                    gen_before;
#if PUBNUB_ENABLE_PRESENCE
    pn_presence_manager_t* pm_before;
    pn_presence_manager_t* pm_after;
    pn_presence_ee_state_t pm_state_before   = (pn_presence_ee_state_t)0;
    uint8_t                pm_queue_before   = 0;
    char                   pm_ch_before[128] = {0};
    char                   pm_gr_before[128] = {0};
    int                    pm_has_ch         = 0;
    int                    pm_has_gr         = 0;
#endif

    assert_non_null(ctx);
    pres_opts.with_presence = 1;

    e      = pubnub_channel(ctx, "pf-room");
    plain  = pubnub_subscription_create(e, NULL);
    pres   = pubnub_subscription_create(e, &pres_opts);
    target = pubnub_subscription_set_create(ctx);
    other  = pubnub_subscription_set_create(ctx);
    assert_non_null(plain);
    assert_non_null(pres);
    assert_int_equal(plain->entry_index, pres->entry_index);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(target, plain));
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(other, pres));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(target));

    mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    entry = &mgr->entries[plain->entry_index];
    ts    = &mgr->sets[target->set_index];

    assert_int_equal(0, entry->with_presence);
    assert_int_equal(0, entry->presence_contributors);

    active_before = entry->active_count;
    queue_before  = mgr->event_queue.count;
    gen_before    = mgr->subscription_generation;

#if PUBNUB_ENABLE_PRESENCE
    pm_before = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    if (NULL != pm_before) {
        pm_state_before = pm_before->ee_state;
        pm_queue_before = pm_before->event_queue.count;
        pm_has_ch       = (NULL != pm_before->channels);
        pm_has_gr       = (NULL != pm_before->groups);
        if (pm_has_ch) {
            assert_true(strlen(pm_before->channels) < sizeof(pm_ch_before));
            strcpy(pm_ch_before, pm_before->channels);
        }
        if (pm_has_gr) {
            assert_true(strlen(pm_before->groups) < sizeof(pm_gr_before));
            strcpy(pm_gr_before, pm_before->groups);
        }
    }
#endif

    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription_set(target, other));

#if PUBNUB_ENABLE_PRESENCE
    pm_after = (pn_presence_manager_t*)pn_context_feature_state(
        ctx, PUBNUB_FEATURE_PRESENCE);
    assert_ptr_equal(pm_before, pm_after);
    if (NULL != pm_after) {
        assert_int_equal(pm_state_before, pm_after->ee_state);
        assert_int_equal(pm_queue_before, pm_after->event_queue.count);
        assert_int_equal(pm_has_ch, NULL != pm_after->channels);
        assert_int_equal(pm_has_gr, NULL != pm_after->groups);
        if (pm_has_ch) {
            assert_string_equal(pm_ch_before, pm_after->channels);
        }
        if (pm_has_gr) {
            assert_string_equal(pm_gr_before, pm_after->groups);
        }
    }
#endif

    assert_int_equal(2, ts->count);
    assert_int_equal(1, entry->with_presence);
    assert_int_equal(1, entry->presence_contributors);
    assert_int_equal(active_before, entry->active_count);
    assert_int_equal(queue_before + 1, mgr->event_queue.count);
    assert_int_equal(gen_before + 1, mgr->subscription_generation);

    pubnub_subscription_set_destroy(target);
    pubnub_subscription_set_destroy(other);
    pubnub_subscription_destroy(plain);
    pubnub_subscription_destroy(pres);
    pubnub_entity_destroy(e);
    pubnub_destroy(ctx);
    assert_int_equal(0, s_live_allocs);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(test_cleanup_no_active_request),
        cmocka_unit_test(test_cleanup_sets_draining),
        cmocka_unit_test(unsubscribe_all_on_idle_context_returns_ok),
        cmocka_unit_test(subscription_unsubscribe_before_subscribe_returns_ok),
        cmocka_unit_test(subscription_set_add_subscription_before_subscribe_ok),
        cmocka_unit_test(subscription_restore_then_subscribe_preserves_timetoken),
        cmocka_unit_test(subscription_handle_alive_in_set_after_destroy),
        cmocka_unit_test(subscription_set_getter_returns_only_members),
        cmocka_unit_test(subscription_set_getter_buffer_too_small),
        cmocka_unit_test(subscription_set_active_share_once_per_entry),
        cmocka_unit_test(subscription_set_duplicate_handle_add_is_noop),
        cmocka_unit_test(subscription_shared_handle_survives_single_remove),
        cmocka_unit_test(context_teardown_releases_live_handles_and_sets),
        cmocka_unit_test(subscriptions_getter_handles_slot_holes),
        cmocka_unit_test(merge_does_not_fit_leaves_target_untouched_unsubscribed),
        cmocka_unit_test(merge_does_not_fit_leaves_target_untouched_subscribed),
        cmocka_unit_test(merge_exactly_fits_succeeds),
        cmocka_unit_test(merge_duplicate_members_counted_correctly),
        cmocka_unit_test(merge_saturated_source_handle_fails_atomically),
#if PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIPTIONS \
    && PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS
        cmocka_unit_test(merge_capacity_overflow_leaves_target_untouched),
#endif
        cmocka_unit_test(handle_table_fills_independent_of_entity),
        cmocka_unit_test(set_table_fills_to_max_subscription_sets),
#if PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET < PUBNUB_CFG_MAX_SUBSCRIPTIONS
        cmocka_unit_test(set_rejects_member_beyond_per_set),
#endif
        cmocka_unit_test(subscription_destroy_from_within_callback),
        cmocka_unit_test(set_destroy_from_within_set_listener_callback),
        cmocka_unit_test(member_listener_fires_via_subscribed_set),
        cmocka_unit_test(member_direct_and_set_fires_once),
        cmocka_unit_test(add_into_subscribed_set_activates_member),
        cmocka_unit_test(member_in_two_sets_shares_accumulate),
        cmocka_unit_test(merge_into_subscribed_target_activates_members),
        cmocka_unit_test(destroy_subscribed_set_silences_member),
        cmocka_unit_test(set_member_presence_follows_handle_flag),
        cmocka_unit_test(
            merge_null_arguments_returns_invalid_and_leaves_target_untouched),
        cmocka_unit_test(merge_self_is_noop_no_event),
        cmocka_unit_test(
            merge_across_contexts_returns_invalid_and_leaves_target_untouched),
        cmocka_unit_test(merge_presence_member_into_subscribed_target_queues_change),
#endif
        cmocka_unit_test(test_cleanup_null_state),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
