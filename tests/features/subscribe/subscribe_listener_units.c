/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_listener_units.c
 * @brief Unit tests for listener management, name-based message routing,
 *        and subscription entry reference counting.
 *
 * Tests operate directly on the subscribe manager internals, bypassing
 * transport and full-context mocking.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "features/subscribe/subscribe_manager_internal.h"
#include "features/subscribe/subscribe_wire_internal.h"
#include "pubnub/client.h"
#include "pubnub/features/subscribe.h"
#include "core_internal.h"
#include "pn_lock.h"
#include "pn_string.h"

#if PUBNUB_CFG_THREAD_SAFETY && !defined(_WIN32)
#include <pthread.h>

#include "integration/it_thread.h"
#endif

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

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    pubnub_buffer_t buf = {0};
    buf.data            = (uint8_t*)malloc(4096);
    buf.cap             = buf.data ? 4096 : 0;
    buf.len             = 0;
    buf.purpose         = purpose;
    return buf;
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->cap  = 0;
    }
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .realloc     = NULL,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
    .buf_grow    = NULL,
};

static pubnub_milliseconds_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static pubnub_milliseconds_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
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
    memset(buf, 0x42, len);
    return 0;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock_ms,
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

static pubnub_context_t* s_test_ctx;
/* PUBNUB_ALIGNAS ensures the buffer satisfies struct alignment on all
 * targets; without it, casting to pubnub_context_t* is UB on
 * Cortex-M0 and other strictly-aligned architectures. */
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

static int group_setup(void** state)
{
    (void)state;
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = &s_mock_allocator;
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = &s_mock_serialization;
    cfg.platform        = &s_mock_platform;

    s_test_ctx = (pubnub_context_t*)s_ctx_mem;
    if (PUBNUB_OK != pubnub_init(s_test_ctx, &cfg)) {
        s_test_ctx = NULL;
    }
    assert_non_null(s_test_ctx);
    return 0;
}

static int group_teardown(void** state)
{
    (void)state;
    if (NULL != s_test_ctx) {
        pubnub_deinit(s_test_ctx);
        s_test_ctx = NULL;
    }
    return 0;
}

/** Track which callbacks were invoked and with what user_data. */
typedef struct callback_record {
    int                             message_count;
    int                             signal_count;
    int                             presence_count;
    int                             status_count;
    int                             objects_count;
    int                             file_count;
    int                             message_action_count;
    const pubnub_subscribe_event_t* last_event;
    void*                           last_user_data;
} callback_record_t;

static void cb_on_message(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->message_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

static void cb_on_signal(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->signal_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

static void cb_on_presence(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->presence_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

static void cb_on_status(const pubnub_subscribe_status_event_t* event, void* ud)
{
    (void)event;
    callback_record_t* rec = (callback_record_t*)ud;
    rec->status_count++;
    rec->last_user_data = ud;
}

static void cb_on_app_context(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->objects_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

static void cb_on_file(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->file_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

static void cb_on_message_action(const pubnub_subscribe_event_t* event, void* ud)
{
    callback_record_t* rec = (callback_record_t*)ud;
    rec->message_action_count++;
    rec->last_event     = event;
    rec->last_user_data = ud;
}

/**
 * @brief Create a zeroed stack manager with minimal fields initialized.
 *
 * Bypasses pn_subscribe_manager_create(); sets s_test_ctx as the context
 * back-pointer so pn_context_allocator() works.
 */
static pn_subscribe_manager_t* create_test_manager(pn_subscribe_manager_t* mgr)
{
    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx            = s_test_ctx;
    mgr->ee_state       = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
    mgr->active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_subscribe_event_queue_init(&mgr->event_queue);
    return mgr;
}

/**
 * @brief Release all occupied entries in a stack-allocated test manager.
 */
static void destroy_test_manager(pn_subscribe_manager_t* mgr)
{
    pubnub_allocator_provider_t* alloc = pn_context_allocator(mgr->ctx);
    uint16_t                     i;

    /* Free any subscription handles still tracked (set members a test did
     * not explicitly destroy). Handle memory and entry names are owned
     * separately, so freeing both arrays releases each exactly once. */
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS; ++i) {
        if (NULL != mgr->tracked_subs[i]) {
            PN_FREE(alloc, mgr->tracked_subs[i]);
            mgr->tracked_subs[i] = NULL;
        }
    }
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (mgr->entries[i].occupied) {
            pn_strfree(mgr->entries[i].name, alloc);
        }
    }
}

/**
 * @brief Acquire a channel entry directly in the manager for testing.
 */
static uint16_t acquire_channel(pn_subscribe_manager_t* mgr, const char* name)
{
    return pn_subscription_acquire(
        mgr, name, (uint16_t)strlen(name), PN_ENTITY_CHANNEL, 0);
}

/**
 * @brief Acquire a channel and mark it active so it appears in the built
 *        channel string.
 *
 * The string builders skip entries with active_count == 0; these internal
 * tests bypass the subscribe path, so activation is applied directly.
 */
static uint16_t acquire_active_channel(pn_subscribe_manager_t* mgr, const char* name)
{
    uint16_t idx = pn_subscription_acquire(
        mgr, name, (uint16_t)strlen(name), PN_ENTITY_CHANNEL, 0);
    if (UINT16_MAX != idx) {
        mgr->entries[idx].active_count++;
    }
    return idx;
}

/** @brief Acquire a channel-group entry and mark it active. */
static uint16_t acquire_active_group(pn_subscribe_manager_t* mgr, const char* name)
{
    uint16_t idx = pn_subscription_acquire(
        mgr, name, (uint16_t)strlen(name), PN_ENTITY_CHANNEL_GROUP, 0);
    if (UINT16_MAX != idx) {
        mgr->entries[idx].active_count++;
    }
    return idx;
}

/**
 * @brief Acquire an active entry of a given entity type and presence flag.
 *
 * Like acquire_active_channel but with a caller-chosen entity type and
 * presence flag, to exercise path/heartbeat string dedup.
 */
static uint16_t acquire_active_typed(pn_subscribe_manager_t*    mgr,
                                     const char*                name,
                                     pn_subscribe_entity_type_t entity_type,
                                     uint8_t                    with_presence)
{
    uint16_t idx = pn_subscription_acquire(
        mgr, name, (uint16_t)strlen(name), entity_type, with_presence);
    if (UINT16_MAX != idx) {
        mgr->entries[idx].active_count++;
        /* Entry wire-presence derives from the presence_contributors
         * counter; seed one contributor so builder-facing assertions
         * (which read entry.with_presence) see a presence-requesting
         * channel. */
        if (with_presence
            && (PN_ENTITY_CHANNEL == entity_type
                || PN_ENTITY_CHANNEL_GROUP == entity_type)) {
            (void)pn_subscription_entry_presence_adjust(mgr, idx, 1);
        }
    }
    return idx;
}

/**
 * @brief Create a subscribed, tracked handle for an existing entry and
 *        return its tracked_subs[] slot.
 *
 * Per-subscription listeners bind to a handle slot and only deliver while
 * the handle is subscribed, so matcher delivery tests need one. Marks the
 * handle subscribed directly instead of running the subscribe effect.
 */
static uint16_t subscribed_slot_for_entry(pn_subscribe_manager_t* mgr,
                                          uint16_t                entry_idx)
{
    pubnub_allocator_provider_t* alloc = pn_context_allocator(mgr->ctx);
    pn_subscription_t*           sub =
        (pn_subscription_t*)PN_ALLOC(alloc, sizeof(*sub), sizeof(void*));

    assert_non_null(sub);
    sub->ctx                 = mgr->ctx;
    sub->entry_index         = entry_idx;
    sub->slot_index          = UINT16_MAX;
    sub->ref_count           = 1;
    sub->subscribed          = 1;
    sub->subscribed_set_refs = 0;
    /* Per-subscription listeners gate presence on the handle's own flag.
     * Mirror the entry's derived cache so a listener bound to a
     * presence-requesting entry routes presence events. */
    sub->with_presence = mgr->entries[entry_idx].with_presence;

    assert_int_not_equal(UINT16_MAX, pn_track_subscription(mgr, sub));
    return sub->slot_index;
}

/**
 * @brief Bind a listener to a subscribed handle sitting on @p entry_idx.
 *
 * Convenience wrapper that creates a subscribed handle for the entry and
 * binds the listener to the handle's slot. Returns the listener handle.
 */
static pn_listener_handle_t add_bound_for_entry(pn_subscribe_manager_t* mgr,
                                                const pubnub_subscribe_listener_t* listener,
                                                uint16_t entry_idx)
{
    uint16_t slot = subscribed_slot_for_entry(mgr, entry_idx);
    return pn_subscribe_listener_add_bound(mgr, listener, slot);
}

/**
 * @brief Add a channel entry to a subscription set (test-local).
 *
 * Replicates the subscribe path's acquire + dedup + capacity semantics:
 * PUBNUB_OK when newly added or already a member, PUBNUB_ERR_QUEUE_FULL
 * when the entry pool or member list is exhausted.
 */
static pubnub_res_t test_set_add(pn_subscribe_manager_t* mgr,
                                 uint16_t                set_index,
                                 const char*             name,
                                 uint16_t                name_len)
{
    pn_subscription_set_data_t*  set;
    pn_subscription_t*           sub;
    pubnub_allocator_provider_t* alloc;
    uint16_t                     entry_idx;

    set = &mgr->sets[set_index];
    if (set->count >= PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    entry_idx = pn_subscription_acquire(mgr, name, name_len, PN_ENTITY_CHANNEL, 0);
    if (UINT16_MAX == entry_idx) {
        return PUBNUB_ERR_QUEUE_FULL;
    }

    /* Keep one member handle per entry (mirrors the old entry-dedup helper
     * so routing-by-entry assertions stay valid under the handle model). */
    if (pn_subscription_set_contains(mgr, set_index, entry_idx)) {
        pn_subscription_release(mgr, entry_idx);
        return PUBNUB_OK;
    }

    alloc = pn_context_allocator(mgr->ctx);
    sub   = (pn_subscription_t*)PN_ALLOC(alloc, sizeof(*sub), sizeof(void*));
    if (NULL == sub) {
        pn_subscription_release(mgr, entry_idx);
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    sub->ctx                 = mgr->ctx;
    sub->entry_index         = entry_idx;
    sub->slot_index          = UINT16_MAX;
    sub->ref_count           = 1;
    sub->subscribed          = 0;
    sub->with_presence       = 0;
    sub->subscribed_set_refs = 0;

    if (UINT16_MAX == pn_track_subscription(mgr, sub)) {
        PN_FREE(alloc, sub);
        pn_subscription_release(mgr, entry_idx);
        return PUBNUB_ERR_QUEUE_FULL;
    }
    if (pn_subscription_set_add_member(mgr, set_index, sub) <= 0) {
        pn_subscription_handle_unref(mgr, sub);
        return PUBNUB_ERR_QUEUE_FULL;
    }

    /* The set now holds a reference; drop the creator reference so the set
     * alone owns the handle and set-destroy fully releases it. */
    pn_subscription_handle_unref(mgr, sub);
    return PUBNUB_OK;
}

/**
 * @brief Build a synthetic event for dispatch testing.
 *
 * Routing is by channel/subscription name.
 */
static pubnub_subscribe_event_t make_message(pubnub_subscribe_message_type_t type,
                                             const char* channel)
{
    pubnub_subscribe_event_t event;
    memset(&event, 0, sizeof(event));
    event.type        = type;
    event.channel.ptr = channel;
    event.channel.len = strlen(channel);
    event.payload     = (const struct pubnub_json_value*)(uintptr_t)0xDEAD;
    return event;
}

/**
 * @brief Build a synthetic event with both channel ("c") and subscription
 *        ("b") views set.
 *
 * The two views may resolve to different entries, driving the name-based
 * match against either candidate. Pass NULL to leave a view unset.
 */
static pubnub_subscribe_event_t make_message_full(pubnub_subscribe_message_type_t type,
                                                  const char* channel,
                                                  const char* subscription)
{
    pubnub_subscribe_event_t event;
    memset(&event, 0, sizeof(event));
    event.type = type;
    if (NULL != channel) {
        event.channel.ptr = channel;
        event.channel.len = strlen(channel);
    }
    if (NULL != subscription) {
        event.subscription.ptr = subscription;
        event.subscription.len = strlen(subscription);
    }
    event.payload = (const struct pubnub_json_value*)(uintptr_t)0xDEAD;
    return event;
}

static void test_add_global_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h);
    assert_int_equal(1, mgr.listener_count);
    assert_int_equal(1, mgr.listeners[h].active);
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_slot_index);
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_set_index);
}

static void test_add_bound_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, idx);

    /* Per-subscription listeners bind to a handle slot, not the entry. */
    uint16_t slot = subscribed_slot_for_entry(&mgr, idx);

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add_bound(&mgr, &listener, slot);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h);
    assert_int_equal(1, mgr.listener_count);
    assert_int_equal(slot, mgr.listeners[h].bound_slot_index);
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_set_index);

    destroy_test_manager(&mgr);
}

static void test_add_set_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_not_equal(UINT16_MAX, set_idx);

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
    };

    pn_listener_handle_t h =
        pn_subscribe_listener_add_to_set(&mgr, &listener, set_idx);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h);
    assert_int_equal(1, mgr.listener_count);
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_slot_index);
    assert_int_equal(set_idx, mgr.listeners[h].bound_set_index);
}

static void test_remove_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
    assert_int_equal(1, mgr.listener_count);

    pn_subscribe_listener_remove(&mgr, h);
    assert_int_equal(0, mgr.listener_count);
    assert_int_equal(0, mgr.listeners[h].active);
}

static void test_remove_invalid_handle_is_noop(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pn_subscribe_listener_remove(&mgr, PN_LISTENER_HANDLE_INVALID);
    assert_int_equal(0, mgr.listener_count);
}

static void test_add_multiple_listeners(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t l1 = {.on_message = cb_on_message};
    pubnub_subscribe_listener_t l2 = {.on_signal = cb_on_signal};
    pubnub_subscribe_listener_t l3 = {.on_presence = cb_on_presence};

    pn_listener_handle_t h1 = pn_subscribe_listener_add(&mgr, &l1);
    pn_listener_handle_t h2 = pn_subscribe_listener_add(&mgr, &l2);
    pn_listener_handle_t h3 = pn_subscribe_listener_add(&mgr, &l3);

    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h1);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h2);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h3);
    assert_int_equal(3, mgr.listener_count);

    /* Handles are unique. */
    assert_int_not_equal(h1, h2);
    assert_int_not_equal(h2, h3);
}

static void test_listener_capacity_exhausted(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {.on_message = cb_on_message};

    /* Fill all listener slots. */
    for (uint16_t i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS; ++i) {
        pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
        assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h);
    }

    /* Next should fail. */
    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
    assert_int_equal(PN_LISTENER_HANDLE_INVALID, h);
}

static void test_add_bound_to_invalid_slot_fails(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {.on_message = cb_on_message};

    /* No handle tracked at slot 0 — binding must fail. */
    pn_listener_handle_t h = pn_subscribe_listener_add_bound(&mgr, &listener, 0);
    assert_int_equal(PN_LISTENER_HANDLE_INVALID, h);
}

static void test_add_to_invalid_set_fails(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {.on_message = cb_on_message};

    /* No set at index 0 — should fail. */
    pn_listener_handle_t h = pn_subscribe_listener_add_to_set(&mgr, &listener, 0);
    assert_int_equal(PN_LISTENER_HANDLE_INVALID, h);
}

static void test_global_listener_receives_all_messages(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");
    acquire_channel(&mgr, "ch2");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_subscribe_listener_add(&mgr, &listener);

    pubnub_subscribe_event_t msg1 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pubnub_subscribe_event_t msg2 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2");

    pn_subscribe_emit_message(&mgr, &msg1);
    pn_subscribe_emit_message(&mgr, &msg2);

    assert_int_equal(2, rec.message_count);

    destroy_test_manager(&mgr);
}

static void test_bound_listener_receives_only_matching_channel(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    acquire_channel(&mgr, "ch2");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };

    /* Bind only to ch1. */
    add_bound_for_entry(&mgr, &listener, idx_ch1);

    pubnub_subscribe_event_t msg1 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pubnub_subscribe_event_t msg2 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2");

    pn_subscribe_emit_message(&mgr, &msg1);
    pn_subscribe_emit_message(&mgr, &msg2);

    /* Should only receive the ch1 message. */
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

static void test_set_listener_receives_only_set_members(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");
    acquire_channel(&mgr, "ch2");
    acquire_channel(&mgr, "ch3");

    /* Create a set containing ch1 and ch2 (but not ch3). */
    uint16_t     set_idx = pn_subscription_set_create(&mgr);
    pubnub_res_t rc      = test_set_add(&mgr, set_idx, "ch1", 3);
    assert_int_equal(PUBNUB_OK, rc);
    rc = test_set_add(&mgr, set_idx, "ch2", 3);
    assert_int_equal(PUBNUB_OK, rc);

    /* Set listeners deliver only while the set is subscribed. */
    mgr.sets[set_idx].subscribed = 1;

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_subscribe_listener_add_to_set(&mgr, &listener, set_idx);

    pubnub_subscribe_event_t msg1 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pubnub_subscribe_event_t msg2 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2");
    pubnub_subscribe_event_t msg3 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch3");

    pn_subscribe_emit_message(&mgr, &msg1);
    pn_subscribe_emit_message(&mgr, &msg2);
    pn_subscribe_emit_message(&mgr, &msg3);

    /* Only ch1 and ch2 match. */
    assert_int_equal(2, rec.message_count);

    destroy_test_manager(&mgr);
}

static void test_mixed_listeners_coexist(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    acquire_channel(&mgr, "ch2");

    callback_record_t rec_global = {0};
    callback_record_t rec_bound  = {0};

    pubnub_subscribe_listener_t global_listener = {
        .on_message = cb_on_message,
        .user_data  = &rec_global,
    };
    pubnub_subscribe_listener_t bound_listener = {
        .on_message = cb_on_message,
        .user_data  = &rec_bound,
    };

    pn_subscribe_listener_add(&mgr, &global_listener);
    add_bound_for_entry(&mgr, &bound_listener, idx_ch1);

    pubnub_subscribe_event_t msg1 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pubnub_subscribe_event_t msg2 = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2");

    pn_subscribe_emit_message(&mgr, &msg1);
    pn_subscribe_emit_message(&mgr, &msg2);

    /* Global receives both, bound receives only ch1. */
    assert_int_equal(2, rec_global.message_count);
    assert_int_equal(1, rec_bound.message_count);

    destroy_test_manager(&mgr);
}

static void test_typed_dispatch_routes_to_correct_callback(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message        = cb_on_message,
        .on_signal         = cb_on_signal,
        .on_presence       = cb_on_presence,
        .on_app_context    = cb_on_app_context,
        .on_file           = cb_on_file,
        .on_message_action = cb_on_message_action,
        .user_data         = &rec,
    };
    pn_subscribe_listener_add(&mgr, &listener);

    pubnub_subscribe_event_t msg_msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pubnub_subscribe_event_t msg_sig = make_message(PUBNUB_SUBSCRIBE_SIGNAL, "ch1");
    pubnub_subscribe_event_t msg_pres =
        make_message(PUBNUB_SUBSCRIBE_PRESENCE, "ch1");
    pubnub_subscribe_event_t msg_obj =
        make_message(PUBNUB_SUBSCRIBE_APP_CONTEXT, "ch1");
    pubnub_subscribe_event_t msg_file = make_message(PUBNUB_SUBSCRIBE_FILE, "ch1");
    pubnub_subscribe_event_t msg_act =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE_ACTION, "ch1");

    pn_subscribe_emit_message(&mgr, &msg_msg);
    pn_subscribe_emit_message(&mgr, &msg_sig);
    pn_subscribe_emit_message(&mgr, &msg_pres);
    pn_subscribe_emit_message(&mgr, &msg_obj);
    pn_subscribe_emit_message(&mgr, &msg_file);
    pn_subscribe_emit_message(&mgr, &msg_act);

    assert_int_equal(1, rec.message_count);
    assert_int_equal(1, rec.signal_count);
    assert_int_equal(1, rec.presence_count);
    assert_int_equal(1, rec.objects_count);
    assert_int_equal(1, rec.file_count);
    assert_int_equal(1, rec.message_action_count);

    destroy_test_manager(&mgr);
}

static void test_status_delivered_to_all_listeners_regardless_of_binding(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx     = acquire_channel(&mgr, "ch1");
    uint16_t set_idx = pn_subscription_set_create(&mgr);
    test_set_add(&mgr, set_idx, "ch1", 3);

    callback_record_t rec_global = {0};
    callback_record_t rec_bound  = {0};
    callback_record_t rec_set    = {0};

    pubnub_subscribe_listener_t l_global = {
        .on_status = cb_on_status,
        .user_data = &rec_global,
    };
    pubnub_subscribe_listener_t l_bound = {
        .on_status = cb_on_status,
        .user_data = &rec_bound,
    };
    pubnub_subscribe_listener_t l_set = {
        .on_status = cb_on_status,
        .user_data = &rec_set,
    };

    pn_subscribe_listener_add(&mgr, &l_global);
    add_bound_for_entry(&mgr, &l_bound, idx);
    pn_subscribe_listener_add_to_set(&mgr, &l_set, set_idx);

    pn_subscribe_ee_effect_t effect = {0};
    effect.type                     = PN_SUB_EE_EFFECT_EMIT_STATUS;
    effect.status                   = PN_SUB_EE_STATUS_CONNECTED;
    effect.reason                   = PUBNUB_OK;

    pn_subscribe_emit_status(&mgr, &effect);

    /* Status events reach only context-level (unbound) listeners. */
    assert_int_equal(1, rec_global.status_count);
    assert_int_equal(0, rec_bound.status_count);
    assert_int_equal(0, rec_set.status_count);

    destroy_test_manager(&mgr);
}

/* Copy the channel/group views out during the callback: they alias
 * allocator-owned memory that emit_status frees once the callback
 * returns. */
typedef struct status_capture {
    int  status_count;
    int  channels_present;
    int  groups_present;
    char channels[256];
    char groups[256];
} status_capture_t;

static void cb_capture_status(const pubnub_subscribe_status_event_t* event, void* ud)
{
    status_capture_t* cap = (status_capture_t*)ud;
    size_t            n;

    cap->status_count++;

    if (NULL != event->channels.ptr) {
        n = event->channels.len < sizeof(cap->channels) - 1
              ? event->channels.len
              : sizeof(cap->channels) - 1;
        memcpy(cap->channels, event->channels.ptr, n);
        cap->channels[n]      = '\0';
        cap->channels_present = 1;
    }
    if (NULL != event->groups.ptr) {
        n = event->groups.len < sizeof(cap->groups) - 1 ? event->groups.len
                                                        : sizeof(cap->groups) - 1;
        memcpy(cap->groups, event->groups.ptr, n);
        cap->groups[n]      = '\0';
        cap->groups_present = 1;
    }
}

static void emit_connected_status(pn_subscribe_manager_t* mgr)
{
    pn_subscribe_ee_effect_t effect = {0};

    effect.type   = PN_SUB_EE_EFFECT_EMIT_STATUS;
    effect.status = PN_SUB_EE_STATUS_CONNECTED;
    effect.reason = PUBNUB_OK;
    pn_subscribe_emit_status(mgr, &effect);
}

static void test_emit_status_channels_match_subscription(void** state)
{
    (void)state;
    pn_subscribe_manager_t      mgr;
    status_capture_t            cap = {0};
    pubnub_subscribe_listener_t l   = {0};

    create_test_manager(&mgr);
    acquire_active_channel(&mgr, "ch1");
    acquire_active_channel(&mgr, "ch2");
    acquire_active_channel(&mgr, "ch3");

    l.on_status = cb_capture_status;
    l.user_data = &cap;
    pn_subscribe_listener_add(&mgr, &l);

    emit_connected_status(&mgr);

    assert_int_equal(1, cap.status_count);
    assert_int_equal(1, cap.channels_present);
    assert_string_equal("ch1,ch2,ch3", cap.channels);
    assert_int_equal(0, cap.groups_present);

    destroy_test_manager(&mgr);
}

static void test_emit_status_empty_yields_no_views(void** state)
{
    (void)state;
    pn_subscribe_manager_t      mgr;
    status_capture_t            cap = {0};
    pubnub_subscribe_listener_t l   = {0};

    create_test_manager(&mgr);

    l.on_status = cb_capture_status;
    l.user_data = &cap;
    pn_subscribe_listener_add(&mgr, &l);

    emit_connected_status(&mgr);

    assert_int_equal(1, cap.status_count);
    assert_int_equal(0, cap.channels_present);
    assert_int_equal(0, cap.groups_present);

    destroy_test_manager(&mgr);
}

static void test_emit_status_groups_only(void** state)
{
    (void)state;
    pn_subscribe_manager_t      mgr;
    status_capture_t            cap = {0};
    pubnub_subscribe_listener_t l   = {0};

    create_test_manager(&mgr);
    acquire_active_group(&mgr, "grp1");
    acquire_active_group(&mgr, "grp2");

    l.on_status = cb_capture_status;
    l.user_data = &cap;
    pn_subscribe_listener_add(&mgr, &l);

    emit_connected_status(&mgr);

    assert_int_equal(1, cap.status_count);
    assert_int_equal(0, cap.channels_present);
    assert_int_equal(1, cap.groups_present);
    assert_string_equal("grp1,grp2", cap.groups);

    destroy_test_manager(&mgr);
}

static void test_emit_status_channels_and_groups(void** state)
{
    (void)state;
    pn_subscribe_manager_t      mgr;
    status_capture_t            cap = {0};
    pubnub_subscribe_listener_t l   = {0};

    create_test_manager(&mgr);
    acquire_active_channel(&mgr, "ch1");
    acquire_active_group(&mgr, "grp1");

    l.on_status = cb_capture_status;
    l.user_data = &cap;
    pn_subscribe_listener_add(&mgr, &l);

    emit_connected_status(&mgr);

    assert_int_equal(1, cap.status_count);
    assert_int_equal(1, cap.channels_present);
    assert_string_equal("ch1", cap.channels);
    assert_int_equal(1, cap.groups_present);
    assert_string_equal("grp1", cap.groups);

    destroy_test_manager(&mgr);
}

#if PUBNUB_CFG_THREAD_SAFETY && !defined(_WIN32)

#define PN_RACE_ITERATIONS 4000

/* Real pthread-mutex platform: the shared mock installs NULL (no-op) lock
 * hooks, so the context lock would not serialize. The concurrency test
 * needs a real lock to prove emit_status builds the channel string under
 * the same lock the mutation side takes. */
static size_t rl_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(pthread_mutex_t);
}

static int rl_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    return pthread_mutex_init((pthread_mutex_t*)lock, NULL);
}

static void rl_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    pthread_mutex_destroy((pthread_mutex_t*)lock);
}

static void rl_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    pthread_mutex_lock((pthread_mutex_t*)lock);
}

static void rl_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    pthread_mutex_unlock((pthread_mutex_t*)lock);
}

static pubnub_platform_provider_t s_real_lock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
    .secure_zero   = NULL,
    .lock_size     = rl_lock_size,
    .lock_init     = rl_lock_init,
    .lock_destroy  = rl_lock_destroy,
    .lock_acquire  = rl_lock_acquire,
    .lock_release  = rl_lock_release,
    .thread_create = NULL,
    .thread_join   = NULL,
};

/** Shared state handed to the two racing threads. */
typedef struct race_ctx {
    pn_subscribe_manager_t*     mgr;
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
} race_ctx_t;

static void* race_emit_thread(void* arg)
{
    race_ctx_t* rc = (race_ctx_t*)arg;
    int         k;

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        emit_connected_status(rc->mgr);
    }
    return NULL;
}

static void* race_mutate_thread(void* arg)
{
    race_ctx_t* rc = (race_ctx_t*)arg;
    int         k;

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        uint16_t idx;
        /* Mutations run under the context lock. The entry is marked active
         * so the builder reads its name during the two-pass measure/write,
         * then freed on release — the window where an unlocked builder could
         * observe a half-freed name. */
        pn_ctx_lock(rc->platform, rc->lock);
        idx = pn_subscription_acquire(rc->mgr, "chX", 3, PN_ENTITY_CHANNEL, 0);
        if (UINT16_MAX != idx) {
            rc->mgr->entries[idx].active_count++;
        }
        pn_ctx_unlock(rc->platform, rc->lock);
        if (UINT16_MAX != idx) {
            pn_ctx_lock(rc->platform, rc->lock);
            rc->mgr->entries[idx].active_count--;
            pn_subscription_release(rc->mgr, idx);
            pn_ctx_unlock(rc->platform, rc->lock);
        }
    }
    return NULL;
}

static void test_emit_status_channel_build_is_race_free(void** state)
{
    (void)state;
    static PUBNUB_ALIGNAS(max_align_t) uint8_t ctx_mem[PUBNUB_CONTEXT_SIZE];
    pubnub_config_t                            cfg = pubnub_config_defaults();
    pubnub_context_t*                          ctx = (pubnub_context_t*)ctx_mem;
    pn_subscribe_manager_t                     mgr;
    status_capture_t                           cap = {0};
    pubnub_subscribe_listener_t                l   = {0};
    race_ctx_t                                 rc  = {0};
    pn_test_thread_t                           t_emit;
    pn_test_thread_t                           t_mutate;
    pubnub_allocator_provider_t*               alloc;
    uint16_t                                   i;

    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_real_lock_platform;

    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx            = ctx;
    mgr.ee_state       = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
    mgr.active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_subscribe_event_queue_init(&mgr.event_queue);

    /* Persistent channels the emit side must always see intact. */
    acquire_active_channel(&mgr, "ch1");
    acquire_active_channel(&mgr, "ch2");

    l.on_status = cb_capture_status;
    l.user_data = &cap;
    pn_subscribe_listener_add(&mgr, &l);

    rc.mgr      = &mgr;
    rc.platform = &s_real_lock_platform;
    rc.lock     = pn_context_mutex_mem(ctx);

    assert_int_equal(0, pn_test_thread_create(&t_emit, race_emit_thread, &rc));
    assert_int_equal(0, pn_test_thread_create(&t_mutate, race_mutate_thread, &rc));
    pn_test_thread_join(t_emit);
    pn_test_thread_join(t_mutate);

    /* With snapshot-under-lock every status snapshot is well-formed and
     * always contains the persistent channels (TSan/ASan clean). */
    assert_int_equal(PN_RACE_ITERATIONS, cap.status_count);
    assert_int_equal(1, cap.channels_present);
    assert_non_null(strstr(cap.channels, "ch1"));
    assert_non_null(strstr(cap.channels, "ch2"));

    alloc = pn_context_allocator(ctx);
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (mgr.entries[i].occupied) {
            pn_strfree(mgr.entries[i].name, alloc);
        }
    }
    pubnub_deinit(ctx);
}

/** Shared state handed to the message-emit race threads. */
typedef struct msg_race_ctx {
    pn_subscribe_manager_t*     mgr;
    pubnub_platform_provider_t* platform;
    pubnub_lock_t*              lock;
    uint16_t                    set_idx;
    int                         emit_done;
} msg_race_ctx_t;

static callback_record_t s_msg_race_rec;

static void* msg_race_emit_thread(void* arg)
{
    msg_race_ctx_t* rc = (msg_race_ctx_t*)arg;
    int             k;

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        pubnub_subscribe_event_t msg =
            make_message(PUBNUB_SUBSCRIBE_MESSAGE, "chX");
        pn_subscribe_emit_message(rc->mgr, &msg);
    }
    rc->emit_done = 1;
    return NULL;
}

/* Churns a set member "chX" through acquire -> add-to-set -> remove. The
 * remove drops the last ref and frees entries[].name — the exact write
 * the set-listener matcher races when it reads member names. All mutations
 * run under the context lock, matching the public-API contract. */
static void* msg_race_mutate_thread(void* arg)
{
    msg_race_ctx_t*             rc = (msg_race_ctx_t*)arg;
    pn_subscription_set_data_t* set;
    int                         k;

    set = &rc->mgr->sets[rc->set_idx];

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        uint16_t           idx;
        pn_subscription_t* sub = NULL;

        pn_ctx_lock(rc->platform, rc->lock);
        idx = pn_subscription_acquire(rc->mgr, "chX", 3, PN_ENTITY_CHANNEL, 0);
        if (UINT16_MAX != idx
            && !pn_subscription_set_contains(rc->mgr, rc->set_idx, idx)
            && set->count < PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET) {
            pubnub_allocator_provider_t* alloc = pn_context_allocator(rc->mgr->ctx);
            sub = (pn_subscription_t*)PN_ALLOC(alloc, sizeof(*sub), sizeof(void*));
            if (NULL != sub) {
                sub->ctx                 = rc->mgr->ctx;
                sub->entry_index         = idx;
                sub->slot_index          = UINT16_MAX;
                sub->ref_count           = 1;
                sub->subscribed          = 0;
                sub->with_presence       = 0;
                sub->subscribed_set_refs = 0;
                if (UINT16_MAX == pn_track_subscription(rc->mgr, sub)
                    || pn_subscription_set_add_member(rc->mgr, rc->set_idx, sub)
                           <= 0) {
                    pn_subscription_handle_unref(rc->mgr, sub);
                    sub = NULL;
                    pn_subscription_release(rc->mgr, idx);
                }
            } else {
                pn_subscription_release(rc->mgr, idx);
            }
        } else if (UINT16_MAX != idx) {
            /* Already a member or set full — drop the extra acquire. */
            pn_subscription_release(rc->mgr, idx);
        }
        pn_ctx_unlock(rc->platform, rc->lock);

        /* Remove the member and drop both references (set + creator). The
         * final unref frees entries[].name — the write the emit matcher
         * races. */
        if (NULL != sub) {
            pn_ctx_lock(rc->platform, rc->lock);
            (void)pn_subscription_set_remove_member_slot(
                rc->mgr, rc->set_idx, sub->slot_index);
            pn_subscription_handle_unref(rc->mgr, sub);
            pn_subscription_handle_unref(rc->mgr, sub);
            pn_ctx_unlock(rc->platform, rc->lock);
        }
    }
    return NULL;
}

/* Emit-side match reads entries[]/sets[] for a set-bound listener while the
 * mutator frees a member entry's name. The snapshot-under-lock match takes
 * its decision atomically w.r.t. the mutation (TSan/ASan clean). */
static void test_emit_message_match_is_race_free(void** state)
{
    (void)state;
    static PUBNUB_ALIGNAS(max_align_t) uint8_t ctx_mem[PUBNUB_CONTEXT_SIZE];
    pubnub_config_t                            cfg = pubnub_config_defaults();
    pubnub_context_t*                          ctx = (pubnub_context_t*)ctx_mem;
    pn_subscribe_manager_t                     mgr;
    pubnub_subscribe_listener_t                l  = {0};
    msg_race_ctx_t                             rc = {0};
    pn_test_thread_t                           t_emit;
    pn_test_thread_t                           t_mutate;
    pubnub_allocator_provider_t*               alloc;
    uint16_t                                   set_idx;
    uint16_t                                   i;

    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_real_lock_platform;

    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx            = ctx;
    mgr.ee_state       = PN_SUBSCRIBE_STATE_UNSUBSCRIBED;
    mgr.active_slot_id = PUBNUB_SLOT_ID_INVALID;
    pn_subscribe_event_queue_init(&mgr.event_queue);

    /* Persistent baseline member the matcher always reads. */
    set_idx = pn_subscription_set_create(&mgr);
    assert_int_not_equal(UINT16_MAX, set_idx);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "keep", 4));
    mgr.sets[set_idx].subscribed = 1;

    memset(&s_msg_race_rec, 0, sizeof(s_msg_race_rec));
    l.on_message = cb_on_message;
    l.user_data  = &s_msg_race_rec;
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    rc.mgr      = &mgr;
    rc.platform = &s_real_lock_platform;
    rc.lock     = pn_context_mutex_mem(ctx);
    rc.set_idx  = set_idx;

    assert_int_equal(0, pn_test_thread_create(&t_emit, msg_race_emit_thread, &rc));
    assert_int_equal(
        0, pn_test_thread_create(&t_mutate, msg_race_mutate_thread, &rc));
    pn_test_thread_join(t_emit);
    pn_test_thread_join(t_mutate);

    /* The race loop completes with no use-after-free, and routing on the
     * persistent member still works single-threaded. */
    assert_int_equal(1, rc.emit_done);

    {
        pubnub_subscribe_event_t msg =
            make_message(PUBNUB_SUBSCRIBE_MESSAGE, "keep");
        int before = s_msg_race_rec.message_count;
        pn_subscribe_emit_message(&mgr, &msg);
        assert_int_equal(before + 1, s_msg_race_rec.message_count);
    }

    alloc = pn_context_allocator(ctx);
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        if (mgr.entries[i].occupied) {
            pn_strfree(mgr.entries[i].name, alloc);
        }
    }
    pubnub_deinit(ctx);
}

/** State for the callback that re-enters a lock-taking public API. */
typedef struct reenter_state {
    pubnub_context_t*        ctx;
    int                      fired;
    pubnub_listener_handle_t added;
    callback_record_t        inner_rec;
} reenter_state_t;

/* Re-enters pubnub_add_listener, which takes the context lock. If emit still
 * held the (non-recursive) lock while dispatching, this deadlocks. */
static void cb_reenter_add_listener(const pubnub_subscribe_event_t* event, void* ud)
{
    reenter_state_t*            s     = (reenter_state_t*)ud;
    pubnub_subscribe_listener_t inner = {0};

    (void)event;
    s->fired++;
    inner.on_message = cb_on_message;
    inner.user_data  = &s->inner_rec;
    s->added         = pubnub_add_listener(s->ctx, &inner);
}

static void test_emit_message_callback_not_under_lock(void** state)
{
    (void)state;
    static PUBNUB_ALIGNAS(max_align_t) uint8_t ctx_mem[PUBNUB_CONTEXT_SIZE];
    pubnub_config_t                            cfg = pubnub_config_defaults();
    pubnub_context_t*                          ctx = (pubnub_context_t*)ctx_mem;
    pn_subscribe_manager_t*                    mgr;
    reenter_state_t                            rs = {0};
    pubnub_subscribe_listener_t                l  = {0};
    pubnub_listener_handle_t                   h;
    uint16_t                                   idx;

    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_real_lock_platform;

    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    rs.ctx       = ctx;
    l.on_message = cb_reenter_add_listener;
    l.user_data  = &rs;
    h            = pubnub_add_listener(ctx, &l);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, h);

    mgr = pn_subscribe_manager_from_ctx(ctx);
    assert_non_null(mgr);
    idx = acquire_channel(mgr, "ch1");

    {
        pubnub_subscribe_event_t msg =
            make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
        /* Deadlocks here if emit dispatches callbacks under the ctx lock. */
        pn_subscribe_emit_message(mgr, &msg);
    }

    assert_int_equal(1, rs.fired);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, rs.added);

    pubnub_remove_listener(ctx, rs.added);
    pubnub_remove_listener(ctx, h);
    pn_subscription_release(mgr, idx);
    pubnub_deinit(ctx);
}

#if PUBNUB_ENABLE_PRESENCE

/** Shared state for the presence-notify public-API race test. */
typedef struct pf1_race_ctx {
    pubnub_context_t*     ctx;
    pubnub_subscription_t toggle_sub;
} pf1_race_ctx_t;

/* Thread A: drives the presence heartbeat builders via the public API.
 * Each subscribe/unsubscribe builds the heartbeat strings by a two-pass
 * measure/write over the shared entry registry. */
static void* pf1_notify_thread(void* arg)
{
    pf1_race_ctx_t* rc = (pf1_race_ctx_t*)arg;
    int             k;

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        (void)pubnub_subscription_subscribe(rc->toggle_sub);
        (void)pubnub_subscription_unsubscribe(rc->toggle_sub);
    }
    return NULL;
}

/* Thread B: churns a transient channel entry through
 * create -> subscribe -> unsubscribe -> destroy. The final destroy frees
 * the entry name via pn_subscription_release — the write that races thread
 * A's two-pass heartbeat read. */
static void* pf1_churn_thread(void* arg)
{
    pf1_race_ctx_t* rc = (pf1_race_ctx_t*)arg;
    int             k;

    for (k = 0; k < PN_RACE_ITERATIONS; ++k) {
        pubnub_subscription_opts_t opts = {0};
        pubnub_entity_t            ent;
        pubnub_subscription_t      sub;

        opts.with_presence = 1;
        ent                = pubnub_channel(rc->ctx, "pf1-chB");
        if (NULL == ent) {
            continue;
        }
        sub = pubnub_subscription_create(ent, &opts);
        if (NULL != sub) {
            (void)pubnub_subscription_subscribe(sub);
            (void)pubnub_subscription_unsubscribe(sub);
            pubnub_subscription_destroy(sub);
        }
        pubnub_entity_destroy(ent);
    }
    return NULL;
}

static void test_presence_notify_build_is_race_free(void** state)
{
    (void)state;
    static PUBNUB_ALIGNAS(max_align_t) uint8_t ctx_mem[PUBNUB_CONTEXT_SIZE];
    pubnub_config_t                            cfg = pubnub_config_defaults();
    pubnub_context_t*                          ctx = (pubnub_context_t*)ctx_mem;
    pubnub_subscription_opts_t                 opts = {0};
    pf1_race_ctx_t                             rc   = {0};
    pubnub_entity_t                            ent_a;
    pubnub_subscription_t                      sub_a;
    pn_test_thread_t                           t_notify;
    pn_test_thread_t                           t_churn;

    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_real_lock_platform;

    assert_int_equal(PUBNUB_OK, pubnub_init(ctx, &cfg));

    opts.with_presence = 1;

    /* Persistent subscription that thread A toggles to drive the
     * presence notify path on every subscribe/unsubscribe transition. */
    ent_a = pubnub_channel(ctx, "pf1-chA");
    assert_non_null(ent_a);
    sub_a = pubnub_subscription_create(ent_a, &opts);
    assert_non_null(sub_a);

    /* Warm up the presence manager single-threaded (its creation is not
     * lock-guarded) so the race stays focused on the heartbeat-builder vs.
     * pn_subscription_release window, not an unrelated double-create. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub_a));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub_a));

    rc.ctx        = ctx;
    rc.toggle_sub = sub_a;

    assert_int_equal(0, pn_test_thread_create(&t_notify, pf1_notify_thread, &rc));
    assert_int_equal(0, pn_test_thread_create(&t_churn, pf1_churn_thread, &rc));
    pn_test_thread_join(t_notify);
    pn_test_thread_join(t_churn);

    /* The heartbeat builders run under the same context lock
     * pn_subscription_release takes, so TSan reports no data race on the
     * entry name buffers. */
    pubnub_subscription_destroy(sub_a);
    pubnub_entity_destroy(ent_a);
    pubnub_deinit(ctx);
}

#endif /* PUBNUB_ENABLE_PRESENCE */

#endif /* PUBNUB_CFG_THREAD_SAFETY && !defined(_WIN32) */

static void test_removed_listener_stops_receiving(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Remove and dispatch again. */
    pn_subscribe_listener_remove(&mgr, h);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count); /* No increment. */

    destroy_test_manager(&mgr);
}

static void test_channel_name_resolution_for_dispatch(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    add_bound_for_entry(&mgr, &listener, idx_ch1);

    /* Routing is by event channel name. */
    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* A presence-requesting channel entry receives a presence event routed by
 * the raw subscription ("b") whose base matches the entry name. The parser
 * strips the suffix from the channel view, so emit sees channel="ch1"
 * (base) while subscription keeps the raw "ch1-pnpres". */
static void test_pnpres_suffix_stripped_during_resolution(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "ch1", PN_ENTITY_CHANNEL, 1);

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_presence = cb_on_presence,
        .user_data   = &rec,
    };
    add_bound_for_entry(&mgr, &listener, idx);

    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "ch1", "ch1-pnpres");

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* A channel entry WITHOUT presence requested does not receive presence
 * events, even when the base name matches the event. */
static void test_pnpres_no_presence_flag_blocks_delivery(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "ch1", PN_ENTITY_CHANNEL, 0);

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_presence = cb_on_presence,
        .user_data   = &rec,
    };
    add_bound_for_entry(&mgr, &listener, idx);

    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "ch1", "ch1-pnpres");

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(0, rec.presence_count);

    destroy_test_manager(&mgr);
}

static void test_ref_count_increments_on_acquire(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied);
    assert_int_equal(1, mgr.channel_count);

    /* Second acquire of same name should increment. */
    uint16_t idx2 = acquire_channel(&mgr, "ch1");
    assert_int_equal(idx, idx2);
    assert_int_equal(2, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.channel_count); /* Still 1 unique entry. */

    destroy_test_manager(&mgr);
}

static void test_ref_count_decrements_on_release(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    acquire_channel(&mgr, "ch1"); /* ref_count = 2 */

    pn_subscription_release(&mgr, idx);
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied); /* Still alive. */
    assert_int_equal(1, mgr.channel_count);

    destroy_test_manager(&mgr);
}

static void test_entry_freed_when_ref_count_reaches_zero(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.channel_count);

    pn_subscription_release(&mgr, idx);
    assert_int_equal(0, mgr.entries[idx].ref_count);
    assert_int_equal(0, mgr.entries[idx].occupied);
    assert_int_equal(0, mgr.channel_count);
}

static void test_double_release_is_safe(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    pn_subscription_release(&mgr, idx);

    /* Entry is now freed (occupied=0). Second release should no-op. */
    pn_subscription_release(&mgr, idx);
    assert_int_equal(0, mgr.entries[idx].occupied);
    assert_int_equal(0, mgr.channel_count);
}

static void test_set_holds_independent_ref(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1"); /* ref=1 */

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    test_set_add(&mgr, set_idx, "ch1", 3);
    /* set_add does its own acquire → ref=2 */
    assert_int_equal(2, mgr.entries[idx].ref_count);

    /* Release the original reference. */
    pn_subscription_release(&mgr, idx);
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied);

    /* Destroy the set — releases the set's ref. */
    pn_subscription_set_destroy(&mgr, set_idx);
    assert_int_equal(0, mgr.entries[idx].ref_count);
    assert_int_equal(0, mgr.entries[idx].occupied);
    assert_int_equal(0, mgr.channel_count);
}

static void test_multiple_acquires_release_independently(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    /* Simulate: entity + subscription + set all referencing same channel. */
    uint16_t idx = acquire_channel(&mgr, "ch1"); /* entity ref → 1 */
    acquire_channel(&mgr, "ch1");                /* subscription ref → 2 */
    acquire_channel(&mgr, "ch1");                /* set ref → 3 */
    assert_int_equal(3, mgr.entries[idx].ref_count);

    pn_subscription_release(&mgr, idx); /* → 2 */
    assert_int_equal(2, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied);

    pn_subscription_release(&mgr, idx); /* → 1 */
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied);

    pn_subscription_release(&mgr, idx); /* → 0, freed */
    assert_int_equal(0, mgr.entries[idx].ref_count);
    assert_int_equal(0, mgr.entries[idx].occupied);
    assert_int_equal(0, mgr.channel_count);
}

static void test_freed_slot_can_be_reused(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    pn_subscription_release(&mgr, idx); /* free it */

    /* Acquiring a new channel should reuse the freed slot. */
    uint16_t idx2 = acquire_channel(&mgr, "ch2");
    assert_int_equal(idx, idx2);
    assert_int_equal(1, mgr.entries[idx2].ref_count);
    assert_int_equal(1, mgr.entries[idx2].occupied);
    assert_string_equal("ch2", mgr.entries[idx2].name);

    destroy_test_manager(&mgr);
}

static void test_active_count_independent_of_ref_count(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1"); /* ref=1, active=0 */
    assert_int_equal(0, mgr.entries[idx].active_count);

    /* Simulate subscribing (normally done by pubnub_subscription_subscribe). */
    mgr.entries[idx].active_count++;
    assert_int_equal(1, mgr.entries[idx].active_count);
    assert_int_equal(1, mgr.entries[idx].ref_count);

    /* Second subscription on same channel. */
    acquire_channel(&mgr, "ch1"); /* ref=2 */
    mgr.entries[idx].active_count++;
    assert_int_equal(2, mgr.entries[idx].active_count);
    assert_int_equal(2, mgr.entries[idx].ref_count);

    /* Unsubscribe one — active decreases, ref stays. */
    mgr.entries[idx].active_count--;
    assert_int_equal(1, mgr.entries[idx].active_count);
    assert_int_equal(2, mgr.entries[idx].ref_count);

    /* Release one ref — ref decreases, entry still alive (active > 0). */
    pn_subscription_release(&mgr, idx);
    assert_int_equal(1, mgr.entries[idx].ref_count);
    assert_int_equal(1, mgr.entries[idx].occupied);

    destroy_test_manager(&mgr);
}

static void test_acquire_stores_name_dynamically(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "my-channel");
    assert_non_null(mgr.entries[idx].name);
    assert_string_equal("my-channel", mgr.entries[idx].name);
    assert_int_equal(10, mgr.entries[idx].name_len);

    pn_subscription_release(&mgr, idx);
}

static void test_release_frees_name(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    assert_non_null(mgr.entries[idx].name);

    pn_subscription_release(&mgr, idx);
    assert_null(mgr.entries[idx].name);
    assert_int_equal(0, mgr.entries[idx].name_len);
}

static void test_reacquire_same_name_no_new_alloc(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx1 = acquire_channel(&mgr, "ch1");
    char*    ptr  = mgr.entries[idx1].name;

    /* Second acquire of same name — ref_count bumps, same pointer. */
    uint16_t idx2 = acquire_channel(&mgr, "ch1");
    assert_int_equal(idx1, idx2);
    assert_ptr_equal(ptr, mgr.entries[idx2].name);
    assert_int_equal(2, mgr.entries[idx2].ref_count);

    pn_subscription_release(&mgr, idx2);
    pn_subscription_release(&mgr, idx2);
}

static void test_acquire_long_name_succeeds(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    /* Name longer than 92 bytes (old static limit). */
    const char* long_name =
        "this-is-a-very-long-channel-name-that-exceeds-ninety-two-bytes-"
        "in-total-length-for-testing-dynamic-allocation";
    uint16_t idx = pn_subscription_acquire(
        &mgr, long_name, (uint16_t)strlen(long_name), PN_ENTITY_CHANNEL, 0);
    assert_true(idx < UINT16_MAX);
    assert_non_null(mgr.entries[idx].name);
    assert_string_equal(long_name, mgr.entries[idx].name);
    assert_int_equal(strlen(long_name), mgr.entries[idx].name_len);

    pn_subscription_release(&mgr, idx);
}

static void test_release_all_frees_all_names(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx1 = acquire_channel(&mgr, "ch1");
    uint16_t idx2 = acquire_channel(&mgr, "ch2");
    uint16_t idx3 = acquire_channel(&mgr, "ch3");
    assert_int_equal(3, mgr.channel_count);

    pn_subscription_release(&mgr, idx1);
    pn_subscription_release(&mgr, idx2);
    pn_subscription_release(&mgr, idx3);

    assert_int_equal(0, mgr.channel_count);
    assert_null(mgr.entries[idx1].name);
    assert_null(mgr.entries[idx2].name);
    assert_null(mgr.entries[idx3].name);
}

static void test_remove_during_emit_defers(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);

    /* Simulate an in-progress emit cycle. */
    PUBNUB_ATOMIC_STORE_U8(&mgr.invoke_pending, 1);

    pn_subscribe_listener_remove(&mgr, h);

    /* Slot is still active but marked for deferred removal. */
    assert_int_equal(1, mgr.listeners[h].active);
    assert_int_equal(1, mgr.listeners[h].pending_remove);
    assert_int_equal(1, mgr.listener_count);

    PUBNUB_ATOMIC_STORE_U8(&mgr.invoke_pending, 0);
}

static void test_deferred_remove_skipped_in_emit(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);

    /* Manually set pending_remove as if a concurrent remove happened. */
    mgr.listeners[h].pending_remove = 1;

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);

    /* Callback must NOT have fired for the pending-remove slot. */
    assert_int_equal(0, rec.message_count);

    /* Post-emit sweep should have cleaned the slot. */
    assert_int_equal(0, mgr.listeners[h].active);
    assert_int_equal(0, mgr.listeners[h].pending_remove);
    assert_int_equal(0, mgr.listener_count);

    destroy_test_manager(&mgr);
}

/** State passed via user_data to the self-removing callback. */
typedef struct self_remove_state {
    pubnub_context_t*        ctx;
    pubnub_listener_handle_t handle;
    int                      fire_count;
} self_remove_state_t;

static void cb_self_remove(const pubnub_subscribe_event_t* event, void* ud)
{
    (void)event;
    self_remove_state_t* s = (self_remove_state_t*)ud;
    s->fire_count++;
    pubnub_remove_listener(s->ctx, s->handle);
}

static void test_remove_self_from_callback(void** state)
{
    (void)state;
    pn_subscribe_manager_t* mgr;
    self_remove_state_t     rm_state = {0};

    rm_state.ctx = s_test_ctx;

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_self_remove,
        .user_data  = &rm_state,
    };

    rm_state.handle = pubnub_add_listener(s_test_ctx, &listener);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, rm_state.handle);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_non_null(mgr);

    uint16_t idx = acquire_channel(mgr, "ch1");

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");

    /* This would deadlock with the old spin-wait implementation. */
    pn_subscribe_emit_message(mgr, &msg);

    /* Callback fired exactly once, then removed itself. */
    assert_int_equal(1, rm_state.fire_count);

    /* Slot cleaned up by post-emit sweep. */
    assert_int_equal(0, mgr->listeners[(pn_listener_handle_t)rm_state.handle].active);

    pn_subscription_release(mgr, idx);
}

/** State for a callback that removes a DIFFERENT listener. */
typedef struct cross_remove_state {
    pubnub_context_t*        ctx;
    pubnub_listener_handle_t target_handle;
    int                      fire_count;
} cross_remove_state_t;

static void cb_cross_remove(const pubnub_subscribe_event_t* event, void* ud)
{
    (void)event;
    cross_remove_state_t* s = (cross_remove_state_t*)ud;
    s->fire_count++;
    pubnub_remove_listener(s->ctx, s->target_handle);
}

static void test_remove_other_listener_from_callback(void** state)
{
    (void)state;
    pn_subscribe_manager_t* mgr;
    cross_remove_state_t    rm_state   = {0};
    callback_record_t       victim_rec = {0};

    rm_state.ctx = s_test_ctx;

    /* Listener A: removes listener B when called. */
    pubnub_subscribe_listener_t listener_a = {
        .on_message = cb_cross_remove,
        .user_data  = &rm_state,
    };
    pubnub_listener_handle_t h_a = pubnub_add_listener(s_test_ctx, &listener_a);

    /* Listener B: the victim. */
    pubnub_subscribe_listener_t listener_b = {
        .on_message = cb_on_message,
        .user_data  = &victim_rec,
    };
    pubnub_listener_handle_t h_b = pubnub_add_listener(s_test_ctx, &listener_b);

    rm_state.target_handle = h_b;

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_non_null(mgr);

    uint16_t idx = acquire_channel(mgr, "ch1");

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(mgr, &msg);

    /* Listener A fired and removed B. */
    assert_int_equal(1, rm_state.fire_count);

    /* B was marked pending_remove by A's callback. Depending on
     * iteration order (A before B), B may or may not have fired.
     * Either way it must be cleaned up after emit. */
    assert_int_equal(0, mgr->listeners[(pn_listener_handle_t)h_b].active);

    /* Clean up listener A (still active). */
    pubnub_remove_listener(s_test_ctx, h_a);

    pn_subscription_release(mgr, idx);
}

static void test_earlier_callback_removes_later_pending_skipped(void** state)
{
    (void)state;
    pn_subscribe_manager_t* mgr;
    cross_remove_state_t    rm_state   = {0};
    callback_record_t       victim_rec = {0};

    rm_state.ctx = s_test_ctx;

    /* Listener A is added first, so it occupies a lower slot index and the
     * ascending emit loop invokes it before B. A removes B during its
     * callback while B is still pending in the same emit. */
    pubnub_subscribe_listener_t listener_a = {
        .on_message = cb_cross_remove,
        .user_data  = &rm_state,
    };
    pubnub_listener_handle_t h_a = pubnub_add_listener(s_test_ctx, &listener_a);

    pubnub_subscribe_listener_t listener_b = {
        .on_message = cb_on_message,
        .user_data  = &victim_rec,
    };
    pubnub_listener_handle_t h_b = pubnub_add_listener(s_test_ctx, &listener_b);

    rm_state.target_handle = h_b;

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_non_null(mgr);
    assert_true((pn_listener_handle_t)h_a < (pn_listener_handle_t)h_b);

    uint16_t idx = acquire_channel(mgr, "ch1");

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(mgr, &msg);

    /* A fired and marked B pending_remove; the post-callback re-check must
     * skip B so it is never invoked in this emit. */
    assert_int_equal(1, rm_state.fire_count);
    assert_int_equal(0, victim_rec.message_count);
    assert_int_equal(0, mgr->listeners[(pn_listener_handle_t)h_b].active);

    /* A subsequent emit must not invoke the removed listener B. Point A at
     * an invalid target so it does not attempt a second remove. */
    rm_state.target_handle = PUBNUB_LISTENER_HANDLE_INVALID;
    pn_subscribe_emit_message(mgr, &msg);
    assert_int_equal(2, rm_state.fire_count);
    assert_int_equal(0, victim_rec.message_count);

    pubnub_remove_listener(s_test_ctx, h_a);
    pn_subscription_release(mgr, idx);
}

static void test_readd_after_deferred_remove(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    callback_record_t           rec1     = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec1,
    };
    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);

    /* Simulate emit in progress + deferred removal. */
    PUBNUB_ATOMIC_STORE_U8(&mgr.invoke_pending, 1);
    pn_subscribe_listener_remove(&mgr, h);
    assert_int_equal(1, mgr.listeners[h].pending_remove);
    PUBNUB_ATOMIC_STORE_U8(&mgr.invoke_pending, 0);

    /* Slot still has active=1, so add should use a DIFFERENT slot. */
    callback_record_t           rec2      = {0};
    pubnub_subscribe_listener_t listener2 = {
        .on_message = cb_on_message,
        .user_data  = &rec2,
    };
    pn_listener_handle_t h2 = pn_subscribe_listener_add(&mgr, &listener2);
    assert_int_not_equal(h, h2);

    /* Now emit — sweeps the old slot, dispatches to the new one. */
    acquire_channel(&mgr, "ch1");
    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);

    /* Old listener not called, new one called. */
    assert_int_equal(0, rec1.message_count);
    assert_int_equal(1, rec2.message_count);

    /* Old slot cleaned up. */
    assert_int_equal(0, mgr.listeners[h].active);

    destroy_test_manager(&mgr);
}

static void test_set_contains_after_add(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    test_set_add(&mgr, set_idx, "ch1", 3);

    assert_int_equal(1, pn_subscription_set_contains(&mgr, set_idx, idx_ch1));
    assert_int_equal(0, pn_subscription_set_contains(&mgr, set_idx, idx_ch2));

    destroy_test_manager(&mgr);
}

static void test_set_destroy_releases_all_refs(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    /* Create entries with only-set refs. */
    uint16_t set_idx = pn_subscription_set_create(&mgr);
    test_set_add(&mgr, set_idx, "ch1", 3);
    test_set_add(&mgr, set_idx, "ch2", 3);
    test_set_add(&mgr, set_idx, "ch3", 3);
    assert_int_equal(3, mgr.channel_count);

    pn_subscription_set_destroy(&mgr, set_idx);
    assert_int_equal(0, mgr.channel_count);
    assert_int_equal(0, mgr.sets[set_idx].active);
}

/* A channel and a same-named channel-metadata object are distinct entries:
 * a non-presence event reaches a listener on each, but a presence event
 * reaches only the presence-requesting channel entry. */
static void test_same_name_channel_and_metadata_route_to_both(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch =
        acquire_active_typed(&mgr, "my_channel", PN_ENTITY_CHANNEL, 1);
    uint16_t idx_md = pn_subscription_acquire(
        &mgr, "my_channel", 10, PN_ENTITY_CHANNEL_METADATA, 0);
    assert_int_not_equal(UINT16_MAX, idx_ch);
    assert_int_not_equal(UINT16_MAX, idx_md);
    assert_int_not_equal(idx_ch, idx_md);

    callback_record_t           rec_ch = {0};
    callback_record_t           rec_md = {0};
    pubnub_subscribe_listener_t l_ch   = {
          .on_message        = cb_on_message,
          .on_signal         = cb_on_signal,
          .on_presence       = cb_on_presence,
          .on_app_context    = cb_on_app_context,
          .on_file           = cb_on_file,
          .on_message_action = cb_on_message_action,
          .user_data         = &rec_ch,
    };
    pubnub_subscribe_listener_t l_md = l_ch;
    l_md.user_data                   = &rec_md;

    add_bound_for_entry(&mgr, &l_ch, idx_ch);
    add_bound_for_entry(&mgr, &l_md, idx_md);

    pubnub_subscribe_event_t m_msg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "my_channel", NULL);
    pubnub_subscribe_event_t m_sig =
        make_message_full(PUBNUB_SUBSCRIBE_SIGNAL, "my_channel", NULL);
    pubnub_subscribe_event_t m_pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "my_channel", NULL);
    pubnub_subscribe_event_t m_obj =
        make_message_full(PUBNUB_SUBSCRIBE_APP_CONTEXT, "my_channel", NULL);
    pubnub_subscribe_event_t m_fil =
        make_message_full(PUBNUB_SUBSCRIBE_FILE, "my_channel", NULL);
    pubnub_subscribe_event_t m_act =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE_ACTION, "my_channel", NULL);

    pn_subscribe_emit_message(&mgr, &m_msg);
    pn_subscribe_emit_message(&mgr, &m_sig);
    pn_subscribe_emit_message(&mgr, &m_pre);
    pn_subscribe_emit_message(&mgr, &m_obj);
    pn_subscribe_emit_message(&mgr, &m_fil);
    pn_subscribe_emit_message(&mgr, &m_act);

    assert_int_equal(1, rec_ch.message_count);
    assert_int_equal(1, rec_ch.signal_count);
    assert_int_equal(1, rec_ch.presence_count);
    assert_int_equal(1, rec_ch.objects_count);
    assert_int_equal(1, rec_ch.file_count);
    assert_int_equal(1, rec_ch.message_action_count);

    assert_int_equal(1, rec_md.message_count);
    assert_int_equal(1, rec_md.signal_count);
    /* Metadata entries never match presence events. */
    assert_int_equal(0, rec_md.presence_count);
    assert_int_equal(1, rec_md.objects_count);
    assert_int_equal(1, rec_md.file_count);
    assert_int_equal(1, rec_md.message_action_count);

    destroy_test_manager(&mgr);
}

/* Two listeners bound to the same entry both fire, each exactly once, and
 * a single listener fires once even when the channel ("c") and
 * subscription ("b") views both name its bound entry. */
static void test_duplicate_bindings_each_fire_exactly_once(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "dup");
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec1 = {0};
    callback_record_t           rec2 = {0};
    pubnub_subscribe_listener_t l1   = {.on_message = cb_on_message,
                                        .user_data  = &rec1};
    pubnub_subscribe_listener_t l2   = {.on_message = cb_on_message,
                                        .user_data  = &rec2};
    add_bound_for_entry(&mgr, &l1, idx);
    add_bound_for_entry(&mgr, &l2, idx);

    /* Both "c" and "b" name the same entry — must still fire once each. */
    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "dup", "dup");
    pn_subscribe_emit_message(&mgr, &msg);

    assert_int_equal(1, rec1.message_count);
    assert_int_equal(1, rec2.message_count);

    destroy_test_manager(&mgr);
}

/* The "b" (subscription) view can match an entry the "c" view does not,
 * and c/b may resolve to different entries. Each bound listener still
 * fires exactly once via whichever candidate matches. */
static void test_channel_and_subscription_hit_different_entries(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch = acquire_channel(&mgr, "concrete");
    uint16_t idx_grp =
        pn_subscription_acquire(&mgr, "the-group", 9, PN_ENTITY_CHANNEL_GROUP, 0);
    assert_int_not_equal(UINT16_MAX, idx_ch);
    assert_int_not_equal(UINT16_MAX, idx_grp);

    callback_record_t           rec_ch  = {0};
    callback_record_t           rec_grp = {0};
    pubnub_subscribe_listener_t l_ch    = {.on_message = cb_on_message,
                                           .user_data  = &rec_ch};
    pubnub_subscribe_listener_t l_grp   = {.on_message = cb_on_message,
                                           .user_data  = &rec_grp};
    add_bound_for_entry(&mgr, &l_ch, idx_ch);
    add_bound_for_entry(&mgr, &l_grp, idx_grp);

    /* c names the channel, b names the group. */
    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "concrete", "the-group");
    pn_subscribe_emit_message(&mgr, &msg);

    assert_int_equal(1, rec_ch.message_count);
    assert_int_equal(1, rec_grp.message_count);

    /* A group-only delivery still carries the concrete member channel in
     * "c" (the parser guarantees a non-empty channel), so the real wire
     * shape is c=member, b=group. Here the member channel is not a
     * subscribed entry, so only the group listener fires. */
    pubnub_subscribe_event_t grp_only =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "member-7", "the-group");
    pn_subscribe_emit_message(&mgr, &grp_only);

    assert_int_equal(1, rec_ch.message_count);
    assert_int_equal(2, rec_grp.message_count);

    destroy_test_manager(&mgr);
}

/* Name comparison is exact: "my-channel" must never match "my-channel-list"
 * and vice versa. */
static void test_exact_name_match_no_prefix_cross_delivery(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_short = acquire_channel(&mgr, "my-channel");
    uint16_t idx_long  = acquire_channel(&mgr, "my-channel-list");
    assert_int_not_equal(UINT16_MAX, idx_short);
    assert_int_not_equal(UINT16_MAX, idx_long);

    callback_record_t           rec_short = {0};
    callback_record_t           rec_long  = {0};
    pubnub_subscribe_listener_t l_short   = {.on_message = cb_on_message,
                                             .user_data  = &rec_short};
    pubnub_subscribe_listener_t l_long    = {.on_message = cb_on_message,
                                             .user_data  = &rec_long};
    add_bound_for_entry(&mgr, &l_short, idx_short);
    add_bound_for_entry(&mgr, &l_long, idx_long);

    pubnub_subscribe_event_t on_short =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "my-channel", NULL);
    pn_subscribe_emit_message(&mgr, &on_short);
    assert_int_equal(1, rec_short.message_count);
    assert_int_equal(0, rec_long.message_count);

    pubnub_subscribe_event_t on_long =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "my-channel-list", NULL);
    pn_subscribe_emit_message(&mgr, &on_long);
    assert_int_equal(1, rec_short.message_count);
    assert_int_equal(1, rec_long.message_count);

    destroy_test_manager(&mgr);
}

/* A presence-requesting base-name binding ("room") receives a presence
 * event. The parser delivers channel="room" (base) and the raw
 * subscription "room-pnpres"; routing strips the subscription suffix to
 * match the base name. */
static void test_pnpres_channel_routes_to_base_name_binding(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "room", PN_ENTITY_CHANNEL, 1);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .user_data   = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");
    pn_subscribe_emit_message(&mgr, &msg);

    assert_int_equal(1, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* A presence-only entity (name already ends in "-pnpres") receives
 * presence events for its base name by exact match, regardless of its
 * own with_presence flag, and does NOT receive non-presence events. */
static void test_pnpres_entity_receives_presence_only(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "room-pnpres", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .on_message  = cb_on_message,
                                       .user_data   = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");
    pubnub_subscribe_event_t msg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "room", NULL);
    pn_subscribe_emit_message(&mgr, &pre);
    pn_subscribe_emit_message(&mgr, &msg);

    assert_int_equal(1, rec.presence_count);
    assert_int_equal(0, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Trailing-wildcard fallback: when the server omits "b" for a wildcard
 * presence event, the parser's b<-c fallback yields a concrete base (e.g.
 * "room.lobby"). The matcher's wildcard rule still routes it to a "room.*"
 * entry by matching the concrete channel base against the "room." prefix. */
static void test_pnpres_wildcard_fallback_matches_pattern(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "room.*", PN_ENTITY_CHANNEL, 1);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .user_data   = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    /* Server omitted "b"; parser set subscription from raw channel
     * "room.lobby-pnpres", leaving channel base "room.lobby". */
    pubnub_subscribe_event_t msg = make_message_full(
        PUBNUB_SUBSCRIBE_PRESENCE, "room.lobby", "room.lobby-pnpres");
    pn_subscribe_emit_message(&mgr, &msg);

    assert_int_equal(1, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* A concrete channel in "c" routes to a "foo.*" wildcard entry for
 * non-presence events regardless of the entry's presence flag; covers b
 * absent (concrete fallback) and b carrying the pattern, each firing once. */
static void test_wildcard_matches_concrete_regular_bound(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_message = cb_on_message,
                                       .on_signal  = cb_on_signal,
                                       .user_data  = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    /* b absent: subscription equals the concrete channel. */
    pubnub_subscribe_event_t m1 =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.bar");
    /* b present carrying the pattern. */
    pubnub_subscribe_event_t m2 =
        make_message_full(PUBNUB_SUBSCRIBE_SIGNAL, "foo.baz", "foo.*");
    pn_subscribe_emit_message(&mgr, &m1);
    pn_subscribe_emit_message(&mgr, &m2);

    assert_int_equal(1, rec.message_count);
    assert_int_equal(1, rec.signal_count);

    destroy_test_manager(&mgr);
}

/* A "foo.*" wildcard entry receives presence events only when it requested
 * presence; without the flag the concrete presence channel does not route
 * to it. */
static void test_wildcard_presence_requires_flag(void** state)
{
    (void)state;
    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "foo.bar", "foo.bar-pnpres");

    pn_subscribe_manager_t mgr_off;
    create_test_manager(&mgr_off);
    uint16_t idx_off =
        acquire_active_typed(&mgr_off, "foo.*", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx_off);
    callback_record_t           rec_off = {0};
    pubnub_subscribe_listener_t l_off   = {.on_presence = cb_on_presence,
                                           .user_data   = &rec_off};
    add_bound_for_entry(&mgr_off, &l_off, idx_off);
    pn_subscribe_emit_message(&mgr_off, &pre);
    assert_int_equal(0, rec_off.presence_count);
    destroy_test_manager(&mgr_off);

    pn_subscribe_manager_t mgr_on;
    create_test_manager(&mgr_on);
    uint16_t idx_on = acquire_active_typed(&mgr_on, "foo.*", PN_ENTITY_CHANNEL, 1);
    assert_int_not_equal(UINT16_MAX, idx_on);
    callback_record_t           rec_on = {0};
    pubnub_subscribe_listener_t l_on   = {.on_presence = cb_on_presence,
                                          .user_data   = &rec_on};
    add_bound_for_entry(&mgr_on, &l_on, idx_on);
    pn_subscribe_emit_message(&mgr_on, &pre);
    assert_int_equal(1, rec_on.presence_count);
    destroy_test_manager(&mgr_on);
}

/* A presence-requesting "foo.*" entry routes a wildcard presence event for
 * all three "b" shapes (pattern+suffix, bare pattern, absent); the listener
 * fires exactly once even when the pattern arrives verbatim in "b". */
static void test_wildcard_presence_b_shapes(void** state)
{
    (void)state;

    struct {
        const char* channel;
        const char* subscription;
    } cases[] = {
        {"foo.bar", "foo.*-pnpres"  }, /* b present, pattern + suffix */
        {"foo.bar", "foo.*"         }, /* b present, bare pattern */
        {"foo.bar", "foo.bar-pnpres"}  /* b absent -> concrete fallback */
    };

    size_t ci;

    for (ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
        pn_subscribe_manager_t mgr;
        create_test_manager(&mgr);
        uint16_t idx = acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 1);
        assert_int_not_equal(UINT16_MAX, idx);
        callback_record_t           rec = {0};
        pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                           .user_data   = &rec};
        add_bound_for_entry(&mgr, &l, idx);
        pubnub_subscribe_event_t pre = make_message_full(
            PUBNUB_SUBSCRIBE_PRESENCE, cases[ci].channel, cases[ci].subscription);
        pn_subscribe_emit_message(&mgr, &pre);
        assert_int_equal(1, rec.presence_count);
        destroy_test_manager(&mgr);
    }
}

/* A wildcard presence-only entity ("foo.*-pnpres") receives wildcard
 * presence events for concrete channels under its prefix regardless of its
 * own presence flag, and never receives regular events. */
static void test_wildcard_pnpres_entity_presence_only(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "foo.*-pnpres", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .on_message  = cb_on_message,
                                       .user_data   = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "foo.bar", "foo.bar-pnpres");
    pubnub_subscribe_event_t reg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.bar");
    pn_subscribe_emit_message(&mgr, &pre);
    pn_subscribe_emit_message(&mgr, &reg);

    assert_int_equal(1, rec.presence_count);
    assert_int_equal(0, rec.message_count);

    destroy_test_manager(&mgr);
}

/* A channel-metadata entry named "foo.*" never matches via the wildcard
 * rule (wildcard semantics are channel-only): neither regular nor presence
 * events route to it when only the wildcard rule could apply. */
static void test_wildcard_metadata_never_matches(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx =
        acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL_METADATA, 1);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_message  = cb_on_message,
                                       .on_presence = cb_on_presence,
                                       .user_data   = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    /* b absent so subscription is the concrete channel; only a wildcard
     * rule could route these, and metadata is excluded from it. */
    pubnub_subscribe_event_t reg =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.bar");
    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "foo.bar", "foo.bar-pnpres");
    pn_subscribe_emit_message(&mgr, &reg);
    pn_subscribe_emit_message(&mgr, &pre);

    assert_int_equal(0, rec.message_count);
    assert_int_equal(0, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* The wildcard rule is an exact byte-prefix test, not a substring search:
 * "foo.*" must not match "foobar" (no dot), "foo" (the stem), "foo." (no
 * segment after the dot), or "fo.bar" (wrong prefix). */
static void test_wildcard_negatives(void** state)
{
    (void)state;
    const char* non_matches[] = {"foobar", "foo", "foo.", "fo.bar"};
    size_t      ni;

    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    add_bound_for_entry(&mgr, &l, idx);

    for (ni = 0; ni < sizeof(non_matches) / sizeof(non_matches[0]); ++ni) {
        pubnub_subscribe_event_t m = make_message_full(
            PUBNUB_SUBSCRIBE_MESSAGE, non_matches[ni], non_matches[ni]);
        pn_subscribe_emit_message(&mgr, &m);
    }

    assert_int_equal(0, rec.message_count);

    destroy_test_manager(&mgr);
}

/* An exact entry "foo.bar" and a wildcard entry "foo.*" both receive a
 * concrete event, each listener firing exactly once. */
static void test_wildcard_exact_and_wildcard_both_fire_once(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_exact =
        acquire_active_typed(&mgr, "foo.bar", PN_ENTITY_CHANNEL, 0);
    uint16_t idx_wild = acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, idx_exact);
    assert_int_not_equal(UINT16_MAX, idx_wild);

    callback_record_t           rec_exact = {0};
    callback_record_t           rec_wild  = {0};
    callback_record_t           rec_glob  = {0};
    pubnub_subscribe_listener_t l_exact   = {.on_message = cb_on_message,
                                             .user_data  = &rec_exact};
    pubnub_subscribe_listener_t l_wild    = {.on_message = cb_on_message,
                                             .user_data  = &rec_wild};
    pubnub_subscribe_listener_t l_glob    = {.on_message = cb_on_message,
                                             .user_data  = &rec_glob};
    add_bound_for_entry(&mgr, &l_exact, idx_exact);
    add_bound_for_entry(&mgr, &l_wild, idx_wild);
    pn_subscribe_listener_add(&mgr, &l_glob);

    /* Channel concrete, b carries the pattern: the wildcard entry matches
     * both the exact subscription ("foo.*") and the concrete channel by
     * prefix, yet must fire only once. */
    pubnub_subscribe_event_t m =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.*");
    pn_subscribe_emit_message(&mgr, &m);

    assert_int_equal(1, rec_exact.message_count);
    assert_int_equal(1, rec_wild.message_count);
    assert_int_equal(1, rec_glob.message_count);

    destroy_test_manager(&mgr);
}

/* A set-bound listener receives concrete events whose channel matches a
 * wildcard member of the set. */
static void test_wildcard_set_bound(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_not_equal(UINT16_MAX, set_idx);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "foo.*", 5));
    mgr.sets[set_idx].subscribed = 1;

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    pubnub_subscribe_event_t hit =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.bar");
    pubnub_subscribe_event_t miss =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "bar.baz", "bar.baz");
    pn_subscribe_emit_message(&mgr, &hit);
    pn_subscribe_emit_message(&mgr, &miss);

    assert_int_equal(1, rec.message_count);

    pn_subscription_set_destroy(&mgr, set_idx);
    destroy_test_manager(&mgr);
}

/* Add a set member handle for @p name with an explicit presence flag. Mirrors
 * test_set_add but lets the caller choose the member's own with_presence so
 * per-member presence gating can be exercised. Returns the member slot. */
static uint16_t set_add_member_presence(pn_subscribe_manager_t* mgr,
                                        uint16_t                set_index,
                                        const char*             name,
                                        uint8_t                 with_presence)
{
    pubnub_allocator_provider_t* alloc = pn_context_allocator(mgr->ctx);
    pn_subscription_t*           sub;
    uint16_t                     entry_idx;

    entry_idx = pn_subscription_acquire(
        mgr, name, (uint16_t)strlen(name), PN_ENTITY_CHANNEL, 0);
    assert_int_not_equal(UINT16_MAX, entry_idx);

    sub = (pn_subscription_t*)PN_ALLOC(alloc, sizeof(*sub), sizeof(void*));
    assert_non_null(sub);
    sub->ctx                 = mgr->ctx;
    sub->entry_index         = entry_idx;
    sub->slot_index          = UINT16_MAX;
    sub->ref_count           = 1;
    sub->subscribed          = 0;
    sub->with_presence       = with_presence;
    sub->subscribed_set_refs = 0;

    assert_int_not_equal(UINT16_MAX, pn_track_subscription(mgr, sub));
    assert_true(pn_subscription_set_add_member(mgr, set_index, sub) > 0);
    return sub->slot_index;
}

/* A set holds a presence member and a non-presence member of the same entity.
 * A set-bound listener routes a presence event because the presence member's
 * own flag qualifies, independent of the shared entry cache. With only the
 * non-presence member, the same presence event does not route. */
static void test_set_member_presence_gating_per_handle(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_not_equal(UINT16_MAX, set_idx);
    set_add_member_presence(&mgr, set_idx, "room", 1);
    set_add_member_presence(&mgr, set_idx, "room", 0);
    mgr.sets[set_idx].subscribed = 1;

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .user_data   = &rec};
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");
    pn_subscribe_emit_message(&mgr, &pre);
    assert_int_equal(1, rec.presence_count);

    pn_subscription_set_destroy(&mgr, set_idx);
    destroy_test_manager(&mgr);

    /* Second set: only a non-presence member — presence must not route. */
    pn_subscribe_manager_t mgr2;
    create_test_manager(&mgr2);

    uint16_t set_idx2 = pn_subscription_set_create(&mgr2);
    assert_int_not_equal(UINT16_MAX, set_idx2);
    set_add_member_presence(&mgr2, set_idx2, "room", 0);
    mgr2.sets[set_idx2].subscribed = 1;

    callback_record_t           rec2 = {0};
    pubnub_subscribe_listener_t l2   = {.on_presence = cb_on_presence,
                                        .user_data   = &rec2};
    pn_subscribe_listener_add_to_set(&mgr2, &l2, set_idx2);

    pubnub_subscribe_event_t pre2 =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");
    pn_subscribe_emit_message(&mgr2, &pre2);
    assert_int_equal(0, rec2.presence_count);

    pn_subscription_set_destroy(&mgr2, set_idx2);
    destroy_test_manager(&mgr2);
}

/* A global listener receives wildcard-channel events like any other
 * (bindings do not change global routing). */
static void test_wildcard_global_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 0);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add(&mgr, &l);

    pubnub_subscribe_event_t m =
        make_message_full(PUBNUB_SUBSCRIBE_MESSAGE, "foo.bar", "foo.bar");
    pn_subscribe_emit_message(&mgr, &m);

    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* The wire builders treat a wildcard name as any other token: a presence
 * "foo.*" entry emits "foo.*,foo.*-pnpres" (no double suffix), and a
 * separate "foo.*-pnpres" entity deduplicates against that presence token. */
static void test_wildcard_builder_output(void** state)
{
    (void)state;

    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);
    acquire_active_typed(&mgr, "foo.*", PN_ENTITY_CHANNEL, 1);
    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("foo.*,foo.*-pnpres", buf);
    assert_int_equal(18, len);
    destroy_test_manager(&mgr);

    pn_subscribe_manager_t mgr2;
    create_test_manager(&mgr2);
    acquire_active_typed(&mgr2, "foo.*", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr2, "foo.*-pnpres", PN_ENTITY_CHANNEL, 0);
    char   buf2[64];
    size_t len2 = pn_subscribe_build_channel_string(&mgr2, buf2, sizeof(buf2));
    assert_string_equal("foo.*,foo.*-pnpres", buf2);
    assert_int_equal(18, len2);
    destroy_test_manager(&mgr2);
}

/* A channel and a channel-metadata object sharing a name collapse to a
 * single path token. */
static void test_path_string_dedup_same_name_cross_type(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 0);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_int_equal(6, len);
    assert_string_equal("shared", buf);

    destroy_test_manager(&mgr);
}

/* When a deduped path name has a non-metadata entry requesting presence,
 * the -pnpres variant is emitted exactly once even though the name appears
 * on multiple entries. */
static void test_path_string_dedup_presence_emitted_once(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    /* Channel wants presence; metadata never does. */
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("shared,shared-pnpres", buf);
    assert_int_equal(20, len);

    destroy_test_manager(&mgr);
}

/* A "room" entry with presence and a separate "room-pnpres" entity expand
 * to the same wire token; TOKEN-level dedup emits it once (room first). */
static void test_path_string_token_dedup_presence_then_pnpres_entity(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "room", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr, "room-pnpres", PN_ENTITY_CHANNEL, 0);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("room,room-pnpres", buf);
    assert_int_equal(16, len);

    destroy_test_manager(&mgr);
}

/* Same tokens in the other order: the "room-pnpres" entity registers
 * first, then "room" with presence. The presence variant dedups against
 * the earlier bare token. */
static void test_path_string_token_dedup_pnpres_entity_then_presence(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "room-pnpres", PN_ENTITY_CHANNEL, 0);
    acquire_active_typed(&mgr, "room", PN_ENTITY_CHANNEL, 1);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("room-pnpres,room", buf);
    assert_int_equal(16, len);

    destroy_test_manager(&mgr);
}

/* A presence-requesting "room-pnpres" entity never emits a double suffix. */
static void test_path_string_pnpres_entity_no_double_suffix(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "room-pnpres", PN_ENTITY_CHANNEL, 1);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("room-pnpres", buf);
    assert_int_equal(11, len);

    destroy_test_manager(&mgr);
}

/* Metadata-only duplicate never adds -pnpres. */
static void test_path_string_metadata_only_no_presence(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "obj", PN_ENTITY_CHANNEL_METADATA, 1);
    acquire_active_typed(&mgr, "obj", PN_ENTITY_USER_METADATA, 1);

    char   buf[64];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("obj", buf);
    assert_int_equal(3, len);

    destroy_test_manager(&mgr);
}

/* A buffer too small to hold even the first token yields 0 and a NUL at
 * offset 0. */
static void test_path_string_buffer_too_small(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_active_typed(&mgr, "channelA", PN_ENTITY_CHANNEL, 0);

    char   buf[4];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_int_equal(0, len);
    assert_int_equal('\0', buf[0]);

    destroy_test_manager(&mgr);
}

/* The heartbeat channel string dedups the same way but never emits the
 * -pnpres variant. */
static void test_heartbeat_string_dedup_no_presence(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        hb;
    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);

    hb = pn_subscribe_build_heartbeat_channel_string_alloc(&mgr, alloc);
    assert_non_null(hb);
    assert_string_equal("shared", hb);
    PN_FREE(alloc, hb);

    destroy_test_manager(&mgr);
}

/* Entities whose own name ends in "-pnpres" are presence-only and are
 * excluded from heartbeat/leave strings entirely. */
static void test_heartbeat_string_excludes_pnpres_named(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        hb;
    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    acquire_active_typed(&mgr, "room", PN_ENTITY_CHANNEL, 0);
    acquire_active_typed(&mgr, "room-pnpres", PN_ENTITY_CHANNEL, 0);

    hb = pn_subscribe_build_heartbeat_channel_string_alloc(&mgr, alloc);
    assert_non_null(hb);
    assert_string_equal("room", hb);
    PN_FREE(alloc, hb);

    destroy_test_manager(&mgr);
}

/* Releasing one of two references to the same channel keeps it in the path
 * string; releasing the last removes it. */
static void test_unsubscribe_one_duplicate_keeps_entity_in_path(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx1 = acquire_active_channel(&mgr, "keep");
    uint16_t idx2 = acquire_active_channel(&mgr, "keep");
    assert_int_equal(idx1, idx2);
    assert_int_equal(2, mgr.entries[idx1].ref_count);
    assert_int_equal(2, mgr.entries[idx1].active_count);

    char   buf[32];
    size_t len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("keep", buf);
    assert_int_equal(4, len);

    /* Unsubscribe one handle: one activation and one ref drop. */
    mgr.entries[idx1].active_count--;
    pn_subscription_release(&mgr, idx1);
    assert_int_equal(1, mgr.entries[idx1].ref_count);
    assert_int_equal(1, mgr.entries[idx1].active_count);

    len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal("keep", buf);
    assert_int_equal(4, len);

    /* Unsubscribe the last handle: entity leaves the path. */
    mgr.entries[idx1].active_count--;
    pn_subscription_release(&mgr, idx1);
    assert_int_equal(0, mgr.entries[idx1].occupied);

    len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_int_equal(0, len);

    destroy_test_manager(&mgr);
}

/* Production dispatch builds the wire string with the two-pass allocating
 * builder (measure, then allocate + write). A presence channel 'shared'
 * then a channel-metadata 'shared' collapse to one token with -pnpres once;
 * asserting content AND length catches any measure/write divergence. */
static void test_alloc_channel_string_presence_dedup_channel_first(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        s;

    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);

    s = pn_subscribe_build_channel_string_alloc(&mgr, alloc);
    assert_non_null(s);
    assert_string_equal("shared,shared-pnpres", s);
    assert_int_equal(20, strlen(s));
    PN_FREE(alloc, s);

    destroy_test_manager(&mgr);
}

/* Same result with the slot order inverted (metadata in the lower slot):
 * the -pnpres variant appears only if pn_name_wants_presence scans every
 * entry sharing the name, not just the one being emitted. */
static void test_alloc_channel_string_presence_dedup_metadata_first(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        s;

    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 1);

    s = pn_subscribe_build_channel_string_alloc(&mgr, alloc);
    assert_non_null(s);
    assert_string_equal("shared,shared-pnpres", s);
    assert_int_equal(20, strlen(s));
    PN_FREE(alloc, s);

    destroy_test_manager(&mgr);
}

/* The heartbeat alloc variant dedups identically but never appends
 * -pnpres regardless of slot ordering, and the channel alloc builder must
 * agree with the fixed-buffer builder byte-for-byte. */
static void test_alloc_and_heartbeat_string_consistency(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        hb;
    char*                        s;
    char                         buf[64];
    size_t                       len;

    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL_METADATA, 0);
    acquire_active_typed(&mgr, "shared", PN_ENTITY_CHANNEL, 1);

    hb = pn_subscribe_build_heartbeat_channel_string_alloc(&mgr, alloc);
    assert_non_null(hb);
    assert_string_equal("shared", hb);
    assert_int_equal(6, strlen(hb));
    PN_FREE(alloc, hb);

    s = pn_subscribe_build_channel_string_alloc(&mgr, alloc);
    assert_non_null(s);
    len = pn_subscribe_build_channel_string(&mgr, buf, sizeof(buf));
    assert_string_equal(buf, s);
    assert_int_equal(len, strlen(s));
    PN_FREE(alloc, s);

    destroy_test_manager(&mgr);
}

/* Seam pin for the shared token walker (pn_emit_entity_tokens) used by the
 * fixed-buffer, allocating, and heartbeat builders. The allocating builder
 * sizes from the walker's measure pass and writes with the same walker, so
 * measure/write can never silently diverge; the fixed-buffer builder must
 * agree byte-for-byte and never write at or beyond its capacity. Sweeping
 * capacity from 0 to the exact length, with a canary past each boundary,
 * exercises the overflow branch everywhere. */
static void test_builder_walker_capacity_sweep_no_overflow(void** state)
{
    (void)state;
    pn_subscribe_manager_t       mgr;
    pubnub_allocator_provider_t* alloc;
    char*                        ch_ref;
    char*                        gr_ref;
    char*                        hb_ch_ref;
    char*                        hb_gr_ref;
    char*                        tmp;
    char                         buf[512];
    size_t                       ch_len;
    size_t                       gr_len;
    size_t                       cap;

    create_test_manager(&mgr);
    alloc = pn_context_allocator(mgr.ctx);

    /* Presence channel + metadata of the same name (dedup across type). */
    acquire_active_typed(&mgr, "alpha", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(&mgr, "alpha", PN_ENTITY_CHANNEL_METADATA, 0);
    /* Plain channel then a `-pnpres`-named sibling (heartbeat excludes it). */
    acquire_active_typed(&mgr, "beta", PN_ENTITY_CHANNEL, 0);
    acquire_active_typed(&mgr, "beta-pnpres", PN_ENTITY_CHANNEL, 0);
    /* Wildcard presence channel + a long name. */
    acquire_active_typed(&mgr, "wild.*", PN_ENTITY_CHANNEL, 1);
    acquire_active_typed(
        &mgr, "a-very-long-channel-name-0123456789abcdef", PN_ENTITY_CHANNEL, 0);
    /* Groups: presence + plain. (8 entries total — fits the embedded cap.) */
    acquire_active_typed(&mgr, "grpA", PN_ENTITY_CHANNEL_GROUP, 1);
    acquire_active_typed(&mgr, "grpB", PN_ENTITY_CHANNEL_GROUP, 0);

    /* Reference outputs come from the allocating builder; its length is the
     * walker's measure pass, so the sweep below proves all three agree. */
    ch_ref = pn_subscribe_build_channel_string_alloc(&mgr, alloc);
    gr_ref = pn_subscribe_build_channel_group_string_alloc(&mgr, alloc);
    assert_non_null(ch_ref);
    assert_non_null(gr_ref);
    ch_len = strlen(ch_ref);
    gr_len = strlen(gr_ref);
    assert_true(ch_len + 1 < sizeof(buf));
    assert_true(gr_len + 1 < sizeof(buf));

    /* Channel path builder: sweep every capacity from 0 to exact length + 1.
     * On overflow the builder returns 0 and NUL-terminates the prefix it
     * already wrote; it must never write at or beyond the supplied capacity. */
    for (cap = 0; cap <= ch_len + 1; ++cap) {
        size_t len;
        memset(buf, (int)0xAB, sizeof(buf));
        len = pn_subscribe_build_channel_string(&mgr, buf, cap);
        /* Nothing was written at or beyond the supplied capacity. */
        assert_int_equal(0xAB, (unsigned char)buf[cap]);
        if (cap >= ch_len + 1) {
            assert_int_equal(ch_len, len);
            assert_string_equal(ch_ref, buf);
        } else {
            assert_int_equal(0, len);
            /* The written prefix stays NUL-terminated inside the capacity. */
            if (cap >= 1) {
                assert_non_null(memchr(buf, '\0', cap));
            }
        }
    }

    /* Channel-group builder: identical sweep. */
    for (cap = 0; cap <= gr_len + 1; ++cap) {
        size_t len;
        memset(buf, (int)0xAB, sizeof(buf));
        len = pn_subscribe_build_channel_group_string(&mgr, buf, cap);
        assert_int_equal(0xAB, (unsigned char)buf[cap]);
        if (cap >= gr_len + 1) {
            assert_int_equal(gr_len, len);
            assert_string_equal(gr_ref, buf);
        } else {
            assert_int_equal(0, len);
            if (cap >= 1) {
                assert_non_null(memchr(buf, '\0', cap));
            }
        }
    }

    /* Heartbeat has no fixed-buffer builder; the allocating builder
     * self-sizes from the walker's measure pass, so a measure/write
     * divergence would overflow its heap buffer (ASan catches it). Pins
     * deterministic output with no presence tokens. */
    hb_ch_ref = pn_subscribe_build_heartbeat_channel_string_alloc(&mgr, alloc);
    hb_gr_ref = pn_subscribe_build_heartbeat_group_string_alloc(&mgr, alloc);
    assert_non_null(hb_ch_ref);
    assert_non_null(hb_gr_ref);
    assert_null(strstr(hb_ch_ref, "-pnpres"));
    assert_null(strstr(hb_gr_ref, "-pnpres"));

    tmp = pn_subscribe_build_heartbeat_channel_string_alloc(&mgr, alloc);
    assert_non_null(tmp);
    assert_string_equal(hb_ch_ref, tmp);
    PN_FREE(alloc, tmp);
    tmp = pn_subscribe_build_heartbeat_group_string_alloc(&mgr, alloc);
    assert_non_null(tmp);
    assert_string_equal(hb_gr_ref, tmp);
    PN_FREE(alloc, tmp);

    PN_FREE(alloc, hb_ch_ref);
    PN_FREE(alloc, hb_gr_ref);
    PN_FREE(alloc, ch_ref);
    PN_FREE(alloc, gr_ref);
    destroy_test_manager(&mgr);
}

/* End-to-end dedup through the public API: a presence channel 'shared' and
 * a channel-metadata 'shared' subscribed together collapse to one wire
 * token with a single -pnpres variant. Fully unwinds so the shared fixture
 * stays clean for later tests. */
static void test_public_api_presence_dedup_channel_and_metadata(void** state)
{
    (void)state;
    pn_subscribe_manager_t*      mgr;
    pubnub_allocator_provider_t* alloc;
    pubnub_subscription_opts_t   pres_opts = {0};
    pubnub_subscription_opts_t   md_opts   = {0};
    pubnub_entity_t              ch;
    pubnub_entity_t              md;
    pubnub_subscription_t        ch_sub;
    pubnub_subscription_t        md_sub;
    pubnub_listener_handle_t     h;
    callback_record_t            rec = {0};
    pubnub_subscribe_listener_t  listener;
    char*                        s;

    pres_opts.with_presence = 1;

    ch = pubnub_channel(s_test_ctx, "shared");
    assert_non_null(ch);
    md = pubnub_channel_metadata(s_test_ctx, "shared");
    assert_non_null(md);

    ch_sub = pubnub_subscription_create(ch, &pres_opts);
    assert_non_null(ch_sub);
    md_sub = pubnub_subscription_create(md, &md_opts);
    assert_non_null(md_sub);

    memset(&listener, 0, sizeof(listener));
    listener.on_message = cb_on_message;
    listener.user_data  = &rec;
    h                   = pubnub_subscription_add_listener(ch_sub, &listener);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, h);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(ch_sub));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(md_sub));

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_non_null(mgr);
    alloc = pn_context_allocator(s_test_ctx);

    s = pn_subscribe_build_channel_string_alloc(mgr, alloc);
    assert_non_null(s);
    assert_string_equal("shared,shared-pnpres", s);
    assert_int_equal(20, strlen(s));
    PN_FREE(alloc, s);

    pubnub_subscription_remove_listener(ch_sub, h);
    (void)pubnub_subscription_unsubscribe(ch_sub);
    (void)pubnub_subscription_unsubscribe(md_sub);
    pubnub_subscription_destroy(ch_sub);
    pubnub_subscription_destroy(md_sub);
    pubnub_entity_destroy(ch);
    pubnub_entity_destroy(md);

    /* Fixture must be empty again for subsequent tests. */
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/** @brief Read an entry's live presence_contributors counter from a handle. */
static uint16_t entry_presence_count(pubnub_subscription_t sub)
{
    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    uint16_t                ei  = ((pn_subscription_t*)sub)->entry_index;
    return mgr->entries[ei].presence_contributors;
}

/** @brief Read an entry's derived wire-presence cache from a handle. */
static uint8_t entry_wire_presence(pubnub_subscription_t sub)
{
    pn_subscribe_manager_t* mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    uint16_t                ei  = ((pn_subscription_t*)sub)->entry_index;
    return mgr->entries[ei].with_presence;
}

/* Two presence-requesting handles resolve to the same channel entry. Each
 * subscribed handle contributes one presence share; the derived wire cache
 * stays set until the last presence handle leaves. */
static void test_presence_two_contributors_on_entity(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t opts = {0};
    pubnub_entity_t            ch1;
    pubnub_entity_t            ch2;
    pubnub_subscription_t      sub1;
    pubnub_subscription_t      sub2;

    opts.with_presence = 1;
    ch1                = pubnub_channel(s_test_ctx, "room");
    ch2                = pubnub_channel(s_test_ctx, "room");
    assert_non_null(ch1);
    assert_non_null(ch2);
    sub1 = pubnub_subscription_create(ch1, &opts);
    sub2 = pubnub_subscription_create(ch2, &opts);
    assert_non_null(sub1);
    assert_non_null(sub2);

    assert_int_equal(0, entry_presence_count(sub1));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub1));
    assert_int_equal(1, entry_presence_count(sub1));
    assert_int_equal(1, entry_wire_presence(sub1));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub2));
    assert_int_equal(2, entry_presence_count(sub1));
    assert_int_equal(1, entry_wire_presence(sub1));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub1));
    assert_int_equal(1, entry_presence_count(sub2));
    assert_int_equal(1, entry_wire_presence(sub2));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub2));
    assert_int_equal(0, entry_presence_count(sub2));
    assert_int_equal(0, entry_wire_presence(sub2));

    pubnub_subscription_destroy(sub1);
    pubnub_subscription_destroy(sub2);
    pubnub_entity_destroy(ch1);
    pubnub_entity_destroy(ch2);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* One presence handle and one non-presence handle resolve to the same entry.
 * Only the presence handle contributes a share. */
static void test_presence_mixed_handles_same_entity(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t pres  = {0};
    pubnub_subscription_opts_t plain = {0};
    pubnub_entity_t            ch_p;
    pubnub_entity_t            ch_n;
    pubnub_subscription_t      sub_p;
    pubnub_subscription_t      sub_n;

    pres.with_presence = 1;
    ch_p               = pubnub_channel(s_test_ctx, "room");
    ch_n               = pubnub_channel(s_test_ctx, "room");
    assert_non_null(ch_p);
    assert_non_null(ch_n);
    sub_p = pubnub_subscription_create(ch_p, &pres);
    sub_n = pubnub_subscription_create(ch_n, &plain);
    assert_non_null(sub_p);
    assert_non_null(sub_n);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub_p));
    assert_int_equal(1, entry_presence_count(sub_p));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub_n));
    assert_int_equal(1, entry_presence_count(sub_p)); /* No second share. */
    assert_int_equal(1, entry_wire_presence(sub_p));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub_p));
    assert_int_equal(0, entry_presence_count(sub_n));
    assert_int_equal(0, entry_wire_presence(sub_n));

    (void)pubnub_subscription_unsubscribe(sub_n);
    pubnub_subscription_destroy(sub_p);
    pubnub_subscription_destroy(sub_n);
    pubnub_entity_destroy(ch_p);
    pubnub_entity_destroy(ch_n);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* Destroying a subscribed presence handle drops its share even when the
 * destroy also tears down the subscription. */
static void test_presence_destroy_subscribed_handle_drops_share(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t opts = {0};
    pubnub_entity_t            ch1;
    pubnub_entity_t            ch2;
    pubnub_subscription_t      keep;
    pubnub_subscription_t      gone;

    opts.with_presence = 1;
    ch1                = pubnub_channel(s_test_ctx, "room");
    ch2                = pubnub_channel(s_test_ctx, "room");
    assert_non_null(ch1);
    assert_non_null(ch2);
    keep = pubnub_subscription_create(ch1, &opts);
    gone = pubnub_subscription_create(ch2, &opts);
    assert_non_null(keep);
    assert_non_null(gone);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(keep));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(gone));
    assert_int_equal(2, entry_presence_count(keep));

    /* Destroy while subscribed — the destroy path must release the share. */
    pubnub_subscription_destroy(gone);
    assert_int_equal(1, entry_presence_count(keep));
    assert_int_equal(1, entry_wire_presence(keep));

    (void)pubnub_subscription_unsubscribe(keep);
    assert_int_equal(0, entry_presence_count(keep));
    pubnub_subscription_destroy(keep);
    pubnub_entity_destroy(ch1);
    pubnub_entity_destroy(ch2);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* A set contributes a presence share only while subscribed. Adding a presence
 * member to an unsubscribed set does not raise the counter; subscribing the
 * set does; adding another presence member to the already-subscribed set
 * raises it immediately. */
static void test_presence_set_share_tracks_subscribed_state(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t opts = {0};
    pubnub_entity_t            ca;
    pubnub_entity_t            cb;
    pubnub_subscription_t      sa;
    pubnub_subscription_t      sb;
    pubnub_subscription_set_t  set;

    opts.with_presence = 1;
    ca                 = pubnub_channel(s_test_ctx, "alpha");
    cb                 = pubnub_channel(s_test_ctx, "beta");
    assert_non_null(ca);
    assert_non_null(cb);
    sa = pubnub_subscription_create(ca, &opts);
    sb = pubnub_subscription_create(cb, &opts);
    assert_non_null(sa);
    assert_non_null(sb);

    set = pubnub_subscription_set_create(s_test_ctx);
    assert_non_null(set);

    /* Set not yet subscribed — adding a presence member must not count. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sa));
    assert_int_equal(0, entry_presence_count(sa));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(1, entry_presence_count(sa));
    assert_int_equal(1, entry_wire_presence(sa));

    /* Adding a presence member to a subscribed set flips its entry at once. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_add_subscription(set, sb));
    assert_int_equal(1, entry_presence_count(sb));
    assert_int_equal(1, entry_wire_presence(sb));

    /* Removing a presence member drops its entry's share back to zero. */
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_remove_subscription(set, sb));
    assert_int_equal(0, entry_presence_count(sb));
    assert_int_equal(0, entry_wire_presence(sb));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set));
    assert_int_equal(0, entry_presence_count(sa));

    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(sb);
    pubnub_entity_destroy(ca);
    pubnub_entity_destroy(cb);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* A direct presence handle and a subscribed set each hold an independent
 * presence share on the same entry. Tearing both down returns the counter to
 * zero with no underflow. */
static void test_presence_direct_and_set_no_underflow(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t opts = {0};
    pubnub_entity_t            direct_ent;
    pubnub_entity_t            member_ent;
    pubnub_subscription_t      direct;
    pubnub_subscription_t      member;
    pubnub_subscription_set_t  set;

    opts.with_presence = 1;
    direct_ent         = pubnub_channel(s_test_ctx, "room");
    member_ent         = pubnub_channel(s_test_ctx, "room");
    assert_non_null(direct_ent);
    assert_non_null(member_ent);
    direct = pubnub_subscription_create(direct_ent, &opts);
    member = pubnub_subscription_create(member_ent, &opts);
    assert_non_null(direct);
    assert_non_null(member);

    set = pubnub_subscription_set_create(s_test_ctx);
    assert_non_null(set);
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set, member));

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(direct));
    assert_int_equal(1, entry_presence_count(direct));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_subscribe(set));
    assert_int_equal(2, entry_presence_count(direct));

    /* Drop in either order — counter must land exactly on zero. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(direct));
    assert_int_equal(1, entry_presence_count(direct));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_set_unsubscribe(set));
    assert_int_equal(0, entry_presence_count(direct));
    assert_int_equal(0, entry_wire_presence(direct));

    pubnub_subscription_set_destroy(set);
    pubnub_subscription_destroy(direct);
    pubnub_entity_destroy(direct_ent);
    pubnub_entity_destroy(member_ent);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* A channel-metadata entity ignores opts->with_presence: its handle flag stays
 * 0 and subscribing contributes no presence share. */
static void test_presence_metadata_ignores_with_presence(void** state)
{
    (void)state;
    pn_subscribe_manager_t*    mgr;
    pubnub_subscription_opts_t opts = {0};
    pubnub_entity_t            md;
    pubnub_subscription_t      sub;

    opts.with_presence = 1;
    md                 = pubnub_channel_metadata(s_test_ctx, "obj");
    assert_non_null(md);
    sub = pubnub_subscription_create(md, &opts);
    assert_non_null(sub);

    assert_int_equal(0, ((pn_subscription_t*)sub)->with_presence);

    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub));
    assert_int_equal(0, entry_presence_count(sub));
    assert_int_equal(0, entry_wire_presence(sub));

    (void)pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_entity_destroy(md);

    mgr = pn_subscribe_manager_from_ctx(s_test_ctx);
    assert_int_equal(1, pn_subscribe_subscriptions_empty(mgr));
}

/* Scenario (a): two handles on one entity. A listener on the first handle
 * goes silent when that handle unsubscribes while one on the second keeps
 * receiving; resubscribing the first restores delivery, because the binding
 * targets the stable handle slot, not the entry. */
static void test_gating_per_sub_unsubscribe_silences_only_that_handle(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, entry);

    uint16_t slot1 = subscribed_slot_for_entry(&mgr, entry);
    uint16_t slot2 = subscribed_slot_for_entry(&mgr, entry);

    callback_record_t           rec1 = {0};
    callback_record_t           rec2 = {0};
    pubnub_subscribe_listener_t l1   = {.on_message = cb_on_message,
                                        .user_data  = &rec1};
    pubnub_subscribe_listener_t l2   = {.on_message = cb_on_message,
                                        .user_data  = &rec2};
    pn_subscribe_listener_add_bound(&mgr, &l1, slot1);
    pn_subscribe_listener_add_bound(&mgr, &l2, slot2);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec1.message_count);
    assert_int_equal(1, rec2.message_count);

    /* Unsubscribe handle 1 only; the entity stays on the wire via handle 2. */
    mgr.tracked_subs[slot1]->subscribed = 0;
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec1.message_count); /* Silent. */
    assert_int_equal(2, rec2.message_count); /* Still delivered. */

    /* Resubscribe handle 1 — binding survived, delivery resumes. */
    mgr.tracked_subs[slot1]->subscribed = 1;
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec1.message_count);
    assert_int_equal(3, rec2.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (b): a listener bound to a handle that was never subscribed
 * receives nothing even though the entry name matches the event. */
static void test_gating_never_subscribed_handle_is_silent(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry                     = acquire_channel(&mgr, "ch1");
    uint16_t slot                      = subscribed_slot_for_entry(&mgr, entry);
    mgr.tracked_subs[slot]->subscribed = 0; /* Never subscribed. */

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(0, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (c): a set listener delivers only while the set is subscribed.
 * An active-but-unsubscribed set is silent; subscribing it reactivates
 * delivery. */
static void test_gating_set_unsubscribed_is_silent_then_reactivates(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");
    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");

    /* Set active (members present) but not subscribed. */
    mgr.sets[set_idx].subscribed = 0;
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(0, rec.message_count);

    mgr.sets[set_idx].subscribed = 1;
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (d): a subscribed set delivers for a member even when that
 * member's own handle is unsubscribed. The set's subscribed state governs
 * set delivery, independent of per-member handle state. */
static void test_gating_set_delivers_member_whose_handle_unsubscribed(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");
    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));
    mgr.sets[set_idx].subscribed = 1;

    /* Force every member handle to unsubscribed; set delivery must persist. */
    {
        uint16_t j;
        for (j = 0; j < mgr.sets[set_idx].count; ++j) {
            uint16_t slot = mgr.sets[set_idx].member_slots[j];
            if (NULL != mgr.tracked_subs[slot]) {
                mgr.tracked_subs[slot]->subscribed = 0;
            }
        }
    }

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (e): detaching a handle's listeners stops delivery and frees the
 * slot. A global listener registered alongside is unaffected. */
static void test_gating_remove_for_slot_detaches_bound_only(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    uint16_t slot  = subscribed_slot_for_entry(&mgr, entry);

    callback_record_t           rec_bound  = {0};
    callback_record_t           rec_global = {0};
    pubnub_subscribe_listener_t l_bound    = {.on_message = cb_on_message,
                                              .user_data  = &rec_bound};
    pubnub_subscribe_listener_t l_global   = {.on_message = cb_on_message,
                                              .user_data  = &rec_global};
    pn_subscribe_listener_add_bound(&mgr, &l_bound, slot);
    pn_subscribe_listener_add(&mgr, &l_global);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec_bound.message_count);
    assert_int_equal(1, rec_global.message_count);

    pn_subscribe_listener_remove_for_slot(&mgr, slot);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec_bound.message_count);  /* Detached. */
    assert_int_equal(2, rec_global.message_count); /* Unaffected. */

    destroy_test_manager(&mgr);
}

/* Scenario (e): detaching a set's listeners stops set delivery. */
static void test_gating_remove_for_set_detaches_set_listeners(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    acquire_channel(&mgr, "ch1");
    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));
    mgr.sets[set_idx].subscribed = 1;

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_to_set(&mgr, &l, set_idx);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    pn_subscribe_listener_remove_for_set(&mgr, set_idx);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count); /* Detached. */

    destroy_test_manager(&mgr);
}

/** State for a callback that detaches its own handle slot mid-emit. */
typedef struct detach_from_cb_state {
    pn_subscribe_manager_t* mgr;
    uint16_t                slot;
    int                     fired;
} detach_from_cb_state_t;

static void cb_detach_own_slot(const pubnub_subscribe_event_t* event, void* ud)
{
    detach_from_cb_state_t* st = (detach_from_cb_state_t*)ud;
    (void)event;
    st->fired++;
    /* Simulates pubnub_subscription_destroy() running from within a
     * delivery callback: removal must defer to the post-emit sweep. */
    pn_subscribe_listener_remove_for_slot(st->mgr, st->slot);
}

/* Scenario (e): detaching a handle's listeners from within a delivery
 * callback is safe (deferred removal) and stops subsequent delivery. */
static void test_gating_remove_for_slot_from_callback_defers(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    uint16_t slot  = subscribed_slot_for_entry(&mgr, entry);

    detach_from_cb_state_t      st = {0};
    pubnub_subscribe_listener_t l  = {.on_message = cb_detach_own_slot,
                                      .user_data  = &st};
    st.mgr                         = &mgr;
    st.slot                        = slot;
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, st.fired);

    /* Post-emit sweep must have detached the listener. */
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, st.fired);

    destroy_test_manager(&mgr);
}

/* Scenario (f): remove_for_slot/remove_for_set with out-of-range or empty
 * targets is a safe no-op and leaves unrelated listeners intact. */
static void test_gating_remove_for_slot_stale_or_foreign_is_noop(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    uint16_t slot  = subscribed_slot_for_entry(&mgr, entry);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    /* Out-of-range slot and a different (empty) slot — no listener affected. */
    pn_subscribe_listener_remove_for_slot(&mgr, UINT16_MAX);
    pn_subscribe_listener_remove_for_slot(&mgr, (uint16_t)(slot + 1));
    pn_subscribe_listener_remove_for_set(&mgr, UINT16_MAX);
    pn_subscribe_listener_remove_for_set(&mgr, 7);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (g): a global (unbound) listener keeps receiving regardless of
 * any handle's subscribed state. */
static void test_gating_global_listener_unaffected_by_handle_state(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry                     = acquire_channel(&mgr, "ch1");
    uint16_t slot                      = subscribed_slot_for_entry(&mgr, entry);
    mgr.tracked_subs[slot]->subscribed = 0;

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add(&mgr, &l);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (h): per-subscription gating applies to presence events too — an
 * unsubscribed presence-requesting handle receives no presence event. */
static void test_gating_per_sub_presence_respects_subscribed(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_active_typed(&mgr, "room", PN_ENTITY_CHANNEL, 1);
    uint16_t slot  = subscribed_slot_for_entry(&mgr, entry);

    callback_record_t           rec = {0};
    pubnub_subscribe_listener_t l   = {.on_presence = cb_on_presence,
                                       .user_data   = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t pre =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");

    mgr.tracked_subs[slot]->subscribed = 0;
    pn_subscribe_emit_message(&mgr, &pre);
    assert_int_equal(0, rec.presence_count);

    mgr.tracked_subs[slot]->subscribed = 1;
    pn_subscribe_emit_message(&mgr, &pre);
    assert_int_equal(1, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* Mirror pubnub_subscription_set_subscribe's counter maintenance for the
 * white-box manager, which cannot run the real subscribe effect (no transport
 * / bg thread in these unit tests). Marks the set subscribed and grants each
 * member one delivery share, saturating like production. */
static void wb_set_subscribe(pn_subscribe_manager_t* mgr, uint16_t set_idx)
{
    pn_subscription_set_data_t* sd = &mgr->sets[set_idx];
    uint16_t                    m;

    sd->subscribed = 1;
    for (m = 0; m < sd->count; ++m) {
        uint16_t slot = sd->member_slots[m];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS && NULL != mgr->tracked_subs[slot]
            && UINT16_MAX != mgr->tracked_subs[slot]->subscribed_set_refs) {
            mgr->tracked_subs[slot]->subscribed_set_refs++;
        }
    }
}

/* Mirror pubnub_subscription_set_unsubscribe's counter maintenance. */
static void wb_set_unsubscribe(pn_subscribe_manager_t* mgr, uint16_t set_idx)
{
    pn_subscription_set_data_t* sd = &mgr->sets[set_idx];
    uint16_t                    m;

    sd->subscribed = 0;
    for (m = 0; m < sd->count; ++m) {
        uint16_t slot = sd->member_slots[m];
        if (slot < PUBNUB_CFG_MAX_SUBSCRIPTIONS && NULL != mgr->tracked_subs[slot]
            && mgr->tracked_subs[slot]->subscribed_set_refs > 0) {
            mgr->tracked_subs[slot]->subscribed_set_refs--;
        }
    }
}

/* Create an unsubscribed, tracked handle on @p entry_idx with no delivery
 * share, as if created but never directly subscribed. Returns its slot. */
static uint16_t unsub_slot_for_entry(pn_subscribe_manager_t* mgr, uint16_t entry_idx)
{
    pubnub_allocator_provider_t* alloc = pn_context_allocator(mgr->ctx);
    pn_subscription_t*           sub =
        (pn_subscription_t*)PN_ALLOC(alloc, sizeof(*sub), sizeof(void*));

    assert_non_null(sub);
    sub->ctx                 = mgr->ctx;
    sub->entry_index         = entry_idx;
    sub->slot_index          = UINT16_MAX;
    sub->ref_count           = 1;
    sub->subscribed          = 0;
    sub->with_presence       = mgr->entries[entry_idx].with_presence;
    sub->subscribed_set_refs = 0;

    assert_int_not_equal(UINT16_MAX, pn_track_subscription(mgr, sub));
    return sub->slot_index;
}

/* Scenario (a): a member whose own handle was never subscribed still delivers
 * while a subscribed set contains it; unsubscribing the set silences it;
 * resubscribing restores delivery. Binding targets the member handle slot. */
static void test_set_refs_member_delivers_while_set_subscribed(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));
    uint16_t slot = mgr.sets[set_idx].member_slots[0];

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");

    /* Member added but set not subscribed: silent. */
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(0, rec.message_count);

    /* Set subscribed: member gains a delivery share and fires. */
    wb_set_subscribe(&mgr, set_idx);
    assert_int_equal(1, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Set unsubscribed: share drops to zero, silent again. */
    wb_set_unsubscribe(&mgr, set_idx);
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Resubscribe restores delivery. */
    wb_set_subscribe(&mgr, set_idx);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (b): a member that is both directly subscribed and in a subscribed
 * set fires exactly once per event (one listener slot). It keeps firing after
 * the set unsubscribes (own subscribe still holds), and goes silent only once
 * both the direct subscribe and the set share are gone. */
static void test_set_refs_own_and_set_fire_once(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));
    uint16_t slot = mgr.sets[set_idx].member_slots[0];

    /* Direct subscribe on the member's own handle, plus a subscribed set. */
    mgr.tracked_subs[slot]->subscribed = 1;
    wb_set_subscribe(&mgr, set_idx);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count); /* Once, not twice. */

    /* Set unsubscribes: direct subscribe keeps delivery alive. */
    wb_set_unsubscribe(&mgr, set_idx);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec.message_count);

    /* Direct unsubscribe too: now silent. */
    mgr.tracked_subs[slot]->subscribed = 0;
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (c): adding a member to an already-subscribed set grants a delivery
 * share immediately (production pn_subscription_set_add_member path); removing
 * it drops the share. */
static void test_set_refs_add_to_subscribed_set_is_immediate(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    /* Subscribe the (empty) set first, then add a member. */
    mgr.sets[set_idx].subscribed = 1;
    assert_int_equal(PUBNUB_OK, test_set_add(&mgr, set_idx, "ch1", 3));
    uint16_t slot = mgr.sets[set_idx].member_slots[0];
    assert_int_equal(1, mgr.tracked_subs[slot]->subscribed_set_refs);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Remove the member from the subscribed set: share drops, silent. */
    assert_int_equal(1, pn_subscription_set_remove_member_slot(&mgr, set_idx, slot));
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (d): one handle in two subscribed sets. Delivery survives while
 * either set holds it; silent only when both drop the share. Exercises the
 * production add_member / remove_member_slot counter paths. */
static void test_set_refs_handle_in_two_sets(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, entry);
    uint16_t slot = unsub_slot_for_entry(&mgr, entry);

    uint16_t set_a             = pn_subscription_set_create(&mgr);
    uint16_t set_b             = pn_subscription_set_create(&mgr);
    mgr.sets[set_a].subscribed = 1;
    mgr.sets[set_b].subscribed = 1;

    assert_true(
        pn_subscription_set_add_member(&mgr, set_a, mgr.tracked_subs[slot]) > 0);
    assert_true(
        pn_subscription_set_add_member(&mgr, set_b, mgr.tracked_subs[slot]) > 0);
    assert_int_equal(2, mgr.tracked_subs[slot]->subscribed_set_refs);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Drop one set: still delivered via the other. */
    assert_int_equal(1, pn_subscription_set_remove_member_slot(&mgr, set_a, slot));
    assert_int_equal(1, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec.message_count);

    /* Drop the second set: now silent. */
    assert_int_equal(1, pn_subscription_set_remove_member_slot(&mgr, set_b, slot));
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(2, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (e): destroying a subscribed set drops each surviving member's
 * delivery share (production pn_subscription_set_destroy path). A member kept
 * alive by an extra reference goes silent after the set is destroyed. */
static void test_set_refs_set_destroy_drops_member_share(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, entry);
    /* Creator reference keeps the handle alive past set destroy. */
    uint16_t slot = unsub_slot_for_entry(&mgr, entry);

    uint16_t set_idx             = pn_subscription_set_create(&mgr);
    mgr.sets[set_idx].subscribed = 1;
    assert_true(
        pn_subscription_set_add_member(&mgr, set_idx, mgr.tracked_subs[slot]) > 0);
    assert_int_equal(1, mgr.tracked_subs[slot]->subscribed_set_refs);

    callback_record_t rec = {0};
    pubnub_subscribe_listener_t l = {.on_message = cb_on_message, .user_data = &rec};
    pn_subscribe_listener_add_bound(&mgr, &l, slot);

    pubnub_subscribe_event_t msg = make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1");
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    /* Destroy the subscribed set: member survives (creator ref) but its share
     * is revoked, so it goes silent. */
    pn_subscription_set_destroy(&mgr, set_idx);
    assert_non_null(mgr.tracked_subs[slot]);
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);
    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

/* Scenario (g): presence gating stays per-handle for set-activated members. A
 * presence-requesting member in a subscribed set receives presence events
 * (its own flag qualifies) even though it was never directly subscribed; a
 * non-presence member in the same set does not. */
static void test_set_refs_presence_gates_on_member_flag(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t set_idx             = pn_subscription_set_create(&mgr);
    mgr.sets[set_idx].subscribed = 1; /* Subscribe before adding members. */

    uint16_t slot_p = set_add_member_presence(&mgr, set_idx, "room", 1);
    uint16_t slot_n = set_add_member_presence(&mgr, set_idx, "room2", 0);
    assert_int_equal(1, mgr.tracked_subs[slot_p]->subscribed_set_refs);
    assert_int_equal(1, mgr.tracked_subs[slot_n]->subscribed_set_refs);

    callback_record_t           rec_p = {0};
    callback_record_t           rec_n = {0};
    pubnub_subscribe_listener_t l_p   = {.on_presence = cb_on_presence,
                                         .user_data   = &rec_p};
    pubnub_subscribe_listener_t l_n   = {.on_presence = cb_on_presence,
                                         .user_data   = &rec_n};
    pn_subscribe_listener_add_bound(&mgr, &l_p, slot_p);
    pn_subscribe_listener_add_bound(&mgr, &l_n, slot_n);

    pubnub_subscribe_event_t pre_p =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room", "room-pnpres");
    pubnub_subscribe_event_t pre_n =
        make_message_full(PUBNUB_SUBSCRIBE_PRESENCE, "room2", "room2-pnpres");
    pn_subscribe_emit_message(&mgr, &pre_p);
    pn_subscribe_emit_message(&mgr, &pre_n);

    assert_int_equal(1, rec_p.presence_count); /* presence member: delivered */
    assert_int_equal(0, rec_n.presence_count); /* non-presence: blocked */

    destroy_test_manager(&mgr);
}

/* Scenario (h): the counter never underflows. Removing a member from a set
 * that is not subscribed does not decrement; unsubscribing an already-
 * unsubscribed set does not decrement; a add/remove stress cycle ends at 0. */
static void test_set_refs_no_underflow(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t entry = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, entry);
    uint16_t slot = unsub_slot_for_entry(&mgr, entry);

    uint16_t set_idx = pn_subscription_set_create(&mgr);

    /* Add while NOT subscribed: no share granted. */
    assert_true(
        pn_subscription_set_add_member(&mgr, set_idx, mgr.tracked_subs[slot]) > 0);
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);

    /* Remove while NOT subscribed: must not underflow. */
    assert_int_equal(1, pn_subscription_set_remove_member_slot(&mgr, set_idx, slot));
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);

    /* Re-add and run a subscribe/unsubscribe stress cycle; end at zero. */
    assert_true(
        pn_subscription_set_add_member(&mgr, set_idx, mgr.tracked_subs[slot]) > 0);
    {
        int k;
        for (k = 0; k < 100; ++k) {
            wb_set_subscribe(&mgr, set_idx);
            wb_set_unsubscribe(&mgr, set_idx);
        }
    }
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);

    /* Extra unsubscribe on an unsubscribed set stays clamped at zero. */
    wb_set_unsubscribe(&mgr, set_idx);
    assert_int_equal(0, mgr.tracked_subs[slot]->subscribed_set_refs);

    destroy_test_manager(&mgr);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Listener registration */
        cmocka_unit_test(test_add_global_listener),
        cmocka_unit_test(test_add_bound_listener),
        cmocka_unit_test(test_add_set_listener),
        cmocka_unit_test(test_remove_listener),
        cmocka_unit_test(test_remove_invalid_handle_is_noop),
        cmocka_unit_test(test_add_multiple_listeners),
        cmocka_unit_test(test_listener_capacity_exhausted),
        cmocka_unit_test(test_add_bound_to_invalid_slot_fails),
        cmocka_unit_test(test_add_to_invalid_set_fails),
        /* Message routing */
        cmocka_unit_test(test_global_listener_receives_all_messages),
        cmocka_unit_test(test_bound_listener_receives_only_matching_channel),
        cmocka_unit_test(test_set_listener_receives_only_set_members),
        cmocka_unit_test(test_mixed_listeners_coexist),
        cmocka_unit_test(test_typed_dispatch_routes_to_correct_callback),
        cmocka_unit_test(test_status_delivered_to_all_listeners_regardless_of_binding),
        /* Status events snapshot the channel/group strings under the
         * context lock before dispatch, so a concurrent subscription
         * mutation cannot free the entries mid-build. */
        cmocka_unit_test(test_emit_status_channels_match_subscription),
        cmocka_unit_test(test_emit_status_empty_yields_no_views),
        cmocka_unit_test(test_emit_status_groups_only),
        cmocka_unit_test(test_emit_status_channels_and_groups),
#if PUBNUB_CFG_THREAD_SAFETY && !defined(_WIN32)
        cmocka_unit_test(test_emit_status_channel_build_is_race_free),
        cmocka_unit_test(test_emit_message_match_is_race_free),
        cmocka_unit_test(test_emit_message_callback_not_under_lock),
#if PUBNUB_ENABLE_PRESENCE
        cmocka_unit_test(test_presence_notify_build_is_race_free),
#endif
#endif
        cmocka_unit_test(test_removed_listener_stops_receiving),
        cmocka_unit_test(test_channel_name_resolution_for_dispatch),
        cmocka_unit_test(test_pnpres_suffix_stripped_during_resolution),
        cmocka_unit_test(test_pnpres_no_presence_flag_blocks_delivery),
        cmocka_unit_test(test_pnpres_entity_receives_presence_only),
        cmocka_unit_test(test_pnpres_wildcard_fallback_matches_pattern),
        /* Trailing-wildcard (`foo.*`) channel matching */
        cmocka_unit_test(test_wildcard_matches_concrete_regular_bound),
        cmocka_unit_test(test_wildcard_presence_requires_flag),
        cmocka_unit_test(test_wildcard_presence_b_shapes),
        cmocka_unit_test(test_wildcard_pnpres_entity_presence_only),
        cmocka_unit_test(test_wildcard_metadata_never_matches),
        cmocka_unit_test(test_wildcard_negatives),
        cmocka_unit_test(test_wildcard_exact_and_wildcard_both_fire_once),
        cmocka_unit_test(test_wildcard_set_bound),
        cmocka_unit_test(test_wildcard_global_listener),
        cmocka_unit_test(test_wildcard_builder_output),
        /* Reference counting */
        cmocka_unit_test(test_ref_count_increments_on_acquire),
        cmocka_unit_test(test_ref_count_decrements_on_release),
        cmocka_unit_test(test_entry_freed_when_ref_count_reaches_zero),
        cmocka_unit_test(test_double_release_is_safe),
        cmocka_unit_test(test_set_holds_independent_ref),
        cmocka_unit_test(test_multiple_acquires_release_independently),
        cmocka_unit_test(test_freed_slot_can_be_reused),
        cmocka_unit_test(test_active_count_independent_of_ref_count),
        /* Dynamic name allocation */
        cmocka_unit_test(test_acquire_stores_name_dynamically),
        cmocka_unit_test(test_release_frees_name),
        cmocka_unit_test(test_reacquire_same_name_no_new_alloc),
        cmocka_unit_test(test_acquire_long_name_succeeds),
        cmocka_unit_test(test_release_all_frees_all_names),
        /* Deferred removal */
        cmocka_unit_test(test_remove_during_emit_defers),
        cmocka_unit_test(test_deferred_remove_skipped_in_emit),
        cmocka_unit_test(test_remove_self_from_callback),
        cmocka_unit_test(test_remove_other_listener_from_callback),
        cmocka_unit_test(test_earlier_callback_removes_later_pending_skipped),
        cmocka_unit_test(test_readd_after_deferred_remove),
        /* Subscribed-state delivery gating */
        cmocka_unit_test(test_gating_per_sub_unsubscribe_silences_only_that_handle),
        cmocka_unit_test(test_gating_never_subscribed_handle_is_silent),
        cmocka_unit_test(test_gating_set_unsubscribed_is_silent_then_reactivates),
        cmocka_unit_test(test_gating_set_delivers_member_whose_handle_unsubscribed),
        cmocka_unit_test(test_gating_remove_for_slot_detaches_bound_only),
        cmocka_unit_test(test_gating_remove_for_set_detaches_set_listeners),
        cmocka_unit_test(test_gating_remove_for_slot_from_callback_defers),
        cmocka_unit_test(test_gating_remove_for_slot_stale_or_foreign_is_noop),
        cmocka_unit_test(test_gating_global_listener_unaffected_by_handle_state),
        cmocka_unit_test(test_gating_per_sub_presence_respects_subscribed),
        /* Per-handle delivery via subscribed-set membership
         * (subscribed_set_refs) */
        cmocka_unit_test(test_set_refs_member_delivers_while_set_subscribed),
        cmocka_unit_test(test_set_refs_own_and_set_fire_once),
        cmocka_unit_test(test_set_refs_add_to_subscribed_set_is_immediate),
        cmocka_unit_test(test_set_refs_handle_in_two_sets),
        cmocka_unit_test(test_set_refs_set_destroy_drops_member_share),
        cmocka_unit_test(test_set_refs_presence_gates_on_member_flag),
        cmocka_unit_test(test_set_refs_no_underflow),
        /* Set membership */
        cmocka_unit_test(test_set_contains_after_add),
        cmocka_unit_test(test_set_destroy_releases_all_refs),
        /* Name-based routing across entity types */
        cmocka_unit_test(test_same_name_channel_and_metadata_route_to_both),
        cmocka_unit_test(test_duplicate_bindings_each_fire_exactly_once),
        cmocka_unit_test(test_channel_and_subscription_hit_different_entries),
        cmocka_unit_test(test_exact_name_match_no_prefix_cross_delivery),
        cmocka_unit_test(test_pnpres_channel_routes_to_base_name_binding),
        /* Channel/heartbeat string dedup */
        cmocka_unit_test(test_path_string_dedup_same_name_cross_type),
        cmocka_unit_test(test_path_string_dedup_presence_emitted_once),
        cmocka_unit_test(test_path_string_token_dedup_presence_then_pnpres_entity),
        cmocka_unit_test(test_path_string_token_dedup_pnpres_entity_then_presence),
        cmocka_unit_test(test_path_string_pnpres_entity_no_double_suffix),
        cmocka_unit_test(test_path_string_metadata_only_no_presence),
        cmocka_unit_test(test_path_string_buffer_too_small),
        cmocka_unit_test(test_heartbeat_string_dedup_no_presence),
        cmocka_unit_test(test_heartbeat_string_excludes_pnpres_named),
        cmocka_unit_test(test_unsubscribe_one_duplicate_keeps_entity_in_path),
        /* Two-pass alloc builder (production dispatch path) */
        cmocka_unit_test(test_alloc_channel_string_presence_dedup_channel_first),
        cmocka_unit_test(test_alloc_channel_string_presence_dedup_metadata_first),
        cmocka_unit_test(test_alloc_and_heartbeat_string_consistency),
        cmocka_unit_test(test_builder_walker_capacity_sweep_no_overflow),
        /* Public-API end-to-end presence dedup */
        cmocka_unit_test(test_public_api_presence_dedup_channel_and_metadata),
        /* Per-handle presence accounting (presence_contributors counter) */
        cmocka_unit_test(test_presence_two_contributors_on_entity),
        cmocka_unit_test(test_presence_mixed_handles_same_entity),
        cmocka_unit_test(test_presence_destroy_subscribed_handle_drops_share),
        cmocka_unit_test(test_presence_set_share_tracks_subscribed_state),
        cmocka_unit_test(test_presence_direct_and_set_no_underflow),
        cmocka_unit_test(test_presence_metadata_ignores_with_presence),
        cmocka_unit_test(test_set_member_presence_gating_per_handle),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
