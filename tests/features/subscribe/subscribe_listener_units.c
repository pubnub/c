/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_listener_units.c
 * @brief Unit tests for listener management, message routing (filtered
 *        dispatch), and subscription entry reference counting.
 *
 * Tests operate directly on the subscribe manager internals so that
 * listener add/remove, dispatch filtering, and ref-count lifecycle
 * can be verified without mocking transport or the full context.
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

/* ================================================================== */
/* Mock providers for context initialization                           */
/* ================================================================== */

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

/* ================================================================== */
/* Test helpers                                                         */
/* ================================================================== */

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
 * @brief Create a zeroed manager on the stack for testing.
 *
 * Since tests exercise internal functions directly, we bypass
 * pn_subscribe_manager_create() and manually initialize the
 * minimum required fields. The global s_test_ctx is set as the
 * context back-pointer so that pn_context_allocator() works.
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
    for (uint16_t i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
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
 * @brief Acquire a channel and mark it active so it appears in the
 *        built channel string.
 *
 * The channel/group string builders skip entries with active_count == 0
 * (the public subscribe path increments active_count on activation).
 * These manager-internal tests bypass that path, so activation is
 * applied directly here.
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
 * @brief Build a synthetic dispatch entry for dispatch testing.
 */
static pn_subscribe_dispatch_entry_t make_message(pubnub_subscribe_message_type_t type,
                                                  const char* channel,
                                                  uint16_t    entry_index)
{
    pn_subscribe_dispatch_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.event.type        = type;
    entry.event.channel.ptr = channel;
    entry.event.channel.len = strlen(channel);
    entry.event.payload = (const struct pubnub_json_value*)(uintptr_t)0xDEAD;
    entry.entry_index   = entry_index;
    return entry;
}

/* ================================================================== */
/* Listener registration and removal                                   */
/* ================================================================== */

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
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_entry_index);
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_set_index);
}

static void test_add_bound_listener(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");
    assert_int_not_equal(UINT16_MAX, idx);

    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add_bound(&mgr, &listener, idx);
    assert_int_not_equal(PN_LISTENER_HANDLE_INVALID, h);
    assert_int_equal(1, mgr.listener_count);
    assert_int_equal(idx, mgr.listeners[h].bound_entry_index);
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
    assert_int_equal(UINT16_MAX, mgr.listeners[h].bound_entry_index);
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

static void test_add_bound_to_invalid_entry_fails(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    pubnub_subscribe_listener_t listener = {.on_message = cb_on_message};

    /* No entry at index 0 — should fail. */
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

/* ================================================================== */
/* Message routing / dispatch filtering                                 */
/* ================================================================== */

static void test_global_listener_receives_all_messages(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_subscribe_listener_add(&mgr, &listener);

    pn_subscribe_dispatch_entry_t msg1 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx_ch1);
    pn_subscribe_dispatch_entry_t msg2 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2", idx_ch2);

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
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };

    /* Bind only to ch1. */
    pn_subscribe_listener_add_bound(&mgr, &listener, idx_ch1);

    pn_subscribe_dispatch_entry_t msg1 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx_ch1);
    pn_subscribe_dispatch_entry_t msg2 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2", idx_ch2);

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

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");
    uint16_t idx_ch3 = acquire_channel(&mgr, "ch3");

    /* Create a set containing ch1 and ch2 (but not ch3). */
    uint16_t     set_idx = pn_subscription_set_create(&mgr);
    pubnub_res_t rc =
        pn_subscription_set_add(&mgr, set_idx, "ch1", 3, PN_ENTITY_CHANNEL, 0);
    assert_int_equal(PUBNUB_OK, rc);
    rc = pn_subscription_set_add(&mgr, set_idx, "ch2", 3, PN_ENTITY_CHANNEL, 0);
    assert_int_equal(PUBNUB_OK, rc);

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_subscribe_listener_add_to_set(&mgr, &listener, set_idx);

    pn_subscribe_dispatch_entry_t msg1 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx_ch1);
    pn_subscribe_dispatch_entry_t msg2 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2", idx_ch2);
    pn_subscribe_dispatch_entry_t msg3 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch3", idx_ch3);

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
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");

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
    pn_subscribe_listener_add_bound(&mgr, &bound_listener, idx_ch1);

    pn_subscribe_dispatch_entry_t msg1 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx_ch1);
    pn_subscribe_dispatch_entry_t msg2 =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch2", idx_ch2);

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

    uint16_t idx = acquire_channel(&mgr, "ch1");

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

    pn_subscribe_dispatch_entry_t msg_msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);
    pn_subscribe_dispatch_entry_t msg_sig =
        make_message(PUBNUB_SUBSCRIBE_SIGNAL, "ch1", idx);
    pn_subscribe_dispatch_entry_t msg_pres =
        make_message(PUBNUB_SUBSCRIBE_PRESENCE, "ch1", idx);
    pn_subscribe_dispatch_entry_t msg_obj =
        make_message(PUBNUB_SUBSCRIBE_APP_CONTEXT, "ch1", idx);
    pn_subscribe_dispatch_entry_t msg_file =
        make_message(PUBNUB_SUBSCRIBE_FILE, "ch1", idx);
    pn_subscribe_dispatch_entry_t msg_act =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE_ACTION, "ch1", idx);

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
    pn_subscription_set_add(&mgr, set_idx, "ch1", 3, PN_ENTITY_CHANNEL, 0);

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
    pn_subscribe_listener_add_bound(&mgr, &l_bound, idx);
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

/* Capture buffer for the channel/group views delivered to on_status.
 * The views alias allocator-owned memory that emit_status frees after
 * the callback returns, so the content is copied out here while it is
 * still valid — this also verifies the snapshot is intact during the
 * callback. */
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

/* Real pthread-mutex platform: the shared mock platform installs NULL
 * lock hooks (no-ops), so pn_ctx_lock would not actually serialize.
 * This provider makes the context lock real for the concurrency test,
 * which is the only way to validate that emit_status now builds the
 * channel string under the same lock the mutation side takes. */
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
        /* Mutations run under the context lock, matching the API-layer
         * contract. The entry is marked active so the builder actually
         * reads its name during the two-pass measure/write, then it is
         * freed on release — this is the exact window the fix closes.
         * With the fix, emit_status builds under the same lock, so the
         * builder can never observe the half-freed entry name. */
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

    /* Under the buggy (lockless) build the emit thread races the
     * mutator and ASan/TSan flags the use-after-free before these
     * assertions are reached. With the fix, every snapshot is
     * well-formed and always contains the persistent channels. */
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

#if PUBNUB_ENABLE_PRESENCE

/** Shared state for the presence-notify public-API race test. */
typedef struct pf1_race_ctx {
    pubnub_context_t*     ctx;
    pubnub_subscription_t toggle_sub;
} pf1_race_ctx_t;

/* Thread A: drives the presence heartbeat builders through the public
 * API. Each subscribe/unsubscribe transition invokes
 * pn_notify_presence_joined / pn_notify_presence_left, which build the
 * heartbeat channel/group strings by a two-pass measure/write over the
 * shared entry registry. */
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

/* Thread B: churns a transient channel entry through the full
 * create -> subscribe -> unsubscribe -> destroy lifecycle. The final
 * pubnub_entity_destroy drops the last ref and frees the entry name via
 * pn_subscription_release -- the exact write that races the heartbeat
 * builder's two-pass read on thread A when the builders run unlocked. */
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

    /* Warm up the presence manager single-threaded: pn_ensure_presence_manager
     * is not itself lock-guarded, so creating it here (before the threads
     * start) keeps the race focused on the heartbeat-builder vs.
     * pn_subscription_release window this test targets rather than the
     * unrelated feature-state double-create window. */
    assert_int_equal(PUBNUB_OK, pubnub_subscription_subscribe(sub_a));
    assert_int_equal(PUBNUB_OK, pubnub_subscription_unsubscribe(sub_a));

    rc.ctx        = ctx;
    rc.toggle_sub = sub_a;

    assert_int_equal(0, pn_test_thread_create(&t_notify, pf1_notify_thread, &rc));
    assert_int_equal(0, pn_test_thread_create(&t_churn, pf1_churn_thread, &rc));
    pn_test_thread_join(t_notify);
    pn_test_thread_join(t_churn);

    /* With the fix the heartbeat builders run under the same context lock
     * pn_subscription_release takes, so TSan reports no data race on the
     * entry name buffers. Without the fix the two-pass builder reads the
     * name unlocked and TSan flags the use-after-free at
     * pn_compute_heartbeat_*_len / pn_write_heartbeat_* against
     * pn_subscription_release. */
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

    uint16_t idx = acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };

    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);
    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);

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
    pn_subscribe_listener_add_bound(&mgr, &listener, idx_ch1);

    /* Message with entry_index=UINT16_MAX forces name-based resolution. */
    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", UINT16_MAX);

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.message_count);

    destroy_test_manager(&mgr);
}

static void test_pnpres_suffix_stripped_during_resolution(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx = acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_presence = cb_on_presence,
        .user_data   = &rec,
    };
    pn_subscribe_listener_add_bound(&mgr, &listener, idx);

    /* Presence event with -pnpres suffix and unresolved entry_index. */
    pn_subscribe_dispatch_entry_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.event.type        = PUBNUB_SUBSCRIBE_PRESENCE;
    msg.event.channel.ptr = "ch1-pnpres";
    msg.event.channel.len = 10;
    msg.event.payload     = (const struct pubnub_json_value*)(uintptr_t)0xDEAD;
    msg.entry_index       = UINT16_MAX;

    pn_subscribe_emit_message(&mgr, &msg);
    assert_int_equal(1, rec.presence_count);

    destroy_test_manager(&mgr);
}

/* ================================================================== */
/* Reference counting                                                  */
/* ================================================================== */

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
    pn_subscription_set_add(&mgr, set_idx, "ch1", 3, PN_ENTITY_CHANNEL, 0);
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

/* ================================================================== */
/* Dynamic name allocation                                             */
/* ================================================================== */

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

/* ================================================================== */
/* Deferred removal (pending_remove)                                   */
/* ================================================================== */

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

    uint16_t idx = acquire_channel(&mgr, "ch1");

    callback_record_t           rec      = {0};
    pubnub_subscribe_listener_t listener = {
        .on_message = cb_on_message,
        .user_data  = &rec,
    };
    pn_listener_handle_t h = pn_subscribe_listener_add(&mgr, &listener);

    /* Manually set pending_remove as if a concurrent remove happened. */
    mgr.listeners[h].pending_remove = 1;

    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);
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

    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);

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

    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);
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
    uint16_t                      idx = acquire_channel(&mgr, "ch1");
    pn_subscribe_dispatch_entry_t msg =
        make_message(PUBNUB_SUBSCRIBE_MESSAGE, "ch1", idx);
    pn_subscribe_emit_message(&mgr, &msg);

    /* Old listener not called, new one called. */
    assert_int_equal(0, rec1.message_count);
    assert_int_equal(1, rec2.message_count);

    /* Old slot cleaned up. */
    assert_int_equal(0, mgr.listeners[h].active);

    destroy_test_manager(&mgr);
}

/* ================================================================== */
/* Subscription set membership                                         */
/* ================================================================== */

static void test_set_contains_after_add(void** state)
{
    (void)state;
    pn_subscribe_manager_t mgr;
    create_test_manager(&mgr);

    uint16_t idx_ch1 = acquire_channel(&mgr, "ch1");
    uint16_t idx_ch2 = acquire_channel(&mgr, "ch2");

    uint16_t set_idx = pn_subscription_set_create(&mgr);
    pn_subscription_set_add(&mgr, set_idx, "ch1", 3, PN_ENTITY_CHANNEL, 0);

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
    pn_subscription_set_add(&mgr, set_idx, "ch1", 3, PN_ENTITY_CHANNEL, 0);
    pn_subscription_set_add(&mgr, set_idx, "ch2", 3, PN_ENTITY_CHANNEL, 0);
    pn_subscription_set_add(&mgr, set_idx, "ch3", 3, PN_ENTITY_CHANNEL, 0);
    assert_int_equal(3, mgr.channel_count);

    pn_subscription_set_destroy(&mgr, set_idx);
    assert_int_equal(0, mgr.channel_count);
    assert_int_equal(0, mgr.sets[set_idx].active);
}

/* ================================================================== */

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
        cmocka_unit_test(test_add_bound_to_invalid_entry_fails),
        cmocka_unit_test(test_add_to_invalid_set_fails),
        /* Message routing */
        cmocka_unit_test(test_global_listener_receives_all_messages),
        cmocka_unit_test(test_bound_listener_receives_only_matching_channel),
        cmocka_unit_test(test_set_listener_receives_only_set_members),
        cmocka_unit_test(test_mixed_listeners_coexist),
        cmocka_unit_test(test_typed_dispatch_routes_to_correct_callback),
        cmocka_unit_test(test_status_delivered_to_all_listeners_regardless_of_binding),
        /* Status channel-string snapshot (B9 race fix) */
        cmocka_unit_test(test_emit_status_channels_match_subscription),
        cmocka_unit_test(test_emit_status_empty_yields_no_views),
        cmocka_unit_test(test_emit_status_groups_only),
        cmocka_unit_test(test_emit_status_channels_and_groups),
#if PUBNUB_CFG_THREAD_SAFETY && !defined(_WIN32)
        cmocka_unit_test(test_emit_status_channel_build_is_race_free),
#if PUBNUB_ENABLE_PRESENCE
        cmocka_unit_test(test_presence_notify_build_is_race_free),
#endif
#endif
        cmocka_unit_test(test_removed_listener_stops_receiving),
        cmocka_unit_test(test_channel_name_resolution_for_dispatch),
        cmocka_unit_test(test_pnpres_suffix_stripped_during_resolution),
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
        cmocka_unit_test(test_readd_after_deferred_remove),
        /* Set membership */
        cmocka_unit_test(test_set_contains_after_add),
        cmocka_unit_test(test_set_destroy_releases_all_refs),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
