/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_capacity_log_units.c
 * @brief Verifies that hitting a compile-time subscribe capacity limit emits
 *        a WARNING naming the limit, and stays silent otherwise.
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

#include "features/subscribe/subscribe_manager_internal.h"
#include "pubnub/client.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/log.h"

#if PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE > 0

#define MAX_CAPTURED 16
#define MSG_CAP      256

#define NAME_LISTENERS "PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS="
#define NAME_ENTITIES  "PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS="
#define NAME_SUBS      "PUBNUB_CFG_MAX_SUBSCRIPTIONS="
#define NAME_SETS      "PUBNUB_CFG_MAX_SUBSCRIPTION_SETS="
#define NAME_MEMBERS   "PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET="

typedef struct captured_entry {
    pubnub_log_level_t level;
    int                lock_depth;
    char               message[MSG_CAP];
} captured_entry_t;

static captured_entry_t s_captured[MAX_CAPTURED];
static int              s_captured_count;
static unsigned int     s_logger_min_level;
static int              s_lock_depth;

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
    pubnub_buffer_t buf = {0};
    (void)self;
    buf.data    = (uint8_t*)malloc(4096);
    buf.cap     = buf.data ? 4096 : 0;
    buf.purpose = purpose;
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

static size_t mock_lock_size(pubnub_platform_provider_t* self)
{
    (void)self;
    return sizeof(int);
}

static int mock_lock_init(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    *(int*)lock = 0;
    return 0;
}

static void mock_lock_destroy(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
}

static void mock_lock_acquire(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
    s_lock_depth++;
}

static void mock_lock_release(pubnub_platform_provider_t* self, pubnub_lock_t* lock)
{
    (void)self;
    (void)lock;
    s_lock_depth--;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_monotonic,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
    .lock_size     = mock_lock_size,
    .lock_init     = mock_lock_init,
    .lock_destroy  = mock_lock_destroy,
    .lock_acquire  = mock_lock_acquire,
    .lock_release  = mock_lock_release,
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
    .send   = mock_send,
    .poll   = mock_poll,
    .cancel = mock_cancel,
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

static void capture_log(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    const pubnub_log_entry_text_t* text;
    (void)self;

    if (0u == s_logger_min_level || (unsigned int)entry->level < s_logger_min_level) {
        return;
    }
    if (PUBNUB_LOG_ENTRY_TEXT != entry->type || MAX_CAPTURED <= s_captured_count) {
        return;
    }
    text                               = (const pubnub_log_entry_text_t*)entry;
    s_captured[s_captured_count].level = entry->level;
    s_captured[s_captured_count].lock_depth = s_lock_depth;
    snprintf(s_captured[s_captured_count].message, MSG_CAP, "%s", text->message);
    s_captured_count++;
}

static void capture_set_level(struct pubnub_logger_provider* self,
                              pubnub_log_level_t             min_level)
{
    (void)self;
    s_logger_min_level = (PUBNUB_LOG_LEVEL_ALL == min_level)
                           ? (unsigned int)PUBNUB_LOG_LEVEL_TRACE
                           : (unsigned int)min_level;
}

static pubnub_logger_provider_t s_logger = {
    .log       = capture_log,
    .set_level = capture_set_level,
};

static pubnub_context_t* s_ctx;
static PUBNUB_ALIGNAS(max_align_t) uint8_t s_ctx_mem[PUBNUB_CONTEXT_SIZE];

#define MAX_HANDLES 256

PUBNUB_STATIC_ASSERT(PUBNUB_CFG_MAX_SUBSCRIPTIONS < MAX_HANDLES
                         && PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS < MAX_HANDLES
                         && PUBNUB_CFG_MAX_SUBSCRIPTION_SETS < MAX_HANDLES
                         && PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS < MAX_HANDLES,
                     "raise MAX_HANDLES");

static pubnub_entity_t           s_entities[MAX_HANDLES];
static int                       s_entity_count;
static pubnub_subscription_t     s_subs[MAX_HANDLES];
static int                       s_sub_count;
static pubnub_subscription_set_t s_sets[MAX_HANDLES];
static int                       s_set_count;
static pubnub_listener_handle_t  s_listeners[MAX_HANDLES];
static int                       s_listener_count;

static void noop_message(const pubnub_subscribe_event_t* event, void* user_data)
{
    (void)event;
    (void)user_data;
}

static pubnub_subscribe_listener_t make_listener(void)
{
    pubnub_subscribe_listener_t listener = {0};
    listener.on_message                  = noop_message;
    return listener;
}

static void reset_capture(void)
{
    memset(s_captured, 0, sizeof(s_captured));
    s_captured_count = 0;
}

static int setup(void** state)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    (void)state;

    s_entity_count   = 0;
    s_sub_count      = 0;
    s_set_count      = 0;
    s_listener_count = 0;
    s_lock_depth     = 0;

    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_mock_allocator;
    cfg.transport     = &s_mock_transport;
    cfg.serialization = &s_mock_serialization;
    cfg.platform      = &s_mock_platform;
    cfg.logger        = &s_logger;
    cfg.log_level     = PUBNUB_LOG_LEVEL_ALL;

    s_ctx = (pubnub_context_t*)s_ctx_mem;
    if (PUBNUB_OK != pubnub_init(s_ctx, &cfg)) {
        s_ctx = NULL;
    }
    assert_non_null(s_ctx);
    reset_capture();
    return 0;
}

static int teardown(void** state)
{
    int i;
    (void)state;

    for (i = 0; i < s_listener_count; ++i) {
        pubnub_remove_listener(s_ctx, s_listeners[i]);
    }
    for (i = 0; i < s_set_count; ++i) {
        pubnub_subscription_set_destroy(s_sets[i]);
    }
    for (i = 0; i < s_sub_count; ++i) {
        pubnub_subscription_destroy(s_subs[i]);
    }
    for (i = 0; i < s_entity_count; ++i) {
        pubnub_entity_destroy(s_entities[i]);
    }
    pubnub_deinit(s_ctx);
    s_ctx = NULL;
    return 0;
}

static int count_containing(const char* needle)
{
    int i;
    int n = 0;
    for (i = 0; i < s_captured_count; ++i) {
        if (NULL != strstr(s_captured[i].message, needle)) {
            n++;
        }
    }
    return n;
}

static void assert_one_limit_warning(const char* limit_name, unsigned int value)
{
    char needle[MSG_CAP];
    snprintf(needle, sizeof(needle), "%s%u", limit_name, value);
    assert_int_equal(1, s_captured_count);
    assert_int_equal(PUBNUB_LOG_LEVEL_WARNING, s_captured[0].level);
    assert_int_equal(1, count_containing("limit reached"));
    assert_int_equal(1, count_containing(needle));
    assert_int_equal(0, s_captured[0].lock_depth);
}

static pubnub_entity_t add_entity(const char* name)
{
    pubnub_entity_t e = pubnub_channel(s_ctx, name);
    if (NULL != e) {
        s_entities[s_entity_count++] = e;
    }
    return e;
}

static pubnub_subscription_t add_sub(pubnub_entity_t entity)
{
    pubnub_subscription_t s = pubnub_subscription_create(entity, NULL);
    if (PUBNUB_SUBSCRIPTION_INVALID != s) {
        s_subs[s_sub_count++] = s;
    }
    return s;
}

static pubnub_subscription_set_t add_set(void)
{
    pubnub_subscription_set_t set = pubnub_subscription_set_create(s_ctx);
    if (PUBNUB_SUBSCRIPTION_SET_INVALID != set) {
        s_sets[s_set_count++] = set;
    }
    return set;
}

static void fill_listeners(int n)
{
    pubnub_subscribe_listener_t l = make_listener();
    int                         i;
    for (i = 0; i < n; ++i) {
        pubnub_listener_handle_t h = pubnub_add_listener(s_ctx, &l);
        assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, h);
        s_listeners[s_listener_count++] = h;
    }
}

static void listener_global_at_limit_logs_one_warning(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    (void)state;

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS - 1);
    assert_int_equal(0, s_captured_count);

    /* Exactly at the limit: the last slot is still granted, silently. */
    fill_listeners(1);
    assert_int_equal(0, s_captured_count);

    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_add_listener(s_ctx, &l));
    assert_one_limit_warning(NAME_LISTENERS, PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
}

static void listener_bound_at_limit_logs_one_warning(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    pubnub_entity_t             e;
    pubnub_subscription_t       sub;
    (void)state;

    e   = add_entity("ch");
    sub = add_sub(e);
    assert_non_null(e);
    assert_non_null(sub);

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(0, s_captured_count);

    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_subscription_add_listener(sub, &l));
    assert_one_limit_warning(NAME_LISTENERS, PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
}

static void listener_set_at_limit_logs_one_warning(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    pubnub_subscription_set_t   set;
    (void)state;

    set = add_set();
    assert_non_null(set);

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(0, s_captured_count);

    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_subscription_set_add_listener(set, &l));
    assert_one_limit_warning(NAME_LISTENERS, PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
}

static void listener_freed_slot_is_reusable_without_log(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    pubnub_listener_handle_t    h;
    (void)state;

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    pubnub_remove_listener(s_ctx, s_listeners[--s_listener_count]);

    h = pubnub_add_listener(s_ctx, &l);
    assert_int_not_equal(PUBNUB_LISTENER_HANDLE_INVALID, h);
    s_listeners[s_listener_count++] = h;
    assert_int_equal(0, s_captured_count);
}

static void listener_null_binding_does_not_log_limit(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    (void)state;

    /* Invalid binding while the table has free slots is not a capacity
     * failure; the helper must not blame the listener limit. */
    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_subscription_add_listener(NULL, &l));
    assert_int_equal(0, s_captured_count);
}

static void listener_bound_invalid_binding_full_table_is_silent(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    pubnub_entity_t             e;
    pubnub_subscription_t       sub;
    uint16_t                    saved;
    (void)state;

    e   = add_entity("ch");
    sub = add_sub(e);
    assert_non_null(sub);

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(0, s_captured_count);

    /* Forge an untracked slot: the binding check fails before the table
     * scan, so a full listener table must not be blamed. */
    saved           = sub->slot_index;
    sub->slot_index = UINT16_MAX;
    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_subscription_add_listener(sub, &l));
    sub->slot_index = saved;
    assert_int_equal(0, s_captured_count);
}

static void listener_set_invalid_binding_full_table_is_silent(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    pubnub_subscription_set_t   set;
    uint16_t                    saved;
    (void)state;

    set = add_set();
    assert_non_null(set);

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(0, s_captured_count);

    saved          = set->set_index;
    set->set_index = UINT16_MAX;
    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_subscription_set_add_listener(set, &l));
    set->set_index = saved;
    assert_int_equal(0, s_captured_count);

    /* In-range but inactive set slot. */
    if (PUBNUB_CFG_MAX_SUBSCRIPTION_SETS > 1) {
        set->set_index = (uint16_t)((saved + 1) % PUBNUB_CFG_MAX_SUBSCRIPTION_SETS);
        assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                         pubnub_subscription_set_add_listener(set, &l));
        set->set_index = saved;
        assert_int_equal(0, s_captured_count);
    }
}

static void set_member_invalid_handle_full_set_is_silent(void** state)
{
    pubnub_entity_t           e;
    pubnub_subscription_t     extra;
    pubnub_subscription_set_t set;
    uint16_t                  saved;
    int                       i;
    (void)state;

    if (PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        skip();
    }

    e   = add_entity("ch");
    set = add_set();
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET; ++i) {
        assert_int_equal(
            PUBNUB_OK, pubnub_subscription_set_add_subscription(set, add_sub(e)));
    }
    extra = add_sub(e);
    assert_non_null(extra);

    /* The handle is rejected for its untracked slot, not the member cap. */
    saved             = extra->slot_index;
    extra->slot_index = UINT16_MAX;
    assert_int_equal(PUBNUB_ERR_QUEUE_FULL,
                     pubnub_subscription_set_add_subscription(set, extra));
    extra->slot_index = saved;
    assert_int_equal(0, s_captured_count);
}

static void set_create_at_limit_logs_one_warning(void** state)
{
    int i;
    (void)state;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; ++i) {
        assert_non_null(add_set());
    }
    assert_int_equal(0, s_captured_count);

    assert_ptr_equal(PUBNUB_SUBSCRIPTION_SET_INVALID,
                     pubnub_subscription_set_create(s_ctx));
    assert_one_limit_warning(NAME_SETS, PUBNUB_CFG_MAX_SUBSCRIPTION_SETS);
}

static void set_member_at_limit_logs_one_warning(void** state)
{
    pubnub_entity_t           e;
    pubnub_subscription_t     extra;
    pubnub_subscription_set_t set;
    int                       i;
    (void)state;

    if (PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        skip();
    }

    e   = add_entity("ch");
    set = add_set();
    assert_non_null(e);
    assert_non_null(set);

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET; ++i) {
        pubnub_subscription_t s = add_sub(e);
        assert_non_null(s);
        assert_int_equal(PUBNUB_OK,
                         pubnub_subscription_set_add_subscription(set, s));
    }
    assert_int_equal(0, s_captured_count);

    extra = add_sub(e);
    assert_non_null(extra);
    assert_int_equal(PUBNUB_ERR_LIMIT_REACHED,
                     pubnub_subscription_set_add_subscription(set, extra));
    assert_one_limit_warning(NAME_MEMBERS, PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET);
}

static void set_member_duplicate_at_limit_is_silent(void** state)
{
    pubnub_entity_t           e;
    pubnub_subscription_t     first = NULL;
    pubnub_subscription_set_t set;
    int                       i;
    (void)state;

    if (PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET >= PUBNUB_CFG_MAX_SUBSCRIPTIONS) {
        skip();
    }

    e   = add_entity("ch");
    set = add_set();
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET; ++i) {
        pubnub_subscription_t s = add_sub(e);
        if (0 == i) {
            first = s;
        }
        assert_int_equal(PUBNUB_OK,
                         pubnub_subscription_set_add_subscription(set, s));
    }

    /* Re-adding an existing member is a no-op, not a capacity failure. */
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription(set, first));
    assert_int_equal(0, s_captured_count);
}

static void set_merge_over_member_limit_logs_one_warning(void** state)
{
    pubnub_entity_t           e;
    pubnub_subscription_set_t target;
    pubnub_subscription_set_t other;
    int                       i;
    int                       half = PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET / 2;
    (void)state;

    if (PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET + 2 > PUBNUB_CFG_MAX_SUBSCRIPTIONS
        || half < 1) {
        skip();
    }

    e      = add_entity("ch");
    target = add_set();
    other  = add_set();

    /* Exactly at the limit after merge: must succeed silently. */
    for (i = 0; i < half; ++i) {
        assert_int_equal(
            PUBNUB_OK,
            pubnub_subscription_set_add_subscription(target, add_sub(e)));
    }
    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET - half; ++i) {
        assert_int_equal(
            PUBNUB_OK, pubnub_subscription_set_add_subscription(other, add_sub(e)));
    }
    assert_int_equal(PUBNUB_OK,
                     pubnub_subscription_set_add_subscription_set(target, other));
    assert_int_equal(0, s_captured_count);

    /* One more member in the source pushes the next merge over the cap. */
    {
        pubnub_subscription_set_t third = add_set();
        assert_int_equal(
            PUBNUB_OK, pubnub_subscription_set_add_subscription(third, add_sub(e)));
        assert_int_equal(PUBNUB_ERR_LIMIT_REACHED,
                         pubnub_subscription_set_add_subscription_set(target, third));
    }
    assert_one_limit_warning(NAME_MEMBERS, PUBNUB_CFG_MAX_SUBSCRIPTIONS_PER_SET);
}

static void subscription_handle_at_limit_logs_one_warning(void** state)
{
    pubnub_entity_t e;
    int             i;
    (void)state;

    e = add_entity("ch");
    assert_non_null(e);

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTIONS; ++i) {
        assert_non_null(add_sub(e));
    }
    assert_int_equal(0, s_captured_count);

    assert_ptr_equal(PUBNUB_SUBSCRIPTION_INVALID,
                     pubnub_subscription_create(e, NULL));
    assert_one_limit_warning(NAME_SUBS, PUBNUB_CFG_MAX_SUBSCRIPTIONS);
}

static void entity_at_limit_logs_one_warning(void** state)
{
    char name[32];
    int  i;
    (void)state;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        snprintf(name, sizeof(name), "entity-%d", i);
        assert_non_null(add_entity(name));
    }
    assert_int_equal(0, s_captured_count);

    assert_null(pubnub_channel(s_ctx, "one-too-many"));
    assert_one_limit_warning(NAME_ENTITIES, PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS);
}

static void entity_existing_name_at_limit_is_silent(void** state)
{
    char name[32];
    int  i;
    (void)state;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIBE_CHANNELS; ++i) {
        snprintf(name, sizeof(name), "entity-%d", i);
        assert_non_null(add_entity(name));
    }

    /* The name already owns a slot, so the table does not need to grow. */
    assert_non_null(add_entity("entity-0"));
    assert_int_equal(0, s_captured_count);
}

static void entity_invalid_name_does_not_log_limit(void** state)
{
    (void)state;
    assert_null(pubnub_channel(s_ctx, ""));
    assert_null(pubnub_channel(s_ctx, NULL));
    assert_int_equal(0, s_captured_count);
}

static void limit_hit_silent_when_logger_level_none(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    (void)state;

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(PUBNUB_OK, pubnub_set_log_level(s_ctx, PUBNUB_LOG_LEVEL_NONE));
    reset_capture();

    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_add_listener(s_ctx, &l));
    assert_int_equal(0, s_captured_count);
}

static void limit_hit_silent_when_level_above_warning(void** state)
{
    int i;
    (void)state;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; ++i) {
        assert_non_null(add_set());
    }
    assert_int_equal(PUBNUB_OK, pubnub_set_log_level(s_ctx, PUBNUB_LOG_LEVEL_ERROR));
    reset_capture();

    assert_ptr_equal(PUBNUB_SUBSCRIPTION_SET_INVALID,
                     pubnub_subscription_set_create(s_ctx));
    assert_int_equal(0, s_captured_count);
}

static void limit_hit_emitted_when_level_is_warning(void** state)
{
    int i;
    (void)state;

    for (i = 0; i < PUBNUB_CFG_MAX_SUBSCRIPTION_SETS; ++i) {
        assert_non_null(add_set());
    }
    assert_int_equal(PUBNUB_OK,
                     pubnub_set_log_level(s_ctx, PUBNUB_LOG_LEVEL_WARNING));
    reset_capture();

    assert_ptr_equal(PUBNUB_SUBSCRIPTION_SET_INVALID,
                     pubnub_subscription_set_create(s_ctx));
    assert_one_limit_warning(NAME_SETS, PUBNUB_CFG_MAX_SUBSCRIPTION_SETS);
}

static void each_failed_attempt_logs_once(void** state)
{
    pubnub_subscribe_listener_t l = make_listener();
    (void)state;

    fill_listeners(PUBNUB_CFG_MAX_SUBSCRIBE_LISTENERS);
    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_add_listener(s_ctx, &l));
    assert_int_equal(PUBNUB_LISTENER_HANDLE_INVALID,
                     pubnub_add_listener(s_ctx, &l));
    assert_int_equal(2, s_captured_count);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            listener_global_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_bound_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_set_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_freed_slot_is_reusable_without_log, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_null_binding_does_not_log_limit, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_bound_invalid_binding_full_table_is_silent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            listener_set_invalid_binding_full_table_is_silent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_member_invalid_handle_full_set_is_silent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_create_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_member_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_member_duplicate_at_limit_is_silent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            set_merge_over_member_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            subscription_handle_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            entity_at_limit_logs_one_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            entity_existing_name_at_limit_is_silent, setup, teardown),
        cmocka_unit_test_setup_teardown(
            entity_invalid_name_does_not_log_limit, setup, teardown),
        cmocka_unit_test_setup_teardown(
            limit_hit_silent_when_logger_level_none, setup, teardown),
        cmocka_unit_test_setup_teardown(
            limit_hit_silent_when_level_above_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(
            limit_hit_emitted_when_level_is_warning, setup, teardown),
        cmocka_unit_test_setup_teardown(each_failed_attempt_logs_once, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE == 0 */

static void logging_compiled_out_is_skipped(void** state)
{
    (void)state;
    skip();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(logging_compiled_out_is_skipped),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
