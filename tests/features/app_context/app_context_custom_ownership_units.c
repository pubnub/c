/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

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
#include "pubnub/features/app_context.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "support/test_allocator.h"

/* Every setter must consume (attach or destroy) each caller-provided
 * custom_value tree exactly once on every return path. */

#define MAX_POOL  512
#define MAX_TREES 4
#define MAX_SET   3
#define MAX_SWEEP 64
#define BODY_CAP  1024

enum { KIND_SDK = 1, KIND_TREE = 2, KIND_CALLER = 3 };

typedef struct mock_val {
    int kind;
    int live;
} mock_val_t;

/* Nodes come from a never-reused pool so a stale pointer can not alias a
 * fresh node and hide a double release. */
typedef struct mock_serial {
    pubnub_serialization_provider_t base;
    mock_val_t                      pool[MAX_POOL];
    int                             pool_used;
    int                             live_count;
    int                             consumed_trees;
    int                             destroyed_trees;
    int                             fail_at;
    int                             only_object_set;
    pubnub_res_t                    fail_rc;
    int                             ops;
    int                             fired;
} mock_serial_t;

static mock_serial_t s_mock;

static void mock_untrack(mock_serial_t* m, void* v)
{
    mock_val_t* n = (mock_val_t*)v;

    assert_true(n >= m->pool && n < m->pool + m->pool_used);
    assert_true(n->live);
    n->live = 0;
    --m->live_count;
}

static int mock_is_live(const mock_serial_t* m, const void* v)
{
    (void)m;
    return ((const mock_val_t*)v)->live;
}

static int mock_should_fail(mock_serial_t* m, int is_object_set)
{
    if (m->only_object_set && !is_object_set) {
        return 0;
    }
    if (0 != m->fail_at && ++m->ops == m->fail_at) {
        m->fired = 1;
        return 1;
    }
    return 0;
}

static pubnub_json_value_t* mock_new_kind(mock_serial_t* m, int kind)
{
    mock_val_t* v;

    assert_true(m->pool_used < MAX_POOL);
    v       = &m->pool[m->pool_used++];
    v->kind = kind;
    v->live = 1;
    ++m->live_count;
    return (pubnub_json_value_t*)v;
}

static pubnub_json_value_t* mock_new(mock_serial_t* m)
{
    return mock_new_kind(m, KIND_SDK);
}

static pubnub_json_value_t* mock_create_any(pubnub_serialization_provider_t* self)
{
    mock_serial_t* m = (mock_serial_t*)self;

    if (mock_should_fail(m, 0)) {
        return NULL;
    }
    return mock_new(m);
}

static pubnub_json_value_t* mock_create_string(pubnub_serialization_provider_t* self,
                                               const char* str,
                                               size_t      len)
{
    (void)str;
    (void)len;
    return mock_create_any(self);
}

static pubnub_json_value_t* mock_create_raw(pubnub_serialization_provider_t* self,
                                            const uint8_t* bytes,
                                            size_t         len)
{
    (void)bytes;
    (void)len;
    return mock_create_any(self);
}

static pubnub_res_t mock_attach(pubnub_serialization_provider_t* self,
                                pubnub_json_value_t*             child,
                                int                              is_object_set)
{
    mock_serial_t* m = (mock_serial_t*)self;

    if (mock_should_fail(m, is_object_set)) {
        return m->fail_rc;
    }
    mock_untrack(m, child);
    if (KIND_TREE == ((mock_val_t*)child)->kind) {
        ++m->consumed_trees;
    }
    return PUBNUB_OK;
}

static pubnub_res_t mock_object_set(pubnub_serialization_provider_t* self,
                                    pubnub_json_value_t*             obj,
                                    const char*                      key,
                                    size_t                           key_len,
                                    pubnub_json_value_t*             child)
{
    (void)obj;
    (void)key;
    (void)key_len;
    return mock_attach(self, child, 1);
}

static pubnub_res_t mock_array_append(pubnub_serialization_provider_t* self,
                                      pubnub_json_value_t*             arr,
                                      pubnub_json_value_t*             child)
{
    (void)arr;
    return mock_attach(self, child, 0);
}

static pubnub_res_t mock_serialize(pubnub_serialization_provider_t* self,
                                   const pubnub_json_value_t*       value,
                                   uint8_t*                         buf,
                                   size_t                           buf_len,
                                   size_t*                          out_len)
{
    mock_serial_t* m = (mock_serial_t*)self;

    (void)value;
    if (mock_should_fail(m, 0)) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }
    assert_true(buf_len >= 2);
    buf[0]   = '{';
    buf[1]   = '}';
    *out_len = 2;
    return PUBNUB_OK;
}

static pubnub_json_value_t* mock_parse(pubnub_serialization_provider_t* self,
                                       const uint8_t*                   data,
                                       size_t                           len)
{
    (void)self;
    (void)data;
    (void)len;
    return NULL;
}

static void mock_value_destroy(pubnub_serialization_provider_t* self,
                               pubnub_json_value_t*             value)
{
    mock_serial_t* m = (mock_serial_t*)self;

    mock_untrack(m, value);
    if (KIND_TREE == ((mock_val_t*)value)->kind) {
        ++m->destroyed_trees;
    }
}

static void mock_reset(int has_null)
{
    memset(&s_mock, 0, sizeof(s_mock));
    s_mock.fail_rc                  = PUBNUB_ERR_OUT_OF_MEMORY;
    s_mock.base.parse               = mock_parse;
    s_mock.base.serialize           = mock_serialize;
    s_mock.base.value_destroy       = mock_value_destroy;
    s_mock.base.value_create_object = mock_create_any;
    s_mock.base.value_create_array  = mock_create_any;
    s_mock.base.value_create_string = mock_create_string;
    s_mock.base.value_create_raw    = mock_create_raw;
    s_mock.base.value_create_null   = has_null ? mock_create_any : NULL;
    s_mock.base.object_set          = mock_object_set;
    s_mock.base.array_append        = mock_array_append;
}

/* Allocator wrapper that fails the Nth allocation of any kind. */

static pubnub_allocator_provider_t s_alloc;
static int                         s_alloc_fail_at;
static int                         s_alloc_ops;
static int                         s_alloc_fired;

static int alloc_should_fail(void)
{
    if (0 != s_alloc_fail_at && ++s_alloc_ops == s_alloc_fail_at) {
        s_alloc_fired = 1;
        return 1;
    }
    return 0;
}

static void* fw_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    if (alloc_should_fail()) {
        return NULL;
    }
    return pn_test_allocator()->alloc(pn_test_allocator(), size, align);
}

static void* fw_realloc(pubnub_allocator_provider_t* self,
                        void*                        ptr,
                        size_t                       old_size,
                        size_t                       new_size,
                        size_t                       align)
{
    (void)self;
    if (alloc_should_fail()) {
        return NULL;
    }
    return pn_test_allocator()->realloc(
        pn_test_allocator(), ptr, old_size, new_size, align);
}

static void fw_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    pn_test_allocator()->free(pn_test_allocator(), ptr);
}

static pubnub_buffer_t fw_buf_acquire(pubnub_allocator_provider_t* self,
                                      pubnub_buf_purpose_t         purpose)
{
    pubnub_buffer_t none = {0};

    (void)self;
    if (alloc_should_fail()) {
        return none;
    }
    return pn_test_allocator()->buf_acquire(pn_test_allocator(), purpose);
}

static void fw_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    pn_test_allocator()->buf_release(pn_test_allocator(), buf);
}

static int fw_buf_grow(pubnub_allocator_provider_t* self,
                       pubnub_buffer_t*             buf,
                       size_t                       new_cap)
{
    (void)self;
    if (alloc_should_fail()) {
        return -1;
    }
    return pn_test_allocator()->buf_grow(pn_test_allocator(), buf, new_cap);
}

static void alloc_reset(void)
{
    memset(&s_alloc, 0, sizeof(s_alloc));
    s_alloc.alloc       = fw_alloc;
    s_alloc.realloc     = fw_realloc;
    s_alloc.free        = fw_free;
    s_alloc.buf_acquire = fw_buf_acquire;
    s_alloc.buf_release = fw_buf_release;
    s_alloc.buf_grow    = fw_buf_grow;
    s_alloc_fail_at     = 0;
    s_alloc_ops         = 0;
    s_alloc_fired       = 0;
}

/* Capture transport. */

#define MAX_CAPTURES 4

static int                     s_send_count;
static pubnub_http_request_t*  s_req;
static pubnub_http_response_t* s_resp;
static int                     s_handle_storage[MAX_CAPTURES];

static pubnub_transport_handle_t* cap_send(pubnub_transport_provider_t* self,
                                           pubnub_http_request_t*       request,
                                           pubnub_http_response_t* response)
{
    (void)self;
    if (s_send_count >= MAX_CAPTURES) {
        return NULL;
    }
    s_req  = request;
    s_resp = response;
    return (pubnub_transport_handle_t*)&s_handle_storage[s_send_count++];
}

static int cap_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void cap_cancel(pubnub_transport_provider_t* self,
                       pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send   = cap_send,
    .poll   = cap_poll,
    .cancel = cap_cancel,
};

static pubnub_context_t* ctx_create(int use_mock)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    s_send_count = 0;
    s_req        = NULL;
    s_resp       = NULL;
    alloc_reset();
    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "tester";
    cfg.transport     = &s_transport;
    cfg.allocator     = &s_alloc;
    if (use_mock) {
        cfg.serialization = &s_mock.base;
    }
    return pubnub_create(&cfg);
}

/* API adapters: trees[0..MAX_SET-1] are set-item trees, trees[MAX_SET] is
 * the tree of a remove item (ignored by the SDK, so it stays caller-owned). */

typedef enum {
    FAULT_NONE,
    FAULT_CONFLICT,
    FAULT_BAD_ID,
    FAULT_CLEAR_UNSUPPORTED,
    FAULT_NULL_SET
} fault_t;

typedef pubnub_future_t (*call_fn_t)(pubnub_context_t*     ctx,
                                     pubnub_json_value_t** trees,
                                     fault_t               fault);

typedef struct api_case {
    const char* name;
    call_fn_t   call;
    int         n_set;
    int         n_remove;
} api_case_t;

static pubnub_future_t call_uuid(pubnub_context_t*     ctx,
                                 pubnub_json_value_t** trees,
                                 fault_t               fault)
{
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;

    opts.custom_value = trees[0];
    if (FAULT_CONFLICT == fault) {
        opts.custom = "{}";
    }
    if (FAULT_CLEAR_UNSUPPORTED == fault) {
        opts.name = PUBNUB_CLEAR_VALUE;
    }
    return pubnub_set_uuid_metadata(ctx, &opts);
}

static pubnub_future_t call_channel(pubnub_context_t*     ctx,
                                    pubnub_json_value_t** trees,
                                    fault_t               fault)
{
    pubnub_set_channel_metadata_opts_t opts = PUBNUB_SET_CHANNEL_METADATA_OPTS_INIT;

    opts.channel      = (FAULT_BAD_ID == fault) ? "" : "ch";
    opts.custom_value = trees[0];
    if (FAULT_CONFLICT == fault) {
        opts.custom = "{}";
    }
    if (FAULT_CLEAR_UNSUPPORTED == fault) {
        opts.name = PUBNUB_CLEAR_VALUE;
    }
    return pubnub_set_channel_metadata(ctx, &opts);
}

static pubnub_future_t call_memberships(pubnub_context_t*     ctx,
                                        pubnub_json_value_t** trees,
                                        fault_t               fault)
{
    pubnub_set_memberships_opts_t opts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_membership_input_t     items[MAX_SET];
    pubnub_membership_input_t     rem;
    size_t                        i;

    memset(items, 0, sizeof(items));
    memset(&rem, 0, sizeof(rem));
    for (i = 0; i < MAX_SET; ++i) {
        items[i].channel_id   = "c";
        items[i].custom_value = trees[i];
    }
    rem.channel_id   = "r";
    rem.custom_value = trees[MAX_SET];
    if (FAULT_CONFLICT == fault) {
        items[1].custom = "{}";
    }
    if (FAULT_BAD_ID == fault) {
        items[1].channel_id = NULL;
    }
    if (FAULT_CLEAR_UNSUPPORTED == fault) {
        items[1].status = PUBNUB_CLEAR_VALUE;
    }
    opts.set          = (FAULT_NULL_SET == fault) ? NULL : items;
    opts.set_count    = MAX_SET;
    opts.remove       = &rem;
    opts.remove_count = 1;
    return pubnub_set_memberships(ctx, &opts);
}

static pubnub_future_t call_members(pubnub_context_t*     ctx,
                                    pubnub_json_value_t** trees,
                                    fault_t               fault)
{
    pubnub_set_channel_members_opts_t opts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_member_input_t items[MAX_SET];
    pubnub_member_input_t rem;
    size_t                i;

    memset(items, 0, sizeof(items));
    memset(&rem, 0, sizeof(rem));
    for (i = 0; i < MAX_SET; ++i) {
        items[i].uuid_id      = "u";
        items[i].custom_value = trees[i];
    }
    rem.uuid_id      = "r";
    rem.custom_value = trees[MAX_SET];
    if (FAULT_CONFLICT == fault) {
        items[1].custom = "{}";
    }
    if (FAULT_BAD_ID == fault) {
        items[1].uuid_id = NULL;
    }
    if (FAULT_CLEAR_UNSUPPORTED == fault) {
        items[1].status = PUBNUB_CLEAR_VALUE;
    }
    opts.channel      = "ch";
    opts.set          = (FAULT_NULL_SET == fault) ? NULL : items;
    opts.set_count    = MAX_SET;
    opts.remove       = &rem;
    opts.remove_count = 1;
    return pubnub_set_channel_members(ctx, &opts);
}

static const api_case_t k_apis[] = {
    {"set_uuid_metadata",    call_uuid,        1,       0},
    {"set_channel_metadata", call_channel,     1,       0},
    {"set_memberships",      call_memberships, MAX_SET, 1},
    {"set_channel_members",  call_members,     MAX_SET, 1},
};

#define API_COUNT (sizeof(k_apis) / sizeof(k_apis[0]))

static void make_trees(const api_case_t* api, pubnub_json_value_t** trees)
{
    int i;

    for (i = 0; i < MAX_TREES; ++i) {
        trees[i] = NULL;
    }
    for (i = 0; i < api->n_set; ++i) {
        trees[i] = mock_new_kind(&s_mock, KIND_TREE);
    }
    if (api->n_remove > 0) {
        trees[MAX_SET] = mock_new_kind(&s_mock, KIND_CALLER);
    }
}

static void make_real_trees(pubnub_context_t*     ctx,
                            const api_case_t*     api,
                            pubnub_json_value_t** trees)
{
    pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
    int                              i;

    for (i = 0; i < MAX_TREES; ++i) {
        trees[i] = NULL;
        if (i < api->n_set || (MAX_SET == i && api->n_remove > 0)) {
            trees[i] = serial->value_create_object(serial);
            assert_non_null(trees[i]);
        }
    }
}

/* A remove-entry tree must survive the call untouched; free it as the
 * caller would and require that nothing else is left alive. */
static void release_caller_trees(const api_case_t* api, pubnub_json_value_t** trees)
{
    assert_int_equal(api->n_remove, s_mock.live_count);
    if (api->n_remove > 0) {
        assert_true(mock_is_live(&s_mock, trees[MAX_SET]));
        mock_value_destroy(&s_mock.base, trees[MAX_SET]);
    }
    assert_int_equal(0, s_mock.live_count);
}

static void finish(pubnub_context_t* ctx, pubnub_future_t fut)
{
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
}

/* Rejected argument combinations. */

static void run_fault(const api_case_t* api, fault_t fault, pubnub_res_t expect)
{
    pubnub_json_value_t* trees[MAX_TREES];
    pubnub_context_t*    ctx;
    pubnub_future_t      fut;

    mock_reset(FAULT_CLEAR_UNSUPPORTED != fault);
    ctx = ctx_create(1);
    assert_non_null(ctx);
    make_trees(api, trees);

    fut = api->call(ctx, trees, fault);
    assert_int_equal(expect, pubnub_future_status(fut));
    release_caller_trees(api, trees);
    assert_int_equal(0, s_send_count);
    finish(ctx, fut);
}

static void conflict_destroys_every_tree(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        run_fault(&k_apis[i], FAULT_CONFLICT, PUBNUB_ERR_INVALID_ARGUMENT);
        assert_int_equal(k_apis[i].n_set,
                         s_mock.destroyed_trees + s_mock.consumed_trees);
    }
}

static void invalid_id_destroys_every_tree(void** state)
{
    size_t i;

    (void)state;
    /* set_uuid_metadata has no id argument to invalidate. */
    for (i = 1; i < API_COUNT; ++i) {
        run_fault(&k_apis[i], FAULT_BAD_ID, PUBNUB_ERR_INVALID_ARGUMENT);
        assert_int_equal(k_apis[i].n_set,
                         s_mock.destroyed_trees + s_mock.consumed_trees);
    }
}

static void unsupported_clear_marker_destroys_every_tree(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        run_fault(&k_apis[i], FAULT_CLEAR_UNSUPPORTED, PUBNUB_ERR_NOT_SUPPORTED);
    }
}

static void missing_serialize_destroys_every_tree(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        pubnub_json_value_t* trees[MAX_TREES];
        pubnub_context_t*    ctx;
        pubnub_future_t      fut;

        mock_reset(1);
        ctx = ctx_create(1);
        assert_non_null(ctx);
        make_trees(&k_apis[i], trees);
        s_mock.base.serialize = NULL;

        fut = k_apis[i].call(ctx, trees, FAULT_NONE);
        assert_int_equal(PUBNUB_ERR_PROVIDER_MISSING, pubnub_future_status(fut));
        release_caller_trees(&k_apis[i], trees);
        s_mock.base.serialize = mock_serialize;
        finish(ctx, fut);
    }
}

static void membership_later_item_failure_destroys_each_tree_once(void** state)
{
    size_t i;

    (void)state;
    for (i = 2; i < API_COUNT; ++i) {
        run_fault(&k_apis[i], FAULT_BAD_ID, PUBNUB_ERR_INVALID_ARGUMENT);
        assert_int_equal(k_apis[i].n_set,
                         s_mock.destroyed_trees + s_mock.consumed_trees);
        /* Item 0 was already attached, the rest were never built. */
        assert_int_equal(1, s_mock.consumed_trees);
    }
}

/* Serializer / allocator failure injected at every reachable point. */

static void sweep(const api_case_t* api, int fault_allocator)
{
    int n;
    int exercised = 0;

    for (n = 1; n <= MAX_SWEEP; ++n) {
        pubnub_json_value_t* trees[MAX_TREES];
        pubnub_context_t*    ctx;
        pubnub_future_t      fut;
        int                  fired;

        mock_reset(1);
        ctx = ctx_create(1);
        assert_non_null(ctx);
        make_trees(api, trees);

        if (fault_allocator) {
            s_alloc_fail_at = n;
        } else {
            s_mock.fail_at = n;
        }
        fut             = api->call(ctx, trees, FAULT_NONE);
        fired           = fault_allocator ? s_alloc_fired : s_mock.fired;
        s_alloc_fail_at = 0;
        s_mock.fail_at  = 0;

        if (fired) {
            ++exercised;
            assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));
            assert_int_not_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
        }
        /* Success or failure, no tree may survive the call. */
        release_caller_trees(api, trees);
        finish(ctx, fut);
        if (!fired) {
            break;
        }
    }
    assert_true(exercised >= 3);
    assert_true(n <= MAX_SWEEP);
}

static void serializer_failure_at_every_step_consumes_trees(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        sweep(&k_apis[i], 0);
    }
}

static void allocator_failure_at_every_step_consumes_trees(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        sweep(&k_apis[i], 1);
    }
}

/* Success path. */

static void success_attaches_set_trees_and_leaves_remove_trees(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        pubnub_json_value_t* trees[MAX_TREES];
        pubnub_context_t*    ctx;
        pubnub_future_t      fut;

        mock_reset(1);
        ctx = ctx_create(1);
        assert_non_null(ctx);
        make_trees(&k_apis[i], trees);

        fut = k_apis[i].call(ctx, trees, FAULT_NONE);
        assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
        assert_int_equal(1, s_send_count);
        assert_int_equal(k_apis[i].n_set, s_mock.consumed_trees);
        assert_int_equal(0, s_mock.destroyed_trees);
        release_caller_trees(&k_apis[i], trees);
        finish(ctx, fut);
    }
}

static void success_body_contains_the_custom_tree(void** state)
{
    pubnub_config_t                  cfg  = pubnub_config_defaults();
    pubnub_set_uuid_metadata_opts_t  opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_serialization_provider_t* serial;
    pubnub_json_value_t*             tree;
    pubnub_json_value_t*             val;
    pubnub_context_t*                ctx;
    pubnub_future_t                  fut;
    char                             body[BODY_CAP];

    (void)state;
    s_send_count      = 0;
    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "tester";
    cfg.transport     = &s_transport;
    ctx               = pubnub_create(&cfg);
    assert_non_null(ctx);

    serial = pubnub_serialization(ctx);
    tree   = serial->value_create_object(serial);
    val    = serial->value_create_string(serial, "v", 1);
    assert_non_null(tree);
    assert_non_null(val);
    assert_int_equal(PUBNUB_OK, serial->object_set(serial, tree, "k", 1, val));
    opts.custom_value = tree;

    fut = pubnub_set_uuid_metadata(ctx, &opts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_int_equal(1, s_send_count);
    assert_true(s_req->body_len < sizeof(body));
    memcpy(body, s_req->body, s_req->body_len);
    body[s_req->body_len] = '\0';
    assert_non_null(strstr(body, "\"custom\":{\"k\":\"v\"}"));
    finish(ctx, fut);
}

static void invalid_context_leaves_tree_with_caller(void** state)
{
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;

    (void)state;
    mock_reset(1);
    opts.custom_value = mock_new_kind(&s_mock, KIND_TREE);

    /* No context means no provider to free the tree with. */
    fut = pubnub_set_uuid_metadata(NULL, &opts);
    assert_int_not_equal(PUBNUB_OK, pubnub_future_status(fut));
    assert_true(mock_is_live(&s_mock, opts.custom_value));
    mock_value_destroy(&s_mock.base, opts.custom_value);
    assert_int_equal(0, s_mock.live_count);
}

static void null_set_array_leaves_remove_trees_with_caller(void** state)
{
    size_t i;

    (void)state;
    for (i = 2; i < API_COUNT; ++i) {
        pubnub_json_value_t* trees[MAX_TREES] = {NULL};
        pubnub_context_t*    ctx;
        pubnub_future_t      fut;

        mock_reset(1);
        ctx = ctx_create(1);
        assert_non_null(ctx);
        trees[MAX_SET] = mock_new_kind(&s_mock, KIND_CALLER);

        fut = k_apis[i].call(ctx, trees, FAULT_NULL_SET);
        assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, pubnub_future_status(fut));
        assert_int_equal(0, s_mock.destroyed_trees);
        release_caller_trees(&k_apis[i], trees);
        finish(ctx, fut);
    }
}

static void object_set_not_supported_is_reported_not_masked(void** state)
{
    size_t i;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        int n;

        for (n = 1; n <= MAX_SWEEP; ++n) {
            pubnub_json_value_t* trees[MAX_TREES];
            pubnub_context_t*    ctx;
            pubnub_future_t      fut;
            int                  fired;

            mock_reset(1);
            ctx = ctx_create(1);
            assert_non_null(ctx);
            make_trees(&k_apis[i], trees);
            s_mock.only_object_set = 1;
            s_mock.fail_rc         = PUBNUB_ERR_NOT_SUPPORTED;
            s_mock.fail_at         = n;

            fut   = k_apis[i].call(ctx, trees, FAULT_NONE);
            fired = s_mock.fired;
            if (fired) {
                assert_int_equal(PUBNUB_ERR_NOT_SUPPORTED,
                                 pubnub_future_status(fut));
            }
            release_caller_trees(&k_apis[i], trees);
            finish(ctx, fut);
            if (!fired) {
                break;
            }
        }
        assert_true(n > 1);
    }
}

/* Same scenarios on the real provider, so a double destroy or a leak
 * surfaces under the sanitizer builds. */

static void real_provider_consumes_trees_on_every_outcome(void** state)
{
    static const fault_t k_faults[] = {FAULT_NONE, FAULT_CONFLICT, FAULT_BAD_ID};
    size_t i;
    size_t f;

    (void)state;
    for (i = 0; i < API_COUNT; ++i) {
        for (f = 0; f < sizeof(k_faults) / sizeof(k_faults[0]); ++f) {
            pubnub_json_value_t* trees[MAX_TREES];
            pubnub_context_t*    ctx;
            pubnub_future_t      fut;

            if (0 == i && FAULT_BAD_ID == k_faults[f]) {
                continue;
            }
            ctx = ctx_create(0);
            assert_non_null(ctx);
            make_real_trees(ctx, &k_apis[i], trees);

            fut = k_apis[i].call(ctx, trees, k_faults[f]);
            if (FAULT_NONE == k_faults[f]) {
                assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
            } else {
                assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                                 pubnub_future_status(fut));
            }
            if (NULL != trees[MAX_SET]) {
                pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);

                serial->value_destroy(serial, trees[MAX_SET]);
            }
            finish(ctx, fut);
        }
    }
}

static void removal_entry_uses_only_the_id(void** state)
{
    pubnub_config_t               cfg   = pubnub_config_defaults();
    pubnub_set_memberships_opts_t mopts = PUBNUB_SET_MEMBERSHIPS_OPTS_INIT;
    pubnub_set_channel_members_opts_t copts = PUBNUB_SET_CHANNEL_MEMBERS_OPTS_INIT;
    pubnub_membership_input_t        mrem;
    pubnub_member_input_t            crem;
    pubnub_serialization_provider_t* serial;
    pubnub_json_value_t*             tree;
    pubnub_context_t*                ctx;
    pubnub_future_t                  fut;
    char                             body[BODY_CAP];

    (void)state;
    s_send_count      = 0;
    cfg.subscribe_key = "sub-test";
    cfg.user_id       = "tester";
    cfg.transport     = &s_transport;
    ctx               = pubnub_create(&cfg);
    assert_non_null(ctx);
    serial = pubnub_serialization(ctx);
    tree   = serial->value_create_object(serial);
    assert_non_null(tree);

    memset(&mrem, 0, sizeof(mrem));
    mrem.channel_id    = "r";
    mrem.status        = "s";
    mrem.type          = "t";
    mrem.custom        = "{\"x\":1}";
    mrem.custom_value  = tree;
    mopts.remove       = &mrem;
    mopts.remove_count = 1;

    fut = pubnub_set_memberships(ctx, &mopts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    assert_true(s_req->body_len < sizeof(body));
    memcpy(body, s_req->body, s_req->body_len);
    body[s_req->body_len] = '\0';
    assert_string_equal("{\"delete\":[{\"channel\":{\"id\":\"r\"}}]}", body);
    pubnub_future_release(fut);

    memset(&crem, 0, sizeof(crem));
    crem.uuid_id       = "r";
    crem.status        = "s";
    crem.custom        = "{\"x\":1}";
    crem.custom_value  = tree;
    copts.channel      = "ch";
    copts.remove       = &crem;
    copts.remove_count = 1;

    fut = pubnub_set_channel_members(ctx, &copts);
    assert_int_equal(PUBNUB_IN_PROGRESS, pubnub_future_status(fut));
    memcpy(body, s_req->body, s_req->body_len);
    body[s_req->body_len] = '\0';
    assert_string_equal("{\"delete\":[{\"uuid\":{\"id\":\"r\"}}]}", body);

    /* Still ours after both calls: a second free would be a double free. */
    serial->value_destroy(serial, tree);
    finish(ctx, fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(conflict_destroys_every_tree),
        cmocka_unit_test(invalid_id_destroys_every_tree),
        cmocka_unit_test(unsupported_clear_marker_destroys_every_tree),
        cmocka_unit_test(missing_serialize_destroys_every_tree),
        cmocka_unit_test(membership_later_item_failure_destroys_each_tree_once),
        cmocka_unit_test(serializer_failure_at_every_step_consumes_trees),
        cmocka_unit_test(allocator_failure_at_every_step_consumes_trees),
        cmocka_unit_test(success_attaches_set_trees_and_leaves_remove_trees),
        cmocka_unit_test(success_body_contains_the_custom_tree),
        cmocka_unit_test(invalid_context_leaves_tree_with_caller),
        cmocka_unit_test(null_set_array_leaves_remove_trees_with_caller),
        cmocka_unit_test(object_set_not_supported_is_reported_not_masked),
        cmocka_unit_test(real_provider_consumes_trees_on_every_outcome),
        cmocka_unit_test(removal_entry_uses_only_the_id),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
