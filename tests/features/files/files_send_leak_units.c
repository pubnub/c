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
#include "pubnub/features/files.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"
#include "features/files/files_internal.h"
#include "providers/provider_internal.h"
#include "pubnub/response.h"
#include "support/test_allocator.h"

/* Drives the real send_file state machine (generate-url, upload, publish)
 * over a scripted transport and asserts that every parse tree and every
 * allocator block handed out during a send is returned, on success and on
 * each failure step. */

#define MAX_CAPTURES 4
#define MAX_TREES    64
#define MAX_STEPS    3

typedef struct capture {
    pubnub_http_response_t* response;
} capture_t;

static int       s_send_count;
static capture_t s_captures[MAX_CAPTURES];
static int       s_handles[MAX_CAPTURES];

static pubnub_transport_handle_t* script_send(pubnub_transport_provider_t* self,
                                              pubnub_http_request_t*  request,
                                              pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    if (s_send_count >= MAX_CAPTURES) {
        return NULL;
    }
    s_captures[s_send_count].response = response;
    s_send_count++;
    return (pubnub_transport_handle_t*)&s_handles[s_send_count - 1];
}

static int script_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void script_cancel(pubnub_transport_provider_t* self,
                          pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send   = script_send,
    .poll   = script_poll,
    .cancel = script_cancel,
};

typedef struct tracked_serial {
    pubnub_serialization_provider_t  base;
    pubnub_serialization_provider_t* real;
    pubnub_json_value_t*             live[MAX_TREES];
    int                              live_count;
    pubnub_json_value_t*             dead[MAX_TREES];
    int                              dead_count;
    int                              parsed;
    int                              fail_parse_at;
    int                              parse_calls;
} tracked_serial_t;

static tracked_serial_t s_serial;
static tracked_serial_t s_serial_b;

static int tracked_init(pubnub_serialization_provider_t* self,
                        const pubnub_provider_deps_t*    deps)
{
    tracked_serial_t* t = (tracked_serial_t*)self;

    return t->real->init(t->real, deps);
}

static void tracked_deinit(pubnub_serialization_provider_t* self)
{
    tracked_serial_t* t = (tracked_serial_t*)self;

    t->real->deinit(t->real);
}

static pubnub_json_value_t* tracked_parse(pubnub_serialization_provider_t* self,
                                          const uint8_t*                   data,
                                          size_t                           len)
{
    tracked_serial_t*    t = (tracked_serial_t*)self;
    pubnub_json_value_t* tree;
    int                  i;

    if (0 != t->fail_parse_at && ++t->parse_calls >= t->fail_parse_at) {
        return NULL;
    }
    tree = t->real->parse(t->real, data, len);
    if (NULL != tree) {
        assert_true(t->live_count < MAX_TREES);
        t->live[t->live_count++] = tree;
        for (i = 0; i < t->dead_count; ++i) {
            if (t->dead[i] == tree) {
                t->dead[i] = t->dead[--t->dead_count];
                break;
            }
        }
        t->parsed++;
    }
    return tree;
}

static void tracked_destroy(pubnub_serialization_provider_t* self,
                            pubnub_json_value_t*             tree)
{
    tracked_serial_t* t = (tracked_serial_t*)self;
    int               i;

    for (i = 0; i < t->live_count; ++i) {
        if (t->live[i] == tree) {
            t->live[i] = t->live[--t->live_count];
            if (t->dead_count == MAX_TREES) {
                memmove(&t->dead[0],
                        &t->dead[1],
                        (MAX_TREES - 1) * sizeof(t->dead[0]));
                t->dead_count--;
            }
            t->dead[t->dead_count++] = tree;
            t->real->value_destroy(t->real, tree);
            return;
        }
    }
    /* Trees built by the SDK (not parsed) are destroyed here too; only a
     * second destroy of a parsed tree is a defect. */
    for (i = 0; i < t->dead_count; ++i) {
        if (t->dead[i] == tree) {
            fail_msg("value_destroy on an already destroyed parsed tree");
        }
    }
    t->real->value_destroy(t->real, tree);
}

static int s_alloc_live;

static void* counting_alloc(struct pubnub_allocator_provider* self,
                            size_t                            size,
                            size_t                            align)
{
    void* p = pn_test_allocator()->alloc(self, size, align);

    if (NULL != p) {
        s_alloc_live++;
    }
    return p;
}

static void* counting_realloc(struct pubnub_allocator_provider* self,
                              void*                             ptr,
                              size_t                            old_size,
                              size_t                            new_size,
                              size_t                            align)
{
    void* p = pn_test_allocator()->realloc(self, ptr, old_size, new_size, align);

    if (NULL == ptr && NULL != p) {
        s_alloc_live++;
    } else if (NULL != ptr && 0 == new_size) {
        s_alloc_live--;
    }
    return p;
}

static void counting_free(struct pubnub_allocator_provider* self, void* ptr)
{
    if (NULL != ptr) {
        s_alloc_live--;
    }
    pn_test_allocator()->free(self, ptr);
}

static pubnub_buffer_t counting_buf_acquire(struct pubnub_allocator_provider* self,
                                            pubnub_buf_purpose_t purpose)
{
    pubnub_buffer_t b = pn_test_allocator()->buf_acquire(self, purpose);

    if (NULL != b.data) {
        s_alloc_live++;
    }
    return b;
}

static void counting_buf_release(struct pubnub_allocator_provider* self,
                                 pubnub_buffer_t*                  buf)
{
    if (NULL != buf && NULL != buf->data) {
        s_alloc_live--;
    }
    pn_test_allocator()->buf_release(self, buf);
}

static pubnub_allocator_provider_t s_allocator;

typedef struct step {
    int         status;
    const char* body;
} step_t;

static const char k_generate_ok[] =
    "{\"status\":200,\"data\":{\"id\":\"file-id-1\",\"name\":\"a.txt\"},"
    "\"file_upload_request\":{\"url\":\"https://bucket.s3.amazonaws.com/\","
    "\"method\":\"POST\",\"expiration_date\":\"2030-01-01T00:00:00Z\","
    "\"form_fields\":[{\"key\":\"key\",\"value\":\"abc\"},"
    "{\"key\":\"Policy\",\"value\":\"xyz\"}]}}";
static const char k_generate_plain_http_url[] =
    "{\"status\":200,\"data\":{\"id\":\"file-id-1\",\"name\":\"a.txt\"},"
    "\"file_upload_request\":{\"url\":\"ftp://bucket/\","
    "\"form_fields\":[{\"key\":\"key\",\"value\":\"abc\"}]}}";
static const char k_generate_bad_shape[] = "{\"status\":200,\"data\":{}}";
static const char k_generate_403[] =
    "{\"error\":true,\"status\":403,\"message\":\"Forbidden\"}";
static const char k_s3_403[] =
    "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>";
static const char k_publish_ok[]  = "[1,\"Sent\",\"17000000000000000\"]";
static const char k_publish_500[] = "{\"error\":true,\"status\":500,"
                                    "\"message\":\"boom\"}";

#define TRK_REAL(self) (((tracked_serial_t*)(self))->real)

static int s_reuse_hits;

/* Allocators reuse freed addresses: a tree the SDK builds through the
 * forwarded constructors can land on the address of an earlier destroyed
 * parsed tree, so a constructed address stops being "dead". */
static pubnub_json_value_t* tracked_note(pubnub_serialization_provider_t* self,
                                         pubnub_json_value_t* created)
{
    tracked_serial_t* t = (tracked_serial_t*)self;
    int               i;

    for (i = 0; NULL != created && i < t->dead_count; ++i) {
        if (t->dead[i] == created) {
            t->dead[i] = t->dead[--t->dead_count];
            s_reuse_hits++;
            break;
        }
    }
    return created;
}

/* Stateful providers cast `self` to their own struct, so every entry that
 * takes `self` must be forwarded with the real provider as `self`. */
static pubnub_res_t tracked_serialize(pubnub_serialization_provider_t* self,
                                      const pubnub_json_value_t*       value,
                                      uint8_t*                         buf,
                                      size_t                           buf_len,
                                      size_t*                          out_len)
{
    return TRK_REAL(self)->serialize(TRK_REAL(self), value, buf, buf_len, out_len);
}

static pubnub_json_value_t* tracked_create_object(pubnub_serialization_provider_t* self)
{
    return tracked_note(self, TRK_REAL(self)->value_create_object(TRK_REAL(self)));
}

static pubnub_json_value_t* tracked_create_array(pubnub_serialization_provider_t* self)
{
    return tracked_note(self, TRK_REAL(self)->value_create_array(TRK_REAL(self)));
}

static pubnub_json_value_t* tracked_create_null(pubnub_serialization_provider_t* self)
{
    return tracked_note(self, TRK_REAL(self)->value_create_null(TRK_REAL(self)));
}

static pubnub_json_value_t* tracked_create_bool(pubnub_serialization_provider_t* self,
                                                int truthy)
{
    return tracked_note(
        self, TRK_REAL(self)->value_create_bool(TRK_REAL(self), truthy));
}

static pubnub_json_value_t* tracked_create_int(pubnub_serialization_provider_t* self,
                                               int v)
{
    return tracked_note(self, TRK_REAL(self)->value_create_int(TRK_REAL(self), v));
}

static pubnub_json_value_t* tracked_create_double(pubnub_serialization_provider_t* self,
                                                  double v)
{
    return tracked_note(self,
                        TRK_REAL(self)->value_create_double(TRK_REAL(self), v));
}

static pubnub_json_value_t* tracked_create_string(pubnub_serialization_provider_t* self,
                                                  const char* str,
                                                  size_t      len)
{
    return tracked_note(
        self, TRK_REAL(self)->value_create_string(TRK_REAL(self), str, len));
}

static pubnub_json_value_t*
tracked_create_string_view(pubnub_serialization_provider_t* self,
                           const char*                      str,
                           size_t                           len)
{
    return tracked_note(
        self, TRK_REAL(self)->value_create_string_view(TRK_REAL(self), str, len));
}

static pubnub_json_value_t* tracked_create_raw(pubnub_serialization_provider_t* self,
                                               const uint8_t* bytes,
                                               size_t         len)
{
    return tracked_note(
        self, TRK_REAL(self)->value_create_raw(TRK_REAL(self), bytes, len));
}

static pubnub_res_t tracked_object_set(pubnub_serialization_provider_t* self,
                                       pubnub_json_value_t*             obj,
                                       const char*                      key,
                                       size_t                           key_len,
                                       pubnub_json_value_t*             child)
{
    return TRK_REAL(self)->object_set(TRK_REAL(self), obj, key, key_len, child);
}

static pubnub_res_t tracked_array_append(pubnub_serialization_provider_t* self,
                                         pubnub_json_value_t*             arr,
                                         pubnub_json_value_t*             item)
{
    return TRK_REAL(self)->array_append(TRK_REAL(self), arr, item);
}

static pubnub_res_t tracked_object_remove(pubnub_serialization_provider_t* self,
                                          pubnub_json_value_t*             obj,
                                          const char*                      key,
                                          size_t key_len)
{
    return TRK_REAL(self)->object_remove(TRK_REAL(self), obj, key, key_len);
}

static pubnub_res_t tracked_array_remove(pubnub_serialization_provider_t* self,
                                         pubnub_json_value_t*             arr,
                                         size_t                           index)
{
    return TRK_REAL(self)->array_remove(TRK_REAL(self), arr, index);
}

static pubnub_res_t tracked_object_reserve(pubnub_serialization_provider_t* self,
                                           pubnub_json_value_t* obj,
                                           size_t               n)
{
    return TRK_REAL(self)->object_reserve(TRK_REAL(self), obj, n);
}

static pubnub_res_t tracked_array_reserve(pubnub_serialization_provider_t* self,
                                          pubnub_json_value_t*             arr,
                                          size_t                           n)
{
    return TRK_REAL(self)->array_reserve(TRK_REAL(self), arr, n);
}

static void setup_tracked(tracked_serial_t* t, pubnub_serialization_provider_t* real)
{
    memset(t, 0, sizeof(*t));
    t->base               = *real;
    t->real               = real;
    t->base.parse         = tracked_parse;
    t->base.value_destroy = tracked_destroy;
    if (NULL != real->serialize) {
        t->base.serialize = tracked_serialize;
    }
    if (NULL != real->value_create_object) {
        t->base.value_create_object = tracked_create_object;
    }
    if (NULL != real->value_create_array) {
        t->base.value_create_array = tracked_create_array;
    }
    if (NULL != real->value_create_null) {
        t->base.value_create_null = tracked_create_null;
    }
    if (NULL != real->value_create_bool) {
        t->base.value_create_bool = tracked_create_bool;
    }
    if (NULL != real->value_create_int) {
        t->base.value_create_int = tracked_create_int;
    }
    if (NULL != real->value_create_double) {
        t->base.value_create_double = tracked_create_double;
    }
    if (NULL != real->value_create_string) {
        t->base.value_create_string = tracked_create_string;
    }
    if (NULL != real->value_create_string_view) {
        t->base.value_create_string_view = tracked_create_string_view;
    }
    if (NULL != real->value_create_raw) {
        t->base.value_create_raw = tracked_create_raw;
    }
    if (NULL != real->object_set) {
        t->base.object_set = tracked_object_set;
    }
    if (NULL != real->array_append) {
        t->base.array_append = tracked_array_append;
    }
    if (NULL != real->object_remove) {
        t->base.object_remove = tracked_object_remove;
    }
    if (NULL != real->array_remove) {
        t->base.array_remove = tracked_array_remove;
    }
    if (NULL != real->object_reserve) {
        t->base.object_reserve = tracked_object_reserve;
    }
    if (NULL != real->array_reserve) {
        t->base.array_reserve = tracked_array_reserve;
    }
    if (NULL != real->init) {
        t->base.init = tracked_init;
    }
    if (NULL != real->deinit) {
        t->base.deinit = tracked_deinit;
    }
}

static int group_setup(void** state)
{
    pubnub_serialization_provider_t* real = pn_serialization_default();

    (void)state;
    if (NULL == real) {
        print_error("no default serialization provider\n");
        return -1;
    }
    setup_tracked(&s_serial, real);
    setup_tracked(&s_serial_b, real);

    s_allocator             = *pn_test_allocator();
    s_allocator.alloc       = counting_alloc;
    s_allocator.realloc     = counting_realloc;
    s_allocator.free        = counting_free;
    s_allocator.buf_acquire = counting_buf_acquire;
    s_allocator.buf_release = counting_buf_release;
    return 0;
}

typedef void (*before_step_fn)(pubnub_context_t* ctx, int step);
typedef void (*before_release_fn)(pubnub_future_t fut);

static before_step_fn    s_before_step;
static before_release_fn s_before_release;

static pubnub_context_t* make_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    cfg.subscribe_key = "sub-test";
    cfg.publish_key   = "pub-test";
    cfg.user_id       = "tester";
    cfg.transport     = &s_transport;
    cfg.serialization = &s_serial.base;
    cfg.allocator     = &s_allocator;

    s_serial.live_count    = 0;
    s_serial.dead_count    = 0;
    s_serial.parsed        = 0;
    s_serial.fail_parse_at = 0;
    s_serial.parse_calls   = 0;
    s_serial_b.live_count  = 0;
    s_serial_b.dead_count  = 0;
    s_serial_b.parsed      = 0;
    s_alloc_live           = 0;
    s_before_step          = NULL;
    s_before_release       = NULL;
    return pubnub_create(&cfg);
}

/* Returns the final future status; releases the future. */
static pubnub_res_t run_send(pubnub_context_t* ctx,
                             const step_t*     steps,
                             int               nsteps,
                             char (*timetoken)[32])
{
    static const uint8_t    data[] = "hello world";
    pubnub_send_file_opts_t opts   = PUBNUB_SEND_FILE_OPTS_INIT;
    pubnub_future_t         fut;
    pubnub_res_t            rc;
    int                     i;

    opts.channel   = "my-channel";
    opts.file_name = "a.txt";
    opts.data      = data;
    opts.data_len  = sizeof(data) - 1;

    s_send_count = 0;
    memset(s_captures, 0, sizeof(s_captures));

    fut = pubnub_send_file(ctx, &opts);
    for (i = 0; i < nsteps; ++i) {
        pubnub_http_response_t* resp;

        assert_true(s_send_count > i);
        if (NULL != s_before_step) {
            s_before_step(ctx, i);
        }
        resp = s_captures[i].response;
        assert_non_null(resp);
        resp->body        = (const uint8_t*)steps[i].body;
        resp->body_len    = (NULL != steps[i].body) ? strlen(steps[i].body) : 0;
        resp->status_code = steps[i].status;
        resp->completion  = PUBNUB_HTTP_COMPLETE;
        (void)pubnub_process(ctx);
    }
    assert_true(pubnub_future_is_ready(fut));
    rc = pubnub_future_status(fut);
    if (NULL != s_before_release) {
        s_before_release(fut);
    }
    if (NULL != timetoken) {
        pubnub_timetoken_t tt = pubnub_send_file_result(fut).timetoken;

        memset(*timetoken, 0, sizeof(*timetoken));
        if (NULL != tt.ptr && tt.len < sizeof(*timetoken)) {
            memcpy(*timetoken, tt.ptr, tt.len);
        }
    }
    pubnub_future_release(fut);
    return rc;
}

static void assert_balanced(int baseline_allocs)
{
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_serial_b.live_count);
    assert_int_equal(baseline_allocs, s_alloc_live);
}

static void send_success_repeated_leaves_nothing_live(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;

    for (i = 0; i < 8; ++i) {
        const step_t steps[MAX_STEPS] = {
            {200, k_generate_ok},
            {204, NULL         },
            {200, k_publish_ok }
        };
        char tt[32] = {0};

        assert_int_equal(PUBNUB_OK, run_send(ctx, steps, MAX_STEPS, &tt));
        assert_string_equal("17000000000000000", tt);
        assert_balanced(baseline);
        /* One parse for generate-url plus one for publish. */
        assert_int_equal(2 * (i + 1), s_serial.parsed);
    }

    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_generate_server_error(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 5; ++i) {
        const step_t steps[1] = {
            {403, k_generate_403}
        };

        assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, 1, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_generate_bad_shape(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 5; ++i) {
        const step_t steps[1] = {
            {200, k_generate_bad_shape}
        };

        assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, 1, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_generate_parse_failure(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;

    /* Nothing parses: shared cache is empty, the fallback parse fails too. */
    s_serial.fail_parse_at = 1;
    s_serial.parse_calls   = 0;
    {
        const step_t steps[1] = {
            {200, k_generate_ok}
        };

        assert_int_equal(PUBNUB_ERR_SERIALIZATION, run_send(ctx, steps, 1, NULL));
    }
    assert_balanced(baseline);

    /* Shared parse succeeds, the tree variant rejects the shape. */
    s_serial.fail_parse_at = 0;
    s_serial.parsed        = 0;
    {
        const step_t steps[1] = {
            {200, k_generate_bad_shape}
        };

        assert_int_equal(PUBNUB_ERR_SERIALIZATION, run_send(ctx, steps, 1, NULL));
    }
    assert_int_equal(1, s_serial.parsed);
    assert_balanced(baseline);

    pubnub_destroy(ctx);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_invalid_upload_url(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 3; ++i) {
        const step_t steps[1] = {
            {200, k_generate_plain_http_url}
        };

        assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, 1, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_s3_rejection(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 5; ++i) {
        const step_t steps[2] = {
            {200, k_generate_ok},
            {403, k_s3_403     }
        };

        assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, 2, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void send_fails_on_publish_rejection(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 5; ++i) {
        const step_t steps[MAX_STEPS] = {
            {200, k_generate_ok},
            {204, NULL         },
            {500, k_publish_500}
        };

        assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, MAX_STEPS, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static void mixed_failures_then_success_stay_balanced(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    int               i;

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;
    for (i = 0; i < 3; ++i) {
        const step_t ok[MAX_STEPS] = {
            {200, k_generate_ok},
            {204, NULL         },
            {200, k_publish_ok }
        };
        const step_t bad[MAX_STEPS] = {
            {200, k_generate_ok},
            {204, NULL         },
            {500, k_publish_500}
        };

        assert_int_equal(PUBNUB_OK, run_send(ctx, ok, MAX_STEPS, NULL));
        assert_balanced(baseline);
        assert_int_not_equal(PUBNUB_OK, run_send(ctx, bad, MAX_STEPS, NULL));
        assert_balanced(baseline);
    }
    pubnub_destroy(ctx);
    assert_int_equal(0, s_serial.live_count);
    assert_int_equal(0, s_alloc_live);
}

static const char k_generate_bad_url_with_message[] =
    "{\"status\":200,\"message\":\"envelope-note\","
    "\"data\":{\"id\":\"file-id-1\",\"name\":\"a.txt\"},"
    "\"file_upload_request\":{\"url\":\"ftp://bucket/\","
    "\"form_fields\":[{\"key\":\"key\",\"value\":\"abc\"}]}}";

static int  s_env_checked;
static int  s_env_len;
static char s_env_text[64];

static void capture_envelope(pubnub_future_t fut)
{
    pubnub_string_view_t msg = pubnub_response_error_message(fut);

    (void)pubnub_response_status_code(fut);
    s_env_checked = 1;
    s_env_len     = (int)msg.len;
    memset(s_env_text, 0, sizeof(s_env_text));
    if (NULL != msg.ptr && msg.len < sizeof(s_env_text)) {
        memcpy(s_env_text, msg.ptr, msg.len);
    }
}

static void failure_after_shared_parse_keeps_error_envelope(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    const step_t      steps[1] = {
        {200, k_generate_bad_url_with_message}
    };

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline         = s_alloc_live;
    s_env_checked    = 0;
    s_before_release = capture_envelope;

    assert_int_not_equal(PUBNUB_OK, run_send(ctx, steps, 1, NULL));
    assert_true(s_env_checked);
    /* The slot tree must still be alive and readable after the failure. */
    assert_int_equal(1, s_serial.parsed);
    assert_string_equal("envelope-note", s_env_text);
    assert_balanced(baseline);

    pubnub_destroy(ctx);
    assert_int_equal(0, s_alloc_live);
}

static void swap_state_serializer(pubnub_context_t* ctx, int step)
{
    pn_request_pool_t* pool = pn_context_request_pool(ctx);
    uint16_t           i;

    if (1 == step) {
        for (i = 0; i < pool->capacity; ++i) {
            pn_request_t* slot = &pool->slots[i];

            if (PN_REQUEST_IN_FLIGHT == slot->state && NULL != slot->feature_state) {
                ((pn_file_send_state_t*)slot->feature_state)->serialization =
                    &s_serial.base;
            }
        }
        return;
    }
    if (0 != step) {
        return;
    }
    for (i = 0; i < pool->capacity; ++i) {
        pn_request_t* slot = &pool->slots[i];

        if (PN_REQUEST_IN_FLIGHT == slot->state && NULL != slot->feature_state) {
            ((pn_file_send_state_t*)slot->feature_state)->serialization =
                &s_serial_b.base;
            return;
        }
    }
    fail_msg("no in-flight send_file slot found");
}

static void owner_mismatch_falls_back_to_private_parse(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    const step_t      steps[MAX_STEPS] = {
        {200, k_generate_ok},
        {204, NULL         },
        {200, k_publish_ok }
    };

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;

    s_before_step = swap_state_serializer;
    assert_int_equal(PUBNUB_OK, run_send(ctx, steps, MAX_STEPS, NULL));
    /* The context provider parsed the cached generate and publish trees;
     * B only parsed the private fallback copy for the generate step. */
    assert_int_equal(2, s_serial.parsed);
    assert_int_equal(1, s_serial_b.parsed);
    assert_balanced(baseline);

    pubnub_destroy(ctx);
    assert_int_equal(0, s_alloc_live);
}

static void generate_empty_body_keeps_invalid_argument(void** state)
{
    pubnub_context_t* ctx;
    int               baseline;
    const step_t      steps[1] = {
        {200, NULL}
    };

    (void)state;
    ctx = make_ctx();
    assert_non_null(ctx);
    baseline = s_alloc_live;

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, run_send(ctx, steps, 1, NULL));
    assert_balanced(baseline);

    pubnub_destroy(ctx);
    assert_int_equal(0, s_alloc_live);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(send_success_repeated_leaves_nothing_live),
        cmocka_unit_test(send_fails_on_generate_server_error),
        cmocka_unit_test(send_fails_on_generate_bad_shape),
        cmocka_unit_test(send_fails_on_generate_parse_failure),
        cmocka_unit_test(send_fails_on_invalid_upload_url),
        cmocka_unit_test(send_fails_on_s3_rejection),
        cmocka_unit_test(send_fails_on_publish_rejection),
        cmocka_unit_test(mixed_failures_then_success_stay_balanced),
        cmocka_unit_test(failure_after_shared_parse_keeps_error_envelope),
        cmocka_unit_test(owner_mismatch_falls_back_to_private_parse),
        cmocka_unit_test(generate_empty_body_keeps_invalid_argument),
    };

    return cmocka_run_group_tests(tests, group_setup, NULL);
}
