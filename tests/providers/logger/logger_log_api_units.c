/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* Smoke tests for the public log-emission and logger-lifecycle API:
 * pubnub_log_text, pubnub_log_object, pubnub_log_error,
 * pubnub_logger_remove_all, pubnub_logger_log_level. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/log.h"

/* Minimal stub providers sufficient to pass pubnub_init validation. */

static uint64_t stub_monotonic_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return 1000u;
}

static uint64_t stub_wall_clock_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return 1000u;
}

static void stub_sleep_ms(struct pubnub_platform_provider* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int stub_random_bytes(struct pubnub_platform_provider* self,
                             uint8_t*                         buf,
                             size_t                           len)
{
    (void)self;
    memset(buf, 0xABu, len);
    return 0;
}

static pubnub_platform_provider_t s_platform;

static void* stub_alloc(struct pubnub_allocator_provider* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* stub_realloc(struct pubnub_allocator_provider* self,
                          void*                             ptr,
                          size_t                            old_size,
                          size_t                            new_size,
                          size_t                            align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return realloc(ptr, new_size);
}

static void stub_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t stub_buf_acquire(struct pubnub_allocator_provider* self,
                                        pubnub_buf_purpose_t purpose)
{
    pubnub_buffer_t buf = {0};
    size_t          cap = 4096u;
    (void)self;
    buf.data    = (uint8_t*)malloc(cap);
    buf.cap     = (NULL != buf.data) ? cap : 0u;
    buf.purpose = purpose;
    return buf;
}

static void stub_buf_release(struct pubnub_allocator_provider* self,
                             pubnub_buffer_t*                  buf)
{
    (void)self;
    free(buf->data);
    buf->data = NULL;
    buf->len  = 0u;
    buf->cap  = 0u;
}

static pubnub_allocator_provider_t s_allocator;

static pubnub_transport_handle_t* stub_send(struct pubnub_transport_provider* self,
                                            pubnub_http_request_t*  req,
                                            pubnub_http_response_t* resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return NULL;
}

static int stub_poll(struct pubnub_transport_provider* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void stub_cancel(struct pubnub_transport_provider* self,
                        pubnub_transport_handle_t*        handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport;

static pubnub_json_value_t* stub_parse(struct pubnub_serialization_provider* self,
                                       const uint8_t* data,
                                       size_t         len)
{
    (void)self;
    (void)data;
    (void)len;
    return NULL;
}

static pubnub_res_t stub_serialize(struct pubnub_serialization_provider* self,
                                   const pubnub_json_value_t*            value,
                                   uint8_t*                              buf,
                                   size_t  buf_len,
                                   size_t* out_len)
{
    (void)self;
    (void)value;
    (void)buf;
    (void)buf_len;
    if (NULL != out_len) {
        *out_len = 0u;
    }
    return PUBNUB_OK;
}

static void stub_value_destroy(struct pubnub_serialization_provider* self,
                               pubnub_json_value_t*                  value)
{
    (void)self;
    (void)value;
}

static pubnub_serialization_provider_t s_serialization;

static int setup_stubs(void** state)
{
    (void)state;
    memset(&s_platform, 0, sizeof(s_platform));
    s_platform.monotonic_ms  = stub_monotonic_ms;
    s_platform.wall_clock_ms = stub_wall_clock_ms;
    s_platform.sleep_ms      = stub_sleep_ms;
    s_platform.random_bytes  = stub_random_bytes;

    memset(&s_allocator, 0, sizeof(s_allocator));
    s_allocator.alloc       = stub_alloc;
    s_allocator.realloc     = stub_realloc;
    s_allocator.free        = stub_free;
    s_allocator.buf_acquire = stub_buf_acquire;
    s_allocator.buf_release = stub_buf_release;

    memset(&s_transport, 0, sizeof(s_transport));
    s_transport.send   = stub_send;
    s_transport.poll   = stub_poll;
    s_transport.cancel = stub_cancel;

    memset(&s_serialization, 0, sizeof(s_serialization));
    s_serialization.parse         = stub_parse;
    s_serialization.serialize     = stub_serialize;
    s_serialization.value_destroy = stub_value_destroy;
    return 0;
}

static pubnub_context_t* make_test_ctx(void)
{
    size_t            sz  = pubnub_context_size();
    pubnub_context_t* ctx = (pubnub_context_t*)calloc(1u, sz);
    pubnub_config_t   cfg = pubnub_config_defaults();
    pubnub_res_t      rc;

    assert_non_null(ctx);
    cfg.subscribe_key = "sub-c-test";
    cfg.user_id       = "test-user";
    cfg.allocator     = &s_allocator;
    cfg.transport     = &s_transport;
    cfg.serialization = &s_serialization;
    cfg.platform      = &s_platform;
    cfg.logger        = NULL;

    rc = pubnub_init(ctx, &cfg);
    assert_int_equal((int)PUBNUB_OK, (int)rc);
    return ctx;
}

static void free_test_ctx(pubnub_context_t* ctx)
{
    pubnub_deinit(ctx);
    free(ctx);
}

static void test_pubnub_log_text_does_not_crash(void** state)
{
    (void)state;
    pubnub_context_t* ctx = make_test_ctx();
    pubnub_log_text(ctx, PUBNUB_LOG_LEVEL_INFO, "hello from user");
    pubnub_log_text(ctx, PUBNUB_LOG_LEVEL_INFO, NULL); /* NULL-safe */
    free_test_ctx(ctx);
}

static void test_pubnub_log_object_does_not_crash(void** state)
{
    (void)state;
    pubnub_context_t*  ctx = make_test_ctx();
    pubnub_log_value_t v   = pubnub_log_value_string("test");
    pubnub_log_value_t e =
        (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY("key", &v, NULL);
    pubnub_log_value_t* map = pubnub_log_value_map_init();
    pubnub_log_value_map_set_entry(&map, &e);
    pubnub_log_object(ctx, PUBNUB_LOG_LEVEL_DEBUG, "test-label", map);
    pubnub_log_object(ctx, PUBNUB_LOG_LEVEL_DEBUG, NULL, NULL);
    free_test_ctx(ctx);
}

static void test_pubnub_log_error_does_not_crash(void** state)
{
    (void)state;
    pubnub_context_t* ctx = make_test_ctx();
    pubnub_log_error(ctx, (int)PUBNUB_ERR_TIMEOUT, "operation timed out", NULL);
    free_test_ctx(ctx);
}

static void test_pubnub_logger_log_level_returns_current(void** state)
{
    (void)state;
    pubnub_context_t*  ctx = make_test_ctx();
    pubnub_log_level_t lvl = pubnub_logger_log_level(ctx);

    /* Default level set during init is INFO. */
    assert_int_equal((int)PUBNUB_LOG_LEVEL_INFO, (int)lvl);

    pubnub_set_log_level(ctx, (unsigned int)PUBNUB_LOG_LEVEL_WARNING);
    assert_int_equal((int)PUBNUB_LOG_LEVEL_WARNING,
                     (int)pubnub_logger_log_level(ctx));
    free_test_ctx(ctx);
}

static void test_pubnub_logger_remove_all(void** state)
{
    (void)state;
    pubnub_context_t* ctx = make_test_ctx();

    /* remove_all must not crash even with no extra loggers registered. */
    pubnub_logger_remove_all(ctx);

    /* log after remove_all must not crash. */
    pubnub_log_text(ctx, PUBNUB_LOG_LEVEL_INFO, "after remove_all");
    free_test_ctx(ctx);
}

static void test_pubnub_logger_log_level_null_returns_none(void** state)
{
    (void)state;
    assert_int_equal((int)PUBNUB_LOG_LEVEL_NONE, (int)pubnub_logger_log_level(NULL));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pubnub_log_text_does_not_crash),
        cmocka_unit_test(test_pubnub_log_object_does_not_crash),
        cmocka_unit_test(test_pubnub_log_error_does_not_crash),
        cmocka_unit_test(test_pubnub_logger_log_level_returns_current),
        cmocka_unit_test(test_pubnub_logger_remove_all),
        cmocka_unit_test(test_pubnub_logger_log_level_null_returns_none),
    };
    return cmocka_run_group_tests(tests, setup_stubs, NULL);
}
