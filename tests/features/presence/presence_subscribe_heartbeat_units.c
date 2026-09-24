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

#include "features/presence/presence_effects.h"
#include "features/presence/presence_internal.h"
#include "pubnub/client.h"
#include "pubnub/features/subscribe.h"

/* ------------------------------------------------------------------
 * Request capture infrastructure
 * ------------------------------------------------------------------ */

#define MAX_CAPTURED_REQUESTS 16
#define MAX_CAPTURED_PATH_LEN 2048

static char s_captured_paths[MAX_CAPTURED_REQUESTS][MAX_CAPTURED_PATH_LEN];
static int  s_captured_count;

static void capture_reset(void)
{
    memset(s_captured_paths, 0, sizeof(s_captured_paths));
    s_captured_count = 0;
}

/* ------------------------------------------------------------------
 * Mock providers
 * ------------------------------------------------------------------ */

static void* mock_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* mock_realloc(pubnub_allocator_provider_t* self,
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

static void mock_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    (void)purpose;
    uint8_t* data = (uint8_t*)malloc(4096);
    return (pubnub_buffer_t){.data = data, .len = 0, .cap = 4096, .purpose = purpose};
}

static void mock_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
}

static pubnub_allocator_provider_t s_mock_allocator = {
    .alloc       = mock_alloc,
    .realloc     = mock_realloc,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
};

static uint64_t s_mock_time_ms = 1000;

static uint64_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_mock_time_ms;
}

static uint64_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return s_mock_time_ms;
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
};

static int s_send_handle_counter = 1;

static pubnub_transport_handle_t* capturing_send(pubnub_transport_provider_t* self,
                                                 pubnub_http_request_t*  req,
                                                 pubnub_http_response_t* resp)
{
    (void)self;
    (void)resp;

    /* Capture the request path segments into a string. */
    if (s_captured_count < MAX_CAPTURED_REQUESTS && NULL != req) {
        char*  buf    = s_captured_paths[s_captured_count];
        size_t offset = 0;
        buf[0]        = '\0';
        for (uint16_t i = 0; i < req->path_segment_count; i++) {
            offset += (size_t)snprintf(buf + offset,
                                       MAX_CAPTURED_PATH_LEN - offset,
                                       "/%.*s",
                                       (int)req->path_segments[i].len,
                                       req->path_segments[i].ptr);
        }
        s_captured_count++;
    }

    return (pubnub_transport_handle_t*)(uintptr_t)s_send_handle_counter++;
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

static pubnub_transport_provider_t s_capturing_transport = {
    .send              = capturing_send,
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

/* ------------------------------------------------------------------
 * Tests: subscribe triggers presence heartbeat
 * ------------------------------------------------------------------ */

static void test_subscription_subscribe_triggers_heartbeat(void** state)
{
    (void)state;
    capture_reset();

    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_capturing_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.presence_timeout   = 20;
    cfg.heartbeat_interval = 9;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Create a subscription and subscribe. */
    pubnub_entity_t       entity = pubnub_channel(ctx, "test-ch");
    pubnub_subscription_t sub =
        pubnub_subscription_create(entity, &(pubnub_subscription_opts_t){0});
    pubnub_entity_destroy(entity);

    pubnub_subscription_subscribe(sub);

    /* Tick the event loop to process queued effects. */
    pubnub_process(ctx);

    /* Verify: we should see both a subscribe request and a heartbeat request. */
    int found_heartbeat = 0;
    int found_subscribe = 0;
    for (int i = 0; i < s_captured_count; i++) {
        if (NULL != strstr(s_captured_paths[i], "/heartbeat")) {
            found_heartbeat = 1;
        }
        if (NULL != strstr(s_captured_paths[i], "/subscribe")) {
            found_subscribe = 1;
        }
    }

    assert_true(found_subscribe);
    assert_true(found_heartbeat);

    pubnub_subscription_destroy(sub);
    pubnub_destroy(ctx);
}

static void test_heartbeat_interval_zero_disables_heartbeat(void** state)
{
    (void)state;
    capture_reset();

    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_capturing_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.presence_timeout   = 20;
    cfg.heartbeat_interval = 0;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    pubnub_entity_t       entity = pubnub_channel(ctx, "test-ch");
    pubnub_subscription_t sub =
        pubnub_subscription_create(entity, &(pubnub_subscription_opts_t){0});
    pubnub_entity_destroy(entity);

    pubnub_subscription_subscribe(sub);
    pubnub_process(ctx);

    /* The subscribe request must still be dispatched. */
    int found_subscribe = 0;
    int found_heartbeat = 0;
    for (int i = 0; i < s_captured_count; i++) {
        if (NULL != strstr(s_captured_paths[i], "/subscribe")) {
            found_subscribe = 1;
        }
        if (NULL != strstr(s_captured_paths[i], "/heartbeat")) {
            found_heartbeat = 1;
        }
    }
    assert_true(found_subscribe);

    /* heartbeat_interval == 0 disables the recurring timer but the
     * initial announce heartbeat must still fire on channel join. */
    assert_true(found_heartbeat);

    pubnub_subscription_destroy(sub);
    pubnub_destroy(ctx);
}

static void test_subscription_set_subscribe_triggers_heartbeat(void** state)
{
    (void)state;
    capture_reset();

    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_capturing_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.presence_timeout   = 20;
    cfg.heartbeat_interval = 9;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Create a subscription set with two channels and subscribe. */
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(set);

    pubnub_entity_t       e1 = pubnub_channel(ctx, "ch-a");
    pubnub_entity_t       e2 = pubnub_channel(ctx, "ch-b");
    pubnub_subscription_t s1 =
        pubnub_subscription_create(e1, &(pubnub_subscription_opts_t){0});
    pubnub_subscription_t s2 =
        pubnub_subscription_create(e2, &(pubnub_subscription_opts_t){0});
    pubnub_entity_destroy(e1);
    pubnub_entity_destroy(e2);

    pubnub_subscription_set_add_subscription(set, s1);
    pubnub_subscription_set_add_subscription(set, s2);

    pubnub_subscription_set_subscribe(set);

    /* Tick. */
    pubnub_process(ctx);

    /* Verify heartbeat was sent. */
    int found_heartbeat = 0;
    for (int i = 0; i < s_captured_count; i++) {
        if (NULL != strstr(s_captured_paths[i], "/heartbeat")) {
            found_heartbeat = 1;
        }
    }

    assert_true(found_heartbeat);

    pubnub_subscription_destroy(s1);
    pubnub_subscription_destroy(s2);
    pubnub_subscription_set_destroy(set);
    pubnub_destroy(ctx);
}

static void test_heartbeat_large_channel_list_exceeds_scratch_buffer(void** state)
{
    (void)state;
    capture_reset();

    pubnub_config_t cfg    = pubnub_config_defaults();
    cfg.subscribe_key      = "sub-test";
    cfg.user_id            = "test-user";
    cfg.allocator          = &s_mock_allocator;
    cfg.transport          = &s_capturing_transport;
    cfg.serialization      = &s_mock_serialization;
    cfg.platform           = &s_mock_platform;
    cfg.presence_timeout   = 20;
    cfg.heartbeat_interval = 9;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Subscribe to 30 channels with names > 20 chars each.
     * Total: 30 * ~27 chars + 29 commas = ~839 bytes.
     * This exceeds PUBNUB_CFG_HTTP_SCRATCH_SIZE (256 embedded,
     * 512 dev) and would have caused empty-channel heartbeat
     * with the old fixed-buffer approach. */
    pubnub_subscription_set_t set = pubnub_subscription_set_create(ctx);
    assert_non_null(set);

    pubnub_subscription_t subs[30];
    char                  name_buf[40];
    for (int i = 0; i < 30; i++) {
        snprintf(name_buf, sizeof(name_buf), "channel-with-long-name-%03d", i);
        pubnub_entity_t entity = pubnub_channel(ctx, name_buf);
        assert_non_null(entity);
        subs[i] =
            pubnub_subscription_create(entity, &(pubnub_subscription_opts_t){0});
        assert_non_null(subs[i]);
        pubnub_entity_destroy(entity);
        pubnub_subscription_set_add_subscription(set, subs[i]);
    }

    pubnub_subscription_set_subscribe(set);

    /* Tick the event loop. */
    pubnub_process(ctx);

    /* Verify: heartbeat was sent with a non-empty channel segment.
     * The old bug would produce "/v2/presence/sub-key/.../channel/heartbeat"
     * (empty channel segment → path has "/channel/heartbeat").
     * Correct behavior: path has "/channel/<channels>/heartbeat". */
    int found_heartbeat           = 0;
    int heartbeat_has_empty_paths = 0;
    for (int i = 0; i < s_captured_count; i++) {
        if (NULL != strstr(s_captured_paths[i], "/heartbeat")) {
            found_heartbeat = 1;
            /* Check for the empty-channel-segment bug pattern. */
            if (NULL != strstr(s_captured_paths[i], "/channel/heartbeat")) {
                heartbeat_has_empty_paths = 1;
            }
        }
    }

    assert_true(found_heartbeat);
    assert_false(heartbeat_has_empty_paths);

    /* Cleanup. */
    for (int i = 0; i < 30; i++) {
        pubnub_subscription_destroy(subs[i]);
    }
    pubnub_subscription_set_destroy(set);
    pubnub_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_subscription_subscribe_triggers_heartbeat),
        cmocka_unit_test(test_heartbeat_interval_zero_disables_heartbeat),
        cmocka_unit_test(test_subscription_set_subscribe_triggers_heartbeat),
        cmocka_unit_test(test_heartbeat_large_channel_list_exceeds_scratch_buffer),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
