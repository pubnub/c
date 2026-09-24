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
#include "pubnub/error.h"
#include "pubnub/features/presence.h"
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#include "pubnub/future.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "features/presence/presence_api_internal.h"

extern pubnub_serialization_provider_t* pn_serialization_default(void);

static void* test_allocator_alloc(pubnub_allocator_provider_t* self,
                                  size_t                       size,
                                  size_t                       align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void test_allocator_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_test_allocator = {
    .alloc       = test_allocator_alloc,
    .realloc     = NULL,
    .free        = test_allocator_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

static void build_set_state_populates_9_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .uuid           = "user-1",
        .state          = "{\"mood\":\"happy\"}",
        .state_len      = 16,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(9, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "presence", 8);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[5].ptr, "ch1", 3);
    assert_memory_equal(request.path_segments[6].ptr, "uuid", 4);
    assert_memory_equal(request.path_segments[7].ptr, "user-1", 6);
    assert_memory_equal(request.path_segments[8].ptr, "data", 4);
}

static void build_set_state_adds_state_query_param(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .uuid           = "user-1",
        .state          = "{\"k\":1}",
        .state_len      = 7,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    /* pn_request_add_query_param URL-encodes the value, so verify
     * that a "state" query param was produced (encoded form). */
    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (request.query_params[i].key.len == 5
            && 0 == memcmp(request.query_params[i].key.ptr, "state", 5)) {
            assert_true(request.query_params[i].value.len > 0);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_set_state_adds_channel_group(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = "grp1",
        .uuid           = "user-1",
        .state          = "{}",
        .state_len      = 2,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            assert_memory_equal(request.query_params[i].value.ptr, "grp1", 4);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_set_state_rejects_null_state(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .uuid           = "user-1",
        .state          = NULL,
        .state_len      = 0,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_set_state_rejects_null_channels(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = NULL,
        .channel_groups = NULL,
        .uuid           = "user-1",
        .state          = "{}",
        .state_len      = 2,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void build_set_state_channel_groups_only_uses_comma_placeholder(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_set_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = ",",
        .channel_groups = "grp1,grp2",
        .uuid           = "user-1",
        .state          = "{}",
        .state_len      = 2,
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_set_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(9, request.path_segment_count);
    assert_memory_equal(request.path_segments[5].ptr, ",", 1);
    assert_int_equal(1, request.path_segments[5].len);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_get_state_populates_8_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_get_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .uuid           = "user-1",
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_get_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(8, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "presence", 8);
    assert_memory_equal(request.path_segments[2].ptr, "sub-key", 7);
    assert_memory_equal(request.path_segments[3].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "channel", 7);
    assert_memory_equal(request.path_segments[5].ptr, "ch1", 3);
    assert_memory_equal(request.path_segments[6].ptr, "uuid", 4);
    assert_memory_equal(request.path_segments[7].ptr, "user-1", 6);
}

static void build_get_state_adds_channel_group(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_get_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = "grp1",
        .uuid           = "user-1",
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_get_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            assert_memory_equal(request.query_params[i].value.ptr, "grp1", 4);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_get_state_channel_groups_only_uses_comma_placeholder(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_get_state_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = ",",
        .channel_groups = "grp1",
        .uuid           = "user-1",
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_get_state(&request, &inputs);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(8, request.path_segment_count);
    assert_memory_equal(request.path_segments[5].ptr, ",", 1);
    assert_int_equal(1, request.path_segments[5].len);

    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            assert_memory_equal(request.query_params[i].value.ptr, "grp1", 4);
            found = 1;
        }
    }
    assert_int_equal(1, found);
}

static void build_get_state_rejects_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_presence_get_state_wire_inputs_t inputs = {
        .subscribe_key  = NULL,
        .channels       = "ch1",
        .channel_groups = NULL,
        .uuid           = "user-1",
        .timeout_ms     = 0,
    };

    pubnub_res_t rc = pn_presence_build_get_state(&request, &inputs);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void parse_state_single_channel_string_payload(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] = "{\"status\":200,\"payload\":\"online\"}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_state_parsed_t out;
    pubnub_res_t               rc =
        pn_presence_parse_state(serial, tree, &s_test_allocator, &out, 1);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.entry_count);
    assert_non_null(out.entries);
    assert_non_null(out.entries[0].state);

    /* State is the "payload" node — for this test it's a string "online". */
    assert_int_equal(PUBNUB_JSON_STRING, serial->value_type(out.entries[0].state));
    size_t      slen = 0;
    const char* sval = serial->value_as_string(out.entries[0].state, &slen);
    assert_non_null(sval);
    assert_int_equal(6, slen);
    assert_memory_equal(sval, "online", 6);

    /* State is borrowed from the tree — no free needed. */
    s_test_allocator.free(&s_test_allocator, out.entries);
    serial->value_destroy(serial, tree);
}

static void parse_state_multi_channel(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char json[] =
        "{\"status\":200,\"payload\":{\"ch1\":\"idle\",\"ch2\":\"active\"}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_presence_state_parsed_t out;
    pubnub_res_t               rc =
        pn_presence_parse_state(serial, tree, &s_test_allocator, &out, 0);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(2, out.entry_count);
    assert_non_null(out.entries);

    /* Verify both entries have non-empty channel and non-NULL state.
     * Object iteration order is implementation-defined so we check
     * both entries have valid data without asserting specific order. */
    for (size_t i = 0; i < out.entry_count; i++) {
        assert_true(out.entries[i].channel.len > 0);
        assert_non_null(out.entries[i].channel.ptr);
        assert_non_null(out.entries[i].state);
    }

    /* State pointers are borrowed from the tree — no per-entry free. */
    s_test_allocator.free(&s_test_allocator, out.entries);
    serial->value_destroy(serial, tree);
}

/* Mock providers for context-level test (set_state with state_value). */

extern pubnub_allocator_provider_t* pn_allocator_default(void);
extern pubnub_platform_provider_t*  pn_platform_default(void);

static char s_state_handle_backing;

static pubnub_transport_handle_t* state_mock_send(pubnub_transport_provider_t* self,
                                                  pubnub_http_request_t* request,
                                                  pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    (void)response;
    return (pubnub_transport_handle_t*)&s_state_handle_backing;
}

static int state_mock_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void state_mock_cancel(pubnub_transport_provider_t* self,
                              pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_state_mock_transport = {
    .send              = state_mock_send,
    .poll              = state_mock_poll,
    .cancel            = state_mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

#if !PUBNUB_CFG_NO_HEAP
static void interval_presence_event_is_parsed_correctly(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-c-key";
    cfg.user_id         = "user-1";
    cfg.allocator       = pn_allocator_default();
    cfg.transport       = &s_state_mock_transport;
    cfg.serialization   = serial;
    cfg.platform        = pn_platform_default();

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    const char json[] = "{\"action\":\"interval\",\"occupancy\":3,"
                        "\"join\":[\"uuid-a\",\"uuid-b\"],"
                        "\"leave\":[\"uuid-c\"],\"timeout\":[],"
                        "\"timestamp\":1234567890}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pubnub_subscribe_event_t ev = {0};
    ev.type                     = PUBNUB_SUBSCRIBE_PRESENCE;
    ev.payload                  = tree;

    pubnub_subscribe_presence_event_t pres = {0};
    pubnub_res_t rc = pubnub_subscribe_event_presence(ctx, &ev, &pres);

    assert_int_equal(PUBNUB_OK, (int)rc);
    assert_int_equal(PUBNUB_PRESENCE_INTERVAL, (int)pres.action);
    assert_int_equal(3, (int)pres.occupancy);
    assert_non_null(pres.joined);
    assert_non_null(pres.left);

    serial->value_destroy(serial, tree);
    pubnub_destroy(ctx);
}

static void set_state_with_value_tree_builds_request(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-c-key";
    cfg.user_id         = "user-1";
    cfg.allocator       = pn_allocator_default();
    cfg.transport       = &s_state_mock_transport;
    cfg.serialization   = serial;
    cfg.platform        = pn_platform_default();

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Build a JSON state object via the serialization provider. */
    pubnub_json_value_t* obj = serial->value_create_object(serial);
    assert_non_null(obj);

    pubnub_json_value_t* val = serial->value_create_string(serial, "happy", 5);
    assert_non_null(val);

    pubnub_res_t set_rc = serial->object_set(serial, obj, "mood", 4, val);
    assert_int_equal(PUBNUB_OK, set_rc);

    /* Call pubnub_set_state with state_value (the code path that was fixed). */
    pubnub_set_state_opts_t opts = PUBNUB_SET_STATE_OPTS_INIT;
    opts.channels                = "ch1";
    opts.state_value             = obj;

    pubnub_future_t fut = pubnub_set_state(ctx, &opts);

    /* The fix ensures serialization does not fail. */
    pubnub_res_t fut_status = pubnub_future_status(fut);
    assert_int_not_equal(PUBNUB_ERR_SERIALIZATION, fut_status);
    assert_int_not_equal(PUBNUB_ERR_PROVIDER_MISSING, fut_status);

    /* Request should have been dispatched (IN_PROGRESS). */
    assert_int_equal(PUBNUB_IN_PROGRESS, fut_status);

    pubnub_future_release(fut);
    serial->value_destroy(serial, obj);
    pubnub_destroy(ctx);
}
#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_set_state_populates_9_segments),
        cmocka_unit_test(build_set_state_adds_state_query_param),
        cmocka_unit_test(build_set_state_adds_channel_group),
        cmocka_unit_test(build_set_state_rejects_null_state),
        cmocka_unit_test(build_set_state_rejects_null_channels),
        cmocka_unit_test(build_set_state_channel_groups_only_uses_comma_placeholder),
        cmocka_unit_test(build_get_state_populates_8_segments),
        cmocka_unit_test(build_get_state_adds_channel_group),
        cmocka_unit_test(build_get_state_channel_groups_only_uses_comma_placeholder),
        cmocka_unit_test(build_get_state_rejects_null_subscribe_key),
        cmocka_unit_test(parse_state_single_channel_string_payload),
        cmocka_unit_test(parse_state_multi_channel),
#if !PUBNUB_CFG_NO_HEAP
        cmocka_unit_test(interval_presence_event_is_parsed_correctly),
        cmocka_unit_test(set_state_with_value_tree_builds_request),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
