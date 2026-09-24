/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file history_parse_units.c
 * @brief Unit tests for history response parsers.
 *
 * Tests exercise pn_history_parse_fetch and pn_history_parse_counts
 * with real JSON responses processed through the default
 * serialization provider. A malloc/free-backed allocator provides
 * the allocation semantics the parsers require.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/history.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"

#include "features/history/history_internal.h"

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

static pubnub_allocator_provider_t s_alloc = {
    .alloc       = test_allocator_alloc,
    .realloc     = NULL,
    .free        = test_allocator_free,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

static void parse_fetch_multi_channel_response(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] =
        "{"
        "\"status\":200,"
        "\"channels\":{"
        "\"ch1\":["
        "{\"message\":\"hello\",\"timetoken\":\"17001000000000001\"},"
        "{\"message\":\"world\",\"timetoken\":\"17001000000000002\"},"
        "{\"message\":\"!\",\"timetoken\":\"17001000000000003\"}"
        "],"
        "\"ch2\":["
        "{\"message\":\"a\",\"timetoken\":\"17001000000000010\"},"
        "{\"message\":\"b\",\"timetoken\":\"17001000000000020\"},"
        "{\"message\":\"c\",\"timetoken\":\"17001000000000030\"}"
        "]"
        "}"
        "}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 2);
    assert_non_null(out.channel_entries);

    /* Each channel has 3 messages. */
    assert_int_equal(out.channel_entries[0].message_count, 3);
    assert_int_equal(out.channel_entries[1].message_count, 3);

    /* Channel names are present. */
    assert_true(0 != out.channel_entries[0].name.len);
    assert_true(0 != out.channel_entries[1].name.len);

    /* Cleanup. */
    s_alloc.free(&s_alloc, out.channel_entries);
    serial->value_destroy(serial, tree);
}

static void parse_fetch_empty_channels_returns_zero(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] = "{\"status\":200,\"channels\":{}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 0);
    assert_null(out.channel_entries);

    serial->value_destroy(serial, tree);
}

static void parse_fetch_missing_channels_key_returns_zero(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] = "{\"status\":200}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 0);
    assert_null(out.channel_entries);

    serial->value_destroy(serial, tree);
}

static void parse_fetch_rejects_null_args(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pn_history_fetch_parsed_t        out;
    memset(&out, 0, sizeof(out));

    /* Minimal valid tree for non-null tree arg. */
    const char           json[] = "{}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);

    assert_int_equal(pn_history_parse_fetch(NULL, tree, &s_alloc, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_fetch(serial, NULL, &s_alloc, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_fetch(serial, tree, NULL, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_fetch(serial, tree, &s_alloc, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void parse_counts_valid_response(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] = "{"
                        "\"status\":200,"
                        "\"channels\":{"
                        "\"ch1\":5,"
                        "\"ch2\":12,"
                        "\"ch3\":0"
                        "}"
                        "}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_counts_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_counts(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 3);
    assert_non_null(out.channel_entries);

    /* Verify counts are extracted. Sum should be 5+12+0=17. */
    uint32_t total = 0;
    for (uint32_t i = 0; i < out.channel_count; ++i) {
        total += out.channel_entries[i].count;
    }
    assert_int_equal(total, 17);

    s_alloc.free(&s_alloc, out.channel_entries);
    serial->value_destroy(serial, tree);
}

static void parse_counts_empty_channels_returns_zero(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] = "{\"status\":200,\"channels\":{}}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_counts_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_counts(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 0);
    assert_null(out.channel_entries);

    serial->value_destroy(serial, tree);
}

static void parse_counts_rejects_null_args(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pn_history_counts_parsed_t       out;
    memset(&out, 0, sizeof(out));

    const char           json[] = "{}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);

    assert_int_equal(pn_history_parse_counts(NULL, tree, &s_alloc, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_counts(serial, NULL, &s_alloc, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_counts(serial, tree, NULL, &out),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_history_parse_counts(serial, tree, &s_alloc, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    serial->value_destroy(serial, tree);
}

static void parse_counts_rejects_non_object_root(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char           json[] = "[1,2,3]";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_counts_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_counts(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_fetch_rejects_non_object_root(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char           json[] = "[1,2,3]";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_fetch_cursor_present_when_more_object_exists(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] =
        "{"
        "\"status\":200,"
        "\"channels\":{"
        "\"ch1\":["
        "{\"message\":\"A\",\"timetoken\":\"17001000000000001\"},"
        "{\"message\":\"B\",\"timetoken\":\"17001000000000002\"},"
        "{\"message\":\"C\",\"timetoken\":\"17001000000000003\"}"
        "]"
        "},"
        "\"more\":{"
        "\"url\":\"/v3/history/...\","
        "\"start\":\"17001000000000001\","
        "\"end\":\"17000000000000000\","
        "\"limit\":25"
        "}"
        "}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 1);
    assert_true(0 < out.next_cursor.len);
    assert_non_null(out.next_cursor.ptr);
    assert_memory_equal(
        out.next_cursor.ptr, "17001000000000001", out.next_cursor.len);

    s_alloc.free(&s_alloc, out.channel_entries);
    serial->value_destroy(serial, tree);
}

static void parse_fetch_no_cursor_when_more_absent(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char json[] =
        "{"
        "\"status\":200,"
        "\"channels\":{"
        "\"ch1\":["
        "{\"message\":\"A\",\"timetoken\":\"17001000000000001\"}"
        "]"
        "}"
        "}";

    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, sizeof(json) - 1);
    assert_non_null(tree);

    pn_history_fetch_parsed_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_history_parse_fetch(serial, tree, &s_alloc, &out);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(out.channel_count, 1);
    assert_int_equal(0, (int)out.next_cursor.len);

    s_alloc.free(&s_alloc, out.channel_entries);
    serial->value_destroy(serial, tree);
}

static void fetch_message_result_has_crypto_result_field(void** state)
{
    (void)state;
    /* Compile-time: crypto_result is unconditionally present (no #if guard). */
    pubnub_history_message_result_t r = {0};
    assert_int_equal(PUBNUB_OK, (int)r.crypto_result);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_fetch_multi_channel_response),
        cmocka_unit_test(parse_fetch_empty_channels_returns_zero),
        cmocka_unit_test(parse_fetch_missing_channels_key_returns_zero),
        cmocka_unit_test(parse_fetch_rejects_null_args),
        cmocka_unit_test(parse_fetch_rejects_non_object_root),
        cmocka_unit_test(parse_fetch_cursor_present_when_more_object_exists),
        cmocka_unit_test(parse_fetch_no_cursor_when_more_absent),
        cmocka_unit_test(parse_counts_valid_response),
        cmocka_unit_test(parse_counts_empty_channels_returns_zero),
        cmocka_unit_test(parse_counts_rejects_null_args),
        cmocka_unit_test(parse_counts_rejects_non_object_root),
        cmocka_unit_test(fetch_message_result_has_crypto_result_field),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
