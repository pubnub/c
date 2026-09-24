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

#include "pubnub/features/app_context.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

#include "features/app_context/app_context_internal.h"

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

static void include_param_zero_mask_adds_nothing(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_include_param(&req, 0);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void include_param_single_custom_flag(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc =
        pn_app_context_add_include_param(&req, PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "include", 7);
    assert_memory_equal(req.query_params[0].value.ptr, "custom", 6);
    assert_int_equal(req.query_params[0].value.len, 6);
}

static void include_param_multiple_flags_comma_separated(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    uint32_t mask = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                  | PUBNUB_APP_CONTEXT_INCLUDE_TYPE
                  | PUBNUB_APP_CONTEXT_INCLUDE_STATUS;
    pubnub_res_t rc = pn_app_context_add_include_param(&req, mask);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    /* Tokens should be "custom,type,status" in table order. */
    const char* val = req.query_params[0].value.ptr;
    assert_non_null(strstr(val, "custom"));
    assert_non_null(strstr(val, "type"));
    assert_non_null(strstr(val, "status"));
    /* Verify commas present. */
    assert_non_null(strchr(val, ','));
}

static void include_param_total_count_excluded_from_include_string(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    /* Only TOTAL_COUNT set — should produce no include param. */
    pubnub_res_t rc = pn_app_context_add_include_param(
        &req, PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void include_param_total_count_with_other_flags(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    uint32_t mask = PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM
                  | PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT;
    pubnub_res_t rc = pn_app_context_add_include_param(&req, mask);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    /* "custom" only, no "totalCount" token. */
    assert_memory_equal(req.query_params[0].value.ptr, "custom", 6);
    assert_int_equal(req.query_params[0].value.len, 6);
}

static void include_param_uuid_nested_tokens(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    uint32_t mask =
        PUBNUB_APP_CONTEXT_INCLUDE_UUID | PUBNUB_APP_CONTEXT_INCLUDE_UUID_CUSTOM;
    pubnub_res_t rc = pn_app_context_add_include_param(&req, mask);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    const char* val = req.query_params[0].value.ptr;
    assert_non_null(strstr(val, "uuid,"));
    assert_non_null(strstr(val, "uuid.custom"));
}

static void count_param_adds_true_when_total_count_set(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_count_param(
        &req, PUBNUB_APP_CONTEXT_INCLUDE_TOTAL_COUNT);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "count", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "true", 4);
}

static void count_param_skipped_when_not_set(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc =
        pn_app_context_add_count_param(&req, PUBNUB_APP_CONTEXT_INCLUDE_CUSTOM);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void pagination_all_defaults_adds_nothing(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 0, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void pagination_limit_only(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 50, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "limit", 5);
    /* Value should be "50". */
    assert_memory_equal(req.query_params[0].value.ptr, "50", 2);
    assert_int_equal(req.query_params[0].value.len, 2);
}

static void pagination_limit_100_not_clamped(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 100, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "limit", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "100", 3);
    assert_int_equal(req.query_params[0].value.len, 3);
}

static void pagination_limit_one(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 1, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "limit", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "1", 1);
    assert_int_equal(req.query_params[0].value.len, 1);
}

static void pagination_limit_zero_omits_param(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    /* limit == 0 means "unset" -> no limit query param is added. */
    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 0, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void pagination_limit_101_passed_through_unclamped(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    /* NOTE: The wire layer deliberately does NOT clamp or reject a
     * limit above 100 -- it forwards the caller's requested value
     * verbatim and lets the server enforce its own maximum. A
     * previous regression clamped App Context limits client-side; the
     * correct behavior is passthrough. This asserts the value reaches
     * the query string exactly as "101". */
    pubnub_res_t rc = pn_app_context_add_pagination_params(&req, 101, NULL, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "limit", 5);
    assert_memory_equal(req.query_params[0].value.ptr, "101", 3);
    assert_int_equal(req.query_params[0].value.len, 3);
}

static void pagination_start_cursor(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc =
        pn_app_context_add_pagination_params(&req, 0, "cursor123", NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "start", 5);
}

static void pagination_all_params(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc =
        pn_app_context_add_pagination_params(&req, 25, "next_cur", "prev_cur");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 3);
}

static void filter_param_null_adds_nothing(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_filter_param(&req, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void filter_param_adds_expression(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_filter_param(&req, "name == 'test'");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "filter", 6);
}

static void sort_param_null_adds_nothing(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_sort_param(&req, NULL);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 0);
}

static void sort_param_adds_expression(void** state)
{
    (void)state;
    pubnub_http_request_t req = make_request();

    pubnub_res_t rc = pn_app_context_add_sort_param(&req, "name:asc,updated:desc");

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(req.query_param_count, 1);
    assert_memory_equal(req.query_params[0].key.ptr, "sort", 4);
}

static void validator_accepts_200_json(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":200}";

    pubnub_res_t rc =
        pn_app_context_response_validator(body, sizeof(body) - 1, 200);

    assert_int_equal(rc, PUBNUB_OK);
}

static void validator_rejects_403(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":true}";

    pubnub_res_t rc =
        pn_app_context_response_validator(body, sizeof(body) - 1, 403);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void validator_rejects_non_json_body(void** state)
{
    (void)state;
    const uint8_t body[] = "Not JSON at all";

    pubnub_res_t rc =
        pn_app_context_response_validator(body, sizeof(body) - 1, 200);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void validator_rejects_empty_body(void** state)
{
    (void)state;
    pubnub_res_t rc = pn_app_context_response_validator(NULL, 0, 200);

    assert_int_equal(rc, PUBNUB_ERR_SERVER);
}

static void parse_page_extracts_list_envelope(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char* json =
        "{\"status\":200,\"data\":[{\"id\":\"a\"},{\"id\":\"b\"}],"
        "\"totalCount\":42,\"next\":\"cursor_next\","
        "\"prev\":\"cursor_prev\"}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_app_context_page_t page = {0};
    pubnub_res_t rc = pn_app_context_parse_page(serial, tree, &page);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(page.count, 2);
    assert_int_equal(page.total_count, 42);
    assert_non_null(page.next.ptr);
    assert_int_equal(page.next.len, 11);
    assert_memory_equal(page.next.ptr, "cursor_next", 11);
    assert_non_null(page.prev.ptr);
    assert_int_equal(page.prev.len, 11);
    assert_memory_equal(page.prev.ptr, "cursor_prev", 11);

    serial->value_destroy(serial, tree);
}

static void parse_page_handles_minimal_envelope(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* No totalCount, next, or prev. */
    const char*          json = "{\"status\":200,\"data\":[{\"id\":\"x\"}]}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_app_context_page_t page = {0};
    pubnub_res_t rc = pn_app_context_parse_page(serial, tree, &page);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(page.count, 1);
    assert_int_equal(page.total_count, 0);
    assert_null(page.next.ptr);
    assert_null(page.prev.ptr);

    serial->value_destroy(serial, tree);
}

static void get_data_array_returns_array_node(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"data\":[1,2,3]}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_json_value_t* arr = pn_app_context_get_data_array(serial, tree);
    assert_non_null(arr);
    assert_int_equal(serial->value_type(arr), PUBNUB_JSON_ARRAY);
    assert_int_equal(serial->array_size(arr), 3);

    serial->value_destroy(serial, tree);
}

static void get_data_array_returns_null_when_missing(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"status\":200}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_json_value_t* arr = pn_app_context_get_data_array(serial, tree);
    assert_null(arr);

    serial->value_destroy(serial, tree);
}

static void get_data_array_returns_null_when_not_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"data\":{\"id\":\"x\"}}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_json_value_t* arr = pn_app_context_get_data_array(serial, tree);
    assert_null(arr);

    serial->value_destroy(serial, tree);
}

static void get_data_object_returns_object_node(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"data\":{\"id\":\"uuid-1\"}}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_json_value_t* obj = pn_app_context_get_data_object(serial, tree);
    assert_non_null(obj);
    assert_int_equal(serial->value_type(obj), PUBNUB_JSON_OBJECT);

    serial->value_destroy(serial, tree);
}

static void get_data_object_returns_null_when_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char*          json = "{\"data\":[1,2]}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));
    assert_non_null(tree);

    pubnub_json_value_t* obj = pn_app_context_get_data_object(serial, tree);
    assert_null(obj);

    serial->value_destroy(serial, tree);
}

static void cleanup_handles_null_state(void** state)
{
    (void)state;
    /* Must not crash. */
    pn_app_context_feature_state_cleanup(NULL, &s_test_allocator);
}

static void cleanup_frees_encoded_path(void** state)
{
    (void)state;
    pn_app_context_state_t* s =
        (pn_app_context_state_t*)malloc(sizeof(pn_app_context_state_t));
    memset(s, 0, sizeof(*s));
    s->encoded_path_segment = (char*)malloc(16);
    memcpy(s->encoded_path_segment, "test-uuid", 10);

    /* Should not leak. */
    pn_app_context_feature_state_cleanup(s, &s_test_allocator);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(include_param_zero_mask_adds_nothing),
        cmocka_unit_test(include_param_single_custom_flag),
        cmocka_unit_test(include_param_multiple_flags_comma_separated),
        cmocka_unit_test(include_param_total_count_excluded_from_include_string),
        cmocka_unit_test(include_param_total_count_with_other_flags),
        cmocka_unit_test(include_param_uuid_nested_tokens),
        cmocka_unit_test(count_param_adds_true_when_total_count_set),
        cmocka_unit_test(count_param_skipped_when_not_set),
        cmocka_unit_test(pagination_all_defaults_adds_nothing),
        cmocka_unit_test(pagination_limit_only),
        cmocka_unit_test(pagination_limit_100_not_clamped),
        cmocka_unit_test(pagination_limit_one),
        cmocka_unit_test(pagination_limit_zero_omits_param),
        cmocka_unit_test(pagination_limit_101_passed_through_unclamped),
        cmocka_unit_test(pagination_start_cursor),
        cmocka_unit_test(pagination_all_params),
        cmocka_unit_test(filter_param_null_adds_nothing),
        cmocka_unit_test(filter_param_adds_expression),
        cmocka_unit_test(sort_param_null_adds_nothing),
        cmocka_unit_test(sort_param_adds_expression),
        cmocka_unit_test(validator_accepts_200_json),
        cmocka_unit_test(validator_rejects_403),
        cmocka_unit_test(validator_rejects_non_json_body),
        cmocka_unit_test(validator_rejects_empty_body),
        cmocka_unit_test(parse_page_extracts_list_envelope),
        cmocka_unit_test(parse_page_handles_minimal_envelope),
        cmocka_unit_test(get_data_array_returns_array_node),
        cmocka_unit_test(get_data_array_returns_null_when_missing),
        cmocka_unit_test(get_data_array_returns_null_when_not_array),
        cmocka_unit_test(get_data_object_returns_object_node),
        cmocka_unit_test(get_data_object_returns_null_when_array),
        cmocka_unit_test(cleanup_handles_null_state),
        cmocka_unit_test(cleanup_frees_encoded_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
