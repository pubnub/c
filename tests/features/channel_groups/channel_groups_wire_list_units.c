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

#include "pubnub/providers/serialization.h"

/* Internal declarations shared with the feature implementation. */
#include "features/channel_groups/channel_groups_internal.h"

/* Provided by the linked serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

static pubnub_json_value_t* parse_body(pubnub_serialization_provider_t* serial,
                                       const char*                      body)
{
    return serial->parse(serial, (const uint8_t*)body, strlen(body));
}

static void parse_list_should_extract_channels(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body =
        "{\"status\":200,\"payload\":{\"channels\":[\"ch1\",\"ch2\",\"ch3\"]}}";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_channel_groups_parsed_t parsed = {0};
    assert_int_equal(pn_channel_groups_parse_list_response(serial, tree, &parsed),
                     PUBNUB_OK);
    assert_int_equal(parsed.count, 3);
    assert_non_null(parsed.channels_array);

    /* Verify individual channels via the vtable. */
    const pubnub_json_value_t* ch0 = serial->array_get(parsed.channels_array, 0);
    assert_non_null(ch0);
    size_t      len = 0;
    const char* ptr = serial->value_as_string(ch0, &len);
    assert_int_equal(len, 3);
    assert_memory_equal(ptr, "ch1", 3);

    serial->value_destroy(serial, tree);
}

static void parse_list_should_handle_empty_channels(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char* body = "{\"status\":200,\"payload\":{\"channels\":[]}}";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_channel_groups_parsed_t parsed = {0};
    assert_int_equal(pn_channel_groups_parse_list_response(serial, tree, &parsed),
                     PUBNUB_OK);
    assert_int_equal(parsed.count, 0);

    serial->value_destroy(serial, tree);
}

static void parse_list_should_reject_missing_payload(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "{\"status\":200}";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_channel_groups_parsed_t parsed = {0};
    assert_int_equal(pn_channel_groups_parse_list_response(serial, tree, &parsed),
                     PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_list_should_reject_non_object_root(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    const char*                      body   = "[1,2,3]";
    pubnub_json_value_t*             tree   = parse_body(serial, body);
    assert_non_null(tree);

    pn_channel_groups_parsed_t parsed = {0};
    assert_int_equal(pn_channel_groups_parse_list_response(serial, tree, &parsed),
                     PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_list_should_reject_null_arguments(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pn_channel_groups_parsed_t       parsed = {0};

    assert_int_equal(pn_channel_groups_parse_list_response(NULL, NULL, &parsed),
                     PUBNUB_ERR_SERIALIZATION);
    assert_int_equal(pn_channel_groups_parse_list_response(serial, NULL, &parsed),
                     PUBNUB_ERR_SERIALIZATION);
    assert_int_equal(pn_channel_groups_parse_list_response(serial, NULL, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_list_should_extract_channels),
        cmocka_unit_test(parse_list_should_handle_empty_channels),
        cmocka_unit_test(parse_list_should_reject_missing_payload),
        cmocka_unit_test(parse_list_should_reject_non_object_root),
        cmocka_unit_test(parse_list_should_reject_null_arguments),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
