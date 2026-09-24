/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_wire_units.c
 * @brief Unit tests for subscribe wire-level helpers.
 *
 * Tests the URL/path builders (handshake + receive) and the response
 * validator. Parser tests use the real cJSON serialization provider
 * since the parser depends on the vtable to traverse the tree.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

/* Internal wire declarations. */
#include "features/subscribe/subscribe_wire_internal.h"

/* Provided by the linked serialization provider. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* ================================================================== */
/* Helpers                                                              */
/* ================================================================== */

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

/* ================================================================== */
/* Tests: handshake builder                                            */
/* ================================================================== */

static void test_build_handshake_basic(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "my-channel",
        .channel_groups = NULL,
        .filter_expr    = NULL,
        .heartbeat_sec  = 0,
        .timeout_ms     = 310000,
    };

    pubnub_res_t rc = pn_subscribe_build_handshake(&request, &inputs);
    assert_int_equal(PUBNUB_OK, rc);

    /* Path: /v2/subscribe/sub-c-key/my-channel/0 */
    assert_int_equal(5, request.path_segment_count);
    assert_memory_equal(request.path_segments[0].ptr, "v2", 2);
    assert_memory_equal(request.path_segments[1].ptr, "subscribe", 9);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[4].ptr, "0", 1);

    /* Must have tt=0 query param. */
    assert_true(request.query_param_count >= 1);
    assert_memory_equal(request.query_params[0].key.ptr, "tt", 2);
    assert_memory_equal(request.query_params[0].value.ptr, "0", 1);

    assert_int_equal(PUBNUB_HTTP_GET, request.method);
    assert_int_equal(310000, request.timeout_ms);
}

static void test_build_handshake_with_filter(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1,ch2",
        .channel_groups = NULL,
        .filter_expr    = "uuid != 'bot'",
        .heartbeat_sec  = 0,
        .timeout_ms     = 310000,
    };

    pubnub_res_t rc = pn_subscribe_build_handshake(&request, &inputs);
    assert_int_equal(PUBNUB_OK, rc);

    /* Find filter-expr among query params. */
    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (11 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "filter-expr", 11)) {
            found = 1;
            assert_non_null(request.query_params[i].value.ptr);
            break;
        }
    }
    assert_int_equal(1, found);
}

static void test_build_handshake_with_groups(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = "grp1,grp2",
        .filter_expr    = NULL,
        .heartbeat_sec  = 0,
        .timeout_ms     = 310000,
    };

    pubnub_res_t rc = pn_subscribe_build_handshake(&request, &inputs);
    assert_int_equal(PUBNUB_OK, rc);

    /* Find channel-group among query params. PN_ENCODE_KEEP_COMMAS
     * encodes reserved chars but preserves commas as delimiters. */
    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (13 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "channel-group", 13)) {
            found = 1;
            assert_memory_equal(request.query_params[i].value.ptr, "grp1,grp2", 9);
            break;
        }
    }
    assert_int_equal(1, found);
}

static void test_build_handshake_with_heartbeat(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "ch1",
        .channel_groups = NULL,
        .filter_expr    = NULL,
        .heartbeat_sec  = 300,
        .timeout_ms     = 310000,
    };

    pubnub_res_t rc = pn_subscribe_build_handshake(&request, &inputs);
    assert_int_equal(PUBNUB_OK, rc);

    /* Find heartbeat among query params. */
    int found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (9 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "heartbeat", 9)) {
            found = 1;
            assert_memory_equal(request.query_params[i].value.ptr, "300", 3);
            break;
        }
    }
    assert_int_equal(1, found);
}

/* ================================================================== */
/* Tests: receive builder                                              */
/* ================================================================== */

static void test_build_receive_with_cursor(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "chat",
        .channel_groups = NULL,
        .filter_expr    = NULL,
        .heartbeat_sec  = 0,
        .timeout_ms     = 310000,
    };

    pn_subscribe_cursor_t cursor = {0};
    memcpy(cursor.timetoken, "17001234567890123", 17);
    cursor.timetoken_len = 17;
    cursor.region        = 42;

    pubnub_res_t rc = pn_subscribe_build_receive(&request, &inputs, &cursor);
    assert_int_equal(PUBNUB_OK, rc);

    /* tt must be the cursor timetoken. */
    int tt_found = 0;
    int tr_found = 0;
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (2 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "tt", 2)) {
            tt_found = 1;
            assert_memory_equal(
                request.query_params[i].value.ptr, "17001234567890123", 17);
        }
        if (2 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "tr", 2)) {
            tr_found = 1;
            assert_memory_equal(request.query_params[i].value.ptr, "42", 2);
        }
    }
    assert_int_equal(1, tt_found);
    assert_int_equal(1, tr_found);
}

static void test_build_receive_zero_region_omits_tr(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key  = "sub-c-key",
        .channels       = "chat",
        .channel_groups = NULL,
        .filter_expr    = NULL,
        .heartbeat_sec  = 0,
        .timeout_ms     = 310000,
    };

    pn_subscribe_cursor_t cursor = {0};
    memcpy(cursor.timetoken, "17001234567890123", 17);
    cursor.timetoken_len = 17;
    cursor.region        = 0;

    pubnub_res_t rc = pn_subscribe_build_receive(&request, &inputs, &cursor);
    assert_int_equal(PUBNUB_OK, rc);

    /* tr must NOT appear when region is 0. */
    for (unsigned int i = 0; i < request.query_param_count; i++) {
        if (2 == request.query_params[i].key.len
            && 0 == memcmp(request.query_params[i].key.ptr, "tr", 2)) {
            fail_msg("tr query param should be omitted when region is 0");
        }
    }
}

/* ================================================================== */
/* Tests: null/invalid inputs                                          */
/* ================================================================== */

static void test_build_handshake_null_request(void** state)
{
    (void)state;
    pn_subscribe_wire_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channels      = "ch",
    };
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_handshake(NULL, &inputs));
}

static void test_build_handshake_null_inputs(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_handshake(&request, NULL));
}

static void test_build_handshake_null_subscribe_key(void** state)
{
    (void)state;
    pubnub_http_request_t      request = make_request();
    pn_subscribe_wire_inputs_t inputs  = {
         .subscribe_key = NULL,
         .channels      = "ch",
    };
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_handshake(&request, &inputs));
}

static void test_build_handshake_null_channels(void** state)
{
    (void)state;
    pubnub_http_request_t      request = make_request();
    pn_subscribe_wire_inputs_t inputs  = {
         .subscribe_key = "sub-c-key",
         .channels      = NULL,
    };
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_handshake(&request, &inputs));
}

static void test_build_receive_null_cursor(void** state)
{
    (void)state;
    pubnub_http_request_t      request = make_request();
    pn_subscribe_wire_inputs_t inputs  = {
         .subscribe_key = "sub-c-key",
         .channels      = "ch",
    };
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_receive(&request, &inputs, NULL));
}

static void test_build_receive_empty_timetoken(void** state)
{
    (void)state;
    pubnub_http_request_t      request = make_request();
    pn_subscribe_wire_inputs_t inputs  = {
         .subscribe_key = "sub-c-key",
         .channels      = "ch",
    };
    pn_subscribe_cursor_t cursor = {0};
    /* timetoken_len = 0 → invalid. */
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_subscribe_build_receive(&request, &inputs, &cursor));
}

/* ================================================================== */
/* Tests: response validator                                           */
/* ================================================================== */

static void test_response_validator_valid_object(void** state)
{
    (void)state;
    const uint8_t body[] =
        "{\"t\":{\"t\":\"17001234567890123\",\"r\":1},\"m\":[]}";
    assert_int_equal(
        PUBNUB_OK, pn_subscribe_response_validator(body, sizeof(body) - 1, 200));
}

static void test_response_validator_http_403(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":true}";
    assert_int_equal(PUBNUB_ERR_SERVER,
                     pn_subscribe_response_validator(body, sizeof(body) - 1, 403));
}

static void test_response_validator_http_500(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":\"internal\"}";
    assert_int_equal(PUBNUB_ERR_SERVER,
                     pn_subscribe_response_validator(body, sizeof(body) - 1, 500));
}

static void test_response_validator_not_json_object(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\"]";
    assert_int_equal(PUBNUB_ERR_SERIALIZATION,
                     pn_subscribe_response_validator(body, sizeof(body) - 1, 200));
}

static void test_response_validator_empty_body(void** state)
{
    (void)state;
    assert_int_equal(PUBNUB_ERR_SERIALIZATION,
                     pn_subscribe_response_validator(NULL, 0, 200));
}

static void test_response_validator_too_short(void** state)
{
    (void)state;
    const uint8_t body[] = "{}";
    assert_int_equal(PUBNUB_ERR_SERIALIZATION,
                     pn_subscribe_response_validator(body, sizeof(body) - 1, 200));
}

static void test_response_validator_leading_whitespace(void** state)
{
    (void)state;
    const uint8_t body[] = "  \t{\"t\":{\"t\":\"0\",\"r\":0},\"m\":[]}";
    assert_int_equal(
        PUBNUB_OK, pn_subscribe_response_validator(body, sizeof(body) - 1, 200));
}

/* ================================================================== */
/* Tests: response parser (requires real serialization provider)        */
/* ================================================================== */

static void test_parse_response_basic_envelope(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] =
        "{\"t\":{\"t\":\"17001234567890123\",\"r\":42},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(17, out.cursor.timetoken_len);
    assert_memory_equal(out.cursor.timetoken, "17001234567890123", 17);
    assert_int_equal(42, out.cursor.region);
    assert_int_equal(0, out.message_count);
    assert_int_equal(0, out.truncated);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_with_messages(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] =
        "{\"t\":{\"t\":\"17001234567890124\",\"r\":1},"
        "\"m\":[{\"c\":\"chat\",\"d\":\"hello\",\"i\":\"user1\","
        "\"p\":{\"t\":\"17001234567890100\",\"r\":1}}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);

    /* Verify first message fields. */
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, out.messages[0].event.type);
    assert_int_equal(4, out.messages[0].event.channel.len);
    assert_memory_equal(out.messages[0].event.channel.ptr, "chat", 4);
    assert_non_null(out.messages[0].event.payload);
    size_t      msg_len = 0;
    const char* msg_str =
        serial->value_as_string(out.messages[0].event.payload, &msg_len);
    assert_non_null(msg_str);
    assert_int_equal(5, msg_len);
    assert_memory_equal(msg_str, "hello", 5);
    assert_int_equal(5, out.messages[0].event.publisher.len);
    assert_memory_equal(out.messages[0].event.publisher.ptr, "user1", 5);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_all_event_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* A single message carrying every documented wire field:
     * e (type), f (flags), c (channel), b (subscription),
     * i (publisher), cmt (custom message type), d (payload),
     * u (user metadata), and p.t (publish timetoken). */
    const char body[] =
        "{\"t\":{\"t\":\"17001234567890300\",\"r\":7},"
        "\"m\":[{\"e\":0,\"f\":513,\"c\":\"room-42\",\"b\":\"room-*\","
        "\"i\":\"alice\",\"cmt\":\"text\",\"d\":\"hi there\","
        "\"u\":{\"lang\":\"en\"},"
        "\"p\":{\"t\":\"17001234567890299\",\"r\":7}}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);

    const pubnub_subscribe_event_t* ev = &out.messages[0].event;
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, ev->type);
    assert_int_equal(513, ev->flags);
    assert_int_equal(7, ev->channel.len);
    assert_memory_equal(ev->channel.ptr, "room-42", 7);
    assert_int_equal(6, ev->subscription.len);
    assert_memory_equal(ev->subscription.ptr, "room-*", 6);
    assert_int_equal(5, ev->publisher.len);
    assert_memory_equal(ev->publisher.ptr, "alice", 5);
    assert_int_equal(4, ev->custom_message_type.len);
    assert_memory_equal(ev->custom_message_type.ptr, "text", 4);
    assert_int_equal(17, ev->timetoken.len);
    assert_memory_equal(ev->timetoken.ptr, "17001234567890299", 17);

    assert_non_null(ev->payload);
    size_t      plen = 0;
    const char* pstr = serial->value_as_string(ev->payload, &plen);
    assert_non_null(pstr);
    assert_int_equal(8, plen);
    assert_memory_equal(pstr, "hi there", 8);

    assert_non_null(ev->user_metadata);

    serial->value_destroy(serial, out._tree);
}

/* Parse a single-message envelope and assert its decoded event type. */
static void parse_and_assert_type(const char*                     body,
                                  pubnub_subscribe_message_type_t expected)
{
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);
    assert_int_equal(expected, out.messages[0].event.type);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_type_message_default(void** state)
{
    (void)state;
    /* "e" absent -> defaults to MESSAGE. */
    parse_and_assert_type("{\"t\":{\"t\":\"1\",\"r\":0},"
                          "\"m\":[{\"c\":\"ch\",\"d\":\"m\"}]}",
                          PUBNUB_SUBSCRIBE_MESSAGE);
}

static void test_parse_response_type_signal(void** state)
{
    (void)state;
    parse_and_assert_type("{\"t\":{\"t\":\"1\",\"r\":0},"
                          "\"m\":[{\"e\":1,\"c\":\"sig-ch\",\"d\":\"ping\"}]}",
                          PUBNUB_SUBSCRIBE_SIGNAL);
}

static void test_parse_response_type_app_context(void** state)
{
    (void)state;
    parse_and_assert_type("{\"t\":{\"t\":\"1\",\"r\":0},"
                          "\"m\":[{\"e\":2,\"c\":\"obj-ch\",\"d\":{}}]}",
                          PUBNUB_SUBSCRIBE_APP_CONTEXT);
}

static void test_parse_response_type_message_action(void** state)
{
    (void)state;
    parse_and_assert_type("{\"t\":{\"t\":\"1\",\"r\":0},"
                          "\"m\":[{\"e\":3,\"c\":\"act-ch\",\"d\":{}}]}",
                          PUBNUB_SUBSCRIBE_MESSAGE_ACTION);
}

static void test_parse_response_type_file(void** state)
{
    (void)state;
    parse_and_assert_type("{\"t\":{\"t\":\"1\",\"r\":0},"
                          "\"m\":[{\"e\":4,\"c\":\"file-ch\",\"d\":{}}]}",
                          PUBNUB_SUBSCRIBE_FILE);
}

static void test_parse_response_missing_optional_fields(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* Only channel and payload present; every optional field omitted. */
    const char body[] = "{\"t\":{\"t\":\"17001234567890301\",\"r\":0},"
                        "\"m\":[{\"c\":\"bare-ch\",\"d\":\"x\"}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);

    const pubnub_subscribe_event_t* ev = &out.messages[0].event;
    assert_int_equal(PUBNUB_SUBSCRIBE_MESSAGE, ev->type);
    assert_int_equal(0, ev->flags);
    assert_int_equal(7, ev->channel.len);
    assert_memory_equal(ev->channel.ptr, "bare-ch", 7);
    /* Absent optional views default to zero-length; user_metadata NULL. */
    assert_int_equal(0, ev->subscription.len);
    assert_int_equal(0, ev->publisher.len);
    assert_int_equal(0, ev->custom_message_type.len);
    assert_int_equal(0, ev->timetoken.len);
    assert_null(ev->user_metadata);
    assert_non_null(ev->payload);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_empty_message_list(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] =
        "{\"t\":{\"t\":\"17001234567890302\",\"r\":3},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(0, out.message_count);
    assert_int_equal(0, out.truncated);
    /* Cursor still advances even with no messages. */
    assert_int_equal(17, out.cursor.timetoken_len);
    assert_memory_equal(out.cursor.timetoken, "17001234567890302", 17);
    assert_int_equal(3, out.cursor.region);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_multiple_messages(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] = "{\"t\":{\"t\":\"17001234567890303\",\"r\":1},"
                        "\"m\":[{\"c\":\"ch-a\",\"d\":\"a\"},"
                        "{\"c\":\"ch-b\",\"d\":\"b\"},"
                        "{\"c\":\"ch-c\",\"d\":\"c\"}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(3, out.message_count);
    assert_memory_equal(out.messages[0].event.channel.ptr, "ch-a", 4);
    assert_memory_equal(out.messages[1].event.channel.ptr, "ch-b", 4);
    assert_memory_equal(out.messages[2].event.channel.ptr, "ch-c", 4);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_channel_distinct_from_subscription(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* "c" is the concrete channel, "b" is the subscription match
     * pattern (wildcard or group). They must be surfaced separately. */
    const char body[] = "{\"t\":{\"t\":\"17001234567890304\",\"r\":0},"
                        "\"m\":[{\"c\":\"room.lobby\",\"b\":\"room.*\","
                        "\"d\":\"hey\"}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);

    const pubnub_subscribe_event_t* ev = &out.messages[0].event;
    assert_int_equal(10, ev->channel.len);
    assert_memory_equal(ev->channel.ptr, "room.lobby", 10);
    assert_int_equal(6, ev->subscription.len);
    assert_memory_equal(ev->subscription.ptr, "room.*", 6);
    /* The two views must not alias the same bytes. */
    assert_int_not_equal(ev->channel.len, ev->subscription.len);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_presence_channel(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* Channel ending with -pnpres should override type to PRESENCE
     * and strip the suffix from the channel view. */
    const char body[] = "{\"t\":{\"t\":\"17001234567890125\",\"r\":0},"
                        "\"m\":[{\"c\":\"chat-pnpres\",\"d\":\"join\"}]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.message_count);
    assert_int_equal(PUBNUB_SUBSCRIBE_PRESENCE, out.messages[0].event.type);
    /* Channel is "chat" with -pnpres stripped. */
    assert_int_equal(4, out.messages[0].event.channel.len);
    assert_memory_equal(out.messages[0].event.channel.ptr, "chat", 4);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_malformed_body(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] = "not json at all";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
    assert_null(out._tree);
}

static void test_parse_response_missing_cursor(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* Valid JSON object but no "t" cursor field. */
    const char body[] = "{\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
}

static void test_parse_response_rejects_non_digit_cursor(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* A MITM/compromised server returns a short non-numeric timetoken
     * that would otherwise be spliced verbatim into the tt= param. */
    const char body[] = "{\"t\":{\"t\":\"1700abc\",\"r\":1},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
    assert_null(out._tree);
}

static void test_parse_response_rejects_symbol_cursor(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    /* Path-traversal / delimiter bytes must never reach the query. */
    const char body[] = "{\"t\":{\"t\":\"170/../\",\"r\":1},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
    assert_null(out._tree);
}

static void test_parse_response_accepts_17_digit_cursor(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] =
        "{\"t\":{\"t\":\"17001234567890123\",\"r\":7},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc  = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(17, out.cursor.timetoken_len);
    assert_memory_equal(out.cursor.timetoken, "17001234567890123", 17);
    assert_int_equal(7, out.cursor.region);

    serial->value_destroy(serial, out._tree);
}

static void test_parse_response_null_serial(void** state)
{
    (void)state;
    const char body[] = "{\"t\":{\"t\":\"0\",\"r\":0},\"m\":[]}";

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t                   rc =
        pn_subscribe_parse_response(NULL, (const uint8_t*)body, strlen(body), &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
}

static void test_parse_response_null_body(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    pn_subscribe_parsed_response_t out = {0};
    pubnub_res_t rc = pn_subscribe_parse_response(serial, NULL, 0, &out);

    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
}

static void test_parse_response_null_out(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    assert_non_null(serial);

    const char body[] = "{\"t\":{\"t\":\"0\",\"r\":0},\"m\":[]}";

    pubnub_res_t rc = pn_subscribe_parse_response(
        serial, (const uint8_t*)body, strlen(body), NULL);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

/* ================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Handshake builder */
        cmocka_unit_test(test_build_handshake_basic),
        cmocka_unit_test(test_build_handshake_with_filter),
        cmocka_unit_test(test_build_handshake_with_groups),
        cmocka_unit_test(test_build_handshake_with_heartbeat),
        /* Receive builder */
        cmocka_unit_test(test_build_receive_with_cursor),
        cmocka_unit_test(test_build_receive_zero_region_omits_tr),
        /* Null/invalid inputs */
        cmocka_unit_test(test_build_handshake_null_request),
        cmocka_unit_test(test_build_handshake_null_inputs),
        cmocka_unit_test(test_build_handshake_null_subscribe_key),
        cmocka_unit_test(test_build_handshake_null_channels),
        cmocka_unit_test(test_build_receive_null_cursor),
        cmocka_unit_test(test_build_receive_empty_timetoken),
        /* Response validator */
        cmocka_unit_test(test_response_validator_valid_object),
        cmocka_unit_test(test_response_validator_http_403),
        cmocka_unit_test(test_response_validator_http_500),
        cmocka_unit_test(test_response_validator_not_json_object),
        cmocka_unit_test(test_response_validator_empty_body),
        cmocka_unit_test(test_response_validator_too_short),
        cmocka_unit_test(test_response_validator_leading_whitespace),
        /* Response parser */
        cmocka_unit_test(test_parse_response_basic_envelope),
        cmocka_unit_test(test_parse_response_with_messages),
        cmocka_unit_test(test_parse_response_all_event_fields),
        cmocka_unit_test(test_parse_response_type_message_default),
        cmocka_unit_test(test_parse_response_type_signal),
        cmocka_unit_test(test_parse_response_type_app_context),
        cmocka_unit_test(test_parse_response_type_message_action),
        cmocka_unit_test(test_parse_response_type_file),
        cmocka_unit_test(test_parse_response_missing_optional_fields),
        cmocka_unit_test(test_parse_response_empty_message_list),
        cmocka_unit_test(test_parse_response_multiple_messages),
        cmocka_unit_test(test_parse_response_channel_distinct_from_subscription),
        cmocka_unit_test(test_parse_response_presence_channel),
        cmocka_unit_test(test_parse_response_malformed_body),
        cmocka_unit_test(test_parse_response_missing_cursor),
        cmocka_unit_test(test_parse_response_rejects_non_digit_cursor),
        cmocka_unit_test(test_parse_response_rejects_symbol_cursor),
        cmocka_unit_test(test_parse_response_accepts_17_digit_cursor),
        cmocka_unit_test(test_parse_response_null_serial),
        cmocka_unit_test(test_parse_response_null_body),
        cmocka_unit_test(test_parse_response_null_out),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
