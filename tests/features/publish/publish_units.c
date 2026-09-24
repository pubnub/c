/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file publish_units.c
 * @brief Unit tests for the string-form publish path's wire helpers.
 *
 * These tests exercise the URL path builder, query-parameter
 * appender, response parser, and validator in isolation -- no
 * context, no transport, no network. The value-tree path has its
 * own coverage in @c publish_value_units.c. The end-to-end happy
 * path is exercised by the runnable examples under
 * `examples/publish/` plus the mock-transport integration test in
 * `tests/core/client_units.c`.
 *
 * Two groups:
 *   - Wire tests (path + query) use a small malloc/free-backed
 *     allocator because they need real allocator semantics for the
 *     URL-encode scratch.
 *   - Parser / validator tests operate on byte spans only.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/publish.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/publish/publish_internal.h"

/* Provided by the linked serialization provider, used only by the
 * meta-object query test. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Real malloc/free-backed allocator for the build_path wire tests,
 * which need genuine alloc/free semantics for the URL-encode
 * scratch. The stub allocator that ships with the dev preset has
 * NULL callbacks; we don't use pn_allocator_default() here. */
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

/* Zero-initialised request the builders can fill; allocator-owned
 * encoded buffers outlive this struct because we free them in the
 * test body. */
static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    return req;
}

/* ======================================================================== */
/* Tests: path builder                                                       */
/* ======================================================================== */

static void build_path_should_populate_seven_segments_for_plain_channel(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const uint8_t                  serialized[] = "\"hello\"";
    const pn_publish_path_inputs_t inputs       = {
              .publish_key     = "pub-c-key",
              .subscribe_key   = "sub-c-key",
              .channel         = "my-channel",
              .serialized      = serialized,
              .serialized_len  = sizeof(serialized) - 1,
              .include_message = 1,
    };
    pn_publish_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_publish_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    /* Segments: /publish / pub / sub / 0 / channel / 0 / payload */
    assert_int_equal(request.path_segment_count, 7);
    assert_memory_equal(request.path_segments[0].ptr, "publish", 7);
    assert_memory_equal(request.path_segments[1].ptr, "pub-c-key", 9);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "0", 1);
    /* "my-channel" contains only unreserved characters, so the
     * URL-encoded form matches the input byte-for-byte. */
    assert_memory_equal(request.path_segments[4].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[5].ptr, "0", 1);
    /* "\"hello\"" -> quote + hello + quote. Both quotes percent-
     * encode to %22 in the URL. */
    assert_non_null(strstr((const char*)request.path_segments[6].ptr, "%22hello%22"));

    allocator->free(allocator, url_encoded.channel);
    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_percent_encode_channel_with_reserved_chars(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const uint8_t                  serialized[] = "\"x\"";
    const pn_publish_path_inputs_t inputs       = {
              .publish_key   = "pub",
              .subscribe_key = "sub",
        /* Space + slash both require percent-encoding in a path
         * segment. Verifies that the feature delegates to the
         * shared pn_url_encode rather than copying bytes raw. */
              .channel         = "chat room/topic",
              .serialized      = serialized,
              .serialized_len  = sizeof(serialized) - 1,
              .include_message = 1,
    };
    pn_publish_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_publish_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    const char* ch = (const char*)request.path_segments[4].ptr;
    /* Space -> %20, slash -> %2F (or %2f depending on encoder
     * case). Both substrings appearing is enough to confirm
     * encoding took place. */
    assert_non_null(strstr(ch, "%20"));
    assert_true(NULL != strstr(ch, "%2F") || NULL != strstr(ch, "%2f"));

    allocator->free(allocator, url_encoded.channel);
    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_honour_serialized_len_strictly(void** state)
{
    (void)state;
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    /* Input buffer contains trailing garbage past serialized_len
     * bytes; builder must not read past it. The serialized payload
     * here is the JSON string "\"ok\"" (4 bytes). */
    const uint8_t                  buf[]  = "\"ok\"GARBAGE";
    const pn_publish_path_inputs_t inputs = {
        .publish_key     = "pub",
        .subscribe_key   = "sub",
        .channel         = "ch",
        .serialized      = buf,
        .serialized_len  = 4, /* exactly "\"ok\"" */
        .include_message = 1,
    };
    pn_publish_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_publish_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    /* URL-encoded "\"ok\"" contains "%22ok%22" and no G/A/R/B. */
    assert_non_null(strstr((const char*)request.path_segments[6].ptr, "%22ok%22"));
    assert_null(strstr((const char*)request.path_segments[6].ptr, "GARBAGE"));

    allocator->free(allocator, url_encoded.channel);
    allocator->free(allocator, url_encoded.message);
}

static void build_path_should_omit_message_segment_for_post(void** state)
{
    (void)state;
    /* POST-style publish puts the message in the request body, so
     * the URL path stops at the trailing "/0/" separator that
     * precedes where the GET payload would go -- six segments
     * instead of seven. No message buffer is allocated. */
    pubnub_http_request_t        request   = make_request();
    pubnub_allocator_provider_t* allocator = &s_test_allocator;

    const pn_publish_path_inputs_t inputs = {
        .publish_key     = "pub",
        .subscribe_key   = "sub",
        .channel         = "my-channel",
        .serialized      = NULL,
        .serialized_len  = 0,
        .include_message = 0,
    };
    pn_publish_url_encoded_t url_encoded = {0};

    pubnub_res_t rc =
        pn_publish_build_path(&request, allocator, &inputs, &url_encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[4].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[5].ptr, "0", 1);
    /* url_encoded.message must stay NULL -- we did not allocate one. */
    assert_null(url_encoded.message);

    allocator->free(allocator, url_encoded.channel);
}

static void build_path_should_reject_null_inputs(void** state)
{
    (void)state;
    pubnub_http_request_t        request     = make_request();
    pubnub_allocator_provider_t* allocator   = &s_test_allocator;
    pn_publish_url_encoded_t     url_encoded = {0};

    assert_int_equal(pn_publish_build_path(NULL, allocator, NULL, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    const pn_publish_path_inputs_t missing_channel = {
        .publish_key     = "pub",
        .subscribe_key   = "sub",
        .channel         = NULL,
        .serialized      = (const uint8_t*)"\"m\"",
        .serialized_len  = 3,
        .include_message = 1,
    };
    assert_int_equal(pn_publish_build_path(
                         &request, allocator, &missing_channel, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);

    /* include_message==1 with a NULL serialized span must fail. */
    const pn_publish_path_inputs_t missing_serialized = {
        .publish_key     = "pub",
        .subscribe_key   = "sub",
        .channel         = "ch",
        .serialized      = NULL,
        .serialized_len  = 0,
        .include_message = 1,
    };
    assert_int_equal(pn_publish_build_path(
                         &request, allocator, &missing_serialized, &url_encoded),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* Tests: query-parameter helpers                                            */
/* ======================================================================== */

static void add_query_params_should_append_store_yes(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_publish_add_query_params(
                         &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_YES, 0, NULL),
                     PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "store", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "1", 1);
}

static void add_query_params_should_append_store_no(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_publish_add_query_params(
                         &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_NO, 0, NULL),
                     PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].value.ptr, "0", 1);
}

static void add_query_params_should_omit_store_when_account_default(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(
        pn_publish_add_query_params(
            &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_ACCOUNT_DEFAULT, 0, NULL),
        PUBNUB_OK);
    assert_int_equal(request.query_param_count, 0);
}

static void add_query_params_should_serialize_ttl(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(
        pn_publish_add_query_params(
            &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_ACCOUNT_DEFAULT, 48, NULL),
        PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "ttl", 3);
    assert_memory_equal(request.query_params[0].value.ptr, "48", 2);
}

static void add_query_params_should_omit_ttl_when_store_no(void** state)
{
    (void)state;
    /* TTL is meaningless on a non-persisted message: skip the query
     * parameter entirely when the caller explicitly opted out of
     * storage. This pins the client-side suppression so the wire
     * format stays clean. */
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_publish_add_query_params(
                         &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_NO, 48, NULL),
                     PUBNUB_OK);
    /* Only `store=0` on the wire; no `ttl` param. */
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "store", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "0", 1);
}

static void add_query_params_should_send_ttl_when_store_yes(void** state)
{
    (void)state;
    /* TTL flows through as expected when the caller explicitly
     * opts into storage. */
    pubnub_http_request_t request = make_request();

    assert_int_equal(pn_publish_add_query_params(
                         &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_YES, 48, NULL),
                     PUBNUB_OK);
    assert_int_equal(request.query_param_count, 2);
    assert_memory_equal(request.query_params[0].key.ptr, "store", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "1", 1);
    assert_memory_equal(request.query_params[1].key.ptr, "ttl", 3);
    assert_memory_equal(request.query_params[1].value.ptr, "48", 2);
}

static void add_query_params_should_append_custom_message_type(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    assert_int_equal(
        pn_publish_add_query_params(
            &request, 0, NULL, 0, PUBNUB_PUBLISH_STORE_ACCOUNT_DEFAULT, 0, "text_v1"),
        PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "custom_message_type", 19);
    assert_memory_equal(request.query_params[0].value.ptr, "text_v1", 7);
}

static void add_query_params_should_append_meta_string(void** state)
{
    (void)state;
    /* String entry point passes opts->meta verbatim to the helper:
     * the caller already has formatted JSON bytes. The helper is
     * responsible for URL-encoding before attaching the param. */
    pubnub_http_request_t request  = make_request();
    const char            meta[]   = "{\"k\":\"v\"}";
    const size_t          meta_len = sizeof(meta) - 1;

    assert_int_equal(
        pn_publish_add_query_params(
            &request, 1, meta, meta_len, PUBNUB_PUBLISH_STORE_ACCOUNT_DEFAULT, 0, NULL),
        PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "meta", 4);
    /* `{"k":"v"}` -> percent-encoded form contains %22 and braces. */
    const char* v = request.query_params[0].value.ptr;
    assert_non_null(strstr(v, "%22"));
    assert_true(NULL != strstr(v, "%7B") || NULL != strstr(v, "%7b"));
    assert_true(NULL != strstr(v, "%7D") || NULL != strstr(v, "%7d"));
}

static void add_query_params_should_serialize_meta_object(void** state)
{
    (void)state;
    /* This test mirrors the contract the encoded entry point relies
     * on: build a tree, serialize it through the configured
     * provider, hand the resulting NUL-terminated string to the
     * helper, and verify the percent-encoded JSON shows up as the
     * `meta` query parameter. The helper is shared between both
     * paths so this also exercises the string-form contract. */
    pubnub_serialization_provider_t* serial  = pn_serialization_default();
    pubnub_http_request_t            request = make_request();

    pubnub_json_value_t* meta = serial->value_create_object(serial);
    assert_non_null(meta);
    assert_int_equal(
        serial->object_set(
            serial, meta, "k", 1, serial->value_create_string(serial, "v", 1)),
        PUBNUB_OK);

    /* Serialize meta into a stack buffer -- same shape as the
     * encoded entry point. The buffer is sized at
     * PUBNUB_CFG_HTTP_SCRATCH_SIZE so the test mirrors production
     * sizing assumptions. */
    char         meta_text[PUBNUB_CFG_HTTP_SCRATCH_SIZE];
    size_t       meta_len = 0;
    pubnub_res_t rc       = serial->serialize(
        serial, meta, (uint8_t*)meta_text, sizeof(meta_text) - 1, &meta_len);
    assert_int_equal(rc, PUBNUB_OK);
    meta_text[meta_len] = '\0';

    assert_int_equal(
        pn_publish_add_query_params(
            &request, 1, meta_text, meta_len, PUBNUB_PUBLISH_STORE_ACCOUNT_DEFAULT, 0, NULL),
        PUBNUB_OK);
    assert_int_equal(request.query_param_count, 1);
    assert_memory_equal(request.query_params[0].key.ptr, "meta", 4);
    /* `{"k":"v"}` -> percent-encoded "%7B%22k%22%3A%22v%22%7D"
     * (case-insensitive on hex digits). Loose check: must contain
     * percent-encoded quote and braces. */
    const char* v = request.query_params[0].value.ptr;
    assert_non_null(strstr(v, "%22"));
    assert_true(NULL != strstr(v, "%7B") || NULL != strstr(v, "%7b"));
    assert_true(NULL != strstr(v, "%7D") || NULL != strstr(v, "%7d"));

    serial->value_destroy(serial, meta);
}

/* ======================================================================== */
/* Tests: response parser (vtable-driven)                                    */
/* ======================================================================== */

/* Helper: parse a response body via the configured serialization
 * provider and return the resulting tree. The caller MUST destroy
 * the tree when done. */
static pubnub_json_value_t* parse_body(pubnub_serialization_provider_t* serial,
                                       const char*                      body)
{
    return serial->parse(serial, (const uint8_t*)body, strlen(body));
}

static void parse_response_should_decode_successful_publish(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    /* Canonical success response per REST spec. */
    const char*          body = "[1,\"Sent\",\"17001234567890123\"]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_publish_parsed_t parsed = {0};
    assert_int_equal(pn_publish_parse_response(serial, tree, &parsed), PUBNUB_OK);
    assert_non_null(parsed.timetoken.ptr);
    assert_int_equal(parsed.timetoken.len, 17);
    assert_memory_equal(parsed.timetoken.ptr, "17001234567890123", 17);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_decode_forbidden_error_shape(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    /* Two-element error body: PubNub omits the timetoken slot on
     * access-denied responses. */
    const char*          body = "[0,\"Forbidden\"]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_publish_parsed_t parsed = {0};
    assert_int_equal(pn_publish_parse_response(serial, tree, &parsed), PUBNUB_OK);
    assert_null(parsed.timetoken.ptr);
    assert_int_equal(parsed.timetoken.len, 0);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_be_idempotent_across_reruns(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    /* Running the parser twice against the same parsed tree must
     * return identical results -- pins the contract that the
     * slot-level lazy-parse cache relies on. */
    const char*          body = "[1,\"Sent\",\"17001234567890123\"]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_publish_parsed_t first  = {0};
    pn_publish_parsed_t second = {0};
    assert_int_equal(pn_publish_parse_response(serial, tree, &first), PUBNUB_OK);
    assert_int_equal(pn_publish_parse_response(serial, tree, &second), PUBNUB_OK);

    /* Both calls should observe the same timetoken length and bytes. */
    assert_int_equal(first.timetoken.len, second.timetoken.len);
    assert_memory_equal(
        first.timetoken.ptr, second.timetoken.ptr, first.timetoken.len);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_reject_non_array_root(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    /* Object root -- not the publish shape. */
    const char*          body = "{\"status\":1}";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_publish_parsed_t parsed = {0};
    assert_int_equal(pn_publish_parse_response(serial, tree, &parsed),
                     PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_reject_too_few_elements(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    /* Single-element array does not match the publish shape. */
    const char*          body = "[1]";
    pubnub_json_value_t* tree = parse_body(serial, body);
    assert_non_null(tree);

    pn_publish_parsed_t parsed = {0};
    assert_int_equal(pn_publish_parse_response(serial, tree, &parsed),
                     PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

static void parse_response_should_reject_null_arguments(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pn_publish_parsed_t              parsed = {0};

    assert_int_equal(pn_publish_parse_response(NULL, NULL, &parsed),
                     PUBNUB_ERR_SERIALIZATION);
    assert_int_equal(pn_publish_parse_response(serial, NULL, &parsed),
                     PUBNUB_ERR_SERIALIZATION);
    assert_int_equal(pn_publish_parse_response(serial, NULL, NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* Tests: response validator probe                                          */
/* ======================================================================== */

static void validator_should_accept_status_one(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\",\"17001234567890123\"]";
    assert_int_equal(pn_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void validator_should_reject_status_zero(void** state)
{
    (void)state;
    const uint8_t body[] = "[0,\"Forbidden\"]";
    assert_int_equal(pn_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_ERR_SERVER);
}

static void validator_should_reject_http_4xx(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\",\"17001234567890123\"]";
    assert_int_equal(pn_publish_response_validator(body, sizeof(body) - 1, 403),
                     PUBNUB_ERR_SERVER);
}

static void validator_should_accept_unknown_format(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":200}";
    assert_int_equal(pn_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void validator_should_tolerate_leading_whitespace(void** state)
{
    (void)state;
    const uint8_t body[] = "  [1,\"Sent\",\"17001234567890123\"]";
    assert_int_equal(pn_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

/* ======================================================================== */
/* Tests: pubnub_publish entry-point validation                             */
/* ======================================================================== */

static void publish_should_reject_null_ctx(void** state)
{
    (void)state;
    pubnub_publish_opts_t opts = {
        .channel = "ch",
        .message = "\"hi\"",
    };
    pubnub_future_t fut = pubnub_publish(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void publish_should_reject_null_message(void** state)
{
    (void)state;
    pubnub_publish_opts_t opts = {
        .channel = "ch",
        .message = NULL,
    };
    pubnub_future_t fut = pubnub_publish(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_path_should_populate_seven_segments_for_plain_channel),
        cmocka_unit_test(build_path_should_percent_encode_channel_with_reserved_chars),
        cmocka_unit_test(build_path_should_honour_serialized_len_strictly),
        cmocka_unit_test(build_path_should_omit_message_segment_for_post),
        cmocka_unit_test(build_path_should_reject_null_inputs),
        cmocka_unit_test(add_query_params_should_append_store_yes),
        cmocka_unit_test(add_query_params_should_append_store_no),
        cmocka_unit_test(add_query_params_should_omit_store_when_account_default),
        cmocka_unit_test(add_query_params_should_serialize_ttl),
        cmocka_unit_test(add_query_params_should_omit_ttl_when_store_no),
        cmocka_unit_test(add_query_params_should_send_ttl_when_store_yes),
        cmocka_unit_test(add_query_params_should_append_custom_message_type),
        cmocka_unit_test(add_query_params_should_append_meta_string),
        cmocka_unit_test(add_query_params_should_serialize_meta_object),
        cmocka_unit_test(parse_response_should_decode_successful_publish),
        cmocka_unit_test(parse_response_should_decode_forbidden_error_shape),
        cmocka_unit_test(parse_response_should_be_idempotent_across_reruns),
        cmocka_unit_test(parse_response_should_reject_non_array_root),
        cmocka_unit_test(parse_response_should_reject_too_few_elements),
        cmocka_unit_test(parse_response_should_reject_null_arguments),
        cmocka_unit_test(validator_should_accept_status_one),
        cmocka_unit_test(validator_should_reject_status_zero),
        cmocka_unit_test(validator_should_reject_http_4xx),
        cmocka_unit_test(validator_should_accept_unknown_format),
        cmocka_unit_test(validator_should_tolerate_leading_whitespace),
        cmocka_unit_test(publish_should_reject_null_ctx),
        cmocka_unit_test(publish_should_reject_null_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
