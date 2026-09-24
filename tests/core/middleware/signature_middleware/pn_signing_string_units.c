/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_signing_string_units.c
 * @brief Unit tests for the PAMv3 canonical signing-string builder.
 *
 * The canonical string is the only input HMAC-SHA256 sees; every
 * byte matters. These tests pin the legacy c-core `\n`-joined
 * format (`METHOD\nPK\nPATH\nQS\nBODY`), the trailing-LF rule for
 * bodyless methods, and the verbatim copy of already-URL-encoded
 * query values.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "core/runtime/middleware/signature_middleware/pn_signing_string.h"

/* ======================================================================== */
/* Test fixture helpers                                                     */
/* ======================================================================== */

static void set_segment(pubnub_http_request_t* req, unsigned int index, const char* value)
{
    req->path_segments[index].ptr = value;
    req->path_segments[index].len = strlen(value);
}

static void set_query_param(pubnub_http_request_t* req,
                            unsigned int           index,
                            const char*            key,
                            const char*            value)
{
    req->query_params[index].key.ptr   = key;
    req->query_params[index].key.len   = strlen(key);
    req->query_params[index].value.ptr = value;
    req->query_params[index].value.len = strlen(value);
}

/* ======================================================================== */
/* Method verb mapping                                                      */
/* ======================================================================== */

static void verb_should_map_get(void** state)
{
    (void)state;

    assert_string_equal(pn_signing_method_verb(PUBNUB_HTTP_GET), "GET");
}

static void verb_should_map_post(void** state)
{
    (void)state;

    assert_string_equal(pn_signing_method_verb(PUBNUB_HTTP_POST), "POST");
}

static void verb_should_map_patch(void** state)
{
    (void)state;

    assert_string_equal(pn_signing_method_verb(PUBNUB_HTTP_PATCH), "PATCH");
}

static void verb_should_map_delete(void** state)
{
    (void)state;

    assert_string_equal(pn_signing_method_verb(PUBNUB_HTTP_DELETE), "DELETE");
}

static void verb_should_return_unknown_for_out_of_range(void** state)
{
    (void)state;

    assert_string_equal(pn_signing_method_verb((pubnub_http_method_t)42), "UNKNOWN");
}

/* ======================================================================== */
/* needed_bytes                                                             */
/* ======================================================================== */

static void needed_bytes_should_return_zero_for_null_publish_key(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));

    assert_int_equal(pn_signing_string_len(&req, NULL), 0);
}

static void needed_bytes_should_return_zero_for_null_request(void** state)
{
    (void)state;

    assert_int_equal(pn_signing_string_len(NULL, "pk"), 0);
}

static void needed_bytes_should_account_for_trailing_lf_on_bodyless(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    /* GET, no path, no query, no body:
     * "GET\n" + "pk\n" + "/\n" + "\n" = 3+1 + 2+1 + 1+1 + 0+1 = 10 */

    assert_int_equal(pn_signing_string_len(&req, "pk"), 10);
}

static void needed_bytes_should_include_body_for_post(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method           = PUBNUB_HTTP_POST;
    const uint8_t body[] = {'h', 'i'};
    req.body             = body;
    req.body_len         = sizeof(body);

    /* POST, no path, no query, body "hi" (2 bytes):
     *   "POST\n" + "pk\n" + "/\n" + "\n" + "hi" = 5 + 3 + 2 + 1 + 2 = 13 */
    assert_int_equal(pn_signing_string_len(&req, "pk"), 13);
}

static void needed_bytes_should_ignore_body_for_get(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    /* Body set but method is GET: must be excluded. */
    const uint8_t body[] = {'h', 'i'};
    req.body             = body;
    req.body_len         = sizeof(body);

    assert_int_equal(pn_signing_string_len(&req, "pk"), 10);
}

/* ======================================================================== */
/* build: structural                                                        */
/* ======================================================================== */

static void build_should_reject_too_small_output(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    uint8_t out[4] = {0};
    size_t  out_len;

    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_ERR_BUFFER_TOO_SMALL);
}

static void build_should_reject_null_args(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    uint8_t out[32];
    size_t  out_len;

    assert_int_equal(pn_signing_string_build(&req, NULL, out, sizeof(out), &out_len),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_signing_string_build(NULL, "pk", out, sizeof(out), &out_len),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_signing_string_build(&req, "pk", NULL, sizeof(out), &out_len),
                     PUBNUB_ERR_INVALID_ARGUMENT);
    assert_int_equal(pn_signing_string_build(&req, "pk", out, sizeof(out), NULL),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ======================================================================== */
/* build: PAMv3 reference vectors                                           */
/* ======================================================================== */

static void build_should_match_legacy_format_for_get_no_body(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    set_segment(&req, 0, "publish");
    set_segment(&req, 1, "pk");
    set_segment(&req, 2, "sk");
    set_segment(&req, 3, "0");
    set_segment(&req, 4, "ch");
    set_segment(&req, 5, "0");
    req.path_segment_count = 6;
    set_query_param(&req, 0, "pnsdk", "PubNub-C-core%2F0.1.0");
    set_query_param(&req, 1, "uuid", "u1");
    req.query_param_count = 2;

    uint8_t      out[256];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    const char* expected = "GET\n"
                           "pk\n"
                           "/publish/pk/sk/0/ch/0\n"
                           "pnsdk=PubNub-C-core%2F0.1.0&uuid=u1\n";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

static void build_should_include_body_for_post(void** state)
{
    (void)state;
    /* Non-publish POST: body is included in the canonical string. */
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = PUBNUB_HTTP_POST;
    set_segment(&req, 0, "v3");
    set_segment(&req, 1, "pam");
    req.path_segment_count = 2;
    set_query_param(&req, 0, "uuid", "u");
    req.query_param_count = 1;
    const uint8_t body[]  = {'{', '}'};
    req.body              = body;
    req.body_len          = sizeof(body);

    uint8_t      out[128];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pub_k", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    const char* expected = "POST\n"
                           "pub_k\n"
                           "/v3/pam\n"
                           "uuid=u\n"
                           "{}";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

static void build_should_sign_publish_post_as_get_to_work_around_pam_bug(void** state)
{
    (void)state;
    /* PAM has a long-standing bug on /publish: it does not canonicalize
     * the POST body, so the client MUST sign as GET (no body in canonical
     * string, verb written as "GET") to get a signature that matches.
     * Every other SDK (JS reference) applies the same workaround. */
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = PUBNUB_HTTP_POST;
    set_segment(&req, 0, "publish");
    set_segment(&req, 1, "pub_k");
    set_segment(&req, 2, "sub_k");
    set_segment(&req, 3, "0");
    set_segment(&req, 4, "my-channel");
    set_segment(&req, 5, "0");
    req.path_segment_count = 6;
    set_query_param(&req, 0, "uuid", "u1");
    req.query_param_count = 1;
    const uint8_t body[]  = {'"', 'h', 'i', '"'};
    req.body              = body;
    req.body_len          = sizeof(body);

    uint8_t      out[256];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pub_k", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    /* Wire method is POST + body is present, but canonical string is
     * GET-shaped: verb "GET", no body bytes after the trailing QS LF. */
    const char* expected = "GET\n"
                           "pub_k\n"
                           "/publish/pub_k/sub_k/0/my-channel/0\n"
                           "uuid=u1\n";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

static void len_should_match_publish_post_workaround(void** state)
{
    (void)state;
    /* The sizing query must agree with pn_signing_string_build() about
     * the workaround, otherwise _build() would overrun or under-size
     * the output buffer. */
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = PUBNUB_HTTP_POST;
    set_segment(&req, 0, "publish");
    req.path_segment_count = 1;
    const uint8_t body[]   = {'x', 'x', 'x', 'x', 'x'};
    req.body               = body;
    req.body_len           = sizeof(body);

    /* "GET\n" + "pk\n" + "/publish\n" + "\n" = 4+3+9+1 = 17 */
    assert_int_equal(pn_signing_string_len(&req, "pk"), 17);
}

static void build_should_keep_trailing_lf_on_empty_query_and_no_body(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    set_segment(&req, 0, "time");
    set_segment(&req, 1, "0");
    req.path_segment_count = 2;

    uint8_t      out[64];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    /* The final \n between QS and BODY must remain even when both are
     * empty; this matches legacy pn_gen_pam_v3_sign() output. */
    assert_int_equal(out[out_len - 1], '\n');
}

static void build_should_emit_single_slash_for_empty_path(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = PUBNUB_HTTP_DELETE;

    uint8_t      out[64];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    /* Expect: "DELETE\npk\n/\n\n" */
    const char* expected = "DELETE\npk\n/\n\n";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

static void build_should_include_body_for_patch(void** state)
{
    (void)state;
    /* PATCH to /v1/objects/sub-key/channels/ch with JSON body. */
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method = PUBNUB_HTTP_PATCH;
    set_segment(&req, 0, "v1");
    set_segment(&req, 1, "objects");
    set_segment(&req, 2, "sub-key");
    set_segment(&req, 3, "channels");
    set_segment(&req, 4, "ch");
    req.path_segment_count = 5;
    /* No query params. */
    const uint8_t body[] = "{\"name\":\"x\"}";
    req.body             = body;
    req.body_len         = sizeof(body) - 1; /* exclude NUL */

    uint8_t      out[128];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    const char* expected = "PATCH\n"
                           "pk\n"
                           "/v1/objects/sub-key/channels/ch\n"
                           "\n"
                           "{\"name\":\"x\"}";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

static void build_should_not_url_encode_query_values(void** state)
{
    (void)state;
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    set_segment(&req, 0, "x");
    req.path_segment_count = 1;
    /* Value contains an already-percent-encoded sequence; builder
     * must copy it verbatim, not re-encode. */
    set_query_param(&req, 0, "auth", "a%20b");
    req.query_param_count = 1;

    uint8_t      out[128];
    size_t       out_len = 0;
    pubnub_res_t rc =
        pn_signing_string_build(&req, "pk", out, sizeof(out), &out_len);

    assert_int_equal(rc, PUBNUB_OK);
    const char* expected = "GET\npk\n/x\nauth=a%20b\n";
    assert_int_equal(out_len, strlen(expected));
    assert_memory_equal(out, expected, out_len);
}

/* ======================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(verb_should_map_get),
        cmocka_unit_test(verb_should_map_post),
        cmocka_unit_test(verb_should_map_patch),
        cmocka_unit_test(verb_should_map_delete),
        cmocka_unit_test(verb_should_return_unknown_for_out_of_range),
        cmocka_unit_test(needed_bytes_should_return_zero_for_null_publish_key),
        cmocka_unit_test(needed_bytes_should_return_zero_for_null_request),
        cmocka_unit_test(needed_bytes_should_account_for_trailing_lf_on_bodyless),
        cmocka_unit_test(needed_bytes_should_include_body_for_post),
        cmocka_unit_test(needed_bytes_should_ignore_body_for_get),
        cmocka_unit_test(build_should_reject_too_small_output),
        cmocka_unit_test(build_should_reject_null_args),
        cmocka_unit_test(build_should_match_legacy_format_for_get_no_body),
        cmocka_unit_test(build_should_include_body_for_post),
        cmocka_unit_test(build_should_sign_publish_post_as_get_to_work_around_pam_bug),
        cmocka_unit_test(len_should_match_publish_post_workaround),
        cmocka_unit_test(build_should_keep_trailing_lf_on_empty_query_and_no_body),
        cmocka_unit_test(build_should_emit_single_slash_for_empty_path),
        cmocka_unit_test(build_should_include_body_for_patch),
        cmocka_unit_test(build_should_not_url_encode_query_values),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
