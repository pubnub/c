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

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/providers/transport_types.h"

/* Internal declarations shared with the feature implementation. */
#include "features/files/files_internal.h"

/* Provided by the linked serialization provider (cJSON). */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Real malloc/free-backed allocator for wire tests that need genuine
 * alloc/free semantics for URL-encoded path segments. */
static void* test_allocator_alloc(pubnub_allocator_provider_t* self,
                                  size_t                       size,
                                  size_t                       align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* test_allocator_realloc(pubnub_allocator_provider_t* self,
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

static void test_allocator_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t s_test_allocator = {
    .alloc       = test_allocator_alloc,
    .realloc     = test_allocator_realloc,
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

/* Tracking allocator that counts outstanding alloc/free calls.
 *
 * The provider vtable has no user-data slot, so this wrapper embeds
 * the provider as the FIRST member so that a pointer to the provider
 * equals a pointer to the wrapper (standard C struct layout guarantee).
 * Callbacks recover the wrapper via a direct cast of the self pointer.
 */

typedef struct tracking_allocator {
    pubnub_allocator_provider_t base; /* MUST be first */
    int outstanding; /* incremented on alloc, decremented on free */
} tracking_allocator_t;

#define TRACKING_ALLOC(self) ((tracking_allocator_t*)(void*)(self))

static void* tracking_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)align;
    void* p = malloc(size);
    if (NULL != p) {
        TRACKING_ALLOC(self)->outstanding++;
    }
    return p;
}

static void* tracking_realloc(pubnub_allocator_provider_t* self,
                              void*                        ptr,
                              size_t                       old_size,
                              size_t                       new_size,
                              size_t                       align)
{
    (void)old_size;
    (void)align;
    /* When ptr is NULL this behaves like alloc — count the new block. */
    int   was_null = (NULL == ptr);
    void* p        = realloc(ptr, new_size);
    if (NULL != p && was_null) {
        TRACKING_ALLOC(self)->outstanding++;
    }
    return p;
}

static void tracking_free(pubnub_allocator_provider_t* self, void* ptr)
{
    if (NULL != ptr) {
        TRACKING_ALLOC(self)->outstanding--;
        free(ptr);
    }
}

static void tracking_allocator_init(tracking_allocator_t* t)
{
    memset(t, 0, sizeof(*t));
    t->base.alloc   = tracking_alloc;
    t->base.realloc = tracking_realloc;
    t->base.free    = tracking_free;
}

/* ================================================================== */
/* Tests: generate-upload-url request builder                          */
/* ================================================================== */

static void build_generate_url_request_correct_path_and_method(void** state)
{
    (void)state;
    pubnub_http_request_t            request = make_request();
    pubnub_serialization_provider_t* serial  = pn_serialization_default();

    const pn_file_generate_url_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "my-channel",
        .file_name     = "report.pdf",
    };

    pubnub_res_t rc = pn_file_build_generate_url_request(
        &request, serial, &s_test_allocator, &inputs);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.method, PUBNUB_HTTP_POST);

    /* Path: /v1/files/{sub}/channels/{ch}/generate-upload-url
     * = 6 segments. */
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "files", 5);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channels", 8);
    assert_memory_equal(request.path_segments[4].ptr, "my-channel", 10);
    assert_memory_equal(request.path_segments[5].ptr, "generate-upload-url", 19);

    /* Body must contain the filename JSON. */
    assert_non_null(request.body);
    assert_true(request.body_len > 0);
    /* Verify filename appears in body (portable — no memmem). */
    {
        const char* needle   = "report.pdf";
        const char* haystack = (const char*)request.body;
        int         found    = 0;
        for (size_t i = 0; i + 10 <= request.body_len; ++i) {
            if (0 == memcmp(haystack + i, needle, 10)) {
                found = 1;
                break;
            }
        }
        assert_true(found);
    }

    /* Content-Type header. */
    assert_int_equal(request.header_count, 1);
    assert_memory_equal(request.headers[0].key.ptr, "Content-Type", 12);
    assert_memory_equal(request.headers[0].value.ptr, "application/json", 16);

    /* Cleanup body (allocator-owned). */
    s_test_allocator.free(&s_test_allocator, (void*)request.body);
}

static void build_generate_url_request_rejects_null_inputs(void** state)
{
    (void)state;
    pubnub_http_request_t            request = make_request();
    pubnub_serialization_provider_t* serial  = pn_serialization_default();

    assert_int_equal(
        pn_file_build_generate_url_request(NULL, serial, &s_test_allocator, NULL),
        PUBNUB_ERR_INVALID_ARGUMENT);

    const pn_file_generate_url_inputs_t missing_channel = {
        .subscribe_key = "sub",
        .channel       = NULL,
        .file_name     = "f.txt",
    };
    assert_int_equal(pn_file_build_generate_url_request(
                         &request, serial, &s_test_allocator, &missing_channel),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: list-files request builder                                    */
/* ================================================================== */

static void build_list_request_basic_path(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const pn_file_list_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "test-channel",
        .limit         = 0,
        .next          = NULL,
    };

    pubnub_res_t rc = pn_file_build_list_request(&request, &inputs);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.method, PUBNUB_HTTP_GET);

    /* Path: /v1/files/{sub}/channels/{ch}/files = 6 segments. */
    assert_int_equal(request.path_segment_count, 6);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "files", 5);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channels", 8);
    assert_memory_equal(request.path_segments[5].ptr, "files", 5);

    /* No query params when limit=0 and next=NULL. */
    assert_int_equal(request.query_param_count, 0);
}

static void build_list_request_with_pagination(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const pn_file_list_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "ch",
        .limit         = 25,
        .next          = "page-token-abc",
    };

    pubnub_res_t rc = pn_file_build_list_request(&request, &inputs);
    assert_int_equal(rc, PUBNUB_OK);

    /* Must have limit and next query params. */
    assert_int_equal(request.query_param_count, 2);
    assert_memory_equal(request.query_params[0].key.ptr, "limit", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "25", 2);
    assert_memory_equal(request.query_params[1].key.ptr, "next", 4);
}

/* ================================================================== */
/* Tests: delete-file request builder                                   */
/* ================================================================== */

static void build_delete_request_eight_segments(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const pn_file_delete_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "my-channel",
        .file_id       = "abc-123",
        .file_name     = "report.pdf",
    };

    pubnub_res_t rc = pn_file_build_delete_request(&request, &inputs);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.method, PUBNUB_HTTP_DELETE);

    /* /v1/files/{sub}/channels/{ch}/files/{id}/{name} = 8 segments. */
    assert_int_equal(request.path_segment_count, 8);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "files", 5);
    assert_memory_equal(request.path_segments[2].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[3].ptr, "channels", 8);
    assert_memory_equal(request.path_segments[5].ptr, "files", 5);
}

static void build_delete_request_rejects_null_file_id(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const pn_file_delete_inputs_t inputs = {
        .subscribe_key = "sub",
        .channel       = "ch",
        .file_id       = NULL,
        .file_name     = "f.txt",
    };

    assert_int_equal(pn_file_build_delete_request(&request, &inputs),
                     PUBNUB_ERR_INVALID_ARGUMENT);
}

/* ================================================================== */
/* Tests: download-file request builder                                 */
/* ================================================================== */

static void build_download_request_path(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();

    const pn_file_download_inputs_t inputs = {
        .subscribe_key = "sub-c-key",
        .channel       = "my-channel",
        .file_id       = "file-id-xyz",
        .file_name     = "data.bin",
    };

    pubnub_res_t rc = pn_file_build_download_request(&request, &inputs);
    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.method, PUBNUB_HTTP_GET);

    /* Same path structure as delete: 8 segments. */
    assert_int_equal(request.path_segment_count, 8);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "files", 5);
}

/* ================================================================== */
/* Tests: publish-file-message request builder                          */
/* ================================================================== */

static void build_publish_request_nine_segments(void** state)
{
    (void)state;
    pubnub_http_request_t            request   = make_request();
    pubnub_allocator_provider_t*     allocator = &s_test_allocator;
    pubnub_serialization_provider_t* serial    = pn_serialization_default();

    const pn_file_publish_inputs_t inputs = {
        .publish_key         = "pub-c-key",
        .subscribe_key       = "sub-c-key",
        .channel             = "my-channel",
        .file_id             = "abc-123",
        .file_name           = "report.pdf",
        .message             = NULL,
        .meta                = NULL,
        .custom_message_type = NULL,
        .store               = 1,
        .ttl                 = 0,
    };
    pn_file_publish_encoded_t encoded = {0};

    pubnub_res_t rc = pn_file_build_publish_request(
        &request, allocator, serial, &inputs, NULL, &encoded);

    assert_int_equal(rc, PUBNUB_OK);
    assert_int_equal(request.method, PUBNUB_HTTP_GET);

    /* /v1/files/publish-file/{pub}/{sub}/0/{ch}/0/{msg} = 9 segments. */
    assert_int_equal(request.path_segment_count, 9);
    assert_memory_equal(request.path_segments[0].ptr, "v1", 2);
    assert_memory_equal(request.path_segments[1].ptr, "files", 5);
    assert_memory_equal(request.path_segments[2].ptr, "publish-file", 12);
    assert_memory_equal(request.path_segments[3].ptr, "pub-c-key", 9);
    assert_memory_equal(request.path_segments[4].ptr, "sub-c-key", 9);
    assert_memory_equal(request.path_segments[5].ptr, "0", 1);
    assert_memory_equal(request.path_segments[7].ptr, "0", 1);

    /* Encoded message in last segment must contain file id. */
    assert_non_null(encoded.message);
    assert_non_null(strstr(encoded.message, "abc-123"));

    /* No query params when store=1 and ttl=0 and no meta. */
    assert_int_equal(request.query_param_count, 0);

    allocator->free(allocator, encoded.channel);
    allocator->free(allocator, encoded.message);
}

static void build_publish_request_with_store_false(void** state)
{
    (void)state;
    pubnub_http_request_t            request   = make_request();
    pubnub_allocator_provider_t*     allocator = &s_test_allocator;
    pubnub_serialization_provider_t* serial    = pn_serialization_default();

    const pn_file_publish_inputs_t inputs = {
        .publish_key         = "pub",
        .subscribe_key       = "sub",
        .channel             = "ch",
        .file_id             = "id",
        .file_name           = "f.txt",
        .message             = NULL,
        .meta                = NULL,
        .custom_message_type = NULL,
        .store               = 0,
        .ttl                 = 60,
    };
    pn_file_publish_encoded_t encoded = {0};

    pubnub_res_t rc = pn_file_build_publish_request(
        &request, allocator, serial, &inputs, NULL, &encoded);
    assert_int_equal(rc, PUBNUB_OK);

    /* store=0 adds store query param; ttl is suppressed when
     * store==0. */
    assert_true(request.query_param_count >= 1);
    assert_memory_equal(request.query_params[0].key.ptr, "store", 5);
    assert_memory_equal(request.query_params[0].value.ptr, "0", 1);

    allocator->free(allocator, encoded.channel);
    allocator->free(allocator, encoded.message);
}

static void build_publish_request_with_meta_and_cmt(void** state)
{
    (void)state;
    pubnub_http_request_t            request   = make_request();
    pubnub_allocator_provider_t*     allocator = &s_test_allocator;
    pubnub_serialization_provider_t* serial    = pn_serialization_default();

    const pn_file_publish_inputs_t inputs = {
        .publish_key         = "pub",
        .subscribe_key       = "sub",
        .channel             = "ch",
        .file_id             = "id",
        .file_name           = "f.txt",
        .message             = NULL,
        .meta                = "{\"k\":\"v\"}",
        .custom_message_type = "file_v2",
        .store               = 1,
        .ttl                 = 30,
    };
    pn_file_publish_encoded_t encoded = {0};

    pubnub_res_t rc = pn_file_build_publish_request(
        &request, allocator, serial, &inputs, NULL, &encoded);
    assert_int_equal(rc, PUBNUB_OK);

    /* TTL + meta + custom_message_type query params expected. */
    assert_true(request.query_param_count >= 3);

    /* Find ttl param. */
    int found_ttl  = 0;
    int found_meta = 0;
    int found_cmt  = 0;
    for (unsigned int i = 0; i < request.query_param_count; ++i) {
        if (0 == memcmp(request.query_params[i].key.ptr, "ttl", 3)
            && 3 == request.query_params[i].key.len) {
            found_ttl = 1;
            assert_memory_equal(request.query_params[i].value.ptr, "30", 2);
        }
        if (0 == memcmp(request.query_params[i].key.ptr, "meta", 4)
            && 4 == request.query_params[i].key.len) {
            found_meta = 1;
        }
        if (0 == memcmp(request.query_params[i].key.ptr, "custom_message_type", 19)
            && 19 == request.query_params[i].key.len) {
            found_cmt = 1;
        }
    }
    assert_true(found_ttl);
    assert_true(found_meta);
    assert_true(found_cmt);

    allocator->free(allocator, encoded.channel);
    allocator->free(allocator, encoded.message);
}

/* ================================================================== */
/* Tests: response parsers                                              */
/* ================================================================== */

static void parse_list_response_parses_json_tree(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char body[] =
        "{\"status\":200,\"data\":[{\"name\":\"f.txt\"}],\"next\":\"tok\"}";

    pubnub_json_value_t* tree = NULL;
    pubnub_res_t         rc   = pn_file_parse_list_response(
        serial, (const uint8_t*)body, strlen(body), &tree);

    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(tree);

    serial->value_destroy(serial, tree);
}

static void parse_list_response_rejects_empty_body(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pubnub_json_value_t*             tree   = NULL;

    assert_int_equal(
        pn_file_parse_list_response(serial, (const uint8_t*)"", 0, &tree),
        PUBNUB_ERR_INVALID_ARGUMENT);
}

static void parse_publish_response_extracts_timetoken(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char*          body = "[1,\"Sent\",\"17234567890123456\"]";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)body, strlen(body));
    assert_non_null(tree);

    pubnub_timetoken_t tt = {NULL, 0};
    pubnub_res_t       rc = pn_file_parse_publish_response(serial, tree, &tt);
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(tt.ptr);
    assert_int_equal(tt.len, 17);
    assert_memory_equal(tt.ptr, "17234567890123456", 17);

    serial->value_destroy(serial, tree);
}

static void parse_publish_response_handles_two_element_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    /* Two-element arrays (status 0 error) still parse OK but
     * timetoken is empty. */
    const char*          body = "[0,\"Forbidden\"]";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)body, strlen(body));
    assert_non_null(tree);

    pubnub_timetoken_t tt = {NULL, 0};
    pubnub_res_t       rc = pn_file_parse_publish_response(serial, tree, &tt);
    assert_int_equal(rc, PUBNUB_OK);
    assert_null(tt.ptr);
    assert_int_equal(tt.len, 0);

    serial->value_destroy(serial, tree);
}

static void parse_publish_response_rejects_non_array(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();

    const char*          body = "{\"status\":1}";
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)body, strlen(body));
    assert_non_null(tree);

    pubnub_timetoken_t tt = {NULL, 0};
    assert_int_equal(pn_file_parse_publish_response(serial, tree, &tt),
                     PUBNUB_ERR_SERIALIZATION);

    serial->value_destroy(serial, tree);
}

/* ================================================================== */
/* Tests: response validators                                           */
/* ================================================================== */

static void list_response_validator_accepts_status_200(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"status\":200,\"data\":[]}";
    assert_int_equal(pn_file_list_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void list_response_validator_rejects_http_4xx(void** state)
{
    (void)state;
    const uint8_t body[] = "{\"error\":true}";
    assert_int_equal(pn_file_list_response_validator(body, sizeof(body) - 1, 403),
                     PUBNUB_ERR_SERVER);
}

static void publish_response_validator_accepts_status_one(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\",\"17001234567890123\"]";
    assert_int_equal(pn_file_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

static void publish_response_validator_rejects_status_zero(void** state)
{
    (void)state;
    const uint8_t body[] = "[0,\"Forbidden\"]";
    assert_int_equal(pn_file_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_ERR_SERVER);
}

static void publish_response_validator_rejects_http_4xx(void** state)
{
    (void)state;
    const uint8_t body[] = "[1,\"Sent\",\"tt\"]";
    assert_int_equal(pn_file_publish_response_validator(body, sizeof(body) - 1, 403),
                     PUBNUB_ERR_SERVER);
}

static void publish_response_validator_tolerates_whitespace(void** state)
{
    (void)state;
    const uint8_t body[] = " \t[1,\"Sent\",\"tt\"]";
    assert_int_equal(pn_file_publish_response_validator(body, sizeof(body) - 1, 200),
                     PUBNUB_OK);
}

/* ================================================================== */
/* Tests: URL parser (pn_file_parse_upload_url)                         */
/* ================================================================== */

static void parse_upload_url_splits_host_and_path(void** state)
{
    (void)state;
    const char* url  = "https://s3.amazonaws.com/bucket/key?sig=abc";
    char*       host = NULL;
    char*       path = NULL;

    pubnub_res_t rc =
        pn_file_parse_upload_url(url, &s_test_allocator, &host, &path);
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(host);
    assert_non_null(path);
    assert_string_equal(host, "s3.amazonaws.com");
    assert_string_equal(path, "bucket/key?sig=abc");

    s_test_allocator.free(&s_test_allocator, host);
    s_test_allocator.free(&s_test_allocator, path);
}

static void parse_upload_url_handles_no_path(void** state)
{
    (void)state;
    const char* url  = "https://example.com";
    char*       host = NULL;
    char*       path = NULL;

    pubnub_res_t rc =
        pn_file_parse_upload_url(url, &s_test_allocator, &host, &path);
    assert_int_equal(rc, PUBNUB_OK);
    assert_string_equal(host, "example.com");
    assert_string_equal(path, "/");

    s_test_allocator.free(&s_test_allocator, host);
    s_test_allocator.free(&s_test_allocator, path);
}

static void parse_upload_url_rejects_malformed(void** state)
{
    (void)state;
    char* host = NULL;
    char* path = NULL;

    /* No "://" in the URL. */
    assert_int_equal(
        pn_file_parse_upload_url("not-a-url", &s_test_allocator, &host, &path),
        PUBNUB_ERR_INVALID_ARGUMENT);
    assert_null(host);
    assert_null(path);
}

/* ================================================================== */
/* Tests: download response validator (WI-16)                          */
/* ================================================================== */

static void download_validator_accepts_200_any_size(void** state)
{
    (void)state;
    const uint8_t body[] = "file content";
    assert_int_equal(pn_file_download_response_validator(body, 10000000, 200),
                     PUBNUB_OK);
}

static void download_validator_rejects_http_4xx(void** state)
{
    (void)state;
    const uint8_t body[] = "Not Found";
    assert_int_equal(pn_file_download_response_validator(body, sizeof(body) - 1, 404),
                     PUBNUB_ERR_SERVER);
}

#if PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE > 0
static void download_validator_rejects_oversized_body(void** state)
{
    (void)state;
    const uint8_t body[]    = "x";
    size_t        oversized = (size_t)PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE + 1;
    assert_int_equal(pn_file_download_response_validator(body, oversized, 200),
                     PUBNUB_ERR_BUFFER_TOO_SMALL);
}
#endif

/* ================================================================== */
/* Tests: upload request builder does not hardcode timeout (WI-17)      */
/* ================================================================== */

static void upload_request_does_not_set_timeout(void** state)
{
    (void)state;
    pubnub_http_request_t request = make_request();
    const uint8_t         body[]  = "multipart body here";

    pubnub_res_t rc = pn_file_build_upload_request(
        &request, "s3.example.com", "bucket/key", "boundary123", body, sizeof(body) - 1);
    assert_int_equal(rc, PUBNUB_OK);

    /* Wire builder must NOT set timeout — caller controls it. */
    assert_int_equal(request.timeout_ms, 0);
}

/* ================================================================== */
/* Tests: generate-url body freed by state cleanup (WI-13)             */
/* ================================================================== */

static void generate_url_body_freed_by_state_cleanup_on_error_path(void** state)
{
    (void)state;

    tracking_allocator_t             t;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    tracking_allocator_init(&t);

    pubnub_allocator_provider_t* alloc = &t.base;

    /* Allocate and populate a send state the same way files_api.c does. */
    pn_file_send_state_t* send_state = (pn_file_send_state_t*)alloc->alloc(
        alloc, sizeof(*send_state), sizeof(void*));
    assert_non_null(send_state);
    memset(send_state, 0, sizeof(*send_state));
    send_state->allocator     = alloc;
    send_state->serialization = serial;

    /* Build the generate-upload-url request. */
    pubnub_http_request_t               request = make_request();
    const pn_file_generate_url_inputs_t inputs  = {
         .subscribe_key = "sub-c-key",
         .channel       = "my-channel",
         .file_name     = "report.pdf",
    };

    pubnub_res_t rc =
        pn_file_build_generate_url_request(&request, serial, alloc, &inputs);
    assert_int_equal(rc, PUBNUB_OK);
    assert_non_null(request.body);

    /* Mirror what files_api.c does: store body pointer in send state. */
    send_state->generate_url_body = (uint8_t*)request.body;

    /* At least two allocations outstanding: send_state and body buffer. */
    assert_true(t.outstanding >= 2);

    /* Cleanup must free everything including the body buffer. */
    pn_file_send_state_cleanup(send_state, alloc);

    /* All allocations made through the tracking allocator are freed. */
    assert_int_equal(t.outstanding, 0);
}

/* Allocator that fails the Nth allocation (1-based); 0 never fails. */
typedef struct failing_allocator {
    tracking_allocator_t base; /* MUST be first */
    int                  calls;
    int                  fail_at;
} failing_allocator_t;

static void* failing_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    failing_allocator_t* f = (failing_allocator_t*)(void*)self;

    if (0 != f->fail_at && ++f->calls == f->fail_at) {
        return NULL;
    }
    return tracking_alloc(self, size, align);
}

static void failing_allocator_init(failing_allocator_t* f, int fail_at)
{
    memset(f, 0, sizeof(*f));
    tracking_allocator_init(&f->base);
    f->base.base.alloc = failing_alloc;
    f->fail_at         = fail_at;
}

static const char k_gen_ok[] =
    "{\"status\":200,\"data\":{\"id\":\"file-id-1\",\"name\":\"a.txt\"},"
    "\"file_upload_request\":{\"url\":\"https://bucket.s3.amazonaws.com/\","
    "\"form_fields\":[{\"key\":\"key\",\"value\":\"abc\"},"
    "{\"key\":\"Policy\",\"value\":\"xyz\"}]}}";

static pubnub_json_value_t* parse_tree(pubnub_serialization_provider_t* serial,
                                       const char*                      json)
{
    pubnub_json_value_t* tree =
        serial->parse(serial, (const uint8_t*)json, strlen(json));

    assert_non_null(tree);
    return tree;
}

static void assert_state_empty(const pn_file_send_state_t* st)
{
    assert_null(st->file_id);
    assert_null(st->file_name);
    assert_null(st->upload_url);
    assert_null(st->form_fields);
    assert_int_equal(0, st->form_field_count);
    assert_null(st->generate_url_tree);
}

static void assert_borrowed_tree_alive(pubnub_serialization_provider_t* serial,
                                       const pubnub_json_value_t*       tree)
{
    assert_non_null(serial->object_get(tree, "status", 6));
}

static void generate_url_tree_fills_state_and_borrows(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    failing_allocator_t              fa;
    pn_file_send_state_t             st;
    pubnub_json_value_t*             tree = parse_tree(serial, k_gen_ok);

    failing_allocator_init(&fa, 0);
    memset(&st, 0, sizeof(st));
    st.allocator = &fa.base.base;

    assert_int_equal(PUBNUB_OK, pn_file_parse_generate_url_tree(serial, tree, &st));
    assert_string_equal("file-id-1", st.file_id);
    assert_string_equal("a.txt", st.file_name);
    assert_string_equal("https://bucket.s3.amazonaws.com/", st.upload_url);
    assert_int_equal(2, st.form_field_count);
    assert_memory_equal("key", st.form_fields[0].key.ptr, 3);
    assert_memory_equal("xyz", st.form_fields[1].value.ptr, 3);
    assert_null(st.generate_url_tree);
    assert_borrowed_tree_alive(serial, tree);

    fa.base.base.free(&fa.base.base, st.file_id);
    fa.base.base.free(&fa.base.base, st.file_name);
    fa.base.base.free(&fa.base.base, st.upload_url);
    fa.base.base.free(&fa.base.base, st.form_fields);
    assert_int_equal(0, fa.base.outstanding);
    serial->value_destroy(serial, tree);
}

static void generate_url_tree_rejects_bad_shapes_without_side_effects(void** state)
{
    (void)state;
    static const char* const bodies[] = {
        "{\"status\":200}",
        "{\"status\":200,\"data\":{\"name\":\"a\"},"
        "\"file_upload_request\":{\"url\":\"https://h/\",\"form_fields\":[]}}",
        "{\"status\":200,\"data\":{\"id\":\"i\"},"
        "\"file_upload_request\":{\"url\":\"https://h/\",\"form_fields\":[]}}",
        "{\"status\":200,\"data\":{\"id\":\"i\",\"name\":\"a\"},"
        "\"file_upload_request\":{\"url\":\"https://h/\"}}",
        "{\"status\":200,\"data\":{\"id\":\"i\",\"name\":\"a\"},"
        "\"file_upload_request\":{\"form_fields\":[]}}",
        "[1,2,3]",
    };
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    size_t                           i;

    for (i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        failing_allocator_t  fa;
        pn_file_send_state_t st;
        pubnub_json_value_t* tree = parse_tree(serial, bodies[i]);

        failing_allocator_init(&fa, 0);
        memset(&st, 0, sizeof(st));
        st.allocator = &fa.base.base;

        assert_int_equal(PUBNUB_ERR_SERIALIZATION,
                         pn_file_parse_generate_url_tree(serial, tree, &st));
        assert_state_empty(&st);
        assert_int_equal(0, fa.base.outstanding);
        serial->value_destroy(serial, tree);
    }
}

static void generate_url_tree_oom_releases_everything_and_keeps_tree(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    int                              fail_at;

    /* 1 = form_fields array, 2 = file_id, 3 = file_name, 4 = upload_url. */
    for (fail_at = 1; fail_at <= 4; ++fail_at) {
        failing_allocator_t  fa;
        pn_file_send_state_t st;
        pubnub_json_value_t* tree = parse_tree(serial, k_gen_ok);

        failing_allocator_init(&fa, fail_at);
        memset(&st, 0, sizeof(st));
        st.allocator = &fa.base.base;

        assert_int_equal(PUBNUB_ERR_OUT_OF_MEMORY,
                         pn_file_parse_generate_url_tree(serial, tree, &st));
        assert_state_empty(&st);
        assert_int_equal(0, fa.base.outstanding);
        assert_borrowed_tree_alive(serial, tree);
        serial->value_destroy(serial, tree);
    }
}

static void generate_url_tree_rejects_null_inputs(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    pn_file_send_state_t             st;
    pubnub_json_value_t*             tree = parse_tree(serial, k_gen_ok);

    memset(&st, 0, sizeof(st));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_file_parse_generate_url_tree(NULL, tree, &st));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_file_parse_generate_url_tree(serial, NULL, &st));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_file_parse_generate_url_tree(serial, tree, NULL));
    serial->value_destroy(serial, tree);
}

static void generate_url_tree_results_survive_body_clobber(void** state)
{
    (void)state;
    pubnub_serialization_provider_t* serial = pn_serialization_default();
    failing_allocator_t              fa;
    pn_file_send_state_t             st;
    char                             body[sizeof(k_gen_ok)];
    pubnub_json_value_t*             tree;

    memcpy(body, k_gen_ok, sizeof(body));
    tree = parse_tree(serial, body);
    failing_allocator_init(&fa, 0);
    memset(&st, 0, sizeof(st));
    st.allocator = &fa.base.base;

    assert_int_equal(PUBNUB_OK, pn_file_parse_generate_url_tree(serial, tree, &st));

    /* The transport may reuse its rx buffer once the response is handled;
     * the extracted values must not alias it (copy-on-parse contract). */
    memset(body, 'X', sizeof(body) - 1);

    assert_string_equal("file-id-1", st.file_id);
    assert_string_equal("a.txt", st.file_name);
    assert_string_equal("https://bucket.s3.amazonaws.com/", st.upload_url);
    assert_int_equal(2, st.form_field_count);
    assert_int_equal(3, st.form_fields[0].key.len);
    assert_memory_equal("key", st.form_fields[0].key.ptr, 3);
    assert_memory_equal("abc", st.form_fields[0].value.ptr, 3);
    assert_memory_equal("Policy", st.form_fields[1].key.ptr, 6);
    assert_memory_equal("xyz", st.form_fields[1].value.ptr, 3);

    fa.base.base.free(&fa.base.base, st.file_id);
    fa.base.base.free(&fa.base.base, st.file_name);
    fa.base.base.free(&fa.base.base, st.upload_url);
    fa.base.base.free(&fa.base.base, st.form_fields);
    serial->value_destroy(serial, tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_generate_url_request_correct_path_and_method),
        cmocka_unit_test(build_generate_url_request_rejects_null_inputs),
        cmocka_unit_test(build_list_request_basic_path),
        cmocka_unit_test(build_list_request_with_pagination),
        cmocka_unit_test(build_delete_request_eight_segments),
        cmocka_unit_test(build_delete_request_rejects_null_file_id),
        cmocka_unit_test(build_download_request_path),
        cmocka_unit_test(build_publish_request_nine_segments),
        cmocka_unit_test(build_publish_request_with_store_false),
        cmocka_unit_test(build_publish_request_with_meta_and_cmt),
        cmocka_unit_test(parse_list_response_parses_json_tree),
        cmocka_unit_test(parse_list_response_rejects_empty_body),
        cmocka_unit_test(parse_publish_response_extracts_timetoken),
        cmocka_unit_test(parse_publish_response_handles_two_element_array),
        cmocka_unit_test(parse_publish_response_rejects_non_array),
        cmocka_unit_test(list_response_validator_accepts_status_200),
        cmocka_unit_test(list_response_validator_rejects_http_4xx),
        cmocka_unit_test(publish_response_validator_accepts_status_one),
        cmocka_unit_test(publish_response_validator_rejects_status_zero),
        cmocka_unit_test(publish_response_validator_rejects_http_4xx),
        cmocka_unit_test(publish_response_validator_tolerates_whitespace),
        cmocka_unit_test(parse_upload_url_splits_host_and_path),
        cmocka_unit_test(parse_upload_url_handles_no_path),
        cmocka_unit_test(parse_upload_url_rejects_malformed),
        cmocka_unit_test(download_validator_accepts_200_any_size),
        cmocka_unit_test(download_validator_rejects_http_4xx),
#if PUBNUB_CFG_FILES_MAX_DOWNLOAD_SIZE > 0
        cmocka_unit_test(download_validator_rejects_oversized_body),
#endif
        cmocka_unit_test(upload_request_does_not_set_timeout),
        cmocka_unit_test(generate_url_body_freed_by_state_cleanup_on_error_path),
        cmocka_unit_test(generate_url_tree_fills_state_and_borrows),
        cmocka_unit_test(generate_url_tree_rejects_bad_shapes_without_side_effects),
        cmocka_unit_test(generate_url_tree_oom_releases_everything_and_keeps_tree),
        cmocka_unit_test(generate_url_tree_rejects_null_inputs),
        cmocka_unit_test(generate_url_tree_results_survive_body_clobber),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
