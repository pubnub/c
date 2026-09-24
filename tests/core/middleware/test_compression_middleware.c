/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "core/runtime/middleware/compression_middleware/pn_middleware_compression.h"
#include "core/runtime/request_internal.h"

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <cmocka.h>

/** Mock transport that captures the last send() call. */
typedef struct mock_transport {
    pubnub_transport_provider_t vtable;
    pubnub_http_request_t       captured_request;
    uint8_t                     captured_body[4096];
    int                         fake_handle;
    int                         send_called;
} mock_transport_t;

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)response;
    mock_transport_t* mt = (mock_transport_t*)self;
    mt->send_called      = 1;
    mt->captured_request = *request;

    /* Copy body to local buffer. */
    if (NULL != request->body && request->body_len < sizeof(mt->captured_body)) {
        memcpy(mt->captured_body, request->body, request->body_len);
        mt->captured_request.body = mt->captured_body;
    }

    return &mt->fake_handle;
}

static int mock_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   transport_handle)
{
    (void)self;
    (void)transport_handle;
}

static void mock_transport_init(mock_transport_t* mt)
{
    memset(mt, 0, sizeof(*mt));
    mt->vtable.send   = mock_send;
    mt->vtable.poll   = mock_poll;
    mt->vtable.cancel = mock_cancel;
}

/** Simple allocator using libc. */
static void* stdlib_alloc_fn(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* stdlib_realloc_fn(pubnub_allocator_provider_t* self,
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

static void stdlib_free_fn(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_allocator_provider_t test_allocator = {
    .alloc   = stdlib_alloc_fn,
    .realloc = stdlib_realloc_fn,
    .free    = stdlib_free_fn,
};

static int s_buf_release_count = 0;

static pubnub_buffer_t test_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    uint8_t* ptr = (uint8_t*)malloc(4096);
    if (NULL == ptr) {
        return (pubnub_buffer_t){0};
    }
    pubnub_buffer_t buf = {0};
    buf.data            = ptr;
    buf.cap             = 4096;
    buf.len             = 0;
    buf.purpose         = purpose;
    return buf;
}

static void test_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    free(buf->data);
    buf->data    = NULL;
    buf->cap     = 0;
    buf->len     = 0;
    buf->purpose = PUBNUB_BUF_RX;
    ++s_buf_release_count;
}

static pubnub_allocator_provider_t test_allocator_buf = {
    .alloc       = stdlib_alloc_fn,
    .realloc     = stdlib_realloc_fn,
    .free        = stdlib_free_fn,
    .buf_acquire = test_buf_acquire,
    .buf_release = test_buf_release,
};

/** @brief Decompress gzip data for validation. */
static int decompress_gzip(const uint8_t* input,
                           size_t         input_len,
                           uint8_t*       output,
                           size_t         output_cap,
                           size_t*        output_len)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in   = (Bytef*)input;
    stream.avail_in  = (uInt)input_len;
    stream.next_out  = output;
    stream.avail_out = (uInt)output_cap;

    /* 16 + MAX_WBITS = gzip format. */
    int rc = inflateInit2(&stream, 16 + MAX_WBITS);
    if (Z_OK != rc) {
        return 0;
    }

    rc = inflate(&stream, Z_FINISH);
    if (Z_STREAM_END != rc) {
        inflateEnd(&stream);
        return 0;
    }

    *output_len = stream.total_out;
    inflateEnd(&stream);
    return 1;
}

/**
 * @brief Test that POST request body is compressed and
 *        Content-Encoding header is added.
 */
static void test_compress_post_body(void** state)
{
    (void)state;

    mock_transport_t mock_next;
    mock_transport_init(&mock_next);

    pubnub_transport_provider_t* mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator_buf, NULL);
    assert_non_null(mw);

    const char*           body     = "Hello, PubNub! This is a test body.";
    const size_t          body_len = strlen(body);
    pubnub_http_request_t request  = {0};
    request.method                 = PUBNUB_HTTP_POST;
    request.body                   = (const uint8_t*)body;
    request.body_len               = body_len;
    request.compress_body          = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = mw->send(mw, &request, &response);

    assert_non_null(handle);
    assert_int_equal(mock_next.send_called, 1);

    /* Verify body was compressed (should be smaller or similar size). */
    assert_true(mock_next.captured_request.body_len > 0);
    assert_true(mock_next.captured_request.body_len <= body_len + 100);

    /* Verify Content-Encoding header was added. */
    int found_ce = 0;
    for (unsigned int i = 0; i < mock_next.captured_request.header_count; i++) {
        pubnub_kv_t* h = &mock_next.captured_request.headers[i];
        if (0 == strncmp(h->key.ptr, "Content-Encoding", h->key.len)
            && 0 == strncmp(h->value.ptr, "gzip", h->value.len)) {
            found_ce = 1;
            break;
        }
    }
    assert_int_equal(found_ce, 1);

    /* Decompress and verify original content. */
    uint8_t decompressed[1024];
    size_t  decomp_len = 0;
    int     ok         = decompress_gzip(mock_next.captured_request.body,
                             mock_next.captured_request.body_len,
                             decompressed,
                             sizeof(decompressed),
                             &decomp_len);
    assert_int_equal(ok, 1);
    assert_int_equal(decomp_len, body_len);
    assert_memory_equal(decompressed, body, body_len);

    /* Body is mutated in-place during transit; restored on destroy. */
    pn_middleware_compression_destroy(mw, &test_allocator_buf);
    assert_ptr_equal(request.body, body);
    assert_int_equal(request.body_len, body_len);
}

/** @brief Test that GET requests pass through without compression. */
static void test_passthrough_get(void** state)
{
    (void)state;

    mock_transport_t mock_next;
    mock_transport_init(&mock_next);

    pubnub_transport_provider_t* mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator, NULL);
    assert_non_null(mw);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = mw->send(mw, &request, &response);

    assert_non_null(handle);
    assert_int_equal(mock_next.send_called, 1);
    assert_null(mock_next.captured_request.body);
    assert_int_equal(mock_next.captured_request.body_len, 0);

    pn_middleware_compression_destroy(mw, &test_allocator);
}

/** @brief Test that POST with NULL body passes through. */
static void test_passthrough_no_body(void** state)
{
    (void)state;

    mock_transport_t mock_next;
    mock_transport_init(&mock_next);

    pubnub_transport_provider_t* mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator, NULL);
    assert_non_null(mw);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_POST;
    request.body                  = NULL;
    request.body_len              = 0;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = mw->send(mw, &request, &response);

    assert_non_null(handle);
    assert_int_equal(mock_next.send_called, 1);
    assert_null(mock_next.captured_request.body);

    pn_middleware_compression_destroy(mw, &test_allocator);
}

/** @brief Test that original request body is unchanged after send. */
static void test_original_body_unchanged(void** state)
{
    (void)state;

    mock_transport_t mock_next;
    mock_transport_init(&mock_next);

    pubnub_transport_provider_t* mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator, NULL);
    assert_non_null(mw);

    const char*           body     = "Immutable body content.";
    const size_t          body_len = strlen(body);
    pubnub_http_request_t request  = {0};
    request.method                 = PUBNUB_HTTP_POST;
    request.body                   = (const uint8_t*)body;
    request.body_len               = body_len;

    pubnub_http_response_t response = {0};
    mw->send(mw, &request, &response);

    /* Original request must be unchanged. */
    assert_ptr_equal(request.body, body);
    assert_int_equal(request.body_len, body_len);
    assert_memory_equal(request.body, body, body_len);

    pn_middleware_compression_destroy(mw, &test_allocator);
}

/**
 * @brief Test that the same request can be sent twice (retry-safe).
 */
static void test_retry_safe(void** state)
{
    (void)state;

    mock_transport_t mock_next;
    mock_transport_init(&mock_next);

    pubnub_transport_provider_t* mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator_buf, NULL);
    assert_non_null(mw);

    const char*           body     = "Retry test body.";
    const size_t          body_len = strlen(body);
    pubnub_http_request_t request  = {0};
    request.method                 = PUBNUB_HTTP_POST;
    request.body                   = (const uint8_t*)body;
    request.body_len               = body_len;
    request.compress_body          = 1;

    pubnub_http_response_t response = {0};

    /* First send. */
    pubnub_transport_handle_t* handle1 = mw->send(mw, &request, &response);
    assert_non_null(handle1);

    /* Capture first compressed body. */
    uint8_t first_compressed[1024];
    size_t  first_len = mock_next.captured_request.body_len;
    assert_true(first_len < sizeof(first_compressed));
    memcpy(first_compressed, mock_next.captured_request.body, first_len);

    /* Mark first request complete so the slot is swept on next send. */
    response.completion   = PUBNUB_HTTP_COMPLETE;
    mock_next.send_called = 0;

    /* Second send (retry). */
    pubnub_transport_handle_t* handle2 = mw->send(mw, &request, &response);
    assert_non_null(handle2);

    /* Verify second send also succeeded and produced same compressed size. */
    assert_int_equal(mock_next.send_called, 1);
    assert_int_equal(mock_next.captured_request.body_len, first_len);

    /* Decompress second and verify. */
    uint8_t decompressed[1024];
    size_t  decomp_len = 0;
    int     ok         = decompress_gzip(mock_next.captured_request.body,
                             mock_next.captured_request.body_len,
                             decompressed,
                             sizeof(decompressed),
                             &decomp_len);
    assert_int_equal(ok, 1);
    assert_int_equal(decomp_len, body_len);
    assert_memory_equal(decompressed, body, body_len);

    pn_middleware_compression_destroy(mw, &test_allocator_buf);
}

/** @brief Test that cancel() restores body, removes header, releases buffer. */
static void test_cancel_restores_original_body(void** state)
{
    const uint8_t*               original_body_ptr;
    size_t                       original_body_len;
    mock_transport_t             mock_next;
    pubnub_http_request_t        request  = {0};
    pubnub_http_response_t       response = {0};
    pubnub_transport_provider_t* mw;
    pubnub_transport_handle_t*   handle;

    (void)state;

    s_buf_release_count = 0;

    mock_transport_init(&mock_next);

    mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator_buf, NULL);
    assert_non_null(mw);

    request.method        = PUBNUB_HTTP_POST;
    request.body          = (const uint8_t*)"Cancel body test.";
    request.body_len      = strlen("Cancel body test.");
    request.header_count  = 0;
    request.compress_body = 1;

    original_body_ptr = request.body;
    original_body_len = request.body_len;

    handle = mw->send(mw, &request, &response);
    assert_non_null(handle);

    /* Body should be compressed at this point. */
    assert_ptr_not_equal(request.body, original_body_ptr);
    assert_int_equal(0x1f, request.body[0]);

    mw->cancel(mw, handle);

    /* Body must be restored to original. */
    assert_ptr_equal(request.body, original_body_ptr);
    assert_int_equal(request.body_len, original_body_len);
    assert_int_equal(request.header_count, 0);

    /* Buffer must have been released exactly once. */
    assert_int_equal(1, s_buf_release_count);

    /* Original content is untouched. */
    assert_memory_equal(request.body, "Cancel body test.", original_body_len);

    pn_middleware_compression_destroy(mw, &test_allocator_buf);
}

/** Mock transport variant that counts cancel() calls. */
static int s_cancel_count;

static void mock_cancel_counting(pubnub_transport_provider_t* self,
                                 pubnub_transport_handle_t*   transport_handle)
{
    (void)self;
    (void)transport_handle;
    ++s_cancel_count;
}

static void mock_transport_init_counting(mock_transport_t* mt)
{
    mock_transport_init(mt);
    mt->vtable.cancel = mock_cancel_counting;
}

/** cancel with a stale generation must NOT match a compression
 *  slot. When the underlying pn_request_t is recycled (generation
 *  incremented) between send and cancel, the generation stored in the
 *  compression slot no longer matches the live generation, so the slot
 *  is skipped — the body is NOT restored and the buffer is NOT released.
 *  The cancel still forwards to the inner transport. */
static void test_stale_generation_cancel_no_match(void** state)
{
    mock_transport_t             mock_next;
    pubnub_transport_provider_t* mw;
    pubnub_transport_handle_t*   handle;
    pubnub_http_response_t       response = {0};

    (void)state;
    s_buf_release_count = 0;
    s_cancel_count      = 0;

    mock_transport_init_counting(&mock_next);

    mw = pn_middleware_compression_create(
        (pubnub_transport_provider_t*)&mock_next, &test_allocator_buf, NULL);
    assert_non_null(mw);

    /* Build request embedded in a pn_request_t so CONTAINER_OF works. */
    pn_request_t req;
    memset(&req, 0, sizeof(req));
    req.generation = 1;

    const char*    body     = "Stale generation test body.";
    const size_t   body_len = strlen(body);
    const uint8_t* original_body_ptr;

    req.http_request.method        = PUBNUB_HTTP_POST;
    req.http_request.body          = (const uint8_t*)body;
    req.http_request.body_len      = body_len;
    req.http_request.compress_body = 1;

    original_body_ptr = req.http_request.body;

    handle = mw->send(mw, &req.http_request, &response);
    assert_non_null(handle);

    /* Body is now compressed in-place. */
    assert_ptr_not_equal(req.http_request.body, original_body_ptr);

    /* Simulate pool recycling: increment the generation on the live
     * pn_request_t. The compression slot stored generation=1 at send
     * time, but the live request now has generation=2. */
    req.generation = 2;

    /* Cancel with the handle. The compression cancel checks:
     *   slot->handle_generation (1) == live request generation (2)
     * This fails → slot is NOT matched → body NOT restored. */
    mw->cancel(mw, handle);

    /* Buffer must NOT have been released (slot not matched). */
    assert_int_equal(0, s_buf_release_count);

    /* Body must still be compressed (NOT restored to original). */
    assert_ptr_not_equal(req.http_request.body, original_body_ptr);

    /* Inner transport cancel must still have been called (always
     * forwarded regardless of slot match). */
    assert_int_equal(1, s_cancel_count);

    /* Restore generation so destroy can clean up the slot. */
    req.generation = 1;
    pn_middleware_compression_destroy(mw, &test_allocator_buf);

    /* After destroy, body should be restored. */
    assert_ptr_equal(req.http_request.body, original_body_ptr);
    assert_int_equal(req.http_request.body_len, body_len);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_compress_post_body),
        cmocka_unit_test(test_passthrough_get),
        cmocka_unit_test(test_passthrough_no_body),
        cmocka_unit_test(test_original_body_unchanged),
        cmocka_unit_test(test_retry_safe),
        cmocka_unit_test(test_cancel_restores_original_body),
        cmocka_unit_test(test_stale_generation_cancel_no_match),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
