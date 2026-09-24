/**
 * @file test_decompression.c
 * @brief cmocka tests for the socket transport response decompression path.
 *
 * White-boxes transport_socket.c so the file-static decompression helpers
 * can be driven directly. The inflate backend is mocked to control the
 * distinction between the output buffer's capacity and the number of bytes
 * actually inflated -- the two values a single out-param signature made
 * interchangeable.
 *
 * Copyright PubNub Inc.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "providers/transport/socket/transport_socket.c"

#define MOCK_INFLATE_MAX_STEPS 4

/** Scripted outcome of one mocked inflate call. */
typedef struct mock_inflate_step {
    int    rc;
    size_t out_len;
} mock_inflate_step_t;

/** Mock control and observation state. */
static struct {
    mock_inflate_step_t steps[MOCK_INFLATE_MAX_STEPS];
    unsigned            inflate_calls;
    uint8_t*            last_output;
    size_t              last_output_cap;

    unsigned alloc_calls;
    unsigned free_calls;
    unsigned free_decomp_buf_calls;
    int      alloc_fail;
} mock_state;

static void mock_reset(void)
{
    unsigned i;

    memset(&mock_state, 0, sizeof(mock_state));
    for (i = 0; i < MOCK_INFLATE_MAX_STEPS; i++) {
        mock_state.steps[i].rc      = PN_INFLATE_OK;
        mock_state.steps[i].out_len = 1;
    }
}

/**
 * Zero the observation counters while keeping the scripted inflate outcomes,
 * so a second response on the same connection can be asserted on its own
 * allocator traffic rather than on cumulative totals.
 */
static void mock_reset_counters(void)
{
    mock_state.inflate_calls         = 0;
    mock_state.alloc_calls           = 0;
    mock_state.free_calls            = 0;
    mock_state.free_decomp_buf_calls = 0;
}

int pn_inflate_gzip(const uint8_t*                    input,
                    size_t                            input_len,
                    uint8_t*                          output,
                    size_t                            output_cap,
                    size_t*                           out_len,
                    struct pubnub_allocator_provider* alloc,
                    struct pubnub_logger_provider*    logger)
{
    const mock_inflate_step_t* step;

    (void)input;
    (void)input_len;
    (void)alloc;
    (void)logger;

    step = &mock_state.steps[mock_state.inflate_calls < MOCK_INFLATE_MAX_STEPS
                                 ? mock_state.inflate_calls
                                 : MOCK_INFLATE_MAX_STEPS - 1];
    mock_state.inflate_calls++;
    mock_state.last_output     = output;
    mock_state.last_output_cap = output_cap;

    if (PN_INFLATE_OK != step->rc) {
        return step->rc;
    }
    /* Write only out_len bytes so a caller that mistakes the capacity for
     * the inflated length is detectable by the assertions below. */
    assert_true(step->out_len <= output_cap);
    memset(output, 0xAB, step->out_len);
    *out_len = step->out_len;
    return PN_INFLATE_OK;
}

int pn_inflate_deflate(const uint8_t*                    input,
                       size_t                            input_len,
                       uint8_t*                          output,
                       size_t                            output_cap,
                       size_t*                           out_len,
                       struct pubnub_allocator_provider* alloc,
                       struct pubnub_logger_provider*    logger)
{
    return pn_inflate_gzip(
        input, input_len, output, output_cap, out_len, alloc, logger);
}

static void* mock_alloc_fn(struct pubnub_allocator_provider* self,
                           size_t                            size,
                           size_t                            align)
{
    (void)self;
    (void)align;
    if (mock_state.alloc_fail) {
        return NULL;
    }
    mock_state.alloc_calls++;
    return malloc(size);
}

static void mock_free_fn(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    mock_state.free_calls++;
    free(ptr);
}

static pubnub_allocator_provider_t mock_allocator = {
    .alloc       = mock_alloc_fn,
    .realloc     = NULL,
    .free        = mock_free_fn,
    .buf_acquire = NULL,
    .buf_release = NULL,
    .buf_grow    = NULL,
};

/**
 * Stands in for the connection_fsm.c owner-side free. Mirrors the documented
 * contract: only allocators that expose a free hook may reclaim the block and
 * clear the pointer.
 */
void pn_conn_free_decomp_buf(pn_socket_connection_t* conn,
                             pn_socket_transport_t*  transport)
{
    mock_state.free_decomp_buf_calls++;
    if (NULL == conn->decomp_buf || NULL == transport->allocator
        || NULL == transport->allocator->free) {
        return;
    }
    PN_FREE(transport->allocator, conn->decomp_buf);
    conn->decomp_buf = NULL;
}

/* Stub: the decompression test drives inflate behavior, not credential
 * wiping, so a plain free (no volatile scrub) is sufficient here. */
void pn_strfree_secure(const char* ptr, pubnub_allocator_provider_t* alloc)
{
    (void)alloc;
    if (NULL != ptr) {
        free((void*)ptr);
    }
}

void pn_connection_init(pn_socket_connection_t* conn)
{
    memset(conn, 0, sizeof(*conn));
    conn->socket = PN_INVALID_SOCKET;
}

int pn_connection_start(pn_socket_connection_t*      conn,
                        const pubnub_http_request_t* request,
                        pubnub_http_response_t*      response,
                        pn_socket_transport_t*       transport)
{
    (void)conn;
    (void)request;
    (void)response;
    (void)transport;
    return 0;
}

pn_conn_state_t pn_connection_tick(pn_socket_connection_t* conn,
                                   pn_socket_transport_t*  transport)
{
    (void)transport;
    return conn->state;
}

void pn_connection_cancel(pn_socket_connection_t* conn,
                          pn_socket_transport_t*  transport)
{
    (void)transport;
    conn->state = PN_CONN_CANCELLED;
}

void pn_connection_reset(pn_socket_connection_t* conn,
                         pn_socket_transport_t*  transport)
{
    (void)transport;
    conn->state = PN_CONN_IDLE;
}

int pn_dns_resolver_init(pn_dns_resolver_t*               resolver,
                         const pn_socket_platform_ops_t*  ops,
                         struct pubnub_platform_provider* platform)
{
    (void)ops;
    (void)platform;
    memset(resolver, 0, sizeof(*resolver));
    return 0;
}

void pn_dns_resolver_deinit(pn_dns_resolver_t* resolver)
{
    (void)resolver;
}

pn_socket_t pn_dns_resolver_socket(const pn_dns_resolver_t* resolver)
{
    (void)resolver;
    return PN_INVALID_SOCKET;
}

/* Referenced only when the IPv6 resolver path is compiled in; defined
 * unconditionally so the harness links in every toggle configuration. */
pn_socket_t pn_dns_resolver_socket_v6(const pn_dns_resolver_t* resolver)
{
    (void)resolver;
    return PN_INVALID_SOCKET;
}

uint16_t pn_http_resolve_port(const pubnub_http_request_t* request)
{
    (void)request;
    return 443;
}

int pn_keepalive_can_reuse(const pn_keepalive_conn_state_t* conn_state,
                           const pn_keepalive_target_t*     target,
                           uint64_t                         now_ms,
                           uint16_t                         max_requests,
                           uint32_t                         max_idle_ms)
{
    (void)conn_state;
    (void)target;
    (void)now_ms;
    (void)max_requests;
    (void)max_idle_ms;
    return 0;
}

/* Proxy and WPAD stubs. Referenced only when PUBNUB_ENABLE_PROXY is on;
 * defined unconditionally so the harness links in every toggle
 * configuration. */
pn_proxy_module_t* pn_proxy_connect_create(const pn_proxy_config_t* config,
                                           struct pubnub_allocator_provider* allocator)
{
    (void)config;
    (void)allocator;
    return NULL;
}

int pn_proxy_wpad_resolve(const char* target_url, pn_proxy_config_t* out)
{
    (void)target_url;
    memset(out, 0, sizeof(*out));
    return -1;
}

void pn_proxy_wpad_free(pn_proxy_config_t* config)
{
    (void)config;
}

char* pn_strdup(const char* src, pubnub_allocator_provider_t* alloc)
{
    size_t len;
    char*  out;

    if (NULL == src || NULL == alloc || NULL == alloc->alloc) {
        return NULL;
    }
    len = strlen(src);
    out = (char*)alloc->alloc(alloc, len + 1U, sizeof(void*));
    if (NULL != out) {
        memcpy(out, src, len + 1U);
    }
    return out;
}

void pn_strfree(const char* ptr, pubnub_allocator_provider_t* alloc)
{
    if (NULL != ptr && NULL != alloc && NULL != alloc->free) {
        alloc->free(alloc, (void*)ptr);
    }
}

void pn_log_variadic_(pubnub_logger_provider_t* prov,
                      pubnub_log_level_t        level,
                      const char*               file,
                      int                       line,
                      const char*               fmt,
                      ...)
{
    (void)prov;
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const pn_socket_platform_ops_t pn_posix_socket_ops    = {0};
const pn_tls_backend_t         pn_tls_openssl_backend = {0};

static uint8_t                s_compressed[128];
static pn_socket_transport_t  s_transport;
static pn_socket_connection_t s_conn;
static pubnub_http_response_t s_response;

/**
 * Prepare a connection whose parsed response looks like a gzip body of
 * @p body_len bytes.
 */
static void setup_compressed(size_t body_len)
{
    memset(&s_transport, 0, sizeof(s_transport));
    s_transport.allocator = &mock_allocator;
    s_transport.logger    = NULL;

    memset(&s_conn, 0, sizeof(s_conn));
    s_conn.socket = PN_INVALID_SOCKET;
    s_conn.state  = PN_CONN_COMPLETE;

    memset(&s_response, 0, sizeof(s_response));
    s_response.body     = s_compressed;
    s_response.body_len = body_len;

    s_conn.response     = &s_response;
    s_conn.parser.flags = PN_HTTP_FLAG_GZIP;
}

/** Re-arm the same connection for a second response on the same socket. */
static void rearm_compressed(size_t body_len)
{
    memset(&s_response, 0, sizeof(s_response));
    s_response.body     = s_compressed;
    s_response.body_len = body_len;
    s_conn.response     = &s_response;
    s_conn.state        = PN_CONN_COMPLETE;
}

/**
 * The published body length must be the inflated byte count, never the
 * output buffer's capacity. Both are size_t, so a swapped argument pair
 * used to compile silently.
 */
static void test_publishes_inflated_length_not_capacity(void** state)
{
    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.steps[0].out_len = 40;

    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 1);
    assert_int_equal(s_response.body_len, 40);
    assert_int_equal(mock_state.last_output_cap, 100U * PN_DECOMP_CAP_INITIAL_MULT);
    assert_ptr_equal(s_response.body, s_conn.decomp_buf);
    assert_int_equal(s_conn.state, PN_CONN_COMPLETE);

    pn_conn_free_decomp_buf(&s_conn, &s_transport);
}

/**
 * A second response on the same keep-alive connection gets a fresh buffer and
 * releases the previous one exactly once. Skipping the owner-side free would
 * leak the earlier response's buffer for the life of the connection.
 */
static void test_second_response_replaces_previous_buffer(void** state)
{
    uint8_t* first;

    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.steps[0].out_len = 40;
    socket_poll_decompress(&s_transport, &s_conn);
    first = s_conn.decomp_buf;
    assert_non_null(first);
    assert_int_equal(mock_state.alloc_calls, 1);

    rearm_compressed(50);
    mock_reset_counters();
    mock_state.steps[0].out_len = 70;
    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 1);
    assert_int_equal(mock_state.alloc_calls, 1);
    assert_int_equal(mock_state.free_decomp_buf_calls, 1);
    assert_int_equal(mock_state.free_calls, 1);
    assert_int_equal(mock_state.last_output_cap, 50U * PN_DECOMP_CAP_INITIAL_MULT);
    assert_non_null(s_conn.decomp_buf);
    assert_int_equal(s_response.body_len, 70);
    assert_ptr_equal(s_response.body, s_conn.decomp_buf);

    pn_conn_free_decomp_buf(&s_conn, &s_transport);
}

/**
 * A hard inflate failure must release the scratch it was handed and leave the
 * buffer the connection already owns alone -- publish never ran, so ownership
 * never transferred.
 */
static void test_inflate_failure_frees_scratch_only(void** state)
{
    uint8_t* first;

    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.steps[0].out_len = 40;
    socket_poll_decompress(&s_transport, &s_conn);
    first = s_conn.decomp_buf;
    assert_non_null(first);

    rearm_compressed(50);
    mock_reset_counters();
    mock_state.steps[0].rc = PN_INFLATE_ERR_INVALID;
    socket_poll_decompress(&s_transport, &s_conn);

    assert_ptr_equal(s_conn.decomp_buf, first);
    assert_int_equal(mock_state.alloc_calls, 1);
    assert_int_equal(mock_state.free_calls, 1);
    assert_int_equal(mock_state.free_decomp_buf_calls, 0);
    assert_int_equal(s_conn.state, PN_CONN_FAILED);
    assert_int_equal(s_response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(s_response.transport_error, PUBNUB_ERR_TRANSPORT);

    pn_conn_free_decomp_buf(&s_conn, &s_transport);
}

/** An overflow on the first attempt retries with the larger capacity. */
static void test_overflow_retry_uses_larger_buffer(void** state)
{
    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.steps[0].rc      = PN_INFLATE_ERR_OVERFLOW;
    mock_state.steps[1].out_len = 700;

    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 2);
    assert_int_equal(mock_state.alloc_calls, 2);
    assert_int_equal(mock_state.free_calls, 1);
    assert_int_equal(mock_state.last_output_cap, 100U * PN_DECOMP_CAP_RETRY_MULT);
    assert_int_equal(s_response.body_len, 700);
    assert_int_equal(s_conn.state, PN_CONN_COMPLETE);

    pn_conn_free_decomp_buf(&s_conn, &s_transport);
}

/**
 * An overflow retry while the connection still holds the previous response's
 * buffer must free three distinct things exactly once each: the first scratch,
 * the retry scratch on publish, and the prior buffer. Two allocations, two
 * frees, one of them through the owner-side path.
 */
static void test_overflow_retry_after_previous_response(void** state)
{
    uint8_t* first;

    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.steps[0].out_len = 40;
    socket_poll_decompress(&s_transport, &s_conn);
    first = s_conn.decomp_buf;
    assert_non_null(first);
    assert_int_equal(mock_state.alloc_calls, 1);

    rearm_compressed(100);
    mock_reset_counters();
    mock_state.steps[0].rc      = PN_INFLATE_ERR_OVERFLOW;
    mock_state.steps[1].out_len = 900;
    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 2);
    assert_int_equal(mock_state.alloc_calls, 2);
    assert_int_equal(mock_state.free_decomp_buf_calls, 1);
    assert_int_equal(mock_state.free_calls, 2);
    assert_ptr_not_equal(s_conn.decomp_buf, first);
    assert_int_equal(mock_state.last_output_cap, 100U * PN_DECOMP_CAP_RETRY_MULT);
    assert_int_equal(s_response.body_len, 900);

    pn_conn_free_decomp_buf(&s_conn, &s_transport);
}

/** An uncompressed body must pass through untouched. */
static void test_uncompressed_body_untouched(void** state)
{
    (void)state;
    mock_reset();
    setup_compressed(100);
    s_conn.parser.flags = 0;

    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 0);
    assert_int_equal(mock_state.alloc_calls, 0);
    assert_null(s_conn.decomp_buf);
    assert_ptr_equal(s_response.body, s_compressed);
    assert_int_equal(s_response.body_len, 100);
}

/** A failed buffer allocation must surface as an out-of-memory failure. */
static void test_alloc_failure_marks_out_of_memory(void** state)
{
    (void)state;
    mock_reset();
    setup_compressed(100);
    mock_state.alloc_fail = 1;

    socket_poll_decompress(&s_transport, &s_conn);

    assert_int_equal(mock_state.inflate_calls, 0);
    assert_null(s_conn.decomp_buf);
    assert_int_equal(s_conn.state, PN_CONN_FAILED);
    assert_int_equal(s_response.transport_error, PUBNUB_ERR_OUT_OF_MEMORY);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_publishes_inflated_length_not_capacity),
        cmocka_unit_test(test_second_response_replaces_previous_buffer),
        cmocka_unit_test(test_inflate_failure_frees_scratch_only),
        cmocka_unit_test(test_overflow_retry_uses_larger_buffer),
        cmocka_unit_test(test_overflow_retry_after_previous_response),
        cmocka_unit_test(test_uncompressed_body_untouched),
        cmocka_unit_test(test_alloc_failure_marks_out_of_memory),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
