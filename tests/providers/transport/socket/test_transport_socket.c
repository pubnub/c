/**
 * @file test_transport_socket.c
 * @brief cmocka tests for the socket transport vtable integration.
 *
 * Uses mock platform ops, DNS resolver overrides, and TLS backend
 * to test the transport-level send/poll/cancel lifecycle without
 * real networking.
 *
 * Copyright PubNub Inc.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#include "providers/transport/socket/transport_socket_internal.h"
#include "providers/transport/socket/dns/dns_resolver.h"

#include <stdlib.h>

/* Fixed-size RX buffer for round-trip tests. */
#define MOCK_RX_BUF_SIZE 4096
static uint8_t         mock_rx_storage[MOCK_RX_BUF_SIZE];
static pubnub_buffer_t mock_rx_buf;
static int             mock_rx_buf_in_use;

/** Mock control state. */
static struct {
    /* Socket ops. */
    pn_socket_t next_socket;
    int         socket_create_calls;
    int         connect_result;
    int         check_connect_result;
    int         send_result;
    /* When non-zero, the next send returns this value, then self-clears. */
    int send_fail_once;
    int set_nonblocking_result;
    int set_keepalive_result;
    int socket_destroy_calls;
    int poll_add_calls;
    int poll_remove_calls;
    int poll_modify_calls;

    /* Recv data (delivered sequentially). */
    const uint8_t* recv_data;
    size_t         recv_data_len;
    size_t         recv_offset;

    /* Poll wait simulation. */
    int poll_wait_result;

    /* Monotonic time. */
    uint64_t current_time_ms;

    /* DNS resolver mock. */
    pn_dns_state_t dns_state;
    pn_sockaddr_t  dns_results[4];
    size_t         dns_result_count;
    int            dns_init_result;
    int            dns_start_calls;

    /* DNS query capture for response simulation. */
    uint8_t dns_query_a[512];
    size_t  dns_query_a_len;
    uint8_t dns_query_aaaa[512];
    size_t  dns_query_aaaa_len;
    size_t  dns_query_count;
    size_t  dns_recv_call;

    /* TLS mock. */
    int   tls_ctx_create_calls;
    int   tls_ctx_destroy_calls;
    void* tls_fake_ctx;
} mock;

static void mock_reset(void)
{
    memset(&mock, 0, sizeof(mock));
    mock_rx_buf_in_use          = 0;
    mock.next_socket            = 42;
    mock.connect_result         = 1; /* immediate connect */
    mock.check_connect_result   = 1;
    mock.set_nonblocking_result = 0;
    mock.set_keepalive_result   = 0;
    mock.current_time_ms        = 1000000;
    mock.poll_wait_result       = 1;
    mock.dns_state              = PN_DNS_STATE_DONE;
    mock.dns_result_count       = 1;
    mock.dns_init_result        = 0;
    mock.tls_fake_ctx           = (void*)0xCA01;

    mock.dns_results[0].family       = PN_AF_INET;
    mock.dns_results[0].port         = 443;
    mock.dns_results[0].addr.ipv4[0] = 127;
    mock.dns_results[0].addr.ipv4[1] = 0;
    mock.dns_results[0].addr.ipv4[2] = 0;
    mock.dns_results[0].addr.ipv4[3] = 1;
}

/* --- Mock platform ops --- */

static pn_socket_t mock_socket_create(const pn_socket_platform_ops_t* self,
                                      uint16_t                        family,
                                      int                             dgram)
{
    (void)self;
    (void)family;
    (void)dgram;
    mock.socket_create_calls++;
    return mock.next_socket++;
}

static void mock_socket_destroy(const pn_socket_platform_ops_t* self, pn_socket_t sock)
{
    (void)self;
    (void)sock;
    mock.socket_destroy_calls++;
}

static int mock_socket_connect(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const pn_sockaddr_t*            addr)
{
    (void)self;
    (void)sock;
    (void)addr;
    return mock.connect_result;
}

static int mock_socket_check_connect(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return mock.check_connect_result;
}

static int mock_socket_send(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            const uint8_t*                  data,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    (void)data;
    if (0 != mock.send_fail_once) {
        int r               = mock.send_fail_once;
        mock.send_fail_once = 0;
        return r;
    }
    if (0 != mock.send_result) {
        return mock.send_result;
    }
    return (int)len;
}

static int mock_socket_recv(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            uint8_t*                        buf,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    if (NULL == mock.recv_data || mock.recv_offset >= mock.recv_data_len) {
        return 0; /* Would-block. */
    }
    size_t avail = mock.recv_data_len - mock.recv_offset;
    if (avail > len) {
        avail = len;
    }
    memcpy(buf, mock.recv_data + mock.recv_offset, avail);
    mock.recv_offset += avail;
    return (int)avail;
}

static int mock_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return mock.set_nonblocking_result;
}

static int mock_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock,
                                     const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;
    (void)sock;
    (void)config;
    return mock.set_keepalive_result;
}

static int mock_poll_init(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set)
{
    (void)self;
    memset(poll_set, 0, sizeof(*poll_set));
    return 0;
}

static void mock_poll_deinit(const pn_socket_platform_ops_t* self,
                             pn_poll_set_t*                  poll_set)
{
    (void)self;
    (void)poll_set;
}

static int mock_poll_add(const pn_socket_platform_ops_t* self,
                         pn_poll_set_t*                  poll_set,
                         pn_socket_t                     sock,
                         uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    (void)events;
    mock.poll_add_calls++;
    return 0;
}

static int mock_poll_modify(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock,
                            uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    (void)events;
    mock.poll_modify_calls++;
    return 0;
}

static int mock_poll_remove(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock)
{
    (void)self;
    (void)poll_set;
    (void)sock;
    mock.poll_remove_calls++;
    return 0;
}

static int mock_poll_wait(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set,
                          int                             timeout_ms)
{
    (void)self;
    (void)poll_set;
    (void)timeout_ms;
    return mock.poll_wait_result;
}

static size_t mock_poll_ready_count(const pn_socket_platform_ops_t* self,
                                    const pn_poll_set_t*            poll_set)
{
    (void)self;
    (void)poll_set;
    return 0;
}

static int mock_poll_get_ready(const pn_socket_platform_ops_t* self,
                               const pn_poll_set_t*            poll_set,
                               size_t                          index,
                               pn_socket_t*                    out_sock,
                               uint8_t*                        out_events)
{
    (void)self;
    (void)poll_set;
    (void)index;
    (void)out_sock;
    (void)out_events;
    return -1;
}

static int mock_dns_discover_servers(const pn_socket_platform_ops_t* self,
                                     pn_sockaddr_t*                  servers,
                                     size_t                          capacity,
                                     size_t*                         out_count)
{
    (void)self;
    (void)capacity;
    servers[0].family       = PN_AF_INET;
    servers[0].port         = 53;
    servers[0].addr.ipv4[0] = 8;
    servers[0].addr.ipv4[1] = 8;
    servers[0].addr.ipv4[2] = 8;
    servers[0].addr.ipv4[3] = 8;
    *out_count              = 1;
    return 0;
}

static int mock_socket_sendto(const pn_socket_platform_ops_t* self,
                              pn_socket_t                     sock,
                              const uint8_t*                  data,
                              size_t                          len,
                              const pn_sockaddr_t*            addr)
{
    (void)self;
    (void)sock;
    (void)addr;
    /* Capture first two DNS queries (A and AAAA) for response simulation. */
    if (0 == mock.dns_query_count && len <= sizeof(mock.dns_query_a)) {
        memcpy(mock.dns_query_a, data, len);
        mock.dns_query_a_len = len;
        mock.dns_query_count++;
    } else if (1 == mock.dns_query_count && len <= sizeof(mock.dns_query_aaaa)) {
        memcpy(mock.dns_query_aaaa, data, len);
        mock.dns_query_aaaa_len = len;
        mock.dns_query_count++;
    }
    return (int)len;
}

/** @brief Build a minimal DNS A response echoing the query's transaction ID. */
static size_t build_dns_a_response(const uint8_t* query,
                                   size_t         query_len,
                                   uint8_t*       out,
                                   size_t         cap)
{
    if (query_len < 12 || cap < query_len + 16) {
        return 0;
    }
    memcpy(out, query, query_len);
    out[2]     = 0x81;
    out[3]     = 0x80;
    out[6]     = 0x00;
    out[7]     = 0x01;
    size_t pos = query_len;
    out[pos++] = 0xC0;
    out[pos++] = 0x0C;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x01;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x3C;
    out[pos++] = 0x00;
    out[pos++] = 0x04;
    out[pos++] = 93;
    out[pos++] = 184;
    out[pos++] = 216;
    out[pos++] = 34;
    return pos;
}

/** @brief Build a minimal DNS AAAA response with no answers (NXDOMAIN-style). */
static size_t build_dns_nodata_response(const uint8_t* query,
                                        size_t         query_len,
                                        uint8_t*       out,
                                        size_t         cap)
{
    if (query_len < 12 || cap < query_len) {
        return 0;
    }
    memcpy(out, query, query_len);
    out[2] = 0x81;
    out[3] = 0x80;
    out[6] = 0x00;
    out[7] = 0x00;
    return query_len;
}

static int mock_socket_recvfrom(const pn_socket_platform_ops_t* self,
                                pn_socket_t                     sock,
                                uint8_t*                        buf,
                                size_t                          cap,
                                pn_sockaddr_t*                  addr)
{
    (void)self;
    (void)sock;

    /* Return A response on first call, AAAA no-data on second, then nothing. */
    size_t n = 0;
    if (0 == mock.dns_recv_call && mock.dns_query_a_len > 0) {
        n = build_dns_a_response(mock.dns_query_a, mock.dns_query_a_len, buf, cap);
        mock.dns_recv_call++;
        if (n > 0 && NULL != addr) {
            /* Source must match the server configured by mock_socket_get_dns. */
            addr->family       = PN_AF_INET;
            addr->port         = 53;
            addr->addr.ipv4[0] = 8;
            addr->addr.ipv4[1] = 8;
            addr->addr.ipv4[2] = 8;
            addr->addr.ipv4[3] = 8;
        }
        return (n > 0) ? (int)n : 0;
    }
    if (1 == mock.dns_recv_call && mock.dns_query_aaaa_len > 0) {
        n = build_dns_nodata_response(
            mock.dns_query_aaaa, mock.dns_query_aaaa_len, buf, cap);
        mock.dns_recv_call++;
        if (n > 0 && NULL != addr) {
            addr->family       = PN_AF_INET;
            addr->port         = 53;
            addr->addr.ipv4[0] = 8;
            addr->addr.ipv4[1] = 8;
            addr->addr.ipv4[2] = 8;
            addr->addr.ipv4[3] = 8;
        }
        return (n > 0) ? (int)n : 0;
    }
    return 0;
}

static pn_socket_platform_ops_t mock_ops = {
    .socket_create          = mock_socket_create,
    .socket_destroy         = mock_socket_destroy,
    .socket_connect         = mock_socket_connect,
    .socket_check_connect   = mock_socket_check_connect,
    .socket_send            = mock_socket_send,
    .socket_recv            = mock_socket_recv,
    .socket_sendto          = mock_socket_sendto,
    .socket_recvfrom        = mock_socket_recvfrom,
    .socket_set_nonblocking = mock_socket_set_nonblocking,
    .socket_set_keepalive   = mock_socket_set_keepalive,
    .poll_init              = mock_poll_init,
    .poll_deinit            = mock_poll_deinit,
    .poll_add               = mock_poll_add,
    .poll_modify            = mock_poll_modify,
    .poll_remove            = mock_poll_remove,
    .poll_wait              = mock_poll_wait,
    .poll_ready_count       = mock_poll_ready_count,
    .poll_get_ready         = mock_poll_get_ready,
    .dns_discover_servers   = mock_dns_discover_servers,
};

/* --- Mock platform provider --- */

static uint64_t mock_monotonic_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return mock.current_time_ms;
}

static int mock_random_bytes(struct pubnub_platform_provider* self,
                             uint8_t*                         buf,
                             size_t                           len)
{
    (void)self;
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i ^ 0xA5);
    }
    return 0;
}

static struct pubnub_platform_provider mock_platform = {
    .monotonic_ms = mock_monotonic_ms,
    .random_bytes = mock_random_bytes,
};

/* --- Mock allocator provider --- */

static void* mock_alloc(struct pubnub_allocator_provider* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void* mock_realloc(struct pubnub_allocator_provider* self,
                          void*                             ptr,
                          size_t                            old_size,
                          size_t                            new_size,
                          size_t                            align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return realloc(ptr, new_size);
}

static void mock_free(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire(struct pubnub_allocator_provider* self,
                                        pubnub_buf_purpose_t purpose)
{
    (void)self;
    (void)purpose;
    if (mock_rx_buf_in_use) {
        pubnub_buffer_t empty = {0};
        return empty;
    }
    mock_rx_buf.data    = mock_rx_storage;
    mock_rx_buf.cap     = MOCK_RX_BUF_SIZE;
    mock_rx_buf.len     = 0;
    mock_rx_buf.purpose = purpose;
    mock_rx_buf_in_use  = 1;
    return mock_rx_buf;
}

static void mock_buf_release(struct pubnub_allocator_provider* self,
                             pubnub_buffer_t*                  buf)
{
    (void)self;
    (void)buf;
    mock_rx_buf_in_use = 0;
}

static int mock_buf_grow(struct pubnub_allocator_provider* self,
                         pubnub_buffer_t*                  buf,
                         size_t                            new_cap)
{
    (void)self;
    (void)buf;
    (void)new_cap;
    /* Fixed buffer; cannot grow. Signal failure so callers choose another path. */
    return -1;
}

static pubnub_allocator_provider_t mock_allocator = {
    .alloc       = mock_alloc,
    .realloc     = mock_realloc,
    .free        = mock_free,
    .buf_acquire = mock_buf_acquire,
    .buf_release = mock_buf_release,
    .buf_grow    = mock_buf_grow,
};

/* --- Mock TLS backend --- */

static void* mock_tls_ctx_create(const pn_tls_config_t*             cfg,
                                 const struct pubnub_provider_deps* deps)
{
    (void)cfg;
    (void)deps;
    mock.tls_ctx_create_calls++;
    return mock.tls_fake_ctx;
}

static void mock_tls_ctx_destroy(void* ctx)
{
    (void)ctx;
    mock.tls_ctx_destroy_calls++;
}

static pn_tls_backend_t mock_tls_backend = {
    .ctx_create      = mock_tls_ctx_create,
    .ctx_destroy     = mock_tls_ctx_destroy,
    .session_create  = NULL,
    .handshake       = NULL,
    .send            = NULL,
    .recv            = NULL,
    .session_destroy = NULL,
};

/* --- Test helpers --- */

static pubnub_transport_provider_t* create_transport(void)
{
    return pn_socket_transport_create(
        &mock_ops, &mock_tls_backend, NULL, NULL, &mock_allocator);
}

static pubnub_transport_provider_t* create_transport_no_tls(void)
{
    return pn_socket_transport_create(&mock_ops, NULL, NULL, NULL, &mock_allocator);
}

static int init_transport(pubnub_transport_provider_t* tp)
{
    pubnub_provider_deps_t deps = {0};
    deps.allocator              = &mock_allocator;
    deps.platform               = &mock_platform;
    deps.logger                 = NULL;
    return tp->init(tp, &deps);
}

/**
 * @brief Pre-populate the DNS cache so sends to ps.pndsn.com resolve instantly.
 *
 * Directly writes a cache entry into the resolver, bypassing actual UDP I/O.
 * Subsequent calls to pn_dns_resolver_start for the same hostname return DONE
 * immediately without touching the network.
 */
static void prime_dns_cache(pubnub_transport_provider_t* tp)
{
    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;

    pn_dns_cache_entry_t* entry = &t->resolver.cache[0];
    strncpy(entry->hostname, "ps.pndsn.com", PUBNUB_CFG_MAX_HOSTNAME_LEN - 1);
    entry->hostname[PUBNUB_CFG_MAX_HOSTNAME_LEN - 1] = '\0';
    entry->addrs[0].family                           = PN_AF_INET;
    entry->addrs[0].port                             = 0;
    entry->addrs[0].addr.ipv4[0]                     = 93;
    entry->addrs[0].addr.ipv4[1]                     = 184;
    entry->addrs[0].addr.ipv4[2]                     = 216;
    entry->addrs[0].addr.ipv4[3]                     = 34;
    entry->addr_count                                = 1;
    entry->ttl_sec                                   = 3600;
    entry->timestamp_ms                              = mock.current_time_ms;
}

/* --- Tests --- */

static void test_create_returns_valid_vtable(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport();
    assert_non_null(tp);
    assert_non_null(tp->send);
    assert_non_null(tp->poll);
    assert_non_null(tp->cancel);
    assert_non_null(tp->init);
    assert_non_null(tp->deinit);

    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_create_null_ops_returns_null(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = pn_socket_transport_create(
        NULL, &mock_tls_backend, NULL, NULL, &mock_allocator);
    assert_null(tp);
}

static void test_create_null_allocator_returns_null(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp =
        pn_socket_transport_create(&mock_ops, &mock_tls_backend, NULL, NULL, NULL);
    assert_null(tp);
}

static void test_init_stores_deps(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);

    int rc = init_transport(tp);
    assert_int_equal(0, rc);

    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    assert_ptr_equal(&mock_allocator, t->allocator);
    assert_ptr_equal(&mock_platform, t->platform);
    assert_int_equal(1, t->initialized);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_init_creates_tls_context(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport();
    assert_non_null(tp);

    int rc = init_transport(tp);
    assert_int_equal(0, rc);
    assert_int_equal(1, mock.tls_ctx_create_calls);

    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    assert_ptr_equal(mock.tls_fake_ctx, t->tls_ctx);

    tp->deinit(tp);
    assert_int_equal(1, mock.tls_ctx_destroy_calls);

    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_init_null_deps_returns_error(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);

    int rc = tp->init(tp, NULL);
    assert_int_equal(-1, rc);

    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_send_null_request_returns_null(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, NULL, &response);
    assert_null(handle);
    assert_int_equal(PUBNUB_HTTP_ERROR, response.completion);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, response.transport_error);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_send_returns_handle(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Response should still be pending after send. */
    assert_int_equal(PUBNUB_HTTP_PENDING, response.completion);

    tp->cancel(tp, handle);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_send_queue_full(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     responses[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 1];
    pubnub_transport_handle_t* handles[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS + 1];
    memset(responses, 0, sizeof(responses));

    /* Pre-populate DNS cache so all sends resolve instantly. */
    prime_dns_cache(tp);

    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        handles[i] = tp->send(tp, &request, &responses[i]);
        assert_non_null(handles[i]);
    }

    /* Next send should fail with QUEUE_FULL. */
    pubnub_http_response_t     overflow_resp = {0};
    pubnub_transport_handle_t* overflow_handle =
        tp->send(tp, &request, &overflow_resp);
    assert_null(overflow_handle);
    assert_int_equal(PUBNUB_HTTP_ERROR, overflow_resp.completion);
    assert_int_equal(PUBNUB_ERR_QUEUE_FULL, overflow_resp.transport_error);

    /* Cleanup. */
    for (int i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        tp->cancel(tp, handles[i]);
    }
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_cancel_sets_cancelled(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    tp->cancel(tp, handle);

    /* After cancel, response should show error/cancelled. */
    assert_int_equal(PUBNUB_HTTP_ERROR, response.completion);
    assert_int_equal(PUBNUB_ERR_CANCELLED, response.transport_error);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_poll_returns_non_negative(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    int completed = tp->poll(tp, 0);
    assert_true(completed >= 0);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_deinit_closes_connections(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* deinit should close all active connections. */
    tp->deinit(tp);

    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    assert_int_equal(0, t->initialized);
    assert_true(mock.socket_destroy_calls > 0);

    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_destroy_null_is_safe(void** state)
{
    (void)state;
    pn_socket_transport_destroy(NULL, &mock_allocator);
    pn_socket_transport_destroy(NULL, NULL);
}

/**
 * Verify that socket_poll() advances a COMPLETE connection to
 * KEEP_ALIVE_IDLE in the same poll call. Before the bug fix, tick_complete()
 * was never called because the COMPLETE skip at the top of the loop fired on
 * re-entry; the connection slot stayed in COMPLETE indefinitely.
 */
static void test_poll_complete_advances_to_keepalive_idle(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time/0";
    request.path_segments[0].len  = 7;
    request.path_segment_count    = 1;
    request.timeout_ms            = 5000;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Poll until completed (drives DNS → CONNECTING → SENDING_HEADERS →
     * RECEIVING_RESPONSE → COMPLETE → KEEP_ALIVE_IDLE in one or more ticks). */
    int completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }

    /* At least one completion reported. */
    assert_true(completed >= 1);

    /* Decode tagged handle to reach the underlying connection slot. */
    pn_socket_transport_t* t        = (pn_socket_transport_t*)tp;
    int                    conn_idx = (int)((uintptr_t)handle & 0xFFu);
    assert_true(conn_idx >= 0 && conn_idx < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS);
    pn_socket_connection_t* conn = &t->connections[conn_idx];
    assert_int_not_equal(conn->state, PN_CONN_COMPLETE);

    /* Keep-alive enabled path: slot moves to KEEP_ALIVE_IDLE (Connection:
     * close not set in mock response) so the socket stays open. */
    assert_int_equal(conn->state, PN_CONN_KEEP_ALIVE_IDLE);
    assert_int_not_equal(conn->socket, PN_INVALID_SOCKET);

    /* Response must be populated. */
    assert_int_equal(response.completion, PUBNUB_HTTP_COMPLETE);
    assert_int_equal(response.status_code, 200);

    tp->cancel(tp, handle);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
    (void)t;
}

/**
 * Verify that socket_poll() advances a COMPLETE connection all the way to
 * IDLE in the same poll call when the response carries Connection: close.
 * The CLOSING state must not persist across poll boundaries.
 */
static void test_poll_complete_advances_to_idle_on_connection_close(void** state)
{
    (void)state;
    mock_reset();

    /* The real HTTP parser sets PN_HTTP_FLAG_CONNECTION_CLOSE from this header. */
    static const char* resp =
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK";
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time/0";
    request.path_segments[0].len  = 7;
    request.path_segment_count    = 1;
    request.timeout_ms            = 5000;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Decode tagged handle. */
    pn_socket_transport_t*  t2        = (pn_socket_transport_t*)tp;
    int                     conn_idx2 = (int)((uintptr_t)handle & 0xFFu);
    pn_socket_connection_t* conn      = &t2->connections[conn_idx2];

    int completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }

    assert_true(completed >= 1);

    /* Connection: close path: slot must go all the way to IDLE. */
    assert_int_not_equal(conn->state, PN_CONN_COMPLETE);
    assert_int_not_equal(conn->state, PN_CONN_CLOSING);
    assert_int_equal(conn->state, PN_CONN_IDLE);
    assert_int_equal(conn->socket, PN_INVALID_SOCKET);

    /* rx_buf must survive tick_closing so the core can read the body.
     * A premature buf_release on arena would silently hand the slot to the
     * next buf_acquire — assert the body is still accessible. */
    assert_non_null(response.body);
    assert_int_equal(2, (int)response.body_len);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_concurrent_sends(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t resp1 = {0};
    pubnub_http_response_t resp2 = {0};

    /* Pre-populate DNS cache so both sends resolve instantly. */
    prime_dns_cache(tp);

    pubnub_transport_handle_t* h1 = tp->send(tp, &request, &resp1);
    pubnub_transport_handle_t* h2 = tp->send(tp, &request, &resp2);

    assert_non_null(h1);
    assert_non_null(h2);
    assert_ptr_not_equal(h1, h2);

    tp->cancel(tp, h1);
    tp->cancel(tp, h2);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/* socket_cancel rejects invalid handles. */

static void test_cancel_null_handle_no_crash(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    /* Must not crash. */
    tp->cancel(tp, NULL);
    tp->cancel(NULL, NULL);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_cancel_invalid_stack_pointer_rejected(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    /* Send a real request so we have a known-good connection state. */
    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Snapshot the connections array before the invalid cancel. */
    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    pn_socket_connection_t snapshot[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    memcpy(snapshot, t->connections, sizeof(snapshot));

    /* A stack pointer that is not a connection slot. */
    int fake_handle = 42;
    tp->cancel(tp, (pubnub_transport_handle_t*)&fake_handle);

    /* Connections array must be byte-identical — the invalid cancel
     * was rejected without touching any slot. */
    assert_memory_equal(snapshot, t->connections, sizeof(snapshot));

    /* Cleanup the valid handle. */
    tp->cancel(tp, handle);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static void test_cancel_invalid_heap_pointer_rejected(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);

    /* A heap pointer that is not a connection slot. */
    void* fake = malloc(sizeof(pn_socket_connection_t));
    assert_non_null(fake);
    memset(fake, 0, sizeof(pn_socket_connection_t));

    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    pn_socket_connection_t snapshot[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    memcpy(snapshot, t->connections, sizeof(snapshot));

    tp->cancel(tp, (pubnub_transport_handle_t*)fake);

    assert_memory_equal(snapshot, t->connections, sizeof(snapshot));

    free(fake);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/** socket_cancel rejects a pubnub_http_request_t* handle that
 *  arrives via retry middleware passthrough. The request pointer is not
 *  a connection slot, so socket_handle_index must return -1 and the
 *  cancel must be a no-op (no state corruption). */
static void test_cancel_request_pointer_rejected(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    /* Send a real request so we have known-good connection state. */
    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Snapshot connections before the invalid cancel. */
    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    pn_socket_connection_t snapshot[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    memcpy(snapshot, t->connections, sizeof(snapshot));

    /* Cancel with a pubnub_http_request_t* — simulates the retry
     * middleware passthrough path where the retry handle (a request
     * pointer) reaches the socket transport. */
    tp->cancel(tp, (pubnub_transport_handle_t*)&request);

    /* Connections must be byte-identical — the request pointer was
     * rejected without touching any slot. */
    assert_memory_equal(snapshot, t->connections, sizeof(snapshot));

    /* Cleanup the valid handle. */
    tp->cancel(tp, handle);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/** Tagged handle encode/decode round-trip. */
static void test_tagged_handle_encode_decode(void** state)
{
    (void)state;
    int                        idx;
    uint16_t                   gen;
    pubnub_transport_handle_t* h;

    /* Slot 0, gen 0. */
    h   = (pubnub_transport_handle_t*)(uintptr_t)(((uint32_t)0 << 8) | 0u);
    idx = (int)((uintptr_t)h & 0xFFu);
    gen = (uint16_t)(((uintptr_t)h >> 8) & 0xFFFFu);
    assert_int_equal(0, idx);
    assert_int_equal(0, gen);

    /* Slot 3, gen 42. */
    h   = (pubnub_transport_handle_t*)(uintptr_t)(((uint32_t)42 << 8) | 3u);
    idx = (int)((uintptr_t)h & 0xFFu);
    gen = (uint16_t)(((uintptr_t)h >> 8) & 0xFFFFu);
    assert_int_equal(3, idx);
    assert_int_equal(42, gen);

    /* Slot 255, gen 65535 (max values). */
    h = (pubnub_transport_handle_t*)(uintptr_t)(((uint32_t)65535 << 8) | 255u);
    idx = (int)((uintptr_t)h & 0xFFu);
    gen = (uint16_t)(((uintptr_t)h >> 8) & 0xFFFFu);
    assert_int_equal(255, idx);
    assert_int_equal(65535, gen);
}

/** Stale generation handle is rejected by socket_cancel. */
static void test_tagged_handle_stale_generation_rejected(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Cancel (resets the connection, bumps generation). */
    tp->cancel(tp, handle);

    /* Send again to occupy the same slot with a new generation. */
    pubnub_http_response_t response2 = {0};
    prime_dns_cache(tp);
    pubnub_transport_handle_t* handle2 = tp->send(tp, &request, &response2);
    assert_non_null(handle2);
    assert_ptr_not_equal(handle, handle2);

    /* Snapshot state before stale cancel. */
    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;
    pn_socket_connection_t snapshot[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    memcpy(snapshot, t->connections, sizeof(snapshot));

    /* Cancel with the OLD handle (stale generation). Must be a no-op. */
    tp->cancel(tp, handle);

    /* Connections array must be byte-identical. */
    assert_memory_equal(snapshot, t->connections, sizeof(snapshot));

    /* Cleanup with the valid handle. */
    tp->cancel(tp, handle2);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/**
 * Keep-alive reuse must mint a fresh handle. Request A completes into
 * KEEP_ALIVE_IDLE; request B reuses the same slot but must receive a distinct
 * handle (generation bumped in socket_send). Releasing A's now-stale handle
 * must not cancel the live B — the C6 regression where pubnub_future_release
 * cancels a reused slot's in-flight successor.
 *
 * This exercises the transport contract in ISOLATION with the safe
 * send(B)-then-cancel(A) ordering (B reuses and bumps the generation before
 * A's stale handle is cancelled). The complementary requirement — that a
 * caller (subscribe) must issue the successor send before cancelling the
 * previous handle — is a caller-ordering concern verified end-to-end by
 * redispatch_preserves_keepalive_connection in the subscribe effects tests.
 */
static void test_keepalive_reuse_bumps_generation(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time/0";
    request.path_segments[0].len  = 7;
    request.path_segment_count    = 1;
    request.timeout_ms            = 5000;

    /* Request A: drive to KEEP_ALIVE_IDLE. */
    pubnub_http_response_t     resp_a   = {0};
    pubnub_transport_handle_t* handle_a = tp->send(tp, &request, &resp_a);
    assert_non_null(handle_a);

    int completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }
    assert_true(completed >= 1);
    assert_int_equal(resp_a.completion, PUBNUB_HTTP_COMPLETE);

    pn_socket_transport_t* t      = (pn_socket_transport_t*)tp;
    int                    slot_a = (int)((uintptr_t)handle_a & 0xFFu);
    assert_int_equal(t->connections[slot_a].state, PN_CONN_KEEP_ALIVE_IDLE);

    /* Request B: reuses the same keep-alive slot. */
    mock.recv_offset = 0; /* Replay the canned response for B. */
    pubnub_http_response_t     resp_b   = {0};
    pubnub_transport_handle_t* handle_b = tp->send(tp, &request, &resp_b);
    assert_non_null(handle_b);

    int slot_b = (int)((uintptr_t)handle_b & 0xFFu);
    assert_int_equal(slot_a, slot_b);
    assert_ptr_not_equal(handle_a, handle_b);

    /* Releasing A must be a no-op on the live B (stale generation). */
    tp->cancel(tp, handle_a);
    assert_int_not_equal(t->connections[slot_b].state, PN_CONN_CANCELLED);

    /* B still completes normally. */
    completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }
    assert_true(completed >= 1);
    assert_int_equal(resp_b.completion, PUBNUB_HTTP_COMPLETE);
    assert_int_equal(resp_b.status_code, 200);

    tp->cancel(tp, handle_b);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/**
 * Re-entry variant: the generation must be bumped exactly once per handle
 * (in socket_send), never inside pn_connection_start. A stale keep-alive
 * retry re-enters pn_connection_start on the same in-flight request whose
 * handle the core already holds; that re-entry must NOT bump the generation,
 * or an explicit mid-flight cancel would be silently rejected.
 */
static void test_reentrant_restart_preserves_generation(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time/0";
    request.path_segments[0].len  = 7;
    request.path_segment_count    = 1;
    request.timeout_ms            = 5000;

    /* Request A: drive to KEEP_ALIVE_IDLE so a reused connection has
     * requests_on_connection > 0 (required for the stale-keepalive retry). */
    pubnub_http_response_t     resp_a   = {0};
    pubnub_transport_handle_t* handle_a = tp->send(tp, &request, &resp_a);
    assert_non_null(handle_a);

    int completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }
    assert_int_equal(resp_a.completion, PUBNUB_HTTP_COMPLETE);

    pn_socket_transport_t* t      = (pn_socket_transport_t*)tp;
    int                    slot_a = (int)((uintptr_t)handle_a & 0xFFu);
    assert_int_equal(t->connections[slot_a].state, PN_CONN_KEEP_ALIVE_IDLE);

    /* Request B reuses the keep-alive slot. Fail the first header write so
     * tick_sending_headers re-enters pn_connection_start (fresh restart). */
    mock.recv_offset                    = 0;
    mock.send_fail_once                 = -1;
    pubnub_http_response_t     resp_b   = {0};
    pubnub_transport_handle_t* handle_b = tp->send(tp, &request, &resp_b);
    assert_non_null(handle_b);

    int      slot_b = (int)((uintptr_t)handle_b & 0xFFu);
    uint16_t gen_b  = (uint16_t)(((uintptr_t)handle_b >> 8) & 0xFFFFu);
    assert_int_equal(slot_a, slot_b);

    /* Drive the poll loop: the first send fails → stale-keepalive retry →
     * fresh DNS/connect → completion. The retry must not bump generation. */
    completed = 0;
    for (int i = 0; i < 30 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }
    assert_int_equal(resp_b.completion, PUBNUB_HTTP_COMPLETE);

    /* The connection's generation must still match handle B: the re-entrant
     * restart preserved it. An explicit cancel with B's handle must be
     * accepted (had the retry bumped it, the cancel would be rejected). */
    assert_int_equal(t->connections[slot_b].generation, gen_b);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/** FAILED connections are reaped after the grace period. */
static void test_failed_connection_reaped_after_grace(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result = -111; /* ECONNREFUSED → conn_fail */

    pubnub_transport_provider_t* tp = create_transport_no_tls();
    assert_non_null(tp);
    init_transport(tp);
    prime_dns_cache(tp);

    mock.current_time_ms = 1000;

    pubnub_http_request_t request = {0};
    request.method                = PUBNUB_HTTP_GET;
    request.host                  = "ps.pndsn.com";
    request.secure                = 0;
    request.path_segments[0].ptr  = "/time";
    request.path_segments[0].len  = 5;
    request.path_segment_count    = 1;
    request.timeout_ms            = 5000;

    pubnub_http_response_t     response = {0};
    pubnub_transport_handle_t* handle   = tp->send(tp, &request, &response);
    assert_non_null(handle);

    /* Poll multiple ticks to drive DNS → CONNECTING → FAILED. */
    {
        int tick;
        for (tick = 0; tick < 10; ++tick) {
            (void)tp->poll(tp, 0);
        }
    }

    pn_socket_transport_t*  t    = (pn_socket_transport_t*)tp;
    int                     idx  = (int)((uintptr_t)handle & 0xFFu);
    pn_socket_connection_t* conn = &t->connections[idx];
    assert_int_equal(conn->state, PN_CONN_FAILED);

    /* Poll before grace period expires -- connection stays FAILED. */
    mock.current_time_ms = 1000 + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS - 1;
    (void)tp->poll(tp, 0);
    assert_int_equal(conn->state, PN_CONN_FAILED);

    /* Poll after grace period -- connection is reaped to IDLE. */
    mock.current_time_ms = 1000 + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS + 1;
    (void)tp->poll(tp, 0);
    assert_int_equal(conn->state, PN_CONN_IDLE);

    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_returns_valid_vtable),
        cmocka_unit_test(test_create_null_ops_returns_null),
        cmocka_unit_test(test_create_null_allocator_returns_null),
        cmocka_unit_test(test_init_stores_deps),
        cmocka_unit_test(test_init_creates_tls_context),
        cmocka_unit_test(test_init_null_deps_returns_error),
        cmocka_unit_test(test_send_null_request_returns_null),
        cmocka_unit_test(test_send_returns_handle),
        cmocka_unit_test(test_send_queue_full),
        cmocka_unit_test(test_cancel_sets_cancelled),
        cmocka_unit_test(test_poll_returns_non_negative),
        cmocka_unit_test(test_deinit_closes_connections),
        cmocka_unit_test(test_destroy_null_is_safe),
        cmocka_unit_test(test_concurrent_sends),
        cmocka_unit_test(test_poll_complete_advances_to_keepalive_idle),
        cmocka_unit_test(test_poll_complete_advances_to_idle_on_connection_close),
        cmocka_unit_test(test_cancel_null_handle_no_crash),
        cmocka_unit_test(test_cancel_invalid_stack_pointer_rejected),
        cmocka_unit_test(test_cancel_invalid_heap_pointer_rejected),
        cmocka_unit_test(test_cancel_request_pointer_rejected),
        cmocka_unit_test(test_tagged_handle_encode_decode),
        cmocka_unit_test(test_tagged_handle_stale_generation_rejected),
        cmocka_unit_test(test_keepalive_reuse_bumps_generation),
        cmocka_unit_test(test_reentrant_restart_preserves_generation),
        cmocka_unit_test(test_failed_connection_reaped_after_grace),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
