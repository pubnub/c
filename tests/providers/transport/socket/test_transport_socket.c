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
#define MOCK_RX_SLOTS    16
static uint8_t mock_rx_storage[MOCK_RX_SLOTS][MOCK_RX_BUF_SIZE];
static int     mock_rx_slot_used[MOCK_RX_SLOTS];
static int     mock_rx_buf_in_use;

/** Capacity of the scripted TLS session table. */
#define MOCK_SESS_MAX 16

/** Mock control state. */
static struct {
    /* Socket ops. */
    pn_socket_t next_socket;
    /* When non-zero, every socket_create returns this value. */
    pn_socket_t fixed_socket;
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
    int poll_wait_calls;
    int last_poll_timeout_ms;

    /* Per-socket poll registration table, maintained by poll_add /
     * poll_modify / poll_remove. */
    struct {
        pn_socket_t sock;
        uint8_t     events;
        int         in_use;
    } poll_tbl[16];

    /* Count of poll_add / poll_modify calls with an invalid mask. */
    int poll_bad_mask_calls;

    /* poll_remove calls for a socket not in the poll set. */
    int poll_remove_unregistered;

    /* poll_modify calls for a socket not in the poll set. */
    int poll_modify_unregistered;

    /* pipe_drain calls on the wake read end. */
    int pipe_drain_calls;

    /* socket_destroy calls for the two wake pipe ends. */
    int wake_rd_destroyed;
    int wake_wr_destroyed;

    /* Readiness reported after poll_wait (empty by default). */
    size_t      ready_n;
    pn_socket_t ready_sock[4];
    uint8_t     ready_ev[4];

    /* Self-pipe wake simulation (see mock_wake_pipe_enable). */
    int pipe_create_calls;

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

    /* Scripted TLS sessions, numbered in creation order; the last handshake
     * entry repeats. An empty script completes on the first call. */
    struct {
        int script[8];
        int len;
        int idx;
        int calls;
    } sess[MOCK_SESS_MAX];

    int sess_created;
    int sess_destroyed;

    /* TLS mock. */
    int   tls_ctx_create_calls;
    int   tls_ctx_destroy_calls;
    void* tls_fake_ctx;
} mock;

static void mock_ops_reset_optional(void);

static void mock_reset(void)
{
    memset(&mock, 0, sizeof(mock));
    mock_ops_reset_optional();
    mock_rx_buf_in_use = 0;
    memset(mock_rx_slot_used, 0, sizeof(mock_rx_slot_used));
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
    if (0 != mock.fixed_socket) {
        return mock.fixed_socket;
    }
    return mock.next_socket++;
}

static void mock_socket_destroy(const pn_socket_platform_ops_t* self, pn_socket_t sock)
{
    (void)self;
    mock.socket_destroy_calls++;
    if (900 == sock) {
        mock.wake_rd_destroyed++;
    } else if (901 == sock) {
        mock.wake_wr_destroyed++;
    }
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

static void mock_poll_tbl_set(pn_socket_t sock, uint8_t events)
{
    size_t i;
    size_t cap = sizeof(mock.poll_tbl) / sizeof(mock.poll_tbl[0]);

    if (0 == events || 0 != (events & PN_POLL_ERROR)) {
        mock.poll_bad_mask_calls++;
    }
    for (i = 0; i < cap; ++i) {
        if (mock.poll_tbl[i].in_use && sock == mock.poll_tbl[i].sock) {
            mock.poll_tbl[i].events = events;
            return;
        }
    }
    for (i = 0; i < cap; ++i) {
        if (!mock.poll_tbl[i].in_use) {
            mock.poll_tbl[i].in_use = 1;
            mock.poll_tbl[i].sock   = sock;
            mock.poll_tbl[i].events = events;
            return;
        }
    }
    fail_msg("mock poll table full");
}

/** Registered mask for sock, or -1 when it is not in the poll set. */
static int mock_poll_events_of(pn_socket_t sock)
{
    size_t i;

    for (i = 0; i < sizeof(mock.poll_tbl) / sizeof(mock.poll_tbl[0]); ++i) {
        if (mock.poll_tbl[i].in_use && sock == mock.poll_tbl[i].sock) {
            return (int)mock.poll_tbl[i].events;
        }
    }
    return -1;
}

static int mock_poll_add(const pn_socket_platform_ops_t* self,
                         pn_poll_set_t*                  poll_set,
                         pn_socket_t                     sock,
                         uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    mock.poll_add_calls++;
    mock_poll_tbl_set(sock, events);
    return 0;
}

static int mock_poll_modify(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock,
                            uint8_t                         events)
{
    (void)self;
    (void)poll_set;
    mock.poll_modify_calls++;
    {
        size_t i;

        for (i = 0; i < sizeof(mock.poll_tbl) / sizeof(mock.poll_tbl[0]); ++i) {
            if (mock.poll_tbl[i].in_use && sock == mock.poll_tbl[i].sock) {
                mock_poll_tbl_set(sock, events);
                return 0;
            }
        }
    }
    mock.poll_modify_unregistered++;
    return -22;
}

static int mock_poll_remove(const pn_socket_platform_ops_t* self,
                            pn_poll_set_t*                  poll_set,
                            pn_socket_t                     sock)
{
    size_t i;

    (void)self;
    (void)poll_set;
    mock.poll_remove_calls++;
    for (i = 0; i < sizeof(mock.poll_tbl) / sizeof(mock.poll_tbl[0]); ++i) {
        if (mock.poll_tbl[i].in_use && sock == mock.poll_tbl[i].sock) {
            mock.poll_tbl[i].in_use = 0;
            return 0;
        }
    }
    mock.poll_remove_unregistered++;
    return -22;
}

static int mock_poll_wait(const pn_socket_platform_ops_t* self,
                          pn_poll_set_t*                  poll_set,
                          int                             timeout_ms)
{
    (void)self;
    (void)poll_set;
    mock.poll_wait_calls++;
    mock.last_poll_timeout_ms = timeout_ms;
    return mock.poll_wait_result;
}

static size_t mock_poll_ready_count(const pn_socket_platform_ops_t* self,
                                    const pn_poll_set_t*            poll_set)
{
    (void)self;
    (void)poll_set;
    return mock.ready_n;
}

static int mock_poll_get_ready(const pn_socket_platform_ops_t* self,
                               const pn_poll_set_t*            poll_set,
                               size_t                          index,
                               pn_socket_t*                    out_sock,
                               uint8_t*                        out_events)
{
    (void)self;
    (void)poll_set;
    if (index >= mock.ready_n) {
        return -22;
    }
    *out_sock   = mock.ready_sock[index];
    *out_events = mock.ready_ev[index];
    return 0;
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

static int mock_pipe_create(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     out[2])
{
    (void)self;
    mock.pipe_create_calls++;
    out[0] = 900;
    out[1] = 901;
    return 0;
}

static void mock_pipe_write(const pn_socket_platform_ops_t* self, pn_socket_t wr)
{
    (void)self;
    (void)wr;
}

static void mock_pipe_drain(const pn_socket_platform_ops_t* self, pn_socket_t rd)
{
    (void)self;
    (void)rd;
    mock.pipe_drain_calls++;
}

/** Make the mock platform report a working wake pipe (or none). */
static void mock_wake_pipe_enable(int enabled)
{
    mock_ops.pipe_create = enabled ? mock_pipe_create : NULL;
    mock_ops.pipe_write  = enabled ? mock_pipe_write : NULL;
    mock_ops.pipe_drain  = enabled ? mock_pipe_drain : NULL;
}

static void mock_ops_reset_optional(void)
{
    mock_wake_pipe_enable(0);
}

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
    pubnub_buffer_t buf = {0};
    int             i;

    (void)self;
    for (i = 0; i < MOCK_RX_SLOTS; ++i) {
        if (!mock_rx_slot_used[i]) {
            mock_rx_slot_used[i] = 1;
            mock_rx_buf_in_use++;
            buf.data    = mock_rx_storage[i];
            buf.cap     = MOCK_RX_BUF_SIZE;
            buf.len     = 0;
            buf.purpose = purpose;
            break;
        }
    }
    return buf;
}

static void mock_buf_release(struct pubnub_allocator_provider* self,
                             pubnub_buffer_t*                  buf)
{
    int i;

    (void)self;
    for (i = 0; i < MOCK_RX_SLOTS; ++i) {
        if (buf->data == mock_rx_storage[i] && mock_rx_slot_used[i]) {
            mock_rx_slot_used[i] = 0;
            mock_rx_buf_in_use--;
            return;
        }
    }
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

static int mock_full_tls_session_create(void**      out,
                                        void*       ctx,
                                        pn_socket_t sock,
                                        const struct pn_socket_platform_ops* ops,
                                        const char* host)
{
    (void)ctx;
    (void)sock;
    (void)ops;
    (void)host;
    assert_true(mock.sess_created < MOCK_SESS_MAX);
    *out = &mock.sess[mock.sess_created++];
    return 0;
}

static int mock_full_tls_handshake(void* session)
{
    size_t idx = 0;
    int    rc;

    while (idx < MOCK_SESS_MAX && session != (void*)&mock.sess[idx]) {
        ++idx;
    }
    assert_true(idx < MOCK_SESS_MAX);
    mock.sess[idx].calls++;
    if (0 == mock.sess[idx].len) {
        return PN_TLS_OK;
    }
    rc = mock.sess[idx].script[mock.sess[idx].idx];
    if (mock.sess[idx].idx + 1 < mock.sess[idx].len) {
        mock.sess[idx].idx++;
    }
    return rc;
}

static int mock_full_tls_send(void* session, const void* buf, size_t len)
{
    (void)session;
    (void)buf;
    return (int)len;
}

static int mock_full_tls_recv(void* session, void* buf, size_t len)
{
    size_t avail;

    (void)session;
    if (NULL == mock.recv_data || mock.recv_offset >= mock.recv_data_len) {
        return 0;
    }
    avail = mock.recv_data_len - mock.recv_offset;
    if (avail > len) {
        avail = len;
    }
    memcpy(buf, mock.recv_data + mock.recv_offset, avail);
    mock.recv_offset += avail;
    return (int)avail;
}

static void mock_full_tls_session_destroy(void* session)
{
    (void)session;
    mock.sess_destroyed++;
}

static pn_tls_backend_t mock_tls_full_backend = {
    .ctx_create      = mock_tls_ctx_create,
    .ctx_destroy     = mock_tls_ctx_destroy,
    .session_create  = mock_full_tls_session_create,
    .handshake       = mock_full_tls_handshake,
    .send            = mock_full_tls_send,
    .recv            = mock_full_tls_recv,
    .session_destroy = mock_full_tls_session_destroy,
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

/** Releasing a stale handle after keep-alive reuse must not cancel B. */
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

    /* A's response is released, freeing its keep-alive connection. */
    tp->cancel(tp, handle_a);

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

/** A stale cancel after connection reuse is a complete no-op. */
static void test_cancel_after_keepalive_reuse_is_stale_noop(void** state)
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

    pubnub_http_response_t     resp_a   = {0};
    pubnub_transport_handle_t* handle_a = tp->send(tp, &request, &resp_a);
    assert_non_null(handle_a);
    int completed = 0;
    for (int i = 0; i < 20 && 0 == completed; ++i) {
        completed = tp->poll(tp, 0);
    }
    assert_true(completed >= 1);

    tp->cancel(tp, handle_a);
    mock.recv_offset                    = 0;
    pubnub_http_response_t     resp_b   = {0};
    pubnub_transport_handle_t* handle_b = tp->send(tp, &request, &resp_b);
    assert_non_null(handle_b);
    assert_ptr_not_equal(handle_a, handle_b);

    pn_socket_transport_t*  t = (pn_socket_transport_t*)tp;
    pn_socket_connection_t* conn =
        &t->connections[(int)((uintptr_t)handle_b & 0xFFu)];

    const pn_conn_state_t         state_before    = conn->state;
    const pn_socket_t             socket_before   = conn->socket;
    const pubnub_http_request_t*  request_before  = conn->request;
    const pubnub_http_response_t* response_before = conn->response;
    const int                     destroy_before  = mock.socket_destroy_calls;
    const int                     remove_before   = mock.poll_remove_calls;

    /* Stale cancel, twice: nothing may change. */
    tp->cancel(tp, handle_a);
    tp->cancel(tp, handle_a);

    assert_int_equal(state_before, conn->state);
    assert_true(socket_before == conn->socket);
    assert_ptr_equal(request_before, conn->request);
    assert_ptr_equal(response_before, conn->response);
    assert_int_equal(destroy_before, mock.socket_destroy_calls);
    assert_int_equal(remove_before, mock.poll_remove_calls);

    /* The successor still completes through the same connection. */
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
    tp->cancel(tp, handle_a);
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

#define EV_WR (PN_POLL_WRITE | PN_POLL_READ)

/** Transport with the scripted TLS backend and a primed DNS cache. */
static pubnub_transport_provider_t* interest_create(int wake_pipe)
{
    pubnub_transport_provider_t* tp;

    mock_wake_pipe_enable(wake_pipe);
    tp = pn_socket_transport_create(
        &mock_ops, &mock_tls_full_backend, NULL, NULL, &mock_allocator);
    assert_non_null(tp);
    assert_int_equal(0, init_transport(tp));
    prime_dns_cache(tp);
    return tp;
}

static void interest_teardown(pubnub_transport_provider_t* tp)
{
    assert_int_equal(0, mock.poll_bad_mask_calls);
    assert_int_equal(0, mock.poll_modify_unregistered);
    tp->deinit(tp);
    pn_socket_transport_destroy(tp, &mock_allocator);
}

static pubnub_http_request_t interest_request(int secure)
{
    pubnub_http_request_t request = {0};

    request.method               = PUBNUB_HTTP_GET;
    request.host                 = "ps.pndsn.com";
    request.secure               = (uint8_t)secure;
    request.path_segments[0].ptr = "/time/0";
    request.path_segments[0].len = 7;
    request.path_segment_count   = 1;
    request.timeout_ms           = 5000;
    return request;
}

static pn_socket_connection_t* interest_conn(pubnub_transport_provider_t* tp,
                                             pubnub_transport_handle_t* handle)
{
    pn_socket_transport_t* t = (pn_socket_transport_t*)tp;

    return &t->connections[(int)((uintptr_t)handle & 0xFFu)];
}

/** Poll (timeout 0) until the connection reaches @p want; fail after 30. */
static void interest_poll_until(pubnub_transport_provider_t* tp,
                                pn_socket_connection_t*      conn,
                                pn_conn_state_t              want)
{
    int i;

    for (i = 0; i < 30 && want != conn->state; ++i) {
        (void)tp->poll(tp, 0);
    }
    assert_int_equal(want, conn->state);
}

/** Pending TCP connect waits for writability (and readability for errors). */
static void test_interest_connecting_has_write(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result       = 0;
    mock.check_connect_result = 0;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    (void)tp->poll(tp, 0);
    (void)tp->poll(tp, 0);
    assert_int_equal(PN_CONN_CONNECTING, conn->state);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Before the first handshake call the ClientHello is unsent: WRITE is armed. */
static void test_interest_tls_initial_has_write(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    assert_int_equal(0, mock.sess[0].calls);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** A handshake waiting for the peer registers read-only interest. */
static void test_interest_tls_want_read_read_only(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);
    assert_int_equal(1, mock.sess[0].calls);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, conn->state);
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(conn->socket));

    /* Further WANT_READ iterations leave the registration untouched. */
    {
        int modifies = mock.poll_modify_calls;
        (void)tp->poll(tp, 0);
        (void)tp->poll(tp, 0);
        assert_int_equal(modifies, mock.poll_modify_calls);
    }

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** A handshake blocked on send keeps WRITE interest. */
static void test_interest_tls_want_write_has_write(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_WRITE;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);
    assert_int_equal(1, mock.sess[0].calls);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** The wanted direction flips within TLS_HANDSHAKING: the mask follows. */
static void test_interest_tls_change_within_state(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_WRITE;
    mock.sess[0].script[1] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 2;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));

    {
        int modifies = mock.poll_modify_calls;
        (void)tp->poll(tp, 0);
        assert_int_equal(PN_CONN_TLS_HANDSHAKING, conn->state);
        assert_int_equal(modifies + 1, mock.poll_modify_calls);
        assert_int_equal(PN_POLL_READ, mock_poll_events_of(conn->socket));
    }

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Without a wake pipe the handshake keeps WRITE|READ on a 5 ms tick. */
static void test_interest_tls_no_wake_pipe_keeps_write(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(0);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    assert_int_equal(0, mock.pipe_create_calls);
    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);
    (void)tp->poll(tp, 0);
    assert_true(mock.sess[0].calls >= 2);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Awaiting the response needs readability only. */
static void test_interest_receiving_read_only(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_RECEIVING_RESPONSE);
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Drive two secure requests to one host, deferring the second's TLS. */
static void interest_deferred_scenario(int final_want_read)
{
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].script[1] = PN_TLS_OK;
    mock.sess[0].len       = 2;
    mock.sess[1].script[0] = PN_TLS_WANT_READ;
    mock.sess[1].len       = 1;

    pubnub_transport_provider_t* tp   = interest_create(1);
    pubnub_http_request_t        rq   = interest_request(1);
    pubnub_http_response_t       rs_a = {0};
    pubnub_http_response_t       rs_b = {0};
    pubnub_transport_handle_t*   ha   = tp->send(tp, &rq, &rs_a);
    assert_non_null(ha);
    pn_socket_connection_t* a = interest_conn(tp, ha);

    interest_poll_until(tp, a, PN_CONN_TLS_HANDSHAKING);

    pubnub_transport_handle_t* hb = tp->send(tp, &rq, &rs_b);
    assert_non_null(hb);
    pn_socket_connection_t* b = interest_conn(tp, hb);

    (void)tp->poll(tp, 0); /* A: WANT_READ; B: connects, TLS deferred. */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, a->state);
    assert_int_equal(PN_CONN_TLS_DEFERRED, b->state);
    assert_int_equal(1, mock.sess_created);
    assert_int_equal(EV_WR, mock_poll_events_of(b->socket));

    {
        pn_socket_t sock_b = b->socket;

        (void)tp->poll(tp, 0); /* A completes; B starts its handshake. */
        assert_int_equal(PN_CONN_TLS_HANDSHAKING, b->state);
        assert_int_equal(sock_b, b->socket);
        assert_int_equal(2, mock.sess_created);
        assert_int_equal(PN_POLL_WRITE, b->tls_want);
        assert_int_equal(EV_WR, mock_poll_events_of(b->socket));

        if (final_want_read) {
            (void)tp->poll(tp, 0); /* B: WANT_READ. */
            assert_int_equal(PN_POLL_READ, b->tls_want);
            assert_int_equal(PN_POLL_READ, mock_poll_events_of(b->socket));
        }
    }

    tp->cancel(tp, ha);
    tp->cancel(tp, hb);
    interest_teardown(tp);
}

/** A TLS-deferred connection stays CONNECTING with WRITE|READ. */
static void test_interest_tls_deferred_connecting_keeps_write(void** state)
{
    (void)state;
    interest_deferred_scenario(0);
}

/** After the deferral the registered mask tracks the handshake's wanted side. */
static void test_interest_tls_deferred_to_handshaking_mask(void** state)
{
    (void)state;
    interest_deferred_scenario(1);
}

/** Reusing a keep-alive socket registers a valid (non-empty) mask. */
static void test_interest_send_registration_never_empty(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(0);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_KEEP_ALIVE_IDLE);
    assert_int_equal(-1, mock_poll_events_of(conn->socket));

    {
        pn_socket_t                sock = conn->socket;
        int                        adds = mock.poll_add_calls;
        pubnub_http_response_t     rs2  = {0};
        pubnub_transport_handle_t* h2;

        /* The finished request is released first: its connection is held
         * until then. */
        tp->cancel(tp, h);
        mock.recv_offset = 0;
        h2               = tp->send(tp, &rq, &rs2);
        assert_non_null(h2);
        assert_ptr_equal(conn, interest_conn(tp, h2));
        assert_int_equal(sock, conn->socket);
        assert_int_equal(adds + 1, mock.poll_add_calls);
        assert_int_equal(EV_WR, mock_poll_events_of(sock));
        tp->cancel(tp, h2);
    }

    interest_teardown(tp);
}

/** The handshake deadline fires even when poll reports no readiness. */
static void test_interest_deadline_fires_without_readiness(void** state)
{
    (void)state;
    mock_reset();
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);

    mock.poll_wait_result = 0;
    mock.current_time_ms  = conn->connect_deadline_ms + 1;
    (void)tp->poll(tp, 100);
    assert_int_equal(100, mock.last_poll_timeout_ms);
    assert_int_equal(PN_CONN_FAILED, conn->state);
    assert_int_equal(PUBNUB_HTTP_ERROR, rs.completion);
    assert_int_equal(PUBNUB_ERR_TIMEOUT, rs.transport_error);

    interest_teardown(tp);
}

/** A handshake timeout fallback rebuilds the mask for CONNECTING. */
static void test_interest_same_fd_reuse_after_tls_fallback(void** state)
{
    (void)state;
    mock_reset();
    mock.fixed_socket      = 77;
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp          = interest_create(1);
    pubnub_http_request_t        rq          = interest_request(1);
    pubnub_http_response_t       rs          = {0};
    pn_socket_transport_t*       t           = (pn_socket_transport_t*)tp;
    pn_sockaddr_t                second_addr = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn;

    second_addr.family              = PN_AF_INET;
    second_addr.addr.ipv4[0]        = 93;
    second_addr.addr.ipv4[1]        = 184;
    second_addr.addr.ipv4[2]        = 216;
    second_addr.addr.ipv4[3]        = 35;
    t->resolver.cache[0].addrs[1]   = second_addr;
    t->resolver.cache[0].addr_count = 2;

    h = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    (void)tp->poll(tp, 0);
    assert_int_equal(77, conn->socket);
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(77));

    {
        int creates = mock.socket_create_calls;
        int removes = mock.poll_remove_calls;
        int adds    = mock.poll_add_calls;

        /* The next address connects slowly so the state stays CONNECTING. */
        mock.connect_result       = 0;
        mock.check_connect_result = 0;
        mock.poll_wait_result     = 0;
        mock.current_time_ms      = conn->connect_deadline_ms + 1;
        (void)tp->poll(tp, 100);

        assert_int_equal(PN_CONN_CONNECTING, conn->state);
        assert_int_equal(1, conn->addr_current);
        assert_int_equal(77, conn->socket);
        assert_int_equal(creates + 1, mock.socket_create_calls);
        assert_int_equal(EV_WR, mock_poll_events_of(77));
        assert_true(mock.poll_remove_calls - removes <= 1);
        assert_true(mock.poll_add_calls - adds <= 1);
    }

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Wake pipe read end handed out by mock_pipe_create. */
#define MOCK_WAKE_RD 900
/** Wake pipe write end handed out by mock_pipe_create. */
#define MOCK_WAKE_WR 901

/** Logger that counts WARNING entries and keeps the last text. */
static struct {
    pubnub_logger_provider_t base;
    int                      warnings;
    char                     last[160];
} wake_log;

static void wake_log_fn(struct pubnub_logger_provider* self,
                        const pubnub_log_entry_t*      entry)
{
    (void)self;
    if (PUBNUB_LOG_ENTRY_TEXT == entry->type
        && PUBNUB_LOG_LEVEL_WARNING == entry->level) {
        const pubnub_log_entry_text_t* text = (const pubnub_log_entry_text_t*)entry;

        wake_log.warnings++;
        (void)strncpy(wake_log.last, text->message, sizeof(wake_log.last) - 1U);
    }
}

/** Check the WARNING count; zero expected when logging is compiled out. */
static void wake_expect_warnings(int expected)
{
    if (0 == PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE
        || !PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_WARNING)) {
        expected = 0;
    }
    assert_int_equal(expected, wake_log.warnings);
    if (0 < expected) {
        assert_non_null(strstr(wake_log.last, "wake"));
    }
}

/** Report the wake pipe read end ready with @p events on the next poll. */
static void wake_inject(uint8_t events)
{
    mock.ready_n       = 1;
    mock.ready_sock[0] = MOCK_WAKE_RD;
    mock.ready_ev[0]   = events;
}

/** Create a transport with a wake pipe and a peer-waiting TLS handshake. */
static pn_socket_connection_t* wake_fixture(pubnub_transport_provider_t** out_tp,
                                            pubnub_http_response_t*     rs,
                                            pubnub_transport_handle_t** out_h)
{
    pubnub_http_request_t rq;

    memset(&wake_log, 0, sizeof(wake_log));
    wake_log.base.log      = wake_log_fn;
    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    *out_tp                                   = interest_create(1);
    ((pn_socket_transport_t*)*out_tp)->logger = &wake_log.base;
    rq                                        = interest_request(1);
    *out_h = (*out_tp)->send(*out_tp, &rq, rs);
    assert_non_null(*out_h);
    {
        pn_socket_connection_t* conn = interest_conn(*out_tp, *out_h);

        interest_poll_until(*out_tp, conn, PN_CONN_TLS_HANDSHAKING);
        (void)(*out_tp)->poll(*out_tp, 0);
        assert_int_equal(PN_POLL_READ, mock_poll_events_of(conn->socket));
        assert_int_equal(PN_POLL_READ, mock_poll_events_of(MOCK_WAKE_RD));
        return conn;
    }
}

/** Common degrade checks after one poll that saw @p events on the wake fd. */
static void wake_expect_degraded(pubnub_transport_provider_t* tp,
                                 pn_socket_connection_t*      conn,
                                 uint8_t                      events)
{
    pn_socket_transport_t* t      = (pn_socket_transport_t*)tp;
    int                    drains = mock.pipe_drain_calls;

    wake_inject(events);
    (void)tp->poll(tp, 0);

    assert_int_equal(1, t->wake_degraded);
    /* The failed descriptor is neither re-registered nor drained. */
    assert_int_equal(drains, mock.pipe_drain_calls);
    assert_int_equal(0, mock.poll_modify_unregistered);
    assert_int_equal(-1, mock_poll_events_of(MOCK_WAKE_RD));
    /* Narrowing is off: the handshake is back to WRITE|READ. */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, conn->state);
    assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));
    wake_expect_warnings(1);
}

/** An error on the wake read end removes it and widens the TLS interest. */
static void test_wake_error_degrades_pipe(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);

    wake_expect_degraded(tp, conn, PN_POLL_ERROR);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** A hang-up on the wake read end degrades the pipe the same way. */
static void test_wake_hup_degrades_pipe(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);

    wake_expect_degraded(tp, conn, PN_POLL_READ | PN_POLL_HUP);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** A ready entry without READ/ERROR/HUP bits is also a broken wake pipe. */
static void test_wake_unmapped_event_degrades_pipe(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);

    wake_expect_degraded(tp, conn, 0);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Degrading happens once: later polls do not remove, modify or log again. */
static void test_wake_degrade_is_one_shot(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);
    int                          i;

    wake_expect_degraded(tp, conn, PN_POLL_ERROR);
    {
        int removes = mock.poll_remove_calls;
        int unreg   = mock.poll_remove_unregistered;
        int adds    = mock.poll_add_calls;
        int drains  = mock.pipe_drain_calls;

        /* The backend keeps reporting the dead fd; the transport ignores it. */
        for (i = 0; i < 5; ++i) {
            wake_inject(PN_POLL_ERROR | PN_POLL_HUP);
            (void)tp->poll(tp, 0);
        }
        assert_int_equal(removes, mock.poll_remove_calls);
        assert_int_equal(drains, mock.pipe_drain_calls);
        assert_int_equal(unreg, mock.poll_remove_unregistered);
        assert_int_equal(adds, mock.poll_add_calls);
        wake_expect_warnings(1);
        assert_int_equal(EV_WR, mock_poll_events_of(conn->socket));
    }

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** After degrading, wake() is harmless and deinit releases both pipe ends. */
static void test_wake_degraded_wake_and_cleanup_ok(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);
    pn_socket_transport_t*       t    = (pn_socket_transport_t*)tp;

    wake_expect_degraded(tp, conn, PN_POLL_ERROR);
    tp->wake(tp);
    tp->wake(tp);
    assert_int_equal(MOCK_WAKE_WR, t->wake_pipe_wr);

    tp->cancel(tp, h);
    {
        int unreg = mock.poll_remove_unregistered;

        assert_int_equal(0, mock.poll_bad_mask_calls);
        tp->deinit(tp);
        assert_int_equal(1, mock.wake_rd_destroyed);
        assert_int_equal(1, mock.wake_wr_destroyed);
        assert_int_equal(unreg, mock.poll_remove_unregistered);
        assert_int_equal(PN_INVALID_SOCKET, t->wake_pipe_rd);
        assert_int_equal(PN_INVALID_SOCKET, t->wake_pipe_wr);
        assert_int_equal(0, t->wake_degraded);
    }
    pn_socket_transport_destroy(tp, &mock_allocator);
}

/** A healthy wake byte (READ only) keeps the pipe and the narrowed mask. */
static void test_wake_normal_read_not_degraded(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn   = wake_fixture(&tp, &rs, &h);
    pn_socket_transport_t*       t      = (pn_socket_transport_t*)tp;
    int                          drains = mock.pipe_drain_calls;
    int                          i;

    for (i = 0; i < 3; ++i) {
        tp->wake(tp);
        wake_inject(PN_POLL_READ);
        (void)tp->poll(tp, 0);
    }
    assert_int_equal(drains + 3, mock.pipe_drain_calls);
    assert_int_equal(0, t->wake_degraded);
    assert_int_equal(0, wake_log.warnings);
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(MOCK_WAKE_RD));
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(conn->socket));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Errors on ordinary connection sockets never touch the wake pipe. */
static void test_wake_other_fd_error_ignored(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);
    pn_socket_transport_t*       t    = (pn_socket_transport_t*)tp;

    mock.ready_n       = 1;
    mock.ready_sock[0] = conn->socket;
    mock.ready_ev[0]   = PN_POLL_ERROR | PN_POLL_HUP;
    (void)tp->poll(tp, 0);

    assert_int_equal(0, t->wake_degraded);
    assert_int_equal(PN_POLL_READ, mock_poll_events_of(MOCK_WAKE_RD));

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Without a wake pipe the readiness scan is skipped entirely. */
static void test_wake_none_ignores_ready_set(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = interest_create(0);
    pn_socket_transport_t*       t  = (pn_socket_transport_t*)tp;

    wake_inject(PN_POLL_ERROR);
    (void)tp->poll(tp, 0);
    assert_int_equal(0, t->wake_degraded);
    assert_int_equal(0, mock.poll_remove_calls);
    interest_teardown(tp);
}

/** Without a wake pipe the blocking poll is bounded by the configured max. */
static void test_wake_degraded_bounds_poll_timeout(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp;
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn = wake_fixture(&tp, &rs, &h);

    (void)tp->poll(tp, 600000);
    assert_int_equal(600000, mock.last_poll_timeout_ms);

    wake_expect_degraded(tp, conn, PN_POLL_ERROR);
    mock.ready_n = 0;
    (void)tp->poll(tp, 600000);
    assert_int_equal((int)PUBNUB_CFG_MAX_POLL_MS, mock.last_poll_timeout_ms);
    (void)tp->poll(tp, 3);
    assert_int_equal(3, mock.last_poll_timeout_ms);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** Poll timeout handed to a blocking wait by the caller in these tests. */
#define DIAL_TIMEOUT_MS 5000

/** A fresh connect (no socket yet) must not sit out a full blocking wait. */
static void test_poll_timeout_zero_for_fdless_connecting(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result       = 0;
    mock.check_connect_result = 0;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(0);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    assert_int_equal(PN_CONN_CONNECTING, conn->state);
    assert_int_equal(PN_INVALID_SOCKET, conn->socket);

    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(0, mock.last_poll_timeout_ms);
    /* The tick dialed: the pending socket is now registered. */
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);

    /* Nothing is left to dial, so the next wait keeps the full timeout. */
    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** After a failed address the connection waits without a socket. */
static void test_poll_timeout_zero_after_failed_address(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result       = 0;
    mock.check_connect_result = 0;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(0);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);
    pn_socket_transport_t*  t    = (pn_socket_transport_t*)tp;

    (void)tp->poll(tp, 0);
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);

    /* Address 0 died; address 1 has not been dialed yet. */
    conn->addr_count        = 2;
    conn->resolved_addrs[1] = conn->resolved_addrs[0];
    t->ops->poll_remove(t->ops, &t->poll_set, conn->socket);
    t->ops->socket_destroy(t->ops, conn->socket);
    conn->socket       = PN_INVALID_SOCKET;
    conn->addr_current = 1;
    conn->state        = PN_CONN_CONNECTING;

    mock.socket_create_calls = 0;
    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(0, mock.last_poll_timeout_ms);
    assert_int_equal(1, mock.socket_create_calls);
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);

    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** A dial that cannot proceed ends the connection instead of looping. */
static void test_poll_timeout_zero_is_not_a_spin(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result = -111;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(0);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(0, mock.last_poll_timeout_ms);
    assert_int_equal(PN_CONN_FAILED, conn->state);

    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);

    tp->cancel(tp, h);
    interest_teardown(tp);
}

/** States that own a socket or wait on DNS I/O keep the caller's timeout. */
static void test_poll_timeout_kept_for_normal_states(void** state)
{
    (void)state;
    mock_reset();
    mock.connect_result       = 0;
    mock.check_connect_result = 0;

    pubnub_transport_provider_t* tp = interest_create(1);
    pubnub_http_request_t        rq = interest_request(0);
    pubnub_http_response_t       rs = {0};

    /* No connections at all. */
    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);

    /* CONNECTING with a pending socket. */
    pubnub_transport_handle_t* h = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);
    (void)tp->poll(tp, 0);
    (void)tp->poll(tp, DIAL_TIMEOUT_MS);
    assert_int_equal(PN_CONN_CONNECTING, conn->state);
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);
    assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);
    tp->cancel(tp, h);

    /* DNS_RESOLVING waits on the resolver sockets, not on a dial. */
    {
        pubnub_http_response_t     rs2 = {0};
        pubnub_http_request_t      rq2 = interest_request(0);
        pubnub_transport_handle_t* h2;
        pn_socket_connection_t*    c2;

        rq2.host = "unprimed.example.com";
        h2       = tp->send(tp, &rq2, &rs2);
        assert_non_null(h2);
        c2 = interest_conn(tp, h2);
        assert_int_equal(PN_CONN_DNS_RESOLVING, c2->state);
        (void)tp->poll(tp, DIAL_TIMEOUT_MS);
        assert_int_equal(PN_CONN_DNS_RESOLVING, c2->state);
        assert_int_equal(DIAL_TIMEOUT_MS, mock.last_poll_timeout_ms);
        tp->cancel(tp, h2);
    }

    interest_teardown(tp);
}

static const char release_resp[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";

/** Secure transport with a canned 200 response and a primed DNS cache. */
static pubnub_transport_provider_t* release_create(void)
{
    mock.recv_data     = (const uint8_t*)release_resp;
    mock.recv_data_len = strlen(release_resp);
    return interest_create(0);
}

/** Send @p rq, drive it to KEEP_ALIVE_IDLE and return its handle. */
static pubnub_transport_handle_t* release_complete_one(pubnub_transport_provider_t* tp,
                                                       pubnub_http_request_t* rq,
                                                       pubnub_http_response_t* rs)
{
    pubnub_transport_handle_t* h;

    mock.recv_offset = 0;
    h                = tp->send(tp, rq, rs);
    assert_non_null(h);
    interest_poll_until(tp, interest_conn(tp, h), PN_CONN_KEEP_ALIVE_IDLE);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, rs->completion);
    return h;
}

/** Cancelling a completed request keeps the keep-alive connection alive. */
static void test_release_completed_keeps_connection(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp       = release_create();
    pubnub_http_request_t        rq       = interest_request(1);
    pubnub_http_response_t       rs       = {0};
    pubnub_transport_handle_t*   h        = release_complete_one(tp, &rq, &rs);
    pn_socket_connection_t*      conn     = interest_conn(tp, h);
    pn_socket_t                  sock     = conn->socket;
    void*                        tls      = conn->tls_session;
    const uint16_t               gen      = conn->generation;
    const int                    destroys = mock.socket_destroy_calls;
    const int                    removes  = mock.poll_remove_calls;
    const int                    creates  = mock.socket_create_calls;

    assert_non_null(tls);
    assert_int_equal(1, mock_rx_buf_in_use);

    tp->cancel(tp, h);

    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);
    assert_true(sock == conn->socket);
    assert_ptr_equal(tls, conn->tls_session);
    assert_int_equal(destroys, mock.socket_destroy_calls);
    assert_int_equal(0, mock.sess_destroyed);
    assert_int_equal(removes, mock.poll_remove_calls);
    assert_int_equal(creates, mock.socket_create_calls);
    assert_int_equal(1, mock.sess_created);
    /* Per-request resources are gone. */
    assert_int_equal(0, mock_rx_buf_in_use);
    assert_null(conn->rx_buf.data);
    assert_null(conn->request);
    assert_null(conn->response);
    /* The handle is stale from now on. */
    assert_int_not_equal(gen, conn->generation);
    assert_true(0 != conn->generation);
    assert_true(0 != conn->requests_on_connection);
    assert_true('\0' != conn->connected_host[0]);

    /* A second release of the same handle is a no-op. */
    tp->cancel(tp, h);
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);
    assert_int_equal(destroys, mock.socket_destroy_calls);
    assert_int_equal(0, mock.sess_destroyed);

    interest_teardown(tp);
}

/** The next request reuses the preserved connection; stale release no-op. */
static void test_request_after_release_reuses_connection(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp   = release_create();
    pubnub_http_request_t        rq   = interest_request(1);
    pubnub_http_response_t       rs_a = {0};
    pubnub_http_response_t       rs_b = {0};
    pubnub_transport_handle_t*   a    = release_complete_one(tp, &rq, &rs_a);
    pubnub_transport_handle_t*   b;
    pn_socket_connection_t*      conn    = interest_conn(tp, a);
    const int                    creates = mock.socket_create_calls;

    tp->cancel(tp, a);
    assert_int_equal(0, mock_rx_buf_in_use);

    mock.recv_offset = 0;
    b                = tp->send(tp, &rq, &rs_b);
    assert_non_null(b);
    assert_ptr_not_equal(a, b);
    assert_ptr_equal(conn, interest_conn(tp, b));
    assert_int_equal(creates, mock.socket_create_calls);
    assert_int_equal(1, mock.sess_created);

    /* Stale release of A must not disturb the live B. */
    {
        const int destroys = mock.socket_destroy_calls;

        tp->cancel(tp, a);
        assert_int_equal(destroys, mock.socket_destroy_calls);
        assert_int_equal(PN_CONN_SENDING_HEADERS, conn->state);
    }

    interest_poll_until(tp, conn, PN_CONN_KEEP_ALIVE_IDLE);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, rs_b.completion);
    assert_int_equal(200, rs_b.status_code);
    assert_int_equal(4, (int)rs_b.body_len);
    assert_memory_equal("test", rs_b.body, 4);
    assert_int_equal(creates, mock.socket_create_calls);
    assert_int_equal(1, mock.sess_created);
    assert_int_equal(0, mock.sess_destroyed);

    tp->cancel(tp, b);
    interest_teardown(tp);
}

/** N sequential request + release cycles open exactly one connection. */
static void test_sequential_release_cycles_open_one_connection(void** state)
{
    enum { CYCLES = 10 };

    int creates_after_first = 0;
    int i;

    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = release_create();
    pubnub_http_request_t        rq = interest_request(1);

    for (i = 0; i < CYCLES; ++i) {
        pubnub_http_response_t     rs = {0};
        pubnub_transport_handle_t* h  = release_complete_one(tp, &rq, &rs);

        tp->cancel(tp, h);
        if (0 == i) {
            creates_after_first = mock.socket_create_calls;
        }
    }
    assert_int_equal(creates_after_first, mock.socket_create_calls);
    assert_int_equal(1, mock.sess_created);
    assert_int_equal(0, mock.sess_destroyed);
    assert_int_equal(0, mock_rx_buf_in_use);

    interest_teardown(tp);
    assert_int_equal(1, mock.sess_destroyed);
}

/** A kept idle connection is evicted when a different host needs a slot. */
static void test_release_kept_connection_is_evictable(void** state)
{
    int i;

    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = release_create();
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   a  = release_complete_one(tp, &rq, &rs);
    pubnub_transport_handle_t*   busy[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_http_response_t       busy_rs[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
    pubnub_http_request_t        other = interest_request(1);

    memset(busy_rs, 0, sizeof(busy_rs));
    tp->cancel(tp, a);
    assert_int_equal(0, mock.sess_destroyed);

    /* Different host: occupies every other slot, then evicts the kept one. */
    other.host = "unprimed.example.com";
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS - 1; ++i) {
        busy[i] = tp->send(tp, &other, &busy_rs[i]);
        assert_non_null(busy[i]);
        assert_int_equal(0, mock.sess_destroyed);
    }
    busy[i] = tp->send(tp, &other, &busy_rs[i]);
    assert_non_null(busy[i]);
    assert_int_equal(1, mock.sess_destroyed);
    assert_int_not_equal(PUBNUB_ERR_QUEUE_FULL, busy_rs[i].transport_error);

    /* The pool is now genuinely full. */
    {
        pubnub_http_response_t rs_full = {0};

        assert_null(tp->send(tp, &other, &rs_full));
        assert_int_equal(PUBNUB_ERR_QUEUE_FULL, rs_full.transport_error);
    }

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        tp->cancel(tp, busy[i]);
    }
    interest_teardown(tp);
}

/** A kept connection still expires through the idle timeout. */
static void test_release_kept_connection_idle_timeout_evicts(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp   = release_create();
    pubnub_http_request_t        rq   = interest_request(1);
    pubnub_http_response_t       rs   = {0};
    pubnub_transport_handle_t*   h    = release_complete_one(tp, &rq, &rs);
    pn_socket_connection_t*      conn = interest_conn(tp, h);

    tp->cancel(tp, h);
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);

    mock.current_time_ms += PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS + 1;
    (void)tp->poll(tp, 0);
    assert_int_equal(PN_CONN_IDLE, conn->state);
    assert_int_equal(1, mock.sess_destroyed);
    assert_true(PN_INVALID_SOCKET == conn->socket);

    /* The pre-expiry handle stays stale and the next request dials again. */
    tp->cancel(tp, h);
    {
        pubnub_http_response_t     rs2 = {0};
        pubnub_transport_handle_t* h2  = release_complete_one(tp, &rq, &rs2);

        assert_int_equal(2, mock.sess_created);
        tp->cancel(tp, h2);
    }
    interest_teardown(tp);
}

/** Cancelling an in-flight request still closes the socket and session. */
static void test_cancel_in_flight_still_closes(void** state)
{
    (void)state;
    mock_reset();

    mock.sess[0].script[0] = PN_TLS_WANT_READ;
    mock.sess[0].len       = 1;

    pubnub_transport_provider_t* tp = interest_create(0);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h  = tp->send(tp, &rq, &rs);
    assert_non_null(h);
    pn_socket_connection_t* conn = interest_conn(tp, h);

    interest_poll_until(tp, conn, PN_CONN_TLS_HANDSHAKING);
    tp->cancel(tp, h);

    assert_int_equal(PN_CONN_IDLE, conn->state);
    assert_int_equal(1, mock.sess_destroyed);
    assert_true(0 < mock.socket_destroy_calls);
    assert_true(PN_INVALID_SOCKET == conn->socket);
    assert_int_equal(PUBNUB_ERR_CANCELLED, rs.transport_error);

    interest_teardown(tp);
}

/** Logger that records the worst level seen for the stale-handle message. */
static struct {
    pubnub_logger_provider_t base;
    int                      stale_entries;
    int                      stale_max_level;
    int                      loud_entries;
} stale_log;

static void stale_log_fn(struct pubnub_logger_provider* self,
                         const pubnub_log_entry_t*      entry)
{
    (void)self;
    if (PUBNUB_LOG_ENTRY_TEXT != entry->type) {
        return;
    }
    {
        const pubnub_log_entry_text_t* text = (const pubnub_log_entry_text_t*)entry;

        if (PUBNUB_LOG_LEVEL_WARNING <= entry->level) {
            stale_log.loud_entries++;
        }
        if (NULL != strstr(text->message, "stale handle")) {
            stale_log.stale_entries++;
            if ((int)entry->level > stale_log.stale_max_level) {
                stale_log.stale_max_level = (int)entry->level;
            }
        }
    }
}

/** A stale cancel is routine and must not log at WARNING or above. */
static void test_stale_cancel_logs_below_warning(void** state)
{
    (void)state;
    mock_reset();

    memset(&stale_log, 0, sizeof(stale_log));
    stale_log.base.log = stale_log_fn;

    pubnub_transport_provider_t* tp      = release_create();
    ((pn_socket_transport_t*)tp)->logger = &stale_log.base;
    pubnub_http_request_t      rq        = interest_request(1);
    pubnub_http_response_t     rs        = {0};
    pubnub_transport_handle_t* h         = release_complete_one(tp, &rq, &rs);

    tp->cancel(tp, h);
    tp->cancel(tp, h);
    tp->cancel(tp, h);

    if (0 != PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE
        && PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_DEBUG)) {
        assert_int_equal(2, stale_log.stale_entries);
        assert_int_equal((int)PUBNUB_LOG_LEVEL_DEBUG, stale_log.stale_max_level);
    }
    assert_int_equal(0, stale_log.loud_entries);

    interest_teardown(tp);
}

static const char held_resp_a[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
static const char held_resp_b[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nWXYZ";

/** Point the mock at one of the canned responses and rewind it. */
static void held_use(const char* resp)
{
    mock.recv_data     = (const uint8_t*)resp;
    mock.recv_data_len = strlen(resp);
    mock.recv_offset   = 0;
}

/** While A holds its response, B to the same host uses another connection. */
static void test_unreleased_response_connection_not_reused(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp   = interest_create(0);
    pubnub_http_request_t        rq   = interest_request(1);
    pubnub_http_response_t       rs_a = {0};
    pubnub_http_response_t       rs_b = {0};
    pubnub_http_response_t       rs_c = {0};
    pubnub_transport_handle_t *  a, *b, *c;

    held_use(held_resp_a);
    a = release_complete_one(tp, &rq, &rs_a);
    assert_int_equal(4, (int)rs_a.body_len);
    assert_memory_equal("test", rs_a.body, 4);

    held_use(held_resp_b);
    {
        const int creates  = mock.socket_create_calls;
        const int sessions = mock.sess_created;

        b = release_complete_one(tp, &rq, &rs_b);
        assert_ptr_not_equal(interest_conn(tp, a), interest_conn(tp, b));
        assert_true(mock.socket_create_calls > creates);
        assert_int_equal(sessions + 1, mock.sess_created);
    }
    assert_memory_equal("WXYZ", rs_b.body, 4);
    assert_memory_equal("test", rs_a.body, 4);

    tp->cancel(tp, a);
    tp->cancel(tp, b);
    {
        const int creates  = mock.socket_create_calls;
        const int sessions = mock.sess_created;

        held_use(held_resp_a);
        c = tp->send(tp, &rq, &rs_c);
        assert_non_null(c);
        assert_int_equal(creates, mock.socket_create_calls);
        assert_int_equal(sessions, mock.sess_created);
    }
    tp->cancel(tp, c);
    interest_teardown(tp);
}

/** With every connection held, send reports QUEUE_FULL; release frees one. */
static void test_all_connections_held_reports_queue_full(void** state)
{
    enum { N = PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS };

    pubnub_http_response_t     rs[N];
    pubnub_transport_handle_t* h[N];
    pubnub_http_request_t      rq = {0};
    int                        i;

    (void)state;
    mock_reset();
    memset(rs, 0, sizeof(rs));

    pubnub_transport_provider_t* tp = interest_create(0);
    rq                              = interest_request(1);

    held_use(held_resp_a);
    for (i = 0; i < N; ++i) {
        h[i] = release_complete_one(tp, &rq, &rs[i]);
    }
    assert_int_equal(N, mock.sess_created);
    {
        pubnub_http_response_t rs_x = {0};

        held_use(held_resp_b);
        assert_null(tp->send(tp, &rq, &rs_x));
        assert_int_equal(PUBNUB_ERR_QUEUE_FULL, rs_x.transport_error);
    }
    for (i = 0; i < N; ++i) {
        assert_memory_equal("test", rs[i].body, 4);
    }
    assert_int_equal(0, mock.sess_destroyed);

    tp->cancel(tp, h[0]);
    {
        pubnub_http_response_t     rs_y = {0};
        pubnub_transport_handle_t* y;

        held_use(held_resp_b);
        y = tp->send(tp, &rq, &rs_y);
        assert_non_null(y);
        assert_int_equal(N, mock.sess_created);
        tp->cancel(tp, y);
    }
    for (i = 1; i < N; ++i) {
        tp->cancel(tp, h[i]);
    }
    interest_teardown(tp);
}

/** A server-closed connection keeps its rx buffer; the next send skips it. */
static void test_unreleased_closed_response_slot_not_recycled(void** state)
{
    static const char close_resp[] =
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\ntest";
    pubnub_http_response_t rs_a = {0};
    pubnub_http_response_t rs_b = {0};

    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = interest_create(0);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_transport_handle_t *  a, *b;

    held_use(close_resp);
    a = tp->send(tp, &rq, &rs_a);
    assert_non_null(a);
    interest_poll_until(tp, interest_conn(tp, a), PN_CONN_IDLE);
    assert_int_equal(PUBNUB_HTTP_COMPLETE, rs_a.completion);
    assert_memory_equal("test", rs_a.body, 4);

    held_use(held_resp_b);
    b = release_complete_one(tp, &rq, &rs_b);
    assert_ptr_not_equal(interest_conn(tp, a), interest_conn(tp, b));
    assert_memory_equal("test", rs_a.body, 4);
    assert_memory_equal("WXYZ", rs_b.body, 4);

    tp->cancel(tp, a);
    tp->cancel(tp, b);
    interest_teardown(tp);
}

/** The idle timeout skips unreleased responses; the clock starts at release. */
static void test_idle_timeout_spares_held_response(void** state)
{
    (void)state;
    mock_reset();

    pubnub_transport_provider_t* tp = interest_create(0);
    pubnub_http_request_t        rq = interest_request(1);
    pubnub_http_response_t       rs = {0};
    pubnub_transport_handle_t*   h;
    pn_socket_connection_t*      conn;

    held_use(held_resp_a);
    h    = release_complete_one(tp, &rq, &rs);
    conn = interest_conn(tp, h);

    mock.current_time_ms += 2U * PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS;
    (void)tp->poll(tp, 0);
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);
    assert_int_equal(0, mock.sess_destroyed);
    assert_memory_equal("test", rs.body, 4);

    /* Released after a long hold: the idle clock starts now. */
    tp->cancel(tp, h);
    (void)tp->poll(tp, 0);
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);
    assert_int_equal(0, mock.sess_destroyed);

    mock.current_time_ms += PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS + 1U;
    (void)tp->poll(tp, 0);
    assert_int_equal(PN_CONN_IDLE, conn->state);
    assert_int_equal(1, mock.sess_destroyed);

    interest_teardown(tp);
}

/** Long-poll redispatch shares one connection; a publish takes one more. */
static void test_long_poll_cycles_with_publish_handshake_once(void** state)
{
    enum { CYCLES = 10 };

    int                          cycle;
    pubnub_transport_handle_t*   poll_h = NULL;
    pubnub_http_response_t       poll_rs[CYCLES];
    pubnub_transport_provider_t* tp;
    pubnub_http_request_t        rq;

    (void)state;
    mock_reset();
    memset(poll_rs, 0, sizeof(poll_rs));
    tp = release_create();
    rq = interest_request(1);

    for (cycle = 0; cycle < CYCLES; ++cycle) {
        if (NULL != poll_h) {
            tp->cancel(tp, poll_h);
        }
        poll_h = release_complete_one(tp, &rq, &poll_rs[cycle]);
        assert_int_equal(1, mock.sess_created);
    }

    for (cycle = 0; cycle < CYCLES; ++cycle) {
        pubnub_http_response_t     pub_rs = {0};
        pubnub_transport_handle_t* pub_h;

        /* The poll of this cycle is held while the publish runs. */
        pub_h = release_complete_one(tp, &rq, &pub_rs);
        tp->cancel(tp, pub_h);
        tp->cancel(tp, poll_h);
        assert_int_equal(2, mock.sess_created);

        poll_h = release_complete_one(tp, &rq, &poll_rs[cycle]);
    }
    assert_int_equal(2, mock.sess_created);
    assert_int_equal(0, mock.sess_destroyed);

    tp->cancel(tp, poll_h);
    interest_teardown(tp);
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
        cmocka_unit_test(test_cancel_after_keepalive_reuse_is_stale_noop),
        cmocka_unit_test(test_reentrant_restart_preserves_generation),
        cmocka_unit_test(test_failed_connection_reaped_after_grace),
        cmocka_unit_test(test_interest_connecting_has_write),
        cmocka_unit_test(test_interest_tls_initial_has_write),
        cmocka_unit_test(test_interest_tls_want_read_read_only),
        cmocka_unit_test(test_interest_tls_want_write_has_write),
        cmocka_unit_test(test_interest_tls_change_within_state),
        cmocka_unit_test(test_interest_tls_no_wake_pipe_keeps_write),
        cmocka_unit_test(test_interest_receiving_read_only),
        cmocka_unit_test(test_interest_tls_deferred_connecting_keeps_write),
        cmocka_unit_test(test_interest_tls_deferred_to_handshaking_mask),
        cmocka_unit_test(test_interest_send_registration_never_empty),
        cmocka_unit_test(test_interest_deadline_fires_without_readiness),
        cmocka_unit_test(test_interest_same_fd_reuse_after_tls_fallback),
        cmocka_unit_test(test_wake_error_degrades_pipe),
        cmocka_unit_test(test_wake_hup_degrades_pipe),
        cmocka_unit_test(test_wake_unmapped_event_degrades_pipe),
        cmocka_unit_test(test_wake_degrade_is_one_shot),
        cmocka_unit_test(test_wake_degraded_wake_and_cleanup_ok),
        cmocka_unit_test(test_wake_normal_read_not_degraded),
        cmocka_unit_test(test_wake_other_fd_error_ignored),
        cmocka_unit_test(test_wake_none_ignores_ready_set),
        cmocka_unit_test(test_wake_degraded_bounds_poll_timeout),
        cmocka_unit_test(test_poll_timeout_zero_for_fdless_connecting),
        cmocka_unit_test(test_poll_timeout_zero_after_failed_address),
        cmocka_unit_test(test_poll_timeout_zero_is_not_a_spin),
        cmocka_unit_test(test_poll_timeout_kept_for_normal_states),
        cmocka_unit_test(test_release_completed_keeps_connection),
        cmocka_unit_test(test_request_after_release_reuses_connection),
        cmocka_unit_test(test_sequential_release_cycles_open_one_connection),
        cmocka_unit_test(test_release_kept_connection_is_evictable),
        cmocka_unit_test(test_release_kept_connection_idle_timeout_evicts),
        cmocka_unit_test(test_cancel_in_flight_still_closes),
        cmocka_unit_test(test_stale_cancel_logs_below_warning),
        cmocka_unit_test(test_unreleased_response_connection_not_reused),
        cmocka_unit_test(test_all_connections_held_reports_queue_full),
        cmocka_unit_test(test_unreleased_closed_response_slot_not_recycled),
        cmocka_unit_test(test_idle_timeout_spares_held_response),
        cmocka_unit_test(test_long_poll_cycles_with_publish_handshake_once),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
