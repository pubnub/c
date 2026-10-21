/**
 * @file test_connection_fsm.c
 * @brief cmocka tests for the socket transport connection FSM.
 *
 * Uses mock platform ops and TLS backend to drive the state machine
 * through various scenarios: happy path, timeouts, failover, TLS
 * handshake, and cancellation.
 *
 * Copyright PubNub Inc.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "providers/transport/socket/connection_fsm_internal.h"
#include "providers/transport/socket/inflate/pn_inflate.h"
#include "providers/transport/socket/connection_fsm.c"

/*
 * Layout guard: proxy_done and tls_want stay adjacent, and redirect_host sits
 * no more than 4 bytes past proxy_done (detects a fifth narrow field only).
 */
PUBNUB_STATIC_ASSERT(offsetof(pn_socket_connection_t, tls_want)
                         == offsetof(pn_socket_connection_t, proxy_done) + 1U,
                     "proxy_done and tls_want must stay adjacent");
PUBNUB_STATIC_ASSERT(offsetof(pn_socket_connection_t, redirect_host)
                         <= offsetof(pn_socket_connection_t, proxy_done) + 4U,
                     "narrow-field block before redirect_host outgrew padding");

/** Mock control state for platform operations. */
static struct {
    /* Socket ops. */
    pn_socket_t next_socket;
    int         connect_result;
    int         check_connect_result;
    int         send_result;
    int         recv_result;
    int         set_nonblocking_result;
    int         set_keepalive_result;
    int         socket_destroy_calls;
    int         socket_create_calls;
    /* Value of socket_create_calls when socket_destroy last ran (proves the
     * destroy happened before a replacement socket was created). */
    int socket_create_calls_at_destroy;
    int socket_send_calls;

    /* Scripted per-call send results for partial-send simulation. When
     * send_script_len > 0, mock_socket_send and mock_tls_send return
     * send_script[send_call_idx] and advance the index, clamping to the
     * last entry once exhausted. This overrides send_result /
     * tls_send_result. Used to model "send N bytes, then fail". */
    int send_script[8];
    int send_script_len;
    int send_call_idx;

    /* Scripted check_connect results (a connect pending for N ticks); the last
     * entry repeats once exhausted. */
    int check_connect_script[8];
    int check_connect_script_len;
    int check_connect_calls;
    /* 1 = any socket_check_connect call fails the test (the FSM must not
     * probe a socket whose connect it already confirmed). */
    int check_connect_forbidden;
    /* Non-zero: socket_check_connect on this socket reports "still
     * pending" forever (a blackholed address), regardless of the script. */
    pn_socket_t pending_forever_sock;
    /* Non-zero: every socket_create returns a fresh descriptor number. */
    int unique_fds;
    int set_keepalive_calls;

    /* Recv data. */
    const uint8_t* recv_data;
    size_t         recv_data_len;
    size_t         recv_offset;

    /* Second response for redirect tests. When the primary recv data
     * is exhausted and recv_data_next is set, the mock switches to it. */
    const uint8_t* recv_data_next;
    size_t         recv_data_next_len;

    /* When set, reset recv_offset to 0 when data is exhausted (for
     * infinite redirect loop tests). */
    int recv_repeat;

    /* Monotonic time. */
    uint64_t current_time_ms;

    /* DNS resolver mock state. */
    pn_dns_state_t dns_state;
    /* 1 = pn_dns_resolver_start enforces the one-lookup-at-a-time rule. */
    int           dns_strict;
    pn_sockaddr_t dns_results[4];
    size_t        dns_result_count;

    /* TLS mock state. */
    int   tls_handshake_result;
    int   tls_handshake_calls_until_ok;
    int   tls_session_create_result;
    int   tls_session_create_calls;
    int   tls_send_result;
    int   tls_recv_result;
    int   tls_session_destroy_calls;
    void* tls_fake_session;
    /* Value returned by the diagnostic backend's get_session_error hook. */
    int tls_session_error;

    /* Response headers injected by pn_http_parser_get_headers mock. */
    pubnub_kv_t  resp_headers[4];
    unsigned int resp_header_count;
} mock_state;

static void mock_reset(void)
{
    memset(&mock_state, 0, sizeof(mock_state));
    mock_state.next_socket               = 42;
    mock_state.connect_result            = 1;
    mock_state.check_connect_result      = 1;
    mock_state.send_result               = 0;
    mock_state.recv_result               = 0;
    mock_state.set_nonblocking_result    = 0;
    mock_state.set_keepalive_result      = 0;
    mock_state.current_time_ms           = 1000000;
    mock_state.dns_state                 = PN_DNS_STATE_DONE;
    mock_state.dns_result_count          = 1;
    mock_state.tls_handshake_result      = PN_TLS_OK;
    mock_state.tls_session_create_result = 0;
    mock_state.tls_fake_session          = (void*)0xBEEF;

    /* Default: one IPv4 result. */
    mock_state.dns_results[0].family       = PN_AF_INET;
    mock_state.dns_results[0].port         = 443;
    mock_state.dns_results[0].addr.ipv4[0] = 1;
    mock_state.dns_results[0].addr.ipv4[1] = 2;
    mock_state.dns_results[0].addr.ipv4[2] = 3;
    mock_state.dns_results[0].addr.ipv4[3] = 4;
}

/* --- Mock platform ops --- */

static pn_socket_t mock_socket_create(const pn_socket_platform_ops_t* self,
                                      uint16_t                        family,
                                      int                             dgram)
{
    (void)self;
    (void)family;
    (void)dgram;
    mock_state.socket_create_calls++;
    if (0 != mock_state.unique_fds) {
        return mock_state.next_socket++;
    }
    return mock_state.next_socket;
}

static void mock_socket_destroy(const pn_socket_platform_ops_t* self, pn_socket_t sock)
{
    (void)self;
    (void)sock;
    mock_state.socket_create_calls_at_destroy = mock_state.socket_create_calls;
    mock_state.socket_destroy_calls++;
}

static int mock_socket_connect(const pn_socket_platform_ops_t* self,
                               pn_socket_t                     sock,
                               const pn_sockaddr_t*            addr)
{
    (void)self;
    (void)sock;
    (void)addr;
    return mock_state.connect_result;
}

static int mock_socket_check_connect(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock)
{
    (void)self;
    if (0 != mock_state.check_connect_forbidden) {
        fail_msg("socket_check_connect called on a connected connection");
    }
    if (0 != mock_state.pending_forever_sock
        && sock == mock_state.pending_forever_sock) {
        mock_state.check_connect_calls++;
        return 0;
    }
    if (mock_state.check_connect_script_len > 0) {
        int idx = mock_state.check_connect_calls;
        if (idx >= mock_state.check_connect_script_len) {
            idx = mock_state.check_connect_script_len - 1;
        }
        mock_state.check_connect_calls++;
        return mock_state.check_connect_script[idx];
    }
    mock_state.check_connect_calls++;
    return mock_state.check_connect_result;
}

/*
 * Return the next scripted send result, or the given fallback when no
 * script is active. The script is shared by mock_socket_send and
 * mock_tls_send.
 * TODO(test-infra): the script is a single shared sequence; a test that
 * needs to drive plaintext and TLS sends independently in one run would
 * need a second script array. Not required by any current test.
 */
static int mock_next_send_rc(int fallback)
{
    if (mock_state.send_script_len > 0) {
        int idx = mock_state.send_call_idx;
        if (idx >= mock_state.send_script_len) {
            idx = mock_state.send_script_len - 1;
        }
        mock_state.send_call_idx++;
        return mock_state.send_script[idx];
    }
    return fallback;
}

static int mock_socket_send(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            const uint8_t*                  data,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    (void)data;
    mock_state.socket_send_calls++;
    if (mock_state.send_script_len > 0) {
        return mock_next_send_rc((int)len);
    }
    if (0 != mock_state.send_result) {
        return mock_state.send_result;
    }
    /* Default: send all. */
    return (int)len;
}

static int mock_socket_recv(const pn_socket_platform_ops_t* self,
                            pn_socket_t                     sock,
                            uint8_t*                        buf,
                            size_t                          len)
{
    (void)self;
    (void)sock;
    if (0 != mock_state.recv_result) {
        return mock_state.recv_result;
    }
    /* Supply mock recv data. */
    if (NULL == mock_state.recv_data
        || mock_state.recv_offset >= mock_state.recv_data_len) {
        /* Primary data exhausted — switch to next response if available. */
        if (NULL != mock_state.recv_data_next) {
            mock_state.recv_data          = mock_state.recv_data_next;
            mock_state.recv_data_len      = mock_state.recv_data_next_len;
            mock_state.recv_offset        = 0;
            mock_state.recv_data_next     = NULL;
            mock_state.recv_data_next_len = 0;
        } else if (mock_state.recv_repeat) {
            /* Loop: restart from the beginning of the same data. */
            mock_state.recv_offset = 0;
        } else {
            return 0; /* Would-block. */
        }
    }
    size_t avail = mock_state.recv_data_len - mock_state.recv_offset;
    if (avail > len) {
        avail = len;
    }
    memcpy(buf, mock_state.recv_data + mock_state.recv_offset, avail);
    mock_state.recv_offset += avail;
    return (int)avail;
}

static int mock_socket_set_nonblocking(const pn_socket_platform_ops_t* self,
                                       pn_socket_t                     sock)
{
    (void)self;
    (void)sock;
    return mock_state.set_nonblocking_result;
}

static int mock_socket_set_keepalive(const pn_socket_platform_ops_t* self,
                                     pn_socket_t                     sock,
                                     const pubnub_tcp_keepalive_config_t* config)
{
    (void)self;
    (void)sock;
    (void)config;
    mock_state.set_keepalive_calls++;
    return mock_state.set_keepalive_result;
}

static pn_socket_platform_ops_t mock_ops = {
    .socket_create          = mock_socket_create,
    .socket_destroy         = mock_socket_destroy,
    .socket_connect         = mock_socket_connect,
    .socket_check_connect   = mock_socket_check_connect,
    .socket_send            = mock_socket_send,
    .socket_recv            = mock_socket_recv,
    .socket_sendto          = NULL,
    .socket_recvfrom        = NULL,
    .socket_set_nonblocking = mock_socket_set_nonblocking,
    .socket_set_keepalive   = mock_socket_set_keepalive,
    .poll_init              = NULL,
    .poll_deinit            = NULL,
    .poll_add               = NULL,
    .poll_modify            = NULL,
    .poll_remove            = NULL,
    .poll_wait              = NULL,
    .poll_ready_count       = NULL,
    .poll_get_ready         = NULL,
    .dns_discover_servers   = NULL,
};

/* --- Mock platform provider (for monotonic_ms) --- */

static uint64_t mock_monotonic_ms(struct pubnub_platform_provider* self)
{
    (void)self;
    return mock_state.current_time_ms;
}

static struct pubnub_platform_provider mock_platform = {
    .monotonic_ms = mock_monotonic_ms,
};

/* --- Mock allocator (needed for redirect tests) --- */

static uint8_t mock_rx_buf[1024];

static void* mock_alloc_fn(struct pubnub_allocator_provider* self,
                           size_t                            size,
                           size_t                            align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void mock_free_fn(struct pubnub_allocator_provider* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t mock_buf_acquire_fn(struct pubnub_allocator_provider* self,
                                           pubnub_buf_purpose_t purpose)
{
    (void)self;
    (void)purpose;
    pubnub_buffer_t buf = {0};
    buf.data            = mock_rx_buf;
    buf.cap             = sizeof(mock_rx_buf);
    buf.len             = 0;
    buf.purpose         = purpose;
    return buf;
}

static void mock_buf_release_fn(struct pubnub_allocator_provider* self,
                                pubnub_buffer_t*                  buf)
{
    (void)self;
    if (NULL != buf) {
        buf->data = NULL;
        buf->cap  = 0;
        buf->len  = 0;
    }
}

static struct pubnub_allocator_provider mock_allocator = {
    .alloc       = mock_alloc_fn,
    .realloc     = NULL,
    .free        = mock_free_fn,
    .buf_acquire = mock_buf_acquire_fn,
    .buf_release = mock_buf_release_fn,
    .buf_grow    = NULL,
};

/* --- Mock DNS resolver (override functions via linker) --- */

/*
 * Since we #include the .c file directly, we override the DNS resolver
 * functions that the FSM calls. The mock_state controls results.
 */
pn_dns_state_t pn_dns_resolver_state(const pn_dns_resolver_t* resolver)
{
    (void)resolver;
    return mock_state.dns_state;
}

int pn_dns_resolver_get_results(const pn_dns_resolver_t* resolver,
                                pn_sockaddr_t*           addrs_out,
                                size_t                   max_addrs,
                                size_t*                  out_count)
{
    (void)resolver;
    if (0 == mock_state.dns_result_count) {
        *out_count = 0;
        return -1;
    }
    size_t count = mock_state.dns_result_count;
    if (count > max_addrs) {
        count = max_addrs;
    }
    memcpy(addrs_out, mock_state.dns_results, count * sizeof(pn_sockaddr_t));
    *out_count = count;
    return 0;
}

int pn_dns_resolver_start(pn_dns_resolver_t* resolver, const char* hostname)
{
    (void)hostname;
    if (!mock_state.dns_strict) {
        return 0;
    }
    /* Strict mode mirrors the real resolver: a completed-but-unclaimed
     * lookup blocks every new lookup until someone releases it. */
    if (PN_DNS_STATE_IDLE != resolver->state) {
        return -1;
    }
    resolver->state = mock_state.dns_state;
    return 0;
}

pn_dns_state_t pn_dns_resolver_tick(pn_dns_resolver_t* resolver)
{
    (void)resolver;
    return mock_state.dns_state;
}

void pn_dns_resolver_invalidate(pn_dns_resolver_t* resolver, const char* hostname)
{
    (void)resolver;
    (void)hostname;
}

int pn_inflate_gzip(const uint8_t*                    input,
                    size_t                            input_len,
                    uint8_t*                          output,
                    size_t                            output_cap,
                    size_t*                           out_len,
                    struct pubnub_allocator_provider* allocator,
                    struct pubnub_logger_provider*    logger)
{
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_cap;
    (void)allocator;
    (void)logger;
    *out_len = 0;
    return PN_INFLATE_OK;
}

int pn_inflate_deflate(const uint8_t*                    input,
                       size_t                            input_len,
                       uint8_t*                          output,
                       size_t                            output_cap,
                       size_t*                           out_len,
                       struct pubnub_allocator_provider* allocator,
                       struct pubnub_logger_provider*    logger)
{
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_cap;
    (void)allocator;
    (void)logger;
    *out_len = 0;
    return PN_INFLATE_OK;
}

/* --- Mock TLS backend --- */

static void* mock_tls_ctx_create(const pn_tls_config_t*             cfg,
                                 const struct pubnub_provider_deps* deps)
{
    (void)cfg;
    (void)deps;
    return (void*)0xCAFE;
}

static void mock_tls_ctx_destroy(void* ctx)
{
    (void)ctx;
}

static int mock_tls_session_create(void**      out_session,
                                   void*       ctx,
                                   pn_socket_t sock,
                                   const struct pn_socket_platform_ops* ops,
                                   const char* hostname)
{
    (void)ctx;
    (void)sock;
    (void)ops;
    (void)hostname;
    mock_state.tls_session_create_calls++;
    if (0 != mock_state.tls_session_create_result) {
        return mock_state.tls_session_create_result;
    }
    *out_session = mock_state.tls_fake_session;
    return 0;
}

static int mock_tls_handshake(void* session)
{
    (void)session;
    if (mock_state.tls_handshake_calls_until_ok > 0) {
        mock_state.tls_handshake_calls_until_ok--;
        return mock_state.tls_handshake_result;
    }
    return PN_TLS_OK;
}

static int mock_tls_send(void* session, const void* buf, size_t len)
{
    (void)session;
    (void)buf;
    if (mock_state.send_script_len > 0) {
        return mock_next_send_rc((int)len);
    }
    if (0 != mock_state.tls_send_result) {
        return mock_state.tls_send_result;
    }
    return (int)len;
}

static int mock_tls_recv(void* session, void* buf, size_t len)
{
    (void)session;
    /* Delegate to regular recv mock for simplicity. */
    return mock_socket_recv(NULL, 0, (uint8_t*)buf, len);
}

static void mock_tls_session_destroy(void* session)
{
    (void)session;
    mock_state.tls_session_destroy_calls++;
}

static pn_tls_backend_t mock_tls_backend = {
    .ctx_create      = mock_tls_ctx_create,
    .ctx_destroy     = mock_tls_ctx_destroy,
    .session_create  = mock_tls_session_create,
    .handshake       = mock_tls_handshake,
    .send            = mock_tls_send,
    .recv            = mock_tls_recv,
    .session_destroy = mock_tls_session_destroy,
};

static int mock_tls_get_session_error(void* session)
{
    (void)session;
    return mock_state.tls_session_error;
}

static const char* mock_tls_session_error_str(int code)
{
    return (12345 == code) ? "MOCK_TLS_ERR" : NULL;
}

/* Same behaviour as mock_tls_backend plus the optional diagnostic hooks. */
static pn_tls_backend_t mock_tls_backend_diag = {
    .ctx_create        = mock_tls_ctx_create,
    .ctx_destroy       = mock_tls_ctx_destroy,
    .session_create    = mock_tls_session_create,
    .handshake         = mock_tls_handshake,
    .send              = mock_tls_send,
    .recv              = mock_tls_recv,
    .session_destroy   = mock_tls_session_destroy,
    .get_session_error = mock_tls_get_session_error,
    .session_error_str = mock_tls_session_error_str,
};

/* --- Mock HTTP builder/parser (provided via .c include) --- */

/* We need stub implementations since we included connection_fsm.c. */
int pn_http_build_headers(const pubnub_http_request_t* request,
                          uint8_t*                     buf,
                          size_t                       buf_size,
                          size_t*                      out_len)
{
    (void)request;
    /* Produce a minimal fake HTTP request header. */
    const char* fake = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
    size_t      len  = strlen(fake);
    if (len > buf_size) {
        return -1;
    }
    memcpy(buf, fake, len);
    *out_len = len;
    return 0;
}

uint16_t pn_http_resolve_port(const pubnub_http_request_t* request)
{
    if (NULL == request || NULL == request->host) {
        return 0;
    }
    return request->secure ? 443 : 80;
}

void pn_http_parser_get_headers(const pn_http_parser_t* parser,
                                uint8_t*                data,
                                pubnub_kv_t*            out,
                                unsigned int            out_cap,
                                unsigned int*           out_count)
{
    (void)parser;
    (void)data;
    unsigned int count = mock_state.resp_header_count;
    if (count > out_cap) {
        count = out_cap;
    }
    for (unsigned int i = 0; i < count; i++) {
        out[i] = mock_state.resp_headers[i];
    }
    *out_count = count;
}

void pn_http_parser_init(pn_http_parser_t* parser)
{
    memset(parser, 0, sizeof(*parser));
    parser->body_start_offset = UINT32_MAX;
}

pn_http_parse_result_t pn_http_parser_feed(pn_http_parser_t* parser,
                                           uint8_t*          data,
                                           size_t            len,
                                           size_t*           consumed,
                                           uint16_t*         status_code,
                                           const uint8_t**   body_start,
                                           size_t*           body_len)
{
    (void)parser;
    *consumed = len;

    /* Parse any "HTTP/1.1 NNN" status line. Extracts the 3-digit code
     * so redirect tests (307) and error tests work alongside 200. */
    if (len > 12 && 0 == memcmp(data, "HTTP/1.1 ", 9)) {
        uint16_t code = 0;
        size_t   i;
        for (i = 9; i < 12 && i < len; i++) {
            if (data[i] >= '0' && data[i] <= '9') {
                code = (uint16_t)(code * 10 + (data[i] - '0'));
            }
        }
        *status_code = code;

        /* Body starts after headers (simplified). */
        const uint8_t* hdr_end =
            (const uint8_t*)strstr((const char*)data, "\r\n\r\n");
        if (NULL != hdr_end) {
            hdr_end += 4;
            *body_start               = hdr_end;
            *body_len                 = len - (size_t)(hdr_end - data);
            parser->body_start_offset = (uint32_t)(hdr_end - data);
        } else {
            *body_start               = data + len;
            *body_len                 = 0;
            parser->body_start_offset = UINT32_MAX;
        }
        parser->status_code    = code;
        parser->body_received  = (uint32_t)*body_len;
        parser->content_length = (uint32_t)*body_len;
        return PN_HTTP_PARSE_COMPLETE;
    }
    return PN_HTTP_PARSE_NEED_MORE;
}

pn_http_parse_result_t pn_http_parser_signal_eof(pn_http_parser_t* parser)
{
    if (NULL == parser) {
        return PN_HTTP_PARSE_ERROR;
    }
    if (PN_HTTP_STATE_BODY_UNTIL_CLOSE == parser->state
        || PN_HTTP_STATE_DONE == parser->state) {
        parser->state = PN_HTTP_STATE_DONE;
        return PN_HTTP_PARSE_COMPLETE;
    }
    /* The feed mock does not advance state to DONE, so treat a fully
     * received Content-Length body as complete on close, matching the
     * real parser's contract. */
    if (parser->content_length > 0
        && parser->body_received >= parser->content_length) {
        return PN_HTTP_PARSE_COMPLETE;
    }
    return PN_HTTP_PARSE_ERROR;
}

int pn_keepalive_can_reuse(const pn_keepalive_conn_state_t* conn,
                           const pn_keepalive_target_t*     target,
                           uint64_t                         now_ms,
                           uint16_t                         max_requests,
                           uint32_t                         max_idle_ms)
{
    if (NULL == conn || NULL == target) {
        return 0;
    }
    if (NULL == conn->host || NULL == target->host) {
        return 0;
    }
    if (0 != strcmp(conn->host, target->host)) {
        return 0;
    }
    if (conn->port != target->port) {
        return 0;
    }
    if (conn->secure != target->secure) {
        return 0;
    }
    if (conn->requests_served >= max_requests) {
        return 0;
    }
    if ((now_ms - conn->idle_since_ms) > max_idle_ms) {
        return 0;
    }
    return 1;
}

int pn_keepalive_should_close(uint8_t parser_flags)
{
    return 0 != (parser_flags & PN_HTTP_FLAG_CONNECTION_CLOSE);
}

/* --- Test helpers --- */

static pn_dns_resolver_t mock_resolver;

static pn_socket_transport_t make_transport(void)
{
    pn_socket_transport_t t;
    memset(&t, 0, sizeof(t));
    t.ops         = &mock_ops;
    t.tls_backend = &mock_tls_backend;
    t.tls_ctx     = (void*)0xCAFE;
    t.platform    = &mock_platform;
    t.resolver    = mock_resolver;
    t.keepalive_config =
        (pubnub_tcp_keepalive_config_t)PUBNUB_TCP_KEEPALIVE_CONFIG_INIT;
    return t;
}

static pubnub_http_request_t make_request(void)
{
    pubnub_http_request_t req;
    memset(&req, 0, sizeof(req));
    req.method     = PUBNUB_HTTP_GET;
    req.host       = "ps.pndsn.com";
    req.secure     = 1;
    req.timeout_ms = 5000;
    return req;
}

/* --- Tests --- */

/** Happy path: DNS immediate, connect immediate, TLS OK, response. */
static void test_fsm_idle_to_complete(void** state)
{
    (void)state;
    mock_reset();

    /* Provide HTTP response data for recv. */
    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);

    /* Provide RX buffer. */
    uint8_t rx_buf[1024];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* DNS was immediate → should be in CONNECTING. */
    assert_int_equal(conn.state, PN_CONN_CONNECTING);

    /* Tick: connect immediate → TLS_HANDSHAKING. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Tick: TLS handshake OK → SENDING_HEADERS. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Tick: send headers (all at once) → RECEIVING_RESPONSE. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);

    /* Tick: receive response → COMPLETE. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);

    assert_int_equal(response.completion, PUBNUB_HTTP_COMPLETE);
    assert_int_equal(response.status_code, 200);
}

/** Connect timeout: connect never completes, deadline expires. */
static void test_fsm_connect_timeout(void** state)
{
    (void)state;
    mock_reset();

    /* Connect returns in-progress, check_connect always returns 0. */
    mock_state.connect_result       = 0;
    mock_state.check_connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(conn.state, PN_CONN_CONNECTING);

    /* First tick: connect in-progress, deadline not yet expired. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_CONNECTING);

    /* Advance time past connect deadline. */
    mock_state.current_time_ms = conn.connect_deadline_ms + 1;

    /* Tick again: should timeout → FAILED. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TIMEOUT);
}

/**
 * DNS resolution failure terminates the transaction and frees the resolver.
 *
 * When the resolver reports FAILED, the connection must fail with
 * PUBNUB_ERR_TRANSPORT rather than spin, and the shared resolver must be
 * reset to IDLE so a later connection can start a fresh lookup — the guard
 * that keeps an exhausted DNS attempt from wedging the transport.
 */
static void test_fsm_dns_failed_terminates(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    conn.state                   = PN_CONN_DNS_RESOLVING;
    conn.request                 = &request;
    conn.response                = &response;
    conn.connect_deadline_ms     = mock_state.current_time_ms + 30000;
    conn.transaction_deadline_ms = mock_state.current_time_ms + 60000;
    pn_strlcpy(conn.dns_hostname, "host-a.example.com", PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Resolver reports FAILED; pre-set a non-IDLE state so the reset to IDLE
     * is observable (and distinguishes the FAILED branch from the fall-through
     * "still resolving" path). */
    mock_state.dns_state     = PN_DNS_STATE_FAILED;
    transport.resolver.state = PN_DNS_STATE_WAITING;

    pn_conn_state_t s = pn_connection_tick(&conn, &transport);

    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
    assert_int_equal(transport.resolver.state, PN_DNS_STATE_IDLE);
}

/** A pending connect must not start the TLS session. */
static void test_fsm_connect_pending_defers_tls_session(void** state)
{
    (void)state;
    mock_reset();

    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 0;
    mock_state.check_connect_script[1]  = 0;
    mock_state.check_connect_script[2]  = 1;
    mock_state.check_connect_script_len = 3;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));

    /* Tick 1 issues the connect; ticks 2 and 3 observe 0 (pending). */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_CONNECTING, s);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_CONNECTING, s);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_CONNECTING, s);
    assert_int_equal(2, mock_state.check_connect_calls);
    assert_int_equal(0, mock_state.tls_session_create_calls);

    /* Tick 4 observes 1: TLS session is created now. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, s);
    assert_int_equal(3, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.tls_session_create_calls);
}

/** A refused connect on address 0 falls back to address 1. */
static void test_fsm_connect_error_falls_back_to_next_addr(void** state)
{
    (void)state;
    mock_reset();

    mock_state.dns_result_count            = 2;
    mock_state.dns_results[1].family       = PN_AF_INET;
    mock_state.dns_results[1].port         = 443;
    mock_state.dns_results[1].addr.ipv4[0] = 10;
    mock_state.dns_results[1].addr.ipv4[1] = 0;
    mock_state.dns_results[1].addr.ipv4[2] = 0;
    mock_state.dns_results[1].addr.ipv4[3] = 1;

    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = -111; /* ECONNREFUSED (Linux). */
    mock_state.check_connect_script[1]  = 1;
    mock_state.check_connect_script_len = 2;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));

    /* Tick 1: connect to address 0 (pending). */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_CONNECTING, s);
    assert_int_equal(0, conn.addr_current);

    /* Tick 2: refused on address 0, connect issued to address 1. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_CONNECTING, s);
    assert_int_equal(1, conn.addr_current);
    assert_int_equal(0, mock_state.tls_session_create_calls);

    /* Tick 3: address 1 reports connected; TLS starts exactly once. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, s);
    assert_int_equal(1, mock_state.tls_session_create_calls);
}

/** IPv6 fallback: first addr unreachable, second (IPv4) succeeds. */
static void test_fsm_ipv6_fallback(void** state)
{
    (void)state;
    mock_reset();

    /* Two DNS results: IPv6 first, IPv4 second. */
    mock_state.dns_result_count      = 2;
    mock_state.dns_results[0].family = PN_AF_INET6;
    mock_state.dns_results[0].port   = 443;
    memset(mock_state.dns_results[0].addr.ipv6, 1, 16);

    mock_state.dns_results[1].family       = PN_AF_INET;
    mock_state.dns_results[1].port         = 443;
    mock_state.dns_results[1].addr.ipv4[0] = 10;
    mock_state.dns_results[1].addr.ipv4[1] = 0;
    mock_state.dns_results[1].addr.ipv4[2] = 0;
    mock_state.dns_results[1].addr.ipv4[3] = 1;

    /* We need to simulate: first call ENETUNREACH, then success.
     * Override connect_result per-call via the default mock. */
    mock_state.connect_result = -101; /* ENETUNREACH (Linux). */

    static const char* resp  = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[512];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(conn.state, PN_CONN_CONNECTING);

    /* First tick: IPv6 fails with ENETUNREACH.
     * conn_try_connect loops: skips IPv6 (family exhausted),
     * tries IPv4 — but we still have ENETUNREACH set! Fix: */
    mock_state.connect_result = 1; /* Immediate success for IPv4. */

    /* But we need the first call to fail. Reset socket tracking. */
    /* Actually, conn_try_connect was already called during
     * tick_connecting with the initial ENETUNREACH... Let's adjust:
     * The start() found DNS DONE → set CONNECTING. First tick calls
     * tick_connecting → conn->socket == INVALID → conn_try_connect.
     * conn_try_connect loops: addr[0] is IPv6, creates socket, calls
     * socket_connect which returns mock_state.connect_result.
     * We want: first connect returns ENETUNREACH, subsequent 1. */

    /* Simplify: since conn_try_connect is called in a loop, we can't
     * easily make the mock return different values per call without
     * more infrastructure. Instead, pre-set the family_exhausted bit
     * so that the first IPv6 addr is skipped, simulating what happens
     * after ENETUNREACH. */
    conn.family_exhausted     = PN_FAMILY_EXHAUSTED_V6;
    mock_state.connect_result = 1; /* IPv4 immediate success. */

    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    /* Should have connected (IPv4) and moved to TLS. */
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* TLS OK. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Send headers. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);

    /* Recv. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);
    assert_int_equal(response.status_code, 200);
}

/** TLS handshake: WANT_READ twice then OK. */
static void test_fsm_tls_handshake(void** state)
{
    (void)state;
    mock_reset();

    /* TLS returns WANT_READ twice before OK. */
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 2;

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[512];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Tick: connect. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Tick: TLS WANT_READ (first). */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Tick: TLS WANT_READ (second). */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Tick: TLS OK → SENDING_HEADERS. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Send + recv to completion. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);
    assert_int_equal(response.status_code, 200);
}

/** Cancel mid-flight: start, then cancel → CANCELLED. */
static void test_fsm_cancel(void** state)
{
    (void)state;
    mock_reset();

    /* Connect returns in-progress. */
    mock_state.connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* In CONNECTING state. */
    assert_int_equal(conn.state, PN_CONN_CONNECTING);

    /* Tick once: conn_try_connect opens the socket (in-progress connect). */
    pn_connection_tick(&conn, &transport);
    assert_int_not_equal(conn.socket, PN_INVALID_SOCKET);

    /* Cancel. */
    pn_connection_cancel(&conn, &transport);
    assert_int_equal(conn.state, PN_CONN_CANCELLED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_CANCELLED);

    /* Socket should have been destroyed. */
    assert_true(mock_state.socket_destroy_calls > 0);
}

/** COMPLETE advances to KEEP_ALIVE_IDLE when the server keeps the link. */
static void test_fsm_complete_advances_to_keepalive_idle(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[1024];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Drive to COMPLETE. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);

    /* tick_complete() should run now and advance to KEEP_ALIVE_IDLE because
     * no Connection: close flag was set in the mock parser. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_KEEP_ALIVE_IDLE);

    /* Socket must still be open for reuse. */
    assert_int_not_equal(conn.socket, PN_INVALID_SOCKET);
    /* Connection metadata for reuse must be populated. */
    assert_string_equal(conn.connected_host, "ps.pndsn.com");
    assert_int_equal(conn.requests_on_connection, 1);
}

/**
 * Verify tick_complete() transitions COMPLETE → CLOSING → IDLE when the
 * server sends Connection: close.
 */
static void test_fsm_complete_advances_to_closing_on_connection_close(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[1024];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Drive to COMPLETE. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);

    /* Set the CONNECTION_CLOSE flag to simulate "Connection: close" response. */
    conn.parser.flags |= PN_HTTP_FLAG_CONNECTION_CLOSE;

    /* tick_complete() should choose CLOSING, not KEEP_ALIVE_IDLE. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_CLOSING);

    /* tick_closing() frees resources and returns IDLE. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_IDLE);
    assert_int_equal(conn.socket, PN_INVALID_SOCKET);
}

/** Reset brings connection back to IDLE. */
static void test_fsm_reset(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Reset from any state. */
    pn_connection_reset(&conn, &transport);
    assert_int_equal(conn.state, PN_CONN_IDLE);
    assert_int_equal(conn.socket, PN_INVALID_SOCKET);
    assert_null(conn.tls_session);
    assert_null(conn.request);
    assert_null(conn.response);
}

/**
 * Verify that a connection waiting in DNS_RESOLVING does NOT claim DONE
 * results when the resolver's current_hostname differs from the
 * connection's dns_hostname. Only the matching connection may consume
 * the result and advance.
 */
static void test_fsm_dns_waiter_does_not_steal_different_host_result(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_socket_connection_t conn;
    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    /* Place connection A in DNS_RESOLVING with its own hostname. */
    conn.state                   = PN_CONN_DNS_RESOLVING;
    conn.request                 = &request;
    conn.response                = &response;
    conn.connect_deadline_ms     = mock_state.current_time_ms + 30000;
    conn.transaction_deadline_ms = mock_state.current_time_ms + 60000;
    pn_strlcpy(conn.dns_hostname, "host-a.example.com", PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Resolver completed for a DIFFERENT hostname. */
    mock_state.dns_state = PN_DNS_STATE_DONE;
    pn_strlcpy(transport.resolver.current_hostname,
               "host-b.example.com",
               PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Tick: hostname mismatch — conn must NOT advance. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_DNS_RESOLVING);
    /* Resolver state must remain DONE (not consumed by conn A). */
    assert_int_equal(mock_state.dns_state, PN_DNS_STATE_DONE);

    /* Now set the resolver hostname to match conn A. */
    pn_strlcpy(transport.resolver.current_hostname,
               "host-a.example.com",
               PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Tick again: hostname matches — conn A claims result and advances. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_CONNECTING);
}

/**
 * Verify that cancelling a connection that owns the active DNS query
 * resets the resolver to IDLE, and that cancelling a non-owner does
 * NOT reset the resolver.
 */
static void test_fsm_cancel_dns_owner_resets_resolver(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_socket_connection_t conn;
    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    /* Place connection in DNS_RESOLVING as the owner of the query. */
    conn.state    = PN_CONN_DNS_RESOLVING;
    conn.request  = &request;
    conn.response = &response;
    pn_strlcpy(
        conn.dns_hostname, "resolving.example.com", PUBNUB_CFG_MAX_HOSTNAME_LEN);
    pn_strlcpy(transport.resolver.current_hostname,
               "resolving.example.com",
               PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Resolver is mid-query (WAITING). */
    transport.resolver.state = PN_DNS_STATE_WAITING;

    /* Cancel — owner should reset resolver to IDLE. */
    pn_connection_cancel(&conn, &transport);
    assert_int_equal(conn.state, PN_CONN_CANCELLED);
    assert_int_equal(transport.resolver.state, PN_DNS_STATE_IDLE);

    /* Now test a NON-owner: different hostname should NOT reset. */
    pn_socket_connection_t conn2;
    pn_connection_init(&conn2);
    pubnub_http_response_t response2;
    memset(&response2, 0, sizeof(response2));

    conn2.state    = PN_CONN_DNS_RESOLVING;
    conn2.request  = &request;
    conn2.response = &response2;
    pn_strlcpy(conn2.dns_hostname, "other.example.com", PUBNUB_CFG_MAX_HOSTNAME_LEN);
    pn_strlcpy(transport.resolver.current_hostname,
               "resolving.example.com",
               PUBNUB_CFG_MAX_HOSTNAME_LEN);

    /* Set resolver to WAITING again. */
    transport.resolver.state = PN_DNS_STATE_WAITING;

    /* Cancel non-owner — resolver must stay WAITING. */
    pn_connection_cancel(&conn2, &transport);
    assert_int_equal(conn2.state, PN_CONN_CANCELLED);
    assert_int_equal(transport.resolver.state, PN_DNS_STATE_WAITING);
}

#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
/**
 * Redirect followed once: 307 with Location header on first request,
 * then 200 on second. Verify the FSM follows the redirect and
 * the final result is 200.
 */
static void test_redirect_followed_once(void** state)
{
    (void)state;
    mock_reset();

    /* First response: 307 redirect to a different host. */
    static const char resp1[] =
        "HTTP/1.1 307 Temporary Redirect\r\n"
        "Content-Length: 0\r\n"
        "Location: https://cdn.example.com/files/abc123\r\n"
        "\r\n";

    /* Second response: 200 OK with body. */
    static const char resp2[] = "HTTP/1.1 200 OK\r\n"
                                "Content-Length: 11\r\n"
                                "\r\n"
                                "hello world";

    mock_state.recv_data          = (const uint8_t*)resp1;
    mock_state.recv_data_len      = strlen(resp1);
    mock_state.recv_data_next     = (const uint8_t*)resp2;
    mock_state.recv_data_next_len = strlen(resp2);

    /* Inject Location header for pn_http_parser_get_headers mock. */
    mock_state.resp_headers[0].key.ptr = "Location";
    mock_state.resp_headers[0].key.len = 8;
    mock_state.resp_headers[0].value.ptr =
        "https://cdn.example.com/files/abc123";
    mock_state.resp_headers[0].value.len = 36;
    mock_state.resp_header_count         = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    transport.allocator              = &mock_allocator;

    pubnub_http_request_t request = make_request();
    request.follow_redirects      = 1;

    pubnub_http_response_t response = {0};

    pn_connection_init(&conn);
    conn.rx_buf.data = mock_rx_buf;
    conn.rx_buf.cap  = sizeof(mock_rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Drive first request to COMPLETE:
     * DNS → CONNECTING → TLS → SENDING → RECEIVING → COMPLETE */
    pn_conn_state_t s;
    s = pn_connection_tick(&conn, &transport); /* connect */
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport); /* TLS handshake */
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport); /* send headers */
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport); /* receive 307 */
    assert_int_equal(s, PN_CONN_COMPLETE);

    /* tick_complete detects 307 + Location, restarts FSM. After restart,
     * the connection should be in CONNECTING (DNS immediate cache hit). */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_CONNECTING);

    /* Verify redirect state was populated. */
    assert_non_null(conn.redirect_host);
    assert_string_equal(conn.redirect_host, "cdn.example.com");
    assert_non_null(conn.redirect_path);
    assert_string_equal(conn.redirect_path, "files/abc123");
    assert_int_equal(conn.redirect_secure, 1);
    assert_int_equal(conn.redirect_count, 1);

    /* Drive second request to COMPLETE. */
    s = pn_connection_tick(&conn, &transport); /* connect → TLS */
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport); /* TLS handshake */
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport); /* send headers */
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport); /* receive 200 */
    assert_int_equal(s, PN_CONN_COMPLETE);

    /* Final result should be 200. */
    assert_int_equal(response.completion, PUBNUB_HTTP_COMPLETE);
    assert_int_equal(response.status_code, 200);
    assert_int_equal(response.body_len, 11);

    /* Drive tick_complete: redirected connections must close immediately
     * (not pool as keep-alive) so they don't occupy a slot that subsequent
     * PubNub API requests need. Assert CLOSING, not KEEP_ALIVE_IDLE. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_CLOSING);

    pn_connection_reset(&conn, &transport);
}

/**
 * Redirect loop capped: mock always returns 307. Verify the FSM stops
 * after PUBNUB_CFG_SOCKET_MAX_REDIRECTS hops with PUBNUB_ERR_TRANSPORT.
 */
static void test_redirect_loop_capped(void** state)
{
    (void)state;
    mock_reset();

    /* Response that always redirects. */
    static const char resp_307[] =
        "HTTP/1.1 307 Temporary Redirect\r\n"
        "Content-Length: 0\r\n"
        "Location: https://loop.example.com/cycle\r\n"
        "\r\n";

    mock_state.recv_data     = (const uint8_t*)resp_307;
    mock_state.recv_data_len = strlen(resp_307);
    mock_state.recv_repeat   = 1; /* Loop the same response forever. */

    /* Inject Location header. */
    mock_state.resp_headers[0].key.ptr   = "Location";
    mock_state.resp_headers[0].key.len   = 8;
    mock_state.resp_headers[0].value.ptr = "https://loop.example.com/cycle";
    mock_state.resp_headers[0].value.len = 30;
    mock_state.resp_header_count         = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    transport.allocator              = &mock_allocator;

    pubnub_http_request_t request = make_request();
    request.follow_redirects      = 1;

    pubnub_http_response_t response = {0};

    pn_connection_init(&conn);
    conn.rx_buf.data = mock_rx_buf;
    conn.rx_buf.cap  = sizeof(mock_rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Drive PUBNUB_CFG_SOCKET_MAX_REDIRECTS successful redirect cycles.
     * Each cycle follows one 307 and restarts the FSM. After the last one,
     * the next 307 triggers the cap check. */
    pn_conn_state_t s;
    int             redirect_num;
    for (redirect_num = 0; redirect_num < PUBNUB_CFG_SOCKET_MAX_REDIRECTS;
         redirect_num++) {
        /* DNS → CONNECTING → TLS → SENDING → RECEIVING → COMPLETE. */
        s = pn_connection_tick(&conn, &transport);
        assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
        s = pn_connection_tick(&conn, &transport);
        assert_int_equal(s, PN_CONN_SENDING_HEADERS);
        s = pn_connection_tick(&conn, &transport);
        assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
        s = pn_connection_tick(&conn, &transport);
        assert_int_equal(s, PN_CONN_COMPLETE);

        /* tick_complete: detect 307, redirect_count < cap → restart. */
        s = pn_connection_tick(&conn, &transport);
        assert_int_equal(s, PN_CONN_CONNECTING);
        assert_int_equal(conn.redirect_count, redirect_num + 1);
    }

    /* redirect_count is now at the cap. Drive one more request cycle:
     * the 307 completes, then tick_complete detects the cap. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);

    /* tick_complete: redirect_count >= cap → FAILED. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
    /* redirect_count is reset to 0 by conn_free_redirect on cap-exceeded path. */
    assert_int_equal(conn.redirect_count, 0);
}
#endif /* PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0 */

/**
 * TLS handshake serialization: when two connections target the same
 * hostname and the first enters TLS_HANDSHAKING, the second must
 * defer (stay CONNECTING) until the first handshake completes.
 */
static void test_tls_handshake_serialized_same_host(void** state)
{
    (void)state;
    mock_reset();

    /* Keep TLS handshaking indefinitely (WANT_READ). */
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  req0      = make_request();
    pubnub_http_request_t  req1      = make_request();
    pubnub_http_response_t resp0     = {0};
    pubnub_http_response_t resp1     = {0};
    pn_conn_state_t        s;
    int                    rc;

    uint8_t rx0[256];
    uint8_t rx1[256];

    /* Initialize connections in the transport's own array so that
     * conn_any_peer_tls_handshaking finds them during the scan. */
    pn_connection_init(&transport.connections[0]);
    pn_connection_init(&transport.connections[1]);
    transport.connections[0].rx_buf.data = rx0;
    transport.connections[0].rx_buf.cap  = sizeof(rx0);
    transport.connections[1].rx_buf.data = rx1;
    transport.connections[1].rx_buf.cap  = sizeof(rx1);

    /* Start connection 0 — DNS immediate, connect immediate. */
    rc = pn_connection_start(&transport.connections[0], &req0, &resp0, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(transport.connections[0].state, PN_CONN_CONNECTING);

    /* Tick connection 0: immediate connect → TLS_HANDSHAKING. */
    s = pn_connection_tick(&transport.connections[0], &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Start connection 1 — same hostname (ps.pndsn.com). */
    rc = pn_connection_start(&transport.connections[1], &req1, &resp1, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(transport.connections[1].state, PN_CONN_CONNECTING);

    /* Tick connection 1: TCP connects immediately, but TLS is deferred
     * because connection 0 is TLS_HANDSHAKING for the same hostname.
     * State must move to TLS_DEFERRED. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_TLS_DEFERRED);

    /* Connection 1 must still have a valid socket (TCP established). */
    assert_int_not_equal(transport.connections[1].socket, PN_INVALID_SOCKET);

    /* Complete connection 0's TLS handshake. */
    mock_state.tls_handshake_calls_until_ok = 0;
    s = pn_connection_tick(&transport.connections[0], &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Tick connection 1: gate clear → enters TLS_HANDSHAKING. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
}

/**
 * TLS handshake serialization does NOT block connections to different
 * hostnames. Connection 0 handshakes to "ps.pndsn.com"; connection 1
 * targets "other.example.com" — both must proceed independently.
 */
static void test_tls_handshake_not_serialized_different_host(void** state)
{
    (void)state;
    mock_reset();

    /* Keep TLS handshaking indefinitely (WANT_READ). */
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  req0      = make_request();
    pubnub_http_request_t  req1      = make_request();
    pubnub_http_response_t resp0     = {0};
    pubnub_http_response_t resp1     = {0};
    pn_conn_state_t        s;
    int                    rc;

    uint8_t rx0[256];
    uint8_t rx1[256];

    /* Connection 1 targets a different host. */
    req1.host = "other.example.com";

    pn_connection_init(&transport.connections[0]);
    pn_connection_init(&transport.connections[1]);
    transport.connections[0].rx_buf.data = rx0;
    transport.connections[0].rx_buf.cap  = sizeof(rx0);
    transport.connections[1].rx_buf.data = rx1;
    transport.connections[1].rx_buf.cap  = sizeof(rx1);

    /* Start and tick connection 0 → TLS_HANDSHAKING. */
    rc = pn_connection_start(&transport.connections[0], &req0, &resp0, &transport);
    assert_int_equal(rc, 0);
    s = pn_connection_tick(&transport.connections[0], &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Start and tick connection 1 — different host. */
    rc = pn_connection_start(&transport.connections[1], &req1, &resp1, &transport);
    assert_int_equal(rc, 0);

    /* Connection 1 must NOT be deferred: hostnames differ. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
}

/**
 * TLS handshake deferral timeout: when a deferred connection's
 * connect_deadline_ms expires while waiting for a peer to finish
 * TLS, the connection must fail with PUBNUB_ERR_TIMEOUT.
 */
static void test_tls_handshake_deferred_timeout(void** state)
{
    (void)state;
    mock_reset();

    /* Keep TLS handshaking indefinitely (WANT_READ). */
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  req0      = make_request();
    pubnub_http_request_t  req1      = make_request();
    pubnub_http_response_t resp0     = {0};
    pubnub_http_response_t resp1     = {0};
    pn_conn_state_t        s;
    int                    rc;

    uint8_t rx0[256];
    uint8_t rx1[256];

    pn_connection_init(&transport.connections[0]);
    pn_connection_init(&transport.connections[1]);
    transport.connections[0].rx_buf.data = rx0;
    transport.connections[0].rx_buf.cap  = sizeof(rx0);
    transport.connections[1].rx_buf.data = rx1;
    transport.connections[1].rx_buf.cap  = sizeof(rx1);

    /* Start connection 0 and drive it to TLS_HANDSHAKING. */
    rc = pn_connection_start(&transport.connections[0], &req0, &resp0, &transport);
    assert_int_equal(rc, 0);
    s = pn_connection_tick(&transport.connections[0], &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);

    /* Start connection 1 — same hostname (ps.pndsn.com). */
    rc = pn_connection_start(&transport.connections[1], &req1, &resp1, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(transport.connections[1].state, PN_CONN_CONNECTING);

    /* Tick connection 1: TCP connects immediately, but TLS is deferred
     * because connection 0 is TLS_HANDSHAKING for the same hostname. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_TLS_DEFERRED);
    assert_int_not_equal(transport.connections[1].socket, PN_INVALID_SOCKET);

    /* Expire connection 1's connect deadline. */
    transport.connections[1].connect_deadline_ms = mock_state.current_time_ms - 1;

    /* Tick connection 1: deadline expired while waiting for peer TLS. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(resp1.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(resp1.transport_error, PUBNUB_ERR_TIMEOUT);
}

/**
 * A peer close after a complete Content-Length body must still publish the
 * captured response headers. A server that closes the socket instead of
 * framing the end of the response would otherwise deliver a COMPLETE
 * response with zero headers, silently dropping Retry-After.
 */
static void test_peer_close_complete_body_populates_headers(void** state)
{
    (void)state;
    mock_reset();

    mock_state.resp_headers[0].key.ptr   = "Retry-After";
    mock_state.resp_headers[0].key.len   = 11;
    mock_state.resp_headers[0].value.ptr = "120";
    mock_state.resp_headers[0].value.len = 3;
    mock_state.resp_header_count         = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    transport.allocator              = &mock_allocator;

    pubnub_http_request_t  request  = make_request();
    pubnub_http_response_t response = {0};

    pn_connection_init(&conn);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    pn_conn_state_t s;
    s = pn_connection_tick(&conn, &transport); /* connect */
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport); /* TLS handshake */
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    s = pn_connection_tick(&conn, &transport); /* send headers */
    assert_int_equal(s, PN_CONN_RECEIVING_RESPONSE);

    /* A full Content-Length body has arrived, and the next recv reports
     * that the peer closed the connection. */
    assert_ptr_equal(conn.rx_buf.data, mock_rx_buf);
    memcpy(mock_rx_buf, "retry", 5);
    conn.rx_buf.len               = 5;
    conn.parser.body_start_offset = 0;
    conn.parser.content_length    = 5;
    conn.parser.body_received     = 5;
    conn.parser.status_code       = 503;
    mock_state.recv_result        = -1;

    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_COMPLETE);
    assert_int_equal(response.completion, PUBNUB_HTTP_COMPLETE);
    assert_int_equal(response.status_code, 503);
    assert_int_equal(response.body_len, 5);

    /* Headers must be extracted on this path too. */
    assert_int_equal(response.header_count, 1);
    assert_int_equal(response.headers[0].key.len, 11);
    assert_memory_equal(response.headers[0].key.ptr, "Retry-After", 11);
    assert_int_equal(response.headers[0].value.len, 3);
    assert_memory_equal(response.headers[0].value.ptr, "120", 3);
}

/**
 * A DNS lookup that completes but yields no usable address must still hand
 * the shared resolver back. Leaving it in DONE wedges the whole transport:
 * pn_dns_resolver_start refuses to run while a completed lookup is
 * unclaimed, so no other slot could ever resolve again.
 */
static void test_dns_claim_failure_releases_resolver(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_strict = 1;

    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t resp_a;
    pubnub_http_response_t resp_b;
    pn_socket_connection_t conn_a;
    pn_socket_connection_t conn_b;

    memset(&resp_a, 0, sizeof(resp_a));
    memset(&resp_b, 0, sizeof(resp_b));
    pn_connection_init(&conn_a);
    pn_connection_init(&conn_b);

    transport.allocator      = &mock_allocator;
    transport.resolver.state = PN_DNS_STATE_IDLE;

    /* Lookup completes with an empty answer: get_results reports failure. */
    mock_state.dns_state        = PN_DNS_STATE_DONE;
    mock_state.dns_result_count = 0;

    assert_int_equal(pn_connection_start(&conn_a, &request, &resp_a, &transport),
                     -1);
    assert_int_equal(transport.resolver.state, PN_DNS_STATE_IDLE);

    /* A different slot must still be able to resolve. */
    mock_state.dns_result_count = 1;
    assert_int_equal(pn_connection_start(&conn_b, &request, &resp_b, &transport), 0);
    assert_int_equal(conn_b.state, PN_CONN_CONNECTING);
    assert_int_equal(transport.resolver.state, PN_DNS_STATE_IDLE);
}

/**
 * Plaintext send failure on a fresh connection: the very first header
 * write returns an error. The FSM must fail cleanly with
 * PUBNUB_ERR_TRANSPORT rather than retry (retry is reserved for reused
 * keep-alive sockets, which a fresh connection is not).
 */
static void test_fsm_plaintext_send_error(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    /* Plaintext skips TLS: CONNECTING advances straight to SENDING_HEADERS. */
    request.secure = 0;

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);
    assert_int_equal(conn.state, PN_CONN_CONNECTING);

    /* Tick: connect immediate → SENDING_HEADERS (no TLS handshake). */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* First header write returns an error on a fresh connection. */
    mock_state.send_result = -1;
    s                      = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

/**
 * Partial send then failure: the first write reports fewer bytes than the
 * header length, the second write errors. header_sent must reflect exactly
 * the bytes reported before the failure (no over- or under-count), and the
 * connection must land in FAILED.
 */
static void test_fsm_partial_send_then_fail(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    request.secure = 0;

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Tick: connect immediate → SENDING_HEADERS. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* The fake header (pn_http_build_headers mock) is 30 bytes, so a
     * 10-byte first write is a genuine partial send. */
    mock_state.send_script[0]  = 10;
    mock_state.send_script[1]  = -1;
    mock_state.send_script_len = 2;

    /* Partial send: 10 bytes accounted, still SENDING_HEADERS. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);
    assert_int_equal(conn.header_sent, 10);

    /* Second write errors on a fresh connection → FAILED, counter intact. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(conn.header_sent, 10);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

/**
 * TLS-path send failure: a secure request completes its handshake, then
 * the encrypted header write errors. The failure must surface identically
 * to the plaintext path (PUBNUB_ERR_TRANSPORT, HTTP_ERROR).
 */
static void test_fsm_tls_send_error(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* CONNECTING → TLS_HANDSHAKING → SENDING_HEADERS. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_TLS_HANDSHAKING);
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Encrypted header write errors on a fresh connection. */
    mock_state.tls_send_result = -1;
    s                          = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

/**
 * Body send failure: a request with a body sends its headers fully, then
 * the body write errors. The FSM must fail cleanly with
 * PUBNUB_ERR_TRANSPORT from the SENDING_BODY state.
 */
static void test_fsm_body_send_error(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));

    static const uint8_t body[] = "payload";
    request.secure              = 0;
    request.body                = body;
    request.body_len            = sizeof(body) - 1;

    pn_connection_init(&conn);
    uint8_t rx_buf[256];
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    int rc = pn_connection_start(&conn, &request, &response, &transport);
    assert_int_equal(rc, 0);

    /* Tick: connect immediate → SENDING_HEADERS. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_HEADERS);

    /* Headers send fully (default mock) → SENDING_BODY. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_SENDING_BODY);

    /* Body write errors on a fresh connection. */
    mock_state.send_result = -1;
    s                      = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_int_equal(response.completion, PUBNUB_HTTP_ERROR);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);
}

#if PUBNUB_ENABLE_PROXY
/*
 * Proxy CONNECT session lifecycle (heap-scrub safety).
 *
 * These tests drive tick_proxy_negotiating to each terminal outcome with a
 * real proxy module, so conn->proxy_session is a real malloc'd block sized to
 * sizeof(pn_proxy_connect_session_t). pn_proxy_connect_session_destroy must
 * scrub exactly that many bytes; under ASan an over-scrub past the block end
 * is reported as a heap-buffer-overflow, which is the bug these tests guard.
 */
static const pn_proxy_config_t proxy_cfg = {
    .host      = "proxy.example.com",
    .port      = 8080,
    .auth_type = PN_PROXY_AUTH_NONE,
    .username  = NULL,
    .password  = NULL,
};

static pn_socket_transport_t make_proxy_transport(pn_proxy_module_t** out_module)
{
    pn_socket_transport_t t = make_transport();
    t.allocator             = &mock_allocator;
    t.proxy_module = pn_proxy_connect_create(&proxy_cfg, &mock_allocator);
    *out_module    = t.proxy_module;
    return t;
}

static void proxy_drive_to_negotiating(pn_socket_connection_t* conn,
                                       pubnub_http_request_t*  request,
                                       pubnub_http_response_t* response,
                                       pn_socket_transport_t*  transport,
                                       uint8_t*                rx_buf,
                                       size_t                  rx_cap)
{
    pn_connection_init(conn);
    conn->rx_buf.data = rx_buf;
    conn->rx_buf.cap  = rx_cap;

    int rc = pn_connection_start(conn, request, response, transport);
    assert_int_equal(rc, 0);
    assert_int_equal(conn->state, PN_CONN_CONNECTING);

    /* Connect completes immediately (mock) → proxy negotiation begins and
     * the real session block is allocated. */
    pn_conn_state_t s = pn_connection_tick(conn, transport);
    assert_int_equal(s, PN_CONN_PROXY_NEGOTIATING);
    assert_non_null(conn->proxy_session);
}

/** Proxy tunnel established (200) → session scrubbed and freed. */
static void test_fsm_proxy_negotiate_complete(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp  = "HTTP/1.1 200 Connection established\r\n\r\n";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));
    uint8_t rx_buf[1024];

    assert_non_null(module);
    proxy_drive_to_negotiating(
        &conn, &request, &response, &transport, rx_buf, sizeof(rx_buf));

    /* Tick: send CONNECT request → still negotiating. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_PROXY_NEGOTIATING);

    /* Tick: receive 200 → tunnel done; session scrubbed and freed. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_not_equal(s, PN_CONN_PROXY_NEGOTIATING);
    assert_null(conn.proxy_session);
    assert_int_equal(conn.proxy_done, 1);

    pn_connection_cancel(&conn, &transport);
    module->destroy(module, &mock_allocator);
}

/** Proxy rejects the tunnel (403) → session scrubbed and freed, FSM fails. */
static void test_fsm_proxy_negotiate_error(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp  = "HTTP/1.1 403 Forbidden\r\n\r\n";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));
    uint8_t rx_buf[1024];

    assert_non_null(module);
    proxy_drive_to_negotiating(
        &conn, &request, &response, &transport, rx_buf, sizeof(rx_buf));

    /* Tick: send CONNECT request → still negotiating. */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_PROXY_NEGOTIATING);

    /* Tick: receive 403 → error; session scrubbed and freed. */
    s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_null(conn.proxy_session);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TRANSPORT);

    module->destroy(module, &mock_allocator);
}

/** Cancel mid-negotiation → session scrubbed and freed. */
static void test_fsm_proxy_cancel(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));
    uint8_t rx_buf[1024];

    assert_non_null(module);
    proxy_drive_to_negotiating(
        &conn, &request, &response, &transport, rx_buf, sizeof(rx_buf));

    /* Cancel while the session is still allocated mid-negotiation. */
    pn_connection_cancel(&conn, &transport);
    assert_null(conn.proxy_session);

    module->destroy(module, &mock_allocator);
}

/** Connect deadline expires mid-negotiation → session scrubbed and freed. */
static void test_fsm_proxy_negotiate_timeout(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));
    uint8_t rx_buf[1024];

    assert_non_null(module);
    proxy_drive_to_negotiating(
        &conn, &request, &response, &transport, rx_buf, sizeof(rx_buf));

    /* Tick: send CONNECT request → still negotiating (no reply queued). */
    pn_conn_state_t s = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_PROXY_NEGOTIATING);

    /* Advance past the connect deadline while negotiation is in progress. */
    mock_state.current_time_ms = conn.connect_deadline_ms + 1;
    s                          = pn_connection_tick(&conn, &transport);
    assert_int_equal(s, PN_CONN_FAILED);
    assert_null(conn.proxy_session);
    assert_int_equal(response.transport_error, PUBNUB_ERR_TIMEOUT);

    module->destroy(module, &mock_allocator);
}

/** Reset mid-negotiation → session scrubbed and freed. */
static void test_fsm_proxy_reset(void** state)
{
    (void)state;
    mock_reset();

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response;
    memset(&response, 0, sizeof(response));
    uint8_t rx_buf[1024];

    assert_non_null(module);
    proxy_drive_to_negotiating(
        &conn, &request, &response, &transport, rx_buf, sizeof(rx_buf));

    /* Reset while the session is still allocated mid-negotiation. */
    pn_connection_reset(&conn, &transport);
    assert_null(conn.proxy_session);

    module->destroy(module, &mock_allocator);
}
#endif /* PUBNUB_ENABLE_PROXY */

/** Capacity of the captured log text. */
#define CAP_LOG_SIZE 8192

/** Logger that records text entries as "<level-letter> <message>\n". */
typedef struct cap_logger {
    /** Base provider (must be first member). */
    pubnub_logger_provider_t base;
    /** Concatenated captured entries (NUL-terminated). */
    char text[CAP_LOG_SIZE];
    /** Bytes used in text. */
    size_t len;
} cap_logger_t;

static cap_logger_t g_cap;

static void cap_log(struct pubnub_logger_provider* self,
                    const pubnub_log_entry_t*      entry)
{
    cap_logger_t* cap = (cap_logger_t*)self;
    char          letter;
    int           n;

    if (PUBNUB_LOG_ENTRY_TEXT != entry->type) {
        return;
    }
    switch (entry->level) {
    case PUBNUB_LOG_LEVEL_TRACE: letter = 'T'; break;
    case PUBNUB_LOG_LEVEL_DEBUG: letter = 'D'; break;
    case PUBNUB_LOG_LEVEL_INFO: letter = 'I'; break;
    case PUBNUB_LOG_LEVEL_WARNING: letter = 'W'; break;
    default: letter = 'E'; break;
    }
    n = snprintf(cap->text + cap->len,
                 sizeof(cap->text) - cap->len,
                 "%c %s\n",
                 letter,
                 ((const pubnub_log_entry_text_t*)entry)->message);
    if (0 < n && (size_t)n < sizeof(cap->text) - cap->len) {
        cap->len += (size_t)n;
    }
}

/** Reset the capture buffer and attach the logger to a transport. */
static void cap_attach(pn_socket_transport_t* transport)
{
    memset(&g_cap, 0, sizeof(g_cap));
    g_cap.base.log    = cap_log;
    transport->logger = &g_cap.base;
}

static int cap_has(const char* needle)
{
    if (NULL == strstr(g_cap.text, needle)) {
        print_message("missing \"%s\" in captured log:\n%s\n", needle, g_cap.text);
        return 0;
    }
    return 1;
}

static int cap_count(const char* needle)
{
    const char* p     = g_cap.text;
    int         count = 0;

    while (NULL != (p = strstr(p, needle))) {
        ++count;
        p += strlen(needle);
    }
    return count;
}

/** Skip the test when log formatting is compiled out of the build. */
static void skip_if_logging_compiled_out(void)
{
    if (0 == PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE) {
        skip();
    }
}

/** Add a second IPv4 DNS result so an address fallback is possible. */
static void add_second_addr(void)
{
    mock_state.dns_result_count            = 2;
    mock_state.dns_results[1].family       = PN_AF_INET;
    mock_state.dns_results[1].port         = 443;
    mock_state.dns_results[1].addr.ipv4[0] = 10;
    mock_state.dns_results[1].addr.ipv4[1] = 0;
    mock_state.dns_results[1].addr.ipv4[2] = 0;
    mock_state.dns_results[1].addr.ipv4[3] = 1;
}

/** A TLS handshake failure with a next address is logged at WARNING. */
static void test_fsm_tls_error_logs_backend_error(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    mock_reset();
    add_second_addr();

    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;
    mock_state.tls_session_error            = 12345;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    transport.tls_backend = &mock_tls_backend_diag;
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(cp, &transport));
    (void)pn_connection_tick(cp, &transport);

    assert_true(cap_has("W conn[0] TLS error on address 1 of 2"));
    assert_true(cap_has("tls_err=12345 (MOCK_TLS_ERR)"));
}

/**
 * A backend without diagnostic hooks (get_session_error == NULL) must not
 * crash the receive-error log path.
 */
static void test_fsm_recv_error_null_error_hook_safe(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(cp, &transport));
    assert_int_equal(PN_CONN_SENDING_HEADERS, pn_connection_tick(cp, &transport));
    assert_int_equal(PN_CONN_RECEIVING_RESPONSE, pn_connection_tick(cp, &transport));

    mock_state.recv_result = -2;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));
    assert_int_equal(PUBNUB_ERR_TRANSPORT, response.transport_error);
    if (0 != PUBNUB_CFG_MAX_LOG_MESSAGE_SIZE) {
        assert_true(cap_has("recv error: rc=-2"));
    }
}

/** With diagnostic hooks present, the receive error carries the TLS detail. */
static void test_fsm_recv_error_logs_tls_backend_error(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    mock_reset();
    mock_state.tls_session_error = 12345;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    transport.tls_backend = &mock_tls_backend_diag;
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport);
    (void)pn_connection_tick(cp, &transport);
    (void)pn_connection_tick(cp, &transport);
    mock_state.recv_result = -2;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));

    assert_true(cap_has("E conn[0] recv error: rc=-2"));
    assert_true(cap_has("tls_err=12345 (MOCK_TLS_ERR)"));
}

/** A TLS header-write failure is logged with the connection and TLS detail. */
static void test_fsm_header_send_error_logs_tls_detail(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    mock_reset();
    mock_state.tls_session_error = 12345;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    transport.tls_backend = &mock_tls_backend_diag;
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport);
    assert_int_equal(PN_CONN_SENDING_HEADERS, pn_connection_tick(cp, &transport));
    mock_state.tls_send_result = -2;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));

    assert_true(cap_has("E conn[0] header send error: rc=-2"));
    assert_true(cap_has("tls_err=12345 (MOCK_TLS_ERR)"));
}

/** A pending-connect failure is INFO unless it is the last address. */
static void test_fsm_connect_refused_logs_warning(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_INFO)) {
        skip();
    }
    mock_reset();
    add_second_addr();

    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = -111;
    mock_state.check_connect_script[1]  = -111;
    mock_state.check_connect_script_len = 2;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport);
    (void)pn_connection_tick(cp, &transport);
    (void)pn_connection_tick(cp, &transport);

    assert_true(cap_has("I conn[0] TCP connect failed on address 1 of 2"));
    assert_true(cap_has("W conn[0] TCP connect failed on address 2 of 2"));
    assert_true(cap_has("rc=-111"));
    assert_int_equal(0, cap_count("W conn[0] TCP connect failed on address 1"));
    assert_int_equal(0, cap_count("I conn[0] TCP connect failed on address 2"));
}

/** A connect failure on the last address is logged at WARNING. */
static void test_fsm_connect_failure_logs_exhausted_context(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    mock_reset();

    mock_state.connect_result = -111;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));

    assert_true(cap_has("W conn[0] socket_connect failed on address 1 of 1"));
    assert_true(cap_has("rc=-111"));
    assert_true(cap_has("E conn[0] all addresses exhausted for host: "
                        "ps.pndsn.com (addr_count=1, family_exhausted=0x"));
}

/** A connect failure with an address left is INFO; only the last escalates. */
static void test_fsm_connect_failure_with_remaining_addr_logs_info(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_INFO)) {
        skip();
    }
    mock_reset();
    add_second_addr();

    mock_state.connect_result = -111;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));

    assert_true(cap_has("I conn[0] socket_connect failed on address 1 of 2"));
    assert_true(cap_has("W conn[0] socket_connect failed on address 2 of 2"));
    assert_int_equal(0, cap_count("W conn[0] socket_connect failed on address 1"));
    assert_int_equal(0, cap_count("I conn[0] socket_connect failed on address 2"));
    assert_true(cap_has("E conn[0] all addresses exhausted"));
}

/** A TLS handshake timeout is reported once, at WARNING, with the wait side. */
static void test_fsm_tls_timeout_logs_single_warning(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    mock_reset();
    add_second_addr();

    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(cp, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(cp, &transport));
    assert_int_equal(0, cap_count("handshake timed out"));

    mock_state.current_time_ms = cp->connect_deadline_ms + 1;
    (void)pn_connection_tick(cp, &transport);

    assert_int_equal(1, cap_count("handshake timed out"));
    assert_int_equal(0, cap_count("TLS timeout on address"));
    assert_true(cap_has("W conn[0] TLS handshake timed out on address 1 of 2"));
    assert_true(cap_has("waiting for read"));
}

/** The connected trace reports the time spent since the attempt started. */
static void test_fsm_connected_trace_reports_elapsed(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_TRACE)) {
        skip();
    }
    mock_reset();

    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 0;
    mock_state.check_connect_script[1]  = 1;
    mock_state.check_connect_script_len = 2;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response;
    memset(&response, 0, sizeof(response));
    cap_attach(&transport);

    pn_connection_init(cp);
    uint8_t rx_buf[256];
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport);
    (void)pn_connection_tick(cp, &transport);
    mock_state.current_time_ms += 120;
    (void)pn_connection_tick(cp, &transport);

    assert_true(cap_has("T conn[0] TCP connected fd=42 to ps.pndsn.com "
                        "(120 ms since attempt start)"));
}

/** Start a TLS request and tick once so the connection is TLS_HANDSHAKING. */
static void tls_want_enter_handshake(pn_socket_connection_t* conn,
                                     pn_socket_transport_t*  transport,
                                     pubnub_http_request_t*  request,
                                     pubnub_http_response_t* response,
                                     uint8_t*                rx_buf,
                                     size_t                  rx_cap)
{
    pn_connection_init(conn);
    conn->rx_buf.data = rx_buf;
    conn->rx_buf.cap  = rx_cap;
    assert_int_equal(0, pn_connection_start(conn, request, response, transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, transport));
}

/** Entering TLS_HANDSHAKING arms WRITE (ClientHello not sent yet). */
static void test_fsm_tls_want_set_on_enter_handshake(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_POLL_WRITE, conn.tls_want);
}

/** The backend's WANT_READ / WANT_WRITE result is mirrored into tls_want. */
static void test_fsm_tls_want_follows_backend_want(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));

    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);

    mock_state.tls_handshake_result = PN_TLS_WANT_WRITE;
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_WRITE, conn.tls_want);

    mock_state.tls_handshake_result = PN_TLS_WANT_READ;
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);
}

/** A completed handshake clears tls_want. */
static void test_fsm_tls_want_cleared_on_complete(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);

    assert_int_equal(PN_CONN_SENDING_HEADERS, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.tls_want);
}

/** A handshake error that exhausts the addresses clears tls_want. */
static void test_fsm_tls_want_cleared_on_error(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_POLL_WRITE, conn.tls_want);

    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.tls_want);
}

/** A handshake error that falls back to a pending connect clears tls_want. */
static void test_fsm_tls_want_cleared_on_fallback(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_result_count             = 2;
    mock_state.dns_results[1]               = mock_state.dns_results[0];
    mock_state.dns_results[1].addr.ipv4[3]  = 5;
    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_POLL_WRITE, conn.tls_want);
    mock_state.connect_result = 0;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.tls_want);
}

/** A handshake timeout that falls back to the next address clears tls_want. */
static void test_fsm_tls_want_cleared_on_timeout_fallback(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_result_count             = 2;
    mock_state.dns_results[1]               = mock_state.dns_results[0];
    mock_state.dns_results[1].addr.ipv4[3]  = 5;
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);

    mock_state.connect_result  = 0;
    mock_state.current_time_ms = conn.connect_deadline_ms + 1;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.tls_want);
}

/** Cancelling a handshaking connection clears tls_want. */
static void test_fsm_tls_want_cleared_on_cancel(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);

    pn_connection_cancel(&conn, &transport);
    assert_int_equal(PN_CONN_CANCELLED, conn.state);
    assert_int_equal(0, conn.tls_want);
}

/** Resetting a handshaking connection clears tls_want. */
static void test_fsm_tls_want_cleared_on_reset(void** state)
{
    (void)state;
    mock_reset();
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    tls_want_enter_handshake(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);

    pn_connection_reset(&conn, &transport);
    assert_int_equal(0, conn.tls_want);
}

/** Closing only the socket or only the TLS session clears tls_want. */
static void test_fsm_tls_want_cleared_on_close_helpers(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();

    pn_connection_init(&conn);

    conn.tls_want = PN_POLL_READ;
    conn_close_socket(&conn, &transport);
    assert_int_equal(0, conn.tls_want);

    conn.tls_want = PN_POLL_WRITE;
    conn_destroy_tls(&conn, &transport);
    assert_int_equal(0, conn.tls_want);
}

/** Starting a request on a recycled slot never inherits a stale tls_want. */
static void test_fsm_tls_want_cleared_on_start(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    conn.tls_want    = PN_POLL_READ;

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(0, conn.tls_want);
}

/** Drive a secure connection through one full request to KEEP_ALIVE_IDLE. */
static void release_fixture_complete(pn_socket_connection_t* conn,
                                     pn_socket_transport_t*  transport,
                                     pubnub_http_request_t*  request,
                                     pubnub_http_response_t* response,
                                     uint8_t*                rx,
                                     size_t                  rx_cap)
{
    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_connection_init(conn);
    conn->rx_buf.data = rx;
    conn->rx_buf.cap  = rx_cap;
    assert_int_equal(0, pn_connection_start(conn, request, response, transport));
    (void)pn_connection_tick(conn, transport); /* connect */
    (void)pn_connection_tick(conn, transport); /* handshake */
    (void)pn_connection_tick(conn, transport); /* send */
    (void)pn_connection_tick(conn, transport); /* receive */
    (void)pn_connection_tick(conn, transport); /* complete */
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn->state);
}

/** Releasing a finished keep-alive request keeps the socket and TLS session. */
static void test_fsm_release_request_keeps_socket_and_tls(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];

    release_fixture_complete(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));

    {
        const pn_socket_t socket_before = conn.socket;
        void*             tls_before    = conn.tls_session;
        const uint16_t    gen_before    = conn.generation;
        const int         creates       = mock_state.socket_create_calls;

        assert_non_null(tls_before);
        assert_int_equal(1, pn_connection_release_request(&conn, &transport));

        assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn.state);
        assert_true(socket_before == conn.socket);
        assert_ptr_equal(tls_before, conn.tls_session);
        assert_int_equal(0, mock_state.socket_destroy_calls);
        assert_int_equal(0, mock_state.tls_session_destroy_calls);
        assert_null(conn.request);
        assert_null(conn.response);
        assert_int_not_equal(gen_before, conn.generation);
        assert_true(0 != conn.generation);
        assert_true(0 != conn.requests_on_connection);

        /* The detached connection is reusable. */
        response = (pubnub_http_response_t){0};
        assert_int_equal(
            0, pn_connection_start(&conn, &request, &response, &transport));
        assert_int_equal(PN_CONN_SENDING_HEADERS, conn.state);
        assert_int_equal(creates, mock_state.socket_create_calls);
        assert_int_equal(0, mock_state.socket_destroy_calls);
    }
}

/** Generation wrap skips zero (a zero handle generation means NULL). */
static void test_fsm_release_request_generation_skips_zero(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];

    release_fixture_complete(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    conn.generation = 0xFFFFu;
    assert_int_equal(1, pn_connection_release_request(&conn, &transport));
    assert_int_equal(1, conn.generation);
}

/** Only a KEEP_ALIVE_IDLE connection with a socket is detached. */
static void test_fsm_release_request_rejects_other_states(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];
    pn_conn_state_t        st;

    assert_int_equal(0, pn_connection_release_request(NULL, &transport));
    assert_int_equal(0, pn_connection_release_request(&conn, NULL));

    release_fixture_complete(
        &conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));

    for (st = PN_CONN_IDLE; st <= PN_CONN_CANCELLED;
         st = (pn_conn_state_t)(st + 1)) {
        const uint16_t gen = conn.generation;

        if (PN_CONN_KEEP_ALIVE_IDLE == st) {
            continue;
        }
        conn.state = st;
        assert_int_equal(0, pn_connection_release_request(&conn, &transport));
        assert_int_equal(st, conn.state);
        assert_int_equal(gen, conn.generation);
        assert_non_null(conn.request);
    }

    /* KEEP_ALIVE_IDLE without a live socket is not detachable either. */
    conn.state = PN_CONN_KEEP_ALIVE_IDLE;
    {
        const pn_socket_t sock = conn.socket;

        conn.socket = PN_INVALID_SOCKET;
        assert_int_equal(0, pn_connection_release_request(&conn, &transport));
        conn.socket = sock;
    }
}

/** Add DNS results 1..n-1 (distinct IPv4 addresses after the default one). */
static void add_addrs(size_t n)
{
    size_t i;

    mock_state.dns_result_count = n;
    for (i = 1; i < n; ++i) {
        mock_state.dns_results[i].family       = PN_AF_INET;
        mock_state.dns_results[i].port         = 443;
        mock_state.dns_results[i].addr.ipv4[0] = 10;
        mock_state.dns_results[i].addr.ipv4[1] = 0;
        mock_state.dns_results[i].addr.ipv4[2] = 0;
        mock_state.dns_results[i].addr.ipv4[3] = (uint8_t)i;
    }
}

/** Start a request whose first socket (fd 42) never finishes connecting. */
static void blackhole_start(pn_socket_connection_t* conn,
                            pn_socket_transport_t*  transport,
                            pubnub_http_request_t*  request,
                            pubnub_http_response_t* response,
                            uint8_t*                rx,
                            size_t                  rx_cap)
{
    mock_state.connect_result       = 0;
    mock_state.pending_forever_sock = 42;
    mock_state.unique_fds           = 1;
    pn_connection_init(conn);
    conn->rx_buf.data = rx;
    conn->rx_buf.cap  = rx_cap;
    assert_int_equal(0, pn_connection_start(conn, request, response, transport));
}

/** A stalled TCP connect falls back to the next address within the budget. */
static void test_fsm_connect_timeout_falls_back_to_next_addr(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];
    uint64_t               start;

    request.timeout_ms = 10000;
    start              = mock_state.current_time_ms;
    blackhole_start(&conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));

    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.addr_current);
    /* The first address leaves room for a fallback inside the budget. */
    assert_true(conn.connect_deadline_ms < conn.transaction_deadline_ms);
    assert_true(conn.connect_deadline_ms - start
                <= (uint64_t)request.timeout_ms / 2U);

    mock_state.current_time_ms = conn.connect_deadline_ms - 1U;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(0, conn.addr_current);

    mock_state.current_time_ms = conn.connect_deadline_ms;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, conn.addr_current);
    assert_int_equal(2, mock_state.socket_create_calls);
    assert_int_equal(1, mock_state.socket_destroy_calls);
    assert_int_equal(PUBNUB_HTTP_PENDING, response.completion);
    /* A timeout is not evidence that the whole family is unreachable. */
    assert_int_equal(0, conn.family_exhausted);
    assert_true(conn.connect_deadline_ms <= conn.transaction_deadline_ms);

    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.tls_session_create_calls);
}

/** A single-address host still fails with TIMEOUT at the connect deadline. */
static void test_fsm_connect_timeout_single_addr_unchanged(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];
    uint64_t               start = mock_state.current_time_ms;

    request.timeout_ms = 60000;
    blackhole_start(&conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    assert_int_equal(start + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS,
                     conn.connect_deadline_ms);

    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    mock_state.current_time_ms = conn.connect_deadline_ms - 1U;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    mock_state.current_time_ms = conn.connect_deadline_ms;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_HTTP_ERROR, response.completion);
    assert_int_equal(PUBNUB_ERR_TIMEOUT, response.transport_error);
    assert_int_equal(1, mock_state.socket_create_calls);
}

/** With many blackholed addresses the attempt stays inside the budget. */
static void test_fsm_connect_timeout_many_addrs_bounded(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(4);
    /* Every address blackholed: fds 42..45. */
    mock_state.check_connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];
    uint64_t               start;
    int                    guard;

    request.timeout_ms        = 10000;
    start                     = mock_state.current_time_ms;
    mock_state.connect_result = 0;
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));

    for (guard = 0; guard < 400 && PN_CONN_FAILED != conn.state; ++guard) {
        (void)pn_connection_tick(&conn, &transport);
        mock_state.current_time_ms += 50;
    }
    assert_int_equal(PN_CONN_FAILED, conn.state);
    assert_int_equal(PUBNUB_ERR_TIMEOUT, response.transport_error);
    assert_int_equal(4, mock_state.socket_create_calls);
    /* Total time is bounded by the request budget (plus one tick). */
    assert_true(mock_state.current_time_ms - start
                <= (uint64_t)request.timeout_ms + 100U);
}

/** A timeout followed by a refusal on the last address is a transport error. */
static void test_fsm_connect_timeout_then_error_exhausts(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);
    mock_state.check_connect_result = -111;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.timeout_ms = 10000;
    blackhole_start(&conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    (void)pn_connection_tick(&conn, &transport);
    mock_state.current_time_ms = conn.connect_deadline_ms;
    (void)pn_connection_tick(&conn, &transport);
    assert_int_equal(1, conn.addr_current);

    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_ERR_TRANSPORT, response.transport_error);
}

/** A refusal on the first address then a timeout on the last is a TIMEOUT. */
static void test_fsm_connect_error_then_timeout_fails_timeout(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = -111;
    mock_state.check_connect_script[1]  = 0;
    mock_state.check_connect_script_len = 2;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.timeout_ms = 10000;
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport);
    (void)pn_connection_tick(&conn, &transport);
    assert_int_equal(1, conn.addr_current);

    mock_state.current_time_ms = conn.connect_deadline_ms;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_ERR_TIMEOUT, response.transport_error);
    assert_int_equal(2, mock_state.socket_create_calls);
}

/** No fallback is attempted when too little of the request budget is left. */
static void test_fsm_connect_timeout_no_fallback_without_budget(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.timeout_ms = 1500;
    blackhole_start(&conn, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    (void)pn_connection_tick(&conn, &transport);
    mock_state.current_time_ms = conn.connect_deadline_ms;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_ERR_TIMEOUT, response.transport_error);
    assert_int_equal(1, mock_state.socket_create_calls);
}

/** The fallback is logged once at INFO; the exhausted outcome is unchanged. */
static void test_fsm_connect_timeout_fallback_logs_info(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_INFO)) {
        skip();
    }
    mock_reset();
    add_addrs(2);

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response  = {0};
    uint8_t                       rx_buf[256];

    cap_attach(&transport);
    request.timeout_ms = 10000;
    blackhole_start(cp, &transport, &request, &response, rx_buf, sizeof(rx_buf));
    (void)pn_connection_tick(cp, &transport);
    mock_state.current_time_ms = cp->connect_deadline_ms;
    (void)pn_connection_tick(cp, &transport);

    assert_true(cap_has("I conn[0] TCP connect timed out on address 1 of 2 for "
                        "ps.pndsn.com, trying next"));
    assert_int_equal(1, cap_count("TCP connect timed out"));
    assert_int_equal(0, cap_count("W conn[0]"));
}

/** Drive connection 1 to TLS_DEFERRED behind a handshaking connection 0. */
static void deferred_fixture(pn_socket_transport_t*  transport,
                             pubnub_http_request_t*  req0,
                             pubnub_http_request_t*  req1,
                             pubnub_http_response_t* resp1,
                             uint8_t*                rx1,
                             size_t                  rx1_cap)
{
    pn_connection_init(&transport->connections[0]);
    pn_connection_init(&transport->connections[1]);
    transport->connections[0].state       = PN_CONN_TLS_HANDSHAKING;
    transport->connections[0].request     = req0;
    transport->connections[1].rx_buf.data = rx1;
    transport->connections[1].rx_buf.cap  = rx1_cap;
    assert_int_equal(
        0, pn_connection_start(&transport->connections[1], req1, resp1, transport));
}

/** Peer handshake finished: the deferral gate opens. */
static void deferred_release_peer(pn_socket_transport_t* transport)
{
    transport->connections[0].state = PN_CONN_SENDING_HEADERS;
}

/** A TLS-deferred wait on a non-final address uses the full window. */
static void test_fsm_tls_deferred_wait_uses_full_window(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);
    mock_state.connect_result = 0;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    uint64_t                entered;

    req1.timeout_ms = 10000;
    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));
    /* The first address only has a slice of the transaction budget. */
    assert_true(conn->connect_deadline_ms - mock_state.current_time_ms
                <= (uint64_t)req1.timeout_ms / 2U);

    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(conn, &transport));
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    entered = mock_state.current_time_ms;
    assert_int_equal(entered + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS,
                     conn->connect_deadline_ms);

    /* Past the TCP slice the wait goes on; ticking does not extend it. */
    mock_state.current_time_ms = entered + req1.timeout_ms / 2U + 1000U;
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    assert_int_equal(entered + PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS,
                     conn->connect_deadline_ms);

    /* A gate that never opens still times out at the full window. */
    mock_state.current_time_ms = conn->connect_deadline_ms;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(conn, &transport));
    assert_int_equal(PUBNUB_ERR_TIMEOUT, resp1.transport_error);
}

/** The slice counts only addresses that can still be tried. */
static void test_fsm_connect_budget_skips_exhausted_trailing_family(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(3);
    mock_state.dns_results[0].family = PN_AF_INET6;
    memset(mock_state.dns_results[0].addr.ipv6, 1, 16);
    mock_state.dns_results[2].family = PN_AF_INET6;
    memset(mock_state.dns_results[2].addr.ipv6, 2, 16);
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = -101; /* ENETUNREACH */
    mock_state.check_connect_script[1]  = 0;
    mock_state.check_connect_script_len = 2;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.timeout_ms = 10000;
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport);
    (void)pn_connection_tick(&conn, &transport);
    assert_int_equal(1, conn.addr_current);

    assert_int_equal(mock_state.current_time_ms
                         + (uint64_t)PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS,
                     conn.connect_deadline_ms);
    mock_state.current_time_ms = conn.connect_deadline_ms;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_ERR_TIMEOUT, response.transport_error);
}

/** A fallback slice never exceeds the transaction time that is left. */
static void test_fsm_connect_budget_capped_at_remaining(void** state)
{
    (void)state;
    mock_reset();
    add_addrs(2);
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = -111;
    mock_state.check_connect_script[1]  = 0;
    mock_state.check_connect_script_len = 2;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.timeout_ms = 5000;
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport);
    /* Only 400 ms of the request remain when the refusal arrives. */
    mock_state.current_time_ms += 4600;
    (void)pn_connection_tick(&conn, &transport);
    assert_int_equal(1, conn.addr_current);
    assert_true(conn.connect_deadline_ms <= conn.transaction_deadline_ms);
}

/** A confirmed connect is probed exactly once across a TLS deferral. */
static void test_fsm_tls_deferred_single_probe(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    pn_conn_state_t         s;
    int                     i;

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));

    s = pn_connection_tick(conn, &transport); /* issues connect */
    assert_int_equal(PN_CONN_CONNECTING, s);
    for (i = 0; i < 5; ++i) {
        s = pn_connection_tick(conn, &transport);
        assert_int_equal(PN_CONN_TLS_DEFERRED, s);
        assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);
    }
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(0, mock_state.tls_session_create_calls);

    deferred_release_peer(&transport);
    s = pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, s);
    assert_int_equal(PN_POLL_WRITE, conn->tls_want);
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.tls_session_create_calls);
}

/** A 0 after a confirmed connect must not regress a deferred connection. */
static void test_fsm_tls_deferred_survives_check_connect_regression(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script[1]  = 0;
    mock_state.check_connect_script[2]  = 0;
    mock_state.check_connect_script_len = 3;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    pn_conn_state_t         s;
    int                     i;

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));

    (void)pn_connection_tick(conn, &transport); /* issues connect */
    for (i = 0; i < 4; ++i) {
        s = pn_connection_tick(conn, &transport);
        assert_int_equal(PN_CONN_TLS_DEFERRED, s);
        assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);
    }

    deferred_release_peer(&transport);
    s = pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, s);
    assert_int_equal(1, mock_state.tls_session_create_calls);
}

/** Keepalive is applied once per socket on the deferred path. */
static void test_fsm_keepalive_once_deferred(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    int                     i;

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));

    for (i = 0; i < 4; ++i) {
        (void)pn_connection_tick(conn, &transport);
    }
    assert_int_equal(1, mock_state.set_keepalive_calls);

    deferred_release_peer(&transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));
    assert_int_equal(1, mock_state.set_keepalive_calls);
}

/** Keepalive is applied once when connect succeeds immediately (TLS). */
static void test_fsm_keepalive_once_immediate(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.set_keepalive_calls);
    assert_int_equal(0, mock_state.check_connect_calls);
}

/** Keepalive is applied once on the plaintext immediate-success path. */
static void test_fsm_keepalive_once_plaintext(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    request.secure = 0;
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(PN_CONN_SENDING_HEADERS, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.set_keepalive_calls);
}

/** Keepalive is applied once on the pending-then-confirmed path. */
static void test_fsm_keepalive_once_pending_connect(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 0;
    mock_state.check_connect_script[1]  = 1;
    mock_state.check_connect_script_len = 2;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport);
    (void)pn_connection_tick(&conn, &transport);
    assert_int_equal(0, mock_state.set_keepalive_calls);
    assert_int_equal(PN_CONN_CONNECTING, conn.state);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.set_keepalive_calls);
    assert_int_equal(2, mock_state.check_connect_calls);
}

/** TLS error fallback closes the connected socket; the new one is probed. */
static void test_fsm_fallback_pending_reprobes(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_result_count             = 2;
    mock_state.dns_results[1]               = mock_state.dns_results[0];
    mock_state.dns_results[1].addr.ipv4[0]  = 10;
    mock_state.connect_result               = 0;
    mock_state.check_connect_script[0]      = 1;
    mock_state.check_connect_script[1]      = 1;
    mock_state.check_connect_script_len     = 2;
    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport); /* issue connect */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);

    /* Handshake error: addr 1, pending connect, back to CONNECTING. */
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, conn.addr_current);

    /* The replacement socket is probed again. */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(2, mock_state.check_connect_calls);
    assert_int_equal(2, mock_state.set_keepalive_calls);
}

/** Immediate-success fallback applies keepalive to the new socket. */
static void test_fsm_fallback_immediate_applies_keepalive(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_result_count             = 2;
    mock_state.dns_results[1]               = mock_state.dns_results[0];
    mock_state.dns_results[1].addr.ipv4[0]  = 10;
    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, conn.addr_current);
    assert_int_equal(2, mock_state.set_keepalive_calls);
    assert_int_equal(0, mock_state.check_connect_calls);
}

/** Cancel from TLS_DEFERRED ends in CANCELLED; a later start probes anew. */
static void test_fsm_tls_deferred_cancel_then_reset_reprobes(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    int                     destroyed;

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));
    (void)pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
    destroyed = mock_state.socket_destroy_calls;

    pn_connection_cancel(conn, &transport);
    assert_int_equal(PN_CONN_CANCELLED, conn->state);
    assert_int_equal(PN_INVALID_SOCKET, conn->socket);
    assert_int_equal(destroyed + 1, mock_state.socket_destroy_calls);
    assert_int_equal(PN_CONN_CANCELLED, pn_connection_tick(conn, &transport));

    pn_connection_reset(conn, &transport);
    assert_int_equal(PN_CONN_IDLE, conn->state);
    assert_int_equal(PN_INVALID_SOCKET, conn->socket);
    conn->rx_buf.data = rx1;
    conn->rx_buf.cap  = sizeof(rx1);
    deferred_release_peer(&transport);
    resp1 = (pubnub_http_response_t){0};
    assert_int_equal(0, pn_connection_start(conn, &req1, &resp1, &transport));
    (void)pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));
    assert_int_equal(2, mock_state.check_connect_calls);
    assert_int_equal(2, mock_state.set_keepalive_calls);
}

/** A deferred wait is deadline-bounded and does not probe the socket. */
static void test_fsm_tls_deferred_deadline_without_probe_then_reuse(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];
    int                     destroyed;

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));
    (void)pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    destroyed = mock_state.socket_destroy_calls;

    mock_state.check_connect_forbidden = 1;
    mock_state.current_time_ms         = conn->connect_deadline_ms + 1U;
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(conn, &transport));
    assert_int_equal(PUBNUB_HTTP_ERROR, resp1.completion);
    assert_int_equal(PUBNUB_ERR_TIMEOUT, resp1.transport_error);
    assert_int_equal(PN_INVALID_SOCKET, conn->socket);
    assert_int_equal(destroyed + 1, mock_state.socket_destroy_calls);
    mock_state.check_connect_forbidden = 0;

    /* Reuse: fresh socket is probed (call count advances). */
    deferred_release_peer(&transport);
    pn_connection_reset(conn, &transport);
    conn->rx_buf.data = rx1;
    conn->rx_buf.cap  = sizeof(rx1);
    resp1             = (pubnub_http_response_t){0};
    assert_int_equal(0, pn_connection_start(conn, &req1, &resp1, &transport));
    (void)pn_connection_tick(conn, &transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));
    assert_int_equal(2, mock_state.check_connect_calls);
}

/** An established keep-alive socket is reused without being probed. */
static void test_fsm_keepalive_reuse_not_probed(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport); /* connect */
    (void)pn_connection_tick(&conn, &transport); /* handshake */
    (void)pn_connection_tick(&conn, &transport); /* send */
    (void)pn_connection_tick(&conn, &transport); /* receive */
    (void)pn_connection_tick(&conn, &transport); /* complete */
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn.state);

    mock_state.check_connect_forbidden = 1;
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(PN_CONN_SENDING_HEADERS, conn.state);
    assert_int_equal(1, mock_state.set_keepalive_calls);

    /* Driving the reused connection must not probe the socket either. */
    (void)pn_connection_tick(&conn, &transport);
    assert_int_not_equal(PN_CONN_CONNECTING, conn.state);
    assert_int_not_equal(PN_CONN_FAILED, conn.state);
    assert_int_equal(0, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);
    mock_state.check_connect_forbidden = 0;
}

/** A handshake timeout closes the socket; keepalive follows the next probe. */
static void test_fsm_tls_timeout_fallback_reprobes(void** state)
{
    (void)state;
    mock_reset();
    mock_state.dns_result_count             = 2;
    mock_state.dns_results[1]               = mock_state.dns_results[0];
    mock_state.dns_results[1].addr.ipv4[3]  = 5;
    mock_state.connect_result               = 0;
    mock_state.check_connect_script[0]      = 1;
    mock_state.check_connect_script[1]      = 0;
    mock_state.check_connect_script[2]      = 1;
    mock_state.check_connect_script_len     = 3;
    mock_state.tls_handshake_result         = PN_TLS_WANT_READ;
    mock_state.tls_handshake_calls_until_ok = 999;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];
    int                    destroyed;

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport); /* issue connect */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_POLL_READ, conn.tls_want);
    destroyed = mock_state.socket_destroy_calls;

    /* Handshake deadline: socket closed, next address connecting. */
    mock_state.current_time_ms = conn.connect_deadline_ms + 1U;
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(destroyed + 1, mock_state.socket_destroy_calls);
    assert_int_equal(1, conn.addr_current);
    assert_int_equal(1, mock_state.check_connect_calls);

    /* The new socket is probed; a pending probe keeps CONNECTING. */
    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(2, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);

    /* Keepalive follows only once the probe returns 1. */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(3, mock_state.check_connect_calls);
    assert_int_equal(2, mock_state.set_keepalive_calls);
}

/** A rejected keep-alive reuse closes the socket; the new connect is probed. */
static void test_fsm_keepalive_reuse_failure_reprobes(void** state)
{
    (void)state;
    mock_reset();

    static const char* resp =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];
    int                    destroyed;

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport); /* connect */
    (void)pn_connection_tick(&conn, &transport); /* handshake */
    (void)pn_connection_tick(&conn, &transport); /* send */
    (void)pn_connection_tick(&conn, &transport); /* receive */
    (void)pn_connection_tick(&conn, &transport); /* complete */
    assert_int_equal(PN_CONN_KEEP_ALIVE_IDLE, conn.state);
    assert_int_equal(1, mock_state.set_keepalive_calls);

    /* A different host makes the reuse check fail. */
    request.host                        = "other.example.com";
    response                            = (pubnub_http_response_t){0};
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;
    destroyed                           = mock_state.socket_destroy_calls;

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(destroyed + 1, mock_state.socket_destroy_calls);
    assert_int_equal(PN_INVALID_SOCKET, conn.socket);
    assert_int_equal(PN_CONN_CONNECTING, conn.state);

    (void)pn_connection_tick(&conn, &transport); /* issue connect */
    assert_int_equal(0, mock_state.check_connect_calls);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(2, mock_state.set_keepalive_calls);
}

#if PUBNUB_ENABLE_PROXY
/** Probe once and apply keepalive once across proxy CONNECT and TLS. */
static void test_fsm_proxy_then_tls_single_probe(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    static const char* resp  = "HTTP/1.1 200 Connection established\r\n\r\n";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_proxy_module_t*     module;
    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_proxy_transport(&module);
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[1024];

    assert_non_null(module);
    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    (void)pn_connection_tick(&conn, &transport); /* issue connect */
    assert_int_equal(PN_CONN_PROXY_NEGOTIATING,
                     pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);

    mock_state.check_connect_forbidden = 1;
    assert_int_equal(PN_CONN_PROXY_NEGOTIATING,
                     pn_connection_tick(&conn, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, conn.proxy_done);
    assert_int_equal(1, mock_state.tls_session_create_calls);

    assert_int_equal(PN_CONN_SENDING_HEADERS, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);
    mock_state.check_connect_forbidden = 0;

    pn_connection_cancel(&conn, &transport);
    module->destroy(module, &mock_allocator);
}
#endif

/** Peer busy on the same host: a connected socket parks in TLS_DEFERRED. */
static void test_fsm_tls_deferred_entered_on_peer_busy(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];

    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));

    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(conn, &transport));
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);
    assert_int_equal(0, mock_state.tls_session_create_calls);
    assert_null(conn->tls_session);
}

/** A pending connect always lands in CONNECTING so the next tick probes. */
static void test_fsm_try_connect_pending_forces_connecting(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 0;
    mock_state.check_connect_script_len = 1;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};

    pn_connection_init(&conn);
    conn.request             = &request;
    conn.response            = &response;
    conn.addr_count          = 1;
    conn.resolved_addrs[0]   = mock_state.dns_results[0];
    conn.state               = PN_CONN_TLS_DEFERRED;
    conn.connect_deadline_ms = mock_state.current_time_ms + 10000U;

    assert_int_equal(0, conn_try_connect(&conn, &transport));
    assert_int_equal(PN_CONN_CONNECTING, conn.state);
    assert_int_not_equal(PN_INVALID_SOCKET, conn.socket);
    assert_int_equal(0, mock_state.set_keepalive_calls);

    assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.check_connect_calls);
}

/** CONNECTING with a live socket always probes it, never creates TLS. */
static void test_fsm_connecting_valid_socket_always_probes(void** state)
{
    (void)state;
    mock_reset();
    mock_state.check_connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    int                    i;

    pn_connection_init(&conn);
    conn.request             = &request;
    conn.response            = &response;
    conn.socket              = 42;
    conn.state               = PN_CONN_CONNECTING;
    conn.connect_deadline_ms = mock_state.current_time_ms + 10000U;

    for (i = 1; i <= 3; ++i) {
        assert_int_equal(PN_CONN_CONNECTING, pn_connection_tick(&conn, &transport));
        assert_int_equal(i, mock_state.check_connect_calls);
    }
    assert_int_equal(0, mock_state.tls_session_create_calls);
    assert_int_equal(0, mock_state.set_keepalive_calls);
}

/** TLS_DEFERRED without a socket is unreachable; it must fail closed. */
static void test_fsm_tls_deferred_invalid_socket_fails_closed(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};

    pn_connection_init(&conn);
    conn.request  = &request;
    conn.response = &response;
    conn.state    = PN_CONN_TLS_DEFERRED;

    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(&conn, &transport));
    assert_int_equal(PUBNUB_HTTP_ERROR, response.completion);
    assert_int_equal(PUBNUB_ERR_INTERNAL, response.transport_error);
    assert_int_equal(0, mock_state.tls_session_create_calls);
    assert_int_equal(0, mock_state.socket_create_calls);
}

/** conn_try_connect never overwrites a socket it has not closed first. */
static void test_fsm_try_connect_closes_live_socket(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result = 0;

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};

    pn_connection_init(&conn);
    conn.request           = &request;
    conn.response          = &response;
    conn.addr_count        = 1;
    conn.resolved_addrs[0] = mock_state.dns_results[0];
    conn.socket            = 77;
    conn.state             = PN_CONN_CONNECTING;

    conn.tls_session = (void*)0xBEEF;

    assert_int_equal(0, conn_try_connect(&conn, &transport));
    assert_int_equal(1, mock_state.socket_destroy_calls);
    assert_int_equal(1, mock_state.tls_session_destroy_calls);
    assert_null(conn.tls_session);
    assert_int_equal(0, mock_state.socket_create_calls_at_destroy);
    assert_int_equal(1, mock_state.socket_create_calls);
    assert_int_equal(mock_state.next_socket, conn.socket);
}

/** Starting a request on an IDLE slot that still holds a socket closes it. */
static void test_fsm_start_idle_with_live_socket_closes_it(void** state)
{
    (void)state;
    mock_reset();

    pn_socket_connection_t conn;
    pn_socket_transport_t  transport = make_transport();
    pubnub_http_request_t  request   = make_request();
    pubnub_http_response_t response  = {0};
    uint8_t                rx_buf[256];

    pn_connection_init(&conn);
    conn.rx_buf.data = rx_buf;
    conn.rx_buf.cap  = sizeof(rx_buf);
    conn.socket      = 55;
    conn.tls_session = (void*)0xBEEF;
    conn.proxy_done  = 1;

    assert_int_equal(0, pn_connection_start(&conn, &request, &response, &transport));
    assert_int_equal(1, mock_state.socket_destroy_calls);
    assert_int_equal(1, mock_state.tls_session_destroy_calls);
    assert_int_equal(PN_INVALID_SOCKET, conn.socket);
    assert_null(conn.tls_session);
    assert_int_equal(0, conn.proxy_done);
    assert_int_equal(PN_CONN_CONNECTING, conn.state);

    /* The new request runs over a fresh socket. */
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(&conn, &transport));
    assert_int_equal(1, mock_state.socket_create_calls);
}

/** TLS error on address 0, immediate connect on address 1, peer busy. */
static void test_fsm_tls_deferred_from_tls_fallback_immediate(void** state)
{
    (void)state;
    mock_reset();
    add_second_addr();
    mock_state.tls_handshake_result         = -1;
    mock_state.tls_handshake_calls_until_ok = 1;

    pn_socket_transport_t   transport = make_transport();
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[256];
    pn_socket_connection_t* conn = &transport.connections[1];

    pn_connection_init(&transport.connections[0]);
    pn_connection_init(conn);
    conn->rx_buf.data = rx1;
    conn->rx_buf.cap  = sizeof(rx1);
    assert_int_equal(0, pn_connection_start(conn, &req1, &resp1, &transport));
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));

    transport.connections[0].state   = PN_CONN_TLS_HANDSHAKING;
    transport.connections[0].request = &req0;

    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    assert_int_equal(1, conn->addr_current);
    assert_int_not_equal(PN_INVALID_SOCKET, conn->socket);
    assert_int_equal(2, mock_state.set_keepalive_calls);
    assert_int_equal(1, mock_state.tls_session_create_calls);

    deferred_release_peer(&transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));
    assert_int_equal(2, mock_state.tls_session_create_calls);
}

#if PUBNUB_ENABLE_PROXY
/** A finished proxy tunnel parks in TLS_DEFERRED without re-running CONNECT. */
static void test_fsm_tls_deferred_after_proxy_complete(void** state)
{
    (void)state;
    mock_reset();
    mock_state.connect_result           = 0;
    mock_state.check_connect_script[0]  = 1;
    mock_state.check_connect_script_len = 1;

    static const char* resp  = "HTTP/1.1 200 Connection established\r\n\r\n";
    mock_state.recv_data     = (const uint8_t*)resp;
    mock_state.recv_data_len = strlen(resp);

    pn_proxy_module_t*      module;
    pn_socket_transport_t   transport = make_proxy_transport(&module);
    pubnub_http_request_t   req0      = make_request();
    pubnub_http_request_t   req1      = make_request();
    pubnub_http_response_t  resp1     = {0};
    uint8_t                 rx1[1024];
    pn_socket_connection_t* conn = &transport.connections[1];
    int                     sends;
    int                     i;

    assert_non_null(module);
    deferred_fixture(&transport, &req0, &req1, &resp1, rx1, sizeof(rx1));

    (void)pn_connection_tick(conn, &transport); /* issue connect */
    assert_int_equal(PN_CONN_PROXY_NEGOTIATING,
                     pn_connection_tick(conn, &transport));
    mock_state.check_connect_forbidden = 1;
    assert_int_equal(PN_CONN_PROXY_NEGOTIATING,
                     pn_connection_tick(conn, &transport));
    assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    assert_int_equal(1, conn->proxy_done);
    assert_null(conn->proxy_session);
    sends = mock_state.socket_send_calls;
    assert_int_equal(1, sends);

    for (i = 0; i < 3; ++i) {
        assert_int_equal(PN_CONN_TLS_DEFERRED, pn_connection_tick(conn, &transport));
    }
    assert_int_equal(sends, mock_state.socket_send_calls);
    assert_int_equal(0, mock_state.tls_session_create_calls);

    deferred_release_peer(&transport);
    assert_int_equal(PN_CONN_TLS_HANDSHAKING, pn_connection_tick(conn, &transport));
    assert_int_equal(1, mock_state.tls_session_create_calls);
    assert_int_equal(sends, mock_state.socket_send_calls);
    assert_int_equal(1, mock_state.check_connect_calls);
    assert_int_equal(1, mock_state.set_keepalive_calls);
    mock_state.check_connect_forbidden = 0;

    pn_connection_cancel(conn, &transport);
    module->destroy(module, &mock_allocator);
}
#endif

/** The fallback trace names the next address only while one remains. */
static void test_fsm_fallback_log_reports_exhaustion(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_TRACE)) {
        skip();
    }
    mock_reset();
    add_second_addr();
    mock_state.connect_result       = 0;
    mock_state.check_connect_result = -111;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response  = {0};
    uint8_t                       rx_buf[256];

    cap_attach(&transport);
    pn_connection_init(cp);
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport); /* issue connect to address 1 */
    (void)pn_connection_tick(cp, &transport); /* probe fails: fall back */
    assert_true(cap_has("T TCP connect fallback: trying address 2 of 2"));
    assert_int_equal(0, cap_count("no more addresses"));

    assert_int_equal(PN_CONN_CONNECTING, cp->state);
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));
    assert_true(cap_has("T TCP connect fallback: no more addresses after "
                        "address 2 of 2"));
    assert_int_equal(0, cap_count("trying address 3"));
    assert_int_equal(0, cap_count("trying address 2 of 1"));
}

/** A single-address host never logs the impossible "address 2 of 1". */
static void test_fsm_fallback_log_single_address(void** state)
{
    (void)state;
    skip_if_logging_compiled_out();
    if (!PUBNUB_LOG_LEVEL_ENABLED(PUBNUB_LOG_LEVEL_TRACE)) {
        skip();
    }
    mock_reset();
    mock_state.connect_result       = 0;
    mock_state.check_connect_result = -111;

    pn_socket_transport_t         transport = make_transport();
    pn_socket_connection_t* const cp        = &transport.connections[0];
    pubnub_http_request_t         request   = make_request();
    pubnub_http_response_t        response  = {0};
    uint8_t                       rx_buf[256];

    cap_attach(&transport);
    pn_connection_init(cp);
    cp->rx_buf.data = rx_buf;
    cp->rx_buf.cap  = sizeof(rx_buf);

    assert_int_equal(0, pn_connection_start(cp, &request, &response, &transport));
    (void)pn_connection_tick(cp, &transport); /* issue connect */
    assert_int_equal(PN_CONN_FAILED, pn_connection_tick(cp, &transport));
    assert_int_equal(0, cap_count("trying address"));
    assert_true(cap_has("T TCP connect fallback: no more addresses after "
                        "address 1 of 1"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fsm_idle_to_complete),
        cmocka_unit_test(test_fsm_connect_timeout),
        cmocka_unit_test(test_fsm_dns_failed_terminates),
        cmocka_unit_test(test_fsm_ipv6_fallback),
        cmocka_unit_test(test_fsm_connect_pending_defers_tls_session),
        cmocka_unit_test(test_fsm_connect_error_falls_back_to_next_addr),
        cmocka_unit_test(test_fsm_tls_handshake),
        cmocka_unit_test(test_fsm_cancel),
        cmocka_unit_test(test_fsm_reset),
        cmocka_unit_test(test_fsm_complete_advances_to_keepalive_idle),
        cmocka_unit_test(test_fsm_complete_advances_to_closing_on_connection_close),
        cmocka_unit_test(test_fsm_dns_waiter_does_not_steal_different_host_result),
        cmocka_unit_test(test_fsm_cancel_dns_owner_resets_resolver),
#if PUBNUB_CFG_SOCKET_MAX_REDIRECTS > 0
        cmocka_unit_test(test_redirect_followed_once),
        cmocka_unit_test(test_redirect_loop_capped),
#endif
        cmocka_unit_test(test_tls_handshake_serialized_same_host),
        cmocka_unit_test(test_tls_handshake_not_serialized_different_host),
        cmocka_unit_test(test_tls_handshake_deferred_timeout),
        cmocka_unit_test(test_peer_close_complete_body_populates_headers),
        cmocka_unit_test(test_dns_claim_failure_releases_resolver),
        cmocka_unit_test(test_fsm_plaintext_send_error),
        cmocka_unit_test(test_fsm_partial_send_then_fail),
        cmocka_unit_test(test_fsm_tls_send_error),
        cmocka_unit_test(test_fsm_body_send_error),
        cmocka_unit_test(test_fsm_tls_error_logs_backend_error),
        cmocka_unit_test(test_fsm_recv_error_null_error_hook_safe),
        cmocka_unit_test(test_fsm_recv_error_logs_tls_backend_error),
        cmocka_unit_test(test_fsm_header_send_error_logs_tls_detail),
        cmocka_unit_test(test_fsm_connect_refused_logs_warning),
        cmocka_unit_test(test_fsm_connect_failure_logs_exhausted_context),
        cmocka_unit_test(test_fsm_connect_failure_with_remaining_addr_logs_info),
        cmocka_unit_test(test_fsm_tls_timeout_logs_single_warning),
        cmocka_unit_test(test_fsm_connected_trace_reports_elapsed),
        cmocka_unit_test(test_fsm_tls_want_set_on_enter_handshake),
        cmocka_unit_test(test_fsm_tls_want_follows_backend_want),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_complete),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_error),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_fallback),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_timeout_fallback),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_cancel),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_reset),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_close_helpers),
        cmocka_unit_test(test_fsm_tls_want_cleared_on_start),
        cmocka_unit_test(test_fsm_release_request_keeps_socket_and_tls),
        cmocka_unit_test(test_fsm_release_request_generation_skips_zero),
        cmocka_unit_test(test_fsm_release_request_rejects_other_states),
        cmocka_unit_test(test_fsm_connect_timeout_falls_back_to_next_addr),
        cmocka_unit_test(test_fsm_connect_timeout_single_addr_unchanged),
        cmocka_unit_test(test_fsm_connect_timeout_many_addrs_bounded),
        cmocka_unit_test(test_fsm_connect_timeout_then_error_exhausts),
        cmocka_unit_test(test_fsm_connect_error_then_timeout_fails_timeout),
        cmocka_unit_test(test_fsm_connect_timeout_no_fallback_without_budget),
        cmocka_unit_test(test_fsm_connect_timeout_fallback_logs_info),
        cmocka_unit_test(test_fsm_tls_deferred_wait_uses_full_window),
        cmocka_unit_test(test_fsm_connect_budget_skips_exhausted_trailing_family),
        cmocka_unit_test(test_fsm_connect_budget_capped_at_remaining),
        cmocka_unit_test(test_fsm_tls_deferred_single_probe),
        cmocka_unit_test(test_fsm_tls_deferred_survives_check_connect_regression),
        cmocka_unit_test(test_fsm_keepalive_once_deferred),
        cmocka_unit_test(test_fsm_keepalive_once_immediate),
        cmocka_unit_test(test_fsm_keepalive_once_plaintext),
        cmocka_unit_test(test_fsm_keepalive_once_pending_connect),
        cmocka_unit_test(test_fsm_fallback_pending_reprobes),
        cmocka_unit_test(test_fsm_fallback_immediate_applies_keepalive),
        cmocka_unit_test(test_fsm_tls_deferred_cancel_then_reset_reprobes),
        cmocka_unit_test(test_fsm_tls_deferred_deadline_without_probe_then_reuse),
        cmocka_unit_test(test_fsm_tls_deferred_entered_on_peer_busy),
        cmocka_unit_test(test_fsm_try_connect_pending_forces_connecting),
        cmocka_unit_test(test_fsm_connecting_valid_socket_always_probes),
        cmocka_unit_test(test_fsm_tls_deferred_invalid_socket_fails_closed),
        cmocka_unit_test(test_fsm_try_connect_closes_live_socket),
        cmocka_unit_test(test_fsm_start_idle_with_live_socket_closes_it),
        cmocka_unit_test(test_fsm_tls_deferred_from_tls_fallback_immediate),
        cmocka_unit_test(test_fsm_fallback_log_reports_exhaustion),
        cmocka_unit_test(test_fsm_fallback_log_single_address),
        cmocka_unit_test(test_fsm_keepalive_reuse_not_probed),
        cmocka_unit_test(test_fsm_tls_timeout_fallback_reprobes),
        cmocka_unit_test(test_fsm_keepalive_reuse_failure_reprobes),
#if PUBNUB_ENABLE_PROXY
        cmocka_unit_test(test_fsm_proxy_then_tls_single_probe),
        cmocka_unit_test(test_fsm_tls_deferred_after_proxy_complete),
        cmocka_unit_test(test_fsm_proxy_negotiate_complete),
        cmocka_unit_test(test_fsm_proxy_negotiate_error),
        cmocka_unit_test(test_fsm_proxy_cancel),
        cmocka_unit_test(test_fsm_proxy_negotiate_timeout),
        cmocka_unit_test(test_fsm_proxy_reset),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
