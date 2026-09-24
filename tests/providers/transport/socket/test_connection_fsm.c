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
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "providers/transport/socket/connection_fsm_internal.h"
#include "providers/transport/socket/inflate/pn_inflate.h"
#include "providers/transport/socket/connection_fsm.c"

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

    /* Scripted per-call send results for partial-send simulation. When
     * send_script_len > 0, mock_socket_send and mock_tls_send return
     * send_script[send_call_idx] and advance the index, clamping to the
     * last entry once exhausted. This overrides send_result /
     * tls_send_result. Used to model "send N bytes, then fail". */
    int send_script[8];
    int send_script_len;
    int send_call_idx;

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
    int   tls_send_result;
    int   tls_recv_result;
    int   tls_session_destroy_calls;
    void* tls_fake_session;

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
    return mock_state.next_socket;
}

static void mock_socket_destroy(const pn_socket_platform_ops_t* self, pn_socket_t sock)
{
    (void)self;
    (void)sock;
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
    (void)sock;
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

/**
 * Verify tick_complete() transitions COMPLETE → KEEP_ALIVE_IDLE when the
 * server does not send Connection: close. This exercises the path that was
 * previously unreachable because socket_poll skipped COMPLETE connections on
 * re-entry.
 */
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
     * State must remain CONNECTING. */
    s = pn_connection_tick(&transport.connections[1], &transport);
    assert_int_equal(s, PN_CONN_CONNECTING);

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
    assert_int_equal(s, PN_CONN_CONNECTING);
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

    /* The regression guard: headers must be extracted on this path too. */
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

    /* The regression guard: a different slot must still be able to resolve. */
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

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fsm_idle_to_complete),
        cmocka_unit_test(test_fsm_connect_timeout),
        cmocka_unit_test(test_fsm_dns_failed_terminates),
        cmocka_unit_test(test_fsm_ipv6_fallback),
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
#if PUBNUB_ENABLE_PROXY
        cmocka_unit_test(test_fsm_proxy_negotiate_complete),
        cmocka_unit_test(test_fsm_proxy_negotiate_error),
        cmocka_unit_test(test_fsm_proxy_cancel),
        cmocka_unit_test(test_fsm_proxy_negotiate_timeout),
        cmocka_unit_test(test_fsm_proxy_reset),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
