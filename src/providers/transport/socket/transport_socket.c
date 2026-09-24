/* Copyright (c) 2024-2026 PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "transport_socket_internal.h"

#include "core/pn_string.h"
#include "http_builder.h"
#include "inflate/pn_inflate.h"
#include "keepalive.h"
#include "providers/transport/socket/platform/pn_socket_types.h"
#include "proxy/proxy_connect.h"
#include "proxy/proxy_wpad.h"

#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/proxy.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/provider_deps.h"
#include "pubnub/providers/transport_types.h"
#include "pubnub/pubnub_compat.h"

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <stdlib.h>
#include <string.h>

// NOLINTNEXTLINE(misc-use-internal-linkage)
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc);

/** @brief Initial decompression buffer capacity: body_len * this factor. */
#define PN_DECOMP_CAP_INITIAL_MULT 6U
/** @brief Retry decompression buffer capacity: body_len * this factor. */
#define PN_DECOMP_CAP_RETRY_MULT 12U

/**
 * @brief Tagged transport handle encoding.
 *
 * Encodes {slot_index, generation} into the opaque void* handle so
 * that socket_cancel can detect stale handles that reference a
 * recycled connection slot. Low 8 bits = slot index (max 256 slots),
 * bits 8..23 = generation counter (wraps at 65536).
 *
 * The encoded value is never dereferenced - it is decoded back into
 * index + generation by the DECODE macros. Generation starts at 1
 * (pn_connection_init) so ENCODE(0, gen) is never NULL.
 */
#define PN_SOCKET_HANDLE_ENCODE(idx, gen)                           \
    ((pubnub_transport_handle_t*)(uintptr_t)(((uint32_t)(gen) << 8) \
                                             | ((uint32_t)(idx) & 0xFFu)))

#define PN_SOCKET_HANDLE_INDEX(h) ((int)((uintptr_t)(h) & 0xFFu))
#define PN_SOCKET_HANDLE_GEN(h)   ((uint16_t)(((uintptr_t)(h) >> 8) & 0xFFFFu))

/**
 * @brief Outcome of one decompression attempt.
 *
 * Returned by value so the buffer, its capacity, the inflated length and
 * the inflate result travel together. Passing these as four separate
 * out-params made a caller-side argument swap between the two size_t
 * values silently type-correct.
 */
typedef struct pn_decomp_result {
    /** Inflated output buffer, or NULL when the attempt could not run. */
    uint8_t* buf;
    /** Capacity of buf in bytes. */
    size_t cap;
    /** Inflated byte count. Meaningful only when rc is PN_INFLATE_OK. */
    size_t len;
    /** Final PN_INFLATE_* result. Meaningful only when buf is non-NULL. */
    int rc;
} pn_decomp_result_t;

/**
 * @brief Allocate a decompression output buffer.
 *
 * Uses general alloc tier — decompressed size is unknown until inflate
 * completes, so a purpose-tagged slot cannot be pre-specified.
 */
static uint8_t* socket_alloc_decomp_buf(pubnub_allocator_provider_t* alloc,
                                        size_t                       cap)
{
    if (NULL == alloc || NULL == alloc->alloc) {
        return NULL;
    }
    return (uint8_t*)PN_ALLOC(alloc, cap, sizeof(void*));
}

/**
 * @brief Free a decompression buffer that was never published.
 *
 * Distinct from pn_conn_free_decomp_buf: this releases a scratch buffer
 * still owned by the caller, so no connection field is touched.
 *
 * @note No-op when the allocator omits the optional free hook. Both bundled
 *       allocators (stdlib and arena) expose one, so this genuinely reclaims;
 *       the guard exists only for third-party allocators that lack free,
 *       where an overflow retry leaks the first buffer until arena reset. The
 *       waste is bounded by PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE and
 *       happens at most once per response.
 */
static void socket_free_decomp_scratch(pubnub_allocator_provider_t* alloc,
                                       uint8_t*                     buf)
{
    if (NULL != buf && NULL != alloc && NULL != alloc->free) {
        PN_FREE(alloc, buf);
    }
}

/** @brief Dispatch gzip or raw deflate decompression. */
static int socket_inflate_once(int                               is_gzip,
                               const uint8_t*                    input,
                               size_t                            input_len,
                               uint8_t*                          output,
                               size_t                            output_cap,
                               size_t*                           out_len,
                               struct pubnub_allocator_provider* alloc,
                               struct pubnub_logger_provider*    logger)
{
    if (is_gzip) {
        return pn_inflate_gzip(
            input, input_len, output, output_cap, out_len, alloc, logger);
    }
    return pn_inflate_deflate(
        input, input_len, output, output_cap, out_len, alloc, logger);
}

/** @brief Mark a connection as failed due to a decompression error. */
static void socket_decomp_fail(pn_socket_connection_t* conn, pubnub_res_t err)
{
    if (NULL != conn->response) {
        conn->response->completion      = PUBNUB_HTTP_ERROR;
        conn->response->transport_error = err;
    }
    conn->state = PN_CONN_FAILED;
}

/**
 * @brief Find a KEEP_ALIVE_IDLE slot matching the request target.
 *
 * Returns the slot index, or -1 if no reusable connection exists.
 */
static int find_reusable_slot(pn_socket_transport_t*       t,
                              const pubnub_http_request_t* request)
{
    uint16_t port = pn_http_resolve_port(request);
    uint64_t now  = 0;
    int      i;

    if (NULL != t->platform) {
        now = t->platform->monotonic_ms(t->platform);
    }

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_socket_connection_t* conn = &t->connections[i];
        if (PN_CONN_KEEP_ALIVE_IDLE != conn->state) {
            continue;
        }
        pn_keepalive_conn_state_t conn_state = {
            .host            = conn->connected_host,
            .port            = conn->connected_port,
            .secure          = conn->connected_secure,
            .requests_served = conn->requests_on_connection,
            .idle_since_ms   = conn->idle_since_ms,
        };
        pn_keepalive_target_t target = {
            .host   = request->host,
            .port   = port,
            .secure = request->secure,
        };
        if (pn_keepalive_can_reuse(&conn_state,
                                   &target,
                                   now,
                                   PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_REQUESTS,
                                   PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS)) {
            return i;
        }
    }

    return -1;
}

/**
 * @brief Find the first IDLE slot in the connection pool.
 *
 * Returns the slot index, or -1 if all slots are occupied.
 */
static int find_idle_slot(const pn_socket_transport_t* t)
{
    int i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        if (PN_CONN_IDLE == t->connections[i].state) {
            return i;
        }
    }
    return -1;
}

static void poll_unregister_connection(pn_socket_transport_t*  t,
                                       pn_socket_connection_t* conn);

/**
 * @brief Evict the oldest idle connection for reuse.
 *
 * Fallback when no reusable or idle slot exists. Picks the oldest
 * KEEP_ALIVE_IDLE or IDLE slot and resets it. Skips connections
 * whose response is still consumable (completion == COMPLETE).
 *
 * Returns the evicted slot index, or -1 if no evictable slots.
 */
static int find_evictable_slot(pn_socket_transport_t* t)
{
    int      best     = -1;
    uint64_t best_age = 0;
    int      i;

    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_socket_connection_t* conn = &t->connections[i];
        uint64_t                age;

        if (PN_CONN_KEEP_ALIVE_IDLE != conn->state && PN_CONN_IDLE != conn->state) {
            continue;
        }
        /* Skip connections whose response body is still consumable —
         * a caller holding a future may still read the body. */
        if (NULL != conn->response
            && PUBNUB_HTTP_COMPLETE == conn->response->completion) {
            continue;
        }
        age = conn->idle_since_ms;
        if (best < 0 || age < best_age) {
            best     = i;
            best_age = age;
        }
    }

    if (best >= 0) {
        pn_socket_connection_t* conn = &t->connections[best];
        poll_unregister_connection(t, conn);
        pn_connection_reset(conn, t);
    }

    return best;
}

/**
 * @brief Register a connection's socket in the poll set.
 *
 * Adds the socket to the poll set with the appropriate events for the
 * current FSM state. Call after the socket is created or after a state
 * transition that changes the needed I/O direction.
 */
static void poll_register_connection(pn_socket_transport_t*  t,
                                     pn_socket_connection_t* conn,
                                     uint8_t                 events)
{
    if (PN_INVALID_SOCKET == conn->socket) {
        return;
    }
    t->ops->poll_add(t->ops, &t->poll_set, conn->socket, events);
}

/**
 * @brief Update poll events for a connection based on FSM state.
 */
static uint8_t events_for_state(pn_conn_state_t state)
{
    switch (state) {
    case PN_CONN_CONNECTING:
    case PN_CONN_SENDING_HEADERS:
    case PN_CONN_SENDING_BODY:
    case PN_CONN_TLS_HANDSHAKING: return PN_POLL_WRITE | PN_POLL_READ;
    case PN_CONN_RECEIVING_RESPONSE: return PN_POLL_READ;
    case PN_CONN_DNS_RESOLVING:
    case PN_CONN_PROXY_NEGOTIATING: return PN_POLL_READ | PN_POLL_WRITE;
    default: return 0;
    }
}

/**
 * @brief Remove a connection's socket from the poll set.
 */
static void poll_unregister_connection(pn_socket_transport_t*  t,
                                       pn_socket_connection_t* conn)
{
    if (PN_INVALID_SOCKET == conn->socket) {
        return;
    }
    t->ops->poll_remove(t->ops, &t->poll_set, conn->socket);
}

/**
 * @brief Check if a connection is in a terminal state.
 */
static int conn_is_terminal(pn_conn_state_t state)
{
    return (PN_CONN_COMPLETE == state || PN_CONN_FAILED == state
            || PN_CONN_CANCELLED == state);
}

static pubnub_transport_handle_t* socket_send(pubnub_transport_provider_t* self,
                                              pubnub_http_request_t*  request,
                                              pubnub_http_response_t* response)
{
    if (NULL == self || NULL == request || NULL == response) {
        if (NULL != response) {
            response->completion      = PUBNUB_HTTP_ERROR;
            response->transport_error = PUBNUB_ERR_INVALID_ARGUMENT;
        }
        return NULL;
    }

    pn_socket_transport_t* t = (pn_socket_transport_t*)self;

    /* Try to reuse a keep-alive connection first. */
    const char* slot_source = "reuse";
    int         slot        = find_reusable_slot(t, request);
    if (slot < 0) {
        slot_source = "idle";
        slot        = find_idle_slot(t);
    }
    if (slot < 0) {
        slot_source = "evict";
        slot        = find_evictable_slot(t);
    }
    if (slot < 0) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_QUEUE_FULL;
        return NULL;
    }

    pn_socket_connection_t* conn = &t->connections[slot];
    (void)slot_source; /* Used in PUBNUB_LOG below */

    PUBNUB_LOG(t->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "socket_send: conn[%d] via %s, state=%d, "
               "host_req=%s, host_conn=%s, fd=%d",
               slot,
               slot_source,
               (int)conn->state,
               (NULL != request->host) ? request->host : "(null)",
               conn->connected_host,
               (int)conn->socket);

    int rc = pn_connection_start(conn, request, response, t);
    if (0 != rc) {
        response->completion      = PUBNUB_HTTP_ERROR;
        response->transport_error = PUBNUB_ERR_TRANSPORT;
        return NULL;
    }

    /* Mint a fresh generation for every handle handed to the core, so a
     * reused slot (keep-alive or post-close IDLE) never returns the same
     * handle as a prior request. Bumping here — not in pn_connection_start
     * — keeps the count to exactly one per handle: the re-entrant restarts
     * (stale keep-alive, redirect) call pn_connection_start again on the
     * same in-flight request whose handle the core already holds, and must
     * not invalidate it. Skip 0: ENCODE(idx, 0) is indistinguishable from
     * a NULL handle. */
    conn->generation = (uint16_t)(conn->generation + 1U);
    if (0 == conn->generation) {
        conn->generation = 1;
    }

    /* Register in poll set if the connection already has a socket
     * (keep-alive reuse skips DNS/connect). */
    if (PN_INVALID_SOCKET != conn->socket) {
        uint8_t events = events_for_state(conn->state);
        if (0 != events) {
            poll_register_connection(t, conn, events);
        }
    }

    return PN_SOCKET_HANDLE_ENCODE(slot, conn->generation); // NOLINT(performance-no-int-to-ptr)
}

/**
 * @brief Inflate the response body, growing the buffer once on overflow.
 *
 * Sizes an output buffer from the compressed length, inflates, and on
 * overflow retries once with a larger multiplier. The returned buffer is
 * caller-owned scratch — it is not yet attached to the connection.
 *
 * Always allocates fresh. A buffer from the previous response cannot be
 * carried over: the decompression buffer's lifetime deliberately ends at
 * the start of the next request (pn_connection_start releases it) so an
 * idle keep-alive connection holds no decompression scratch. Both bundled
 * allocators expose a free hook, so the per-response allocation is
 * genuinely reclaimed.
 *
 * @param t    Socket transport (provides allocator and logger).
 * @param conn Connection whose response body is inflated.
 * @return Result whose @c buf is set on every inflate outcome, success or
 *         failure, so the caller can inspect @c rc and log the body.
 *         @c buf is NULL when the attempt could not run at all (allocation
 *         failure, or a retry capacity above
 *         PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE); in that case the
 *         connection is already marked failed. Ownership of a non-NULL
 *         @c buf stays with the caller until socket_decomp_publish.
 */
static pn_decomp_result_t socket_decomp_try(pn_socket_transport_t*  t,
                                            pn_socket_connection_t* conn)
{
    pubnub_allocator_provider_t* alloc = t->allocator;
    const int is_gzip = 0 != (conn->parser.flags & PN_HTTP_FLAG_GZIP);
    size_t    cap     = conn->response->body_len * PN_DECOMP_CAP_INITIAL_MULT;
    pn_decomp_result_t res = {0};

    if (cap < 256) {
        cap = 256;
    }
    if (PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE > 0
        && cap > PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE) {
        cap = PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE;
    }

    res.buf = socket_alloc_decomp_buf(alloc, cap);
    res.cap = cap;

    if (NULL == res.buf) {
        PUBNUB_LOG(t->logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "decomp_buf alloc failed: requested %u bytes",
                   (unsigned)cap);
        socket_decomp_fail(conn, PUBNUB_ERR_OUT_OF_MEMORY);
        res.cap = 0;
        return res;
    }

    res.rc = socket_inflate_once(is_gzip,
                                 conn->response->body,
                                 conn->response->body_len,
                                 res.buf,
                                 res.cap,
                                 &res.len,
                                 alloc,
                                 t->logger);
    if (PN_INFLATE_ERR_OVERFLOW != res.rc) {
        return res;
    }

    PUBNUB_LOG(t->logger,
               PUBNUB_LOG_LEVEL_DEBUG,
               "inflate overflow on first attempt "
               "(%u bytes), retrying with larger buffer",
               (unsigned)res.cap);

    cap = conn->response->body_len * PN_DECOMP_CAP_RETRY_MULT;
    if (PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE > 0
        && cap > PUBNUB_CFG_SOCKET_DECOMP_MAX_BUFFER_SIZE) {
        socket_free_decomp_scratch(alloc, res.buf);
        socket_decomp_fail(conn, PUBNUB_ERR_TRANSPORT);
        res.buf = NULL;
        res.cap = 0;
        return res;
    }

    socket_free_decomp_scratch(alloc, res.buf);

    res.buf = socket_alloc_decomp_buf(alloc, cap);
    res.cap = cap;
    if (NULL == res.buf) {
        PUBNUB_LOG(t->logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "decomp_buf retry alloc failed: "
                   "requested %u bytes",
                   (unsigned)cap);
        socket_decomp_fail(conn, PUBNUB_ERR_OUT_OF_MEMORY);
        res.cap = 0;
        return res;
    }

    res.rc = socket_inflate_once(is_gzip,
                                 conn->response->body,
                                 conn->response->body_len,
                                 res.buf,
                                 res.cap,
                                 &res.len,
                                 alloc,
                                 t->logger);
    return res;
}

/** @brief Log an inflate failure with the leading compressed bytes. */
static void socket_decomp_log_failure(pn_socket_transport_t*  t,
                                      pn_socket_connection_t* conn,
                                      int                     inf_rc)
{
    const uint8_t* b   = conn->response->body;
    const size_t   len = conn->response->body_len;

    /* Compiled-out logging turns the PUBNUB_LOG below into ((void)0),
     * leaving every input to the diagnostic unreferenced. */
    (void)t;
    (void)inf_rc;
    (void)b;
    (void)len;

    PUBNUB_LOG(t->logger,
               PUBNUB_LOG_LEVEL_WARNING,
               "inflate error: rc=%d body_len=%u flags=0x%x "
               "body[0..3]=%x %x %x %x",
               inf_rc,
               (unsigned)len,
               (unsigned)(conn->parser.flags
                          & (PN_HTTP_FLAG_GZIP | PN_HTTP_FLAG_DEFLATE
                             | PN_HTTP_FLAG_CHUNKED)),
               (unsigned)(len > 0 ? b[0] : 0),
               (unsigned)(len > 1 ? b[1] : 0),
               (unsigned)(len > 2 ? b[2] : 0),
               (unsigned)(len > 3 ? b[3] : 0));
}

/**
 * @brief Attach an inflated buffer to the connection and response.
 *
 * Takes ownership of the buffer in @p res. Any buffer left over from a
 * previous response on this keep-alive connection is released first.
 *
 * @param t    Socket transport (provides the allocator).
 * @param conn Connection receiving the buffer.
 * @param res  Successful inflate result; buffer ownership transfers to
 *             the connection.
 */
static void socket_decomp_publish(pn_socket_transport_t*    t,
                                  pn_socket_connection_t*   conn,
                                  const pn_decomp_result_t* res)
{
    pn_conn_free_decomp_buf(conn, t);

    conn->decomp_buf         = res->buf;
    conn->response->body     = res->buf;
    conn->response->body_len = res->len;
}

/**
 * @brief Decompress gzip/deflate response body after parse completion.
 *
 * Called from `socket_poll` when a connection reaches `PN_CONN_COMPLETE`
 * and the parser recorded a compressed Content-Encoding. On failure,
 * marks the slot as `PN_CONN_FAILED` and sets the error fields directly.
 *
 * @param t    Socket transport (provides the allocator).
 * @param conn Connection whose response body should be decompressed.
 */
static void socket_poll_decompress(pn_socket_transport_t*  t,
                                   pn_socket_connection_t* conn)
{
    pn_decomp_result_t res;

    if (NULL == conn->response || NULL == conn->response->body
        || 0 == conn->response->body_len
        || 0 == (conn->parser.flags & (PN_HTTP_FLAG_GZIP | PN_HTTP_FLAG_DEFLATE))) {
        return;
    }

    res = socket_decomp_try(t, conn);
    if (NULL == res.buf) {
        return; /* Failure already recorded on the connection. */
    }

    if (PN_INFLATE_OK != res.rc) {
        socket_decomp_log_failure(t, conn, res.rc);
        socket_free_decomp_scratch(t->allocator, res.buf);
        socket_decomp_fail(conn, PUBNUB_ERR_TRANSPORT);
        return;
    }

    socket_decomp_publish(t, conn, &res);
}

/** @brief Thread-safe wake: write one byte to the self-pipe write end. */
static void socket_wake(pubnub_transport_provider_t* self)
{
    pn_socket_transport_t* t = (pn_socket_transport_t*)self;
    if (PN_INVALID_SOCKET == t->wake_pipe_wr) {
        return;
    }
    if (NULL != t->ops->pipe_write) {
        t->ops->pipe_write(t->ops, t->wake_pipe_wr);
    } else {
        const uint8_t b = 0;
        (void)t->ops->socket_send(t->ops, t->wake_pipe_wr, &b, 1);
    }
}

static int socket_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }

    pn_socket_transport_t* t         = (pn_socket_transport_t*)self;
    int                    completed = 0;
    int                    i;

    /* Capture time once for idle-eviction checks below. */
    uint64_t now_ms = 0;
    if (NULL != t->platform) {
        now_ms = t->platform->monotonic_ms(t->platform);
    }

    /* Wait for I/O events. */
    int ready = t->ops->poll_wait(t->ops, &t->poll_set, (int)timeout_ms);
    (void)ready;

    /* Drain the wake pipe so the next blocking poll is not immediately
     * woken by stale wake bytes. Non-blocking; harmless when empty. */
    if (PN_INVALID_SOCKET != t->wake_pipe_rd) {
        if (NULL != t->ops->pipe_drain) {
            t->ops->pipe_drain(t->ops, t->wake_pipe_rd);
        } else {
            /* Fallback: drain all pending bytes via socket_recv.
             * Multiple wake signals can accumulate between polls. */
            uint8_t drain[64];
            while (0 < t->ops->socket_recv(
                       t->ops, t->wake_pipe_rd, drain, sizeof(drain))) {
                /* keep draining */
            }
        }
    }

    /* Tick all non-idle connections. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_socket_connection_t* conn       = &t->connections[i];
        pn_conn_state_t         prev_state = conn->state;

        if (PN_CONN_IDLE == prev_state) {
            continue;
        }

        /* Evict keep-alive connections that exceeded idle timeout. */
        if (PN_CONN_KEEP_ALIVE_IDLE == prev_state) {
            if (0 != now_ms && 0 != conn->idle_since_ms
                && now_ms - conn->idle_since_ms
                       > PUBNUB_CFG_SOCKET_KEEPALIVE_MAX_IDLE_MS) {
                poll_unregister_connection(t, conn);
                pn_connection_reset(conn, t);
            }
            continue;
        }

        /* Reap terminal connections (FAILED/CANCELLED) after a grace
         * period. Tagged handles ensure stale cancels after the reset
         * are safe no-ops. */
        if (conn_is_terminal(prev_state)) {
            if (0 != now_ms && 0 != conn->idle_since_ms
                && now_ms - conn->idle_since_ms
                       > PUBNUB_CFG_SOCKET_CONNECT_TIMEOUT_MS) {
                poll_unregister_connection(t, conn);
                pn_connection_reset(conn, t);
            }
            continue;
        }

        pn_conn_state_t old_socket_state = conn->state;
        pn_socket_t     old_socket       = conn->socket;
        int             just_completed   = 0;

        pn_conn_state_t new_state = pn_connection_tick(conn, t);

        /* When the FSM reaches COMPLETE in this tick, advance it through
         * tick_complete() immediately — keep-alive reuse depends on this
         * transition and must not wait for the next poll call (the COMPLETE
         * skip at the top of this loop would prevent it from ever running). */
        if (PN_CONN_COMPLETE == new_state) {
            if (PUBNUB_ENABLE_COMPRESSION) {
                socket_poll_decompress(t, conn);
            }
            /* tick_complete() → KEEP_ALIVE_IDLE (reuse) or CLOSING (close). */
            new_state = pn_connection_tick(conn, t);
            if (PN_CONN_CLOSING == new_state) {
                /* Remove before tick_closing destroys the socket so that
                 * the poll_remove below and the socket-change block both
                 * see the descriptor removed cleanly without a double-remove. */
                if (PN_INVALID_SOCKET != conn->socket) {
                    t->ops->poll_remove(t->ops, &t->poll_set, conn->socket);
                }
                /* tick_closing() closes socket and returns IDLE. */
                new_state = pn_connection_tick(conn, t);
                /* Suppress the socket-change remove path below: old_socket
                 * is now the same as conn->socket (both INVALID). */
                old_socket = conn->socket;
            }
            just_completed = 1;
        }

        /* Handle socket lifecycle changes. */
        if (old_socket != conn->socket) {
            /* Socket changed: old closed, new created. */
            if (PN_INVALID_SOCKET != old_socket) {
                t->ops->poll_remove(t->ops, &t->poll_set, old_socket);
            }
            if (PN_INVALID_SOCKET != conn->socket) {
                uint8_t ev = events_for_state(new_state);
                if (0 != ev) {
                    t->ops->poll_add(t->ops, &t->poll_set, conn->socket, ev);
                }
            }
        } else if (old_socket_state != new_state && PN_INVALID_SOCKET != conn->socket
                   && !conn_is_terminal(new_state)
                   && PN_CONN_KEEP_ALIVE_IDLE != new_state) {
            /* State changed but same socket: update poll events. */
            uint8_t ev = events_for_state(new_state);
            if (0 != ev) {
                t->ops->poll_modify(t->ops, &t->poll_set, conn->socket, ev);
            }
        }

        /* Count newly completed connections.
         * Remove the socket from the poll set on every completion path,
         * including KEEP_ALIVE_IDLE: socket_send reuse calls poll_add again,
         * so the socket must not remain registered between requests. Idle
         * eviction is driven by the monotonic-clock check at the top of the
         * loop, not by poll events. */
        if (just_completed || conn_is_terminal(new_state)
            || PN_CONN_KEEP_ALIVE_IDLE == new_state) {
            if (PN_INVALID_SOCKET != conn->socket) {
                t->ops->poll_remove(t->ops, &t->poll_set, conn->socket);
            }
            ++completed;
        }
    }

    return completed;
}

/**
 * @brief Cancel a connection via its tagged transport handle.
 *
 * Decodes {slot_index, generation} from the opaque handle. If the
 * index is out of range or the generation does not match the current
 * connection slot, the handle is stale and the call is a safe no-op.
 *
 * For valid handles, cancels the connection and resets the slot to
 * IDLE so it can be reused by the next send().
 */
static void socket_cancel(pubnub_transport_provider_t* self,
                          pubnub_transport_handle_t*   transport_handle)
{
    pn_socket_transport_t*  t;
    pn_socket_connection_t* conn;
    int                     idx;
    uint16_t                gen;

    if (NULL == self || NULL == transport_handle) {
        return;
    }

    t   = (pn_socket_transport_t*)self;
    idx = PN_SOCKET_HANDLE_INDEX(transport_handle);
    gen = PN_SOCKET_HANDLE_GEN(transport_handle);

    if (idx < 0 || idx >= PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS) {
        PUBNUB_LOG(t->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "socket_cancel: handle %p decoded index %d out of range",
                   (const void*)transport_handle,
                   idx);
        return;
    }

    conn = &t->connections[idx];
    if (conn->generation != gen) {
        PUBNUB_LOG(t->logger,
                   PUBNUB_LOG_LEVEL_WARNING,
                   "socket_cancel: stale handle for conn[%d] "
                   "(handle gen=%u, current gen=%u)",
                   idx,
                   (unsigned)gen,
                   (unsigned)conn->generation);
        return;
    }

    /* Unregister from poll before cancelling (socket may close). */
    poll_unregister_connection(t, conn);

    pn_connection_cancel(conn, t);
    /* Reset to IDLE regardless - cancel() is a no-op on terminal
     * slots, so reset handles both in-progress and already-terminal
     * cases, ensuring the slot is reusable after this call. */
    pn_connection_reset(conn, t);
}

#if PUBNUB_ENABLE_CUSTOM_DNS

#define PN_DNS_PORT 53

static int parse_octet(const char* str, int* pos, unsigned int* out)
{
    int          start = *pos;
    unsigned int val   = 0;
    int          count = 0;

    while (str[*pos] >= '0' && str[*pos] <= '9') {
        if (count >= 3) {
            return -1;
        }
        val = val * 10 + (unsigned int)(str[*pos] - '0');
        (*pos)++;
        count++;
    }

    if (0 == count) {
        return -1;
    }
    if (val > 255) {
        return -1;
    }
    if (count > 1 && '0' == str[start]) {
        return -1;
    }

    *out = val;
    return 0;
}

static int try_parse_ipv4(const char* str, pn_sockaddr_t* out)
{
    int          pos = 0;
    unsigned int octets[4];
    int          i;

    for (i = 0; i < 4; i++) {
        if (0 != parse_octet(str, &pos, &octets[i])) {
            return -1;
        }
        if (i < 3) {
            if ('.' != str[pos]) {
                return -1;
            }
            pos++;
        }
    }

    if ('\0' != str[pos]) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->family       = PN_AF_INET;
    out->port         = PN_DNS_PORT;
    out->addr.ipv4[0] = (uint8_t)octets[0];
    out->addr.ipv4[1] = (uint8_t)octets[1];
    out->addr.ipv4[2] = (uint8_t)octets[2];
    out->addr.ipv4[3] = (uint8_t)octets[3];
    return 0;
}

static int parse_hex_group(const char* str, int* pos, uint16_t* out)
{
    unsigned int val   = 0;
    int          count = 0;

    while (count < 4) {
        char c = str[*pos];
        if (c >= '0' && c <= '9') {
            val = (val << 4) | (unsigned int)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            val = (val << 4) | (unsigned int)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            val = (val << 4) | (unsigned int)(c - 'A' + 10);
        } else {
            break;
        }
        (*pos)++;
        count++;
    }

    if (0 == count) {
        return -1;
    }

    *out = (uint16_t)val;
    return 0;
}

static int looks_like_ipv4(const char* str, int pos)
{
    int dot_count   = 0;
    int digit_count = 0;
    int i;

    for (i = pos; '\0' != str[i]; i++) {
        char c = str[i];
        if (c >= '0' && c <= '9') {
            digit_count++;
        } else if ('.' == c) {
            dot_count++;
        } else {
            return 0;
        }
    }

    return (3 == dot_count && digit_count >= 4);
}

static int parse_ipv4_tail(const char* str, int* pos, uint16_t* groups, int* idx)
{
    unsigned int octets[4];
    int          i;

    for (i = 0; i < 4; i++) {
        if (0 != parse_octet(str, pos, &octets[i])) {
            return -1;
        }
        if (i < 3) {
            if ('.' != str[*pos]) {
                return -1;
            }
            (*pos)++;
        }
    }

    groups[*idx] = (uint16_t)((octets[0] << 8) | octets[1]);
    (*idx)++;
    groups[*idx] = (uint16_t)((octets[2] << 8) | octets[3]);
    (*idx)++;
    return 0;
}

static int try_parse_ipv6(const char* str, pn_sockaddr_t* out)
{
    uint16_t groups[8];
    int      group_count  = 0;
    int      double_colon = -1;
    int      pos          = 0;
    int      i;

    memset(groups, 0, sizeof(groups));

    if (':' == str[0] && ':' == str[1]) {
        double_colon = 0;
        pos          = 2;
        if ('\0' == str[pos]) {
            goto expand;
        }
    }

    while ('\0' != str[pos] && group_count < 8) {
        uint16_t g = 0;
        if (looks_like_ipv4(str, pos)) {
            if (group_count > 6) {
                return -1;
            }
            if (0 != parse_ipv4_tail(str, &pos, groups, &group_count)) {
                return -1;
            }
            break;
        }

        if (0 != parse_hex_group(str, &pos, &g)) {
            return -1;
        }
        groups[group_count++] = g;

        if ('\0' == str[pos]) {
            break;
        }

        if (':' != str[pos]) {
            return -1;
        }
        pos++;

        if (':' == str[pos]) {
            if (double_colon >= 0) {
                return -1;
            }
            double_colon = group_count;
            pos++;
            if ('\0' == str[pos]) {
                break;
            }
        }
    }

    if ('\0' != str[pos]) {
        return -1;
    }

expand:
    if (double_colon >= 0) {
        int      zeros_needed;
        uint16_t expanded[8];
        int      after_count;

        zeros_needed = 8 - group_count;
        if (zeros_needed < 0) {
            return -1;
        }
        memset(expanded, 0, sizeof(expanded));
        for (i = 0; i < double_colon; i++) {
            expanded[i] = groups[i];
        }
        after_count = group_count - double_colon;
        for (i = 0; i < after_count; i++) {
            expanded[double_colon + zeros_needed + i] = groups[double_colon + i];
        }
        memcpy(groups, expanded, sizeof(groups));
        group_count = 8;
    }

    if (8 != group_count) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->family = PN_AF_INET6;
    out->port   = PN_DNS_PORT;
    for (i = 0; i < 8; i++) {
        out->addr.ipv6[i * 2]     = (uint8_t)(groups[i] >> 8);
        out->addr.ipv6[i * 2 + 1] = (uint8_t)(groups[i] & 0xFF);
    }
    return 0;
}

static int pn_dns_parse_address(const char* str, pn_sockaddr_t* out)
{
    if (NULL == str || NULL == out) {
        return -1;
    }
    if ('\0' == str[0]) {
        return -1;
    }
    if (0 == try_parse_ipv4(str, out)) {
        return 0;
    }
    return try_parse_ipv6(str, out);
}

#endif /* PUBNUB_ENABLE_CUSTOM_DNS */

/** @brief Set up self-pipe for cross-thread wake. */
static void socket_init_wake_pipe(pn_socket_transport_t* t)
{
    t->wake_pipe_rd = PN_INVALID_SOCKET;
    t->wake_pipe_wr = PN_INVALID_SOCKET;
    if (NULL == t->ops->pipe_create) {
        return;
    }

    pn_socket_t pipe_fds[2] = {PN_INVALID_SOCKET, PN_INVALID_SOCKET};
    if (0 != t->ops->pipe_create(t->ops, pipe_fds)) {
        return;
    }

    t->wake_pipe_rd = pipe_fds[0];
    t->wake_pipe_wr = pipe_fds[1];
    if (0 > t->ops->poll_add(t->ops, &t->poll_set, t->wake_pipe_rd, PN_POLL_READ)) {
        t->ops->socket_destroy(t->ops, t->wake_pipe_rd);
        if (t->wake_pipe_wr != t->wake_pipe_rd) {
            t->ops->socket_destroy(t->ops, t->wake_pipe_wr);
        }
        t->wake_pipe_rd = PN_INVALID_SOCKET;
        t->wake_pipe_wr = PN_INVALID_SOCKET;
    }
}

/** @brief Tear down the self-pipe (poll_remove + close fds). */
static void socket_cleanup_wake_pipe(pn_socket_transport_t* t)
{
    if (PN_INVALID_SOCKET == t->wake_pipe_rd) {
        return;
    }
    t->ops->poll_remove(t->ops, &t->poll_set, t->wake_pipe_rd);
    t->ops->socket_destroy(t->ops, t->wake_pipe_rd);
    if (t->wake_pipe_wr != t->wake_pipe_rd) {
        t->ops->socket_destroy(t->ops, t->wake_pipe_wr);
    }
    t->wake_pipe_rd = PN_INVALID_SOCKET;
    t->wake_pipe_wr = PN_INVALID_SOCKET;
}

/** @brief Register DNS UDP sockets in the poll set. */
static void socket_init_dns_poll(pn_socket_transport_t* t)
{
    pn_socket_t dns_sock = pn_dns_resolver_socket(&t->resolver);
    if (PN_INVALID_SOCKET != dns_sock) {
        t->ops->poll_add(t->ops, &t->poll_set, dns_sock, PN_POLL_READ);
    }
    if (PUBNUB_ENABLE_IPV6) {
        pn_socket_t dns_sock_v6 = pn_dns_resolver_socket_v6(&t->resolver);
        if (PN_INVALID_SOCKET != dns_sock_v6) {
            t->ops->poll_add(t->ops, &t->poll_set, dns_sock_v6, PN_POLL_READ);
        }
    }
}

/** @brief Remove DNS UDP sockets from the poll set. */
static void socket_cleanup_dns_poll(pn_socket_transport_t* t)
{
    if (PUBNUB_ENABLE_IPV6) {
        pn_socket_t dns_sock_v6 = pn_dns_resolver_socket_v6(&t->resolver);
        if (PN_INVALID_SOCKET != dns_sock_v6) {
            t->ops->poll_remove(t->ops, &t->poll_set, dns_sock_v6);
        }
    }
    pn_socket_t dns_sock = pn_dns_resolver_socket(&t->resolver);
    if (PN_INVALID_SOCKET != dns_sock) {
        t->ops->poll_remove(t->ops, &t->poll_set, dns_sock);
    }
}

/** @brief Initialize proxy module from deps. */
static void socket_init_proxy(pn_socket_transport_t*        t,
                              const pubnub_provider_deps_t* deps)
{
    t->proxy_module = NULL;
    memset(&t->proxy_config_stored, 0, sizeof(t->proxy_config_stored));

    if (!PUBNUB_ENABLE_PROXY || NULL == deps->proxy
        || PUBNUB_PROXY_NONE == deps->proxy->type) {
        return;
    }

    if (PUBNUB_PROXY_AUTO == deps->proxy->type) {
        char   target_url[128] = "https://";
        size_t prefix_len      = strlen(target_url);
        size_t origin_len      = strlen(PUBNUB_CFG_ORIGIN);
        if (prefix_len + origin_len < sizeof(target_url)) {
            memcpy(target_url + prefix_len, PUBNUB_CFG_ORIGIN, origin_len + 1);
        }

        pn_proxy_config_t resolved = {0};
        int wpad_rc = pn_proxy_wpad_resolve(target_url, &resolved);

        if (0 == wpad_rc && NULL != resolved.host) {
            t->proxy_config_stored.host = pn_strdup(resolved.host, t->allocator);
            t->proxy_config_stored.port      = resolved.port;
            t->proxy_config_stored.auth_type = resolved.auth_type;
            t->proxy_config_stored.username  = NULL;
            t->proxy_config_stored.password  = NULL;
        }
        pn_proxy_wpad_free(&resolved);
    } else {
        t->proxy_config_stored.host = pn_strdup(deps->proxy->host, t->allocator);
        t->proxy_config_stored.username =
            pn_strdup(deps->proxy->username, t->allocator);
        t->proxy_config_stored.password =
            pn_strdup(deps->proxy->password, t->allocator);
        t->proxy_config_stored.port      = deps->proxy->port;
        t->proxy_config_stored.auth_type = (pn_proxy_auth_t)deps->proxy->auth;
    }

    if (NULL != t->proxy_config_stored.host) {
        t->proxy_module =
            pn_proxy_connect_create(&t->proxy_config_stored, t->allocator);
    }
}

static int socket_init(pubnub_transport_provider_t*  self,
                       const pubnub_provider_deps_t* deps)
{
    if (NULL == self || NULL == deps) {
        return -1;
    }
    if (NULL == deps->allocator || NULL == deps->platform) {
        return -1;
    }

    pn_socket_transport_t* t = (pn_socket_transport_t*)self;

#ifdef _WIN32
    {
        WSADATA wsa_data;
        if (0 != WSAStartup(MAKEWORD(2, 2), &wsa_data)) {
            return -1;
        }
    }
#endif

    t->allocator = deps->allocator;
    t->platform  = deps->platform;
    t->logger    = deps->logger;

    /* Overwrite keepalive from deps — NULL means user disabled it. */
    if (NULL != deps->tcp_keepalive) {
        t->keepalive_config = *deps->tcp_keepalive;
    } else {
        memset(&t->keepalive_config, 0, sizeof(t->keepalive_config));
    }

    /* Initialize DNS resolver. */
    int rc = pn_dns_resolver_init(&t->resolver, t->ops, t->platform);
    if (0 != rc) {
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    /* Parse user DNS servers from deps (init-time configuration). */
#if PUBNUB_ENABLE_CUSTOM_DNS
    t->user_server_count = 0;
    if (NULL != deps->dns_primary) {
        if (0 == pn_dns_parse_address(deps->dns_primary, &t->user_servers[0])) {
            t->user_server_count = 1;
        }
    }
    if (NULL != deps->dns_secondary) {
        if (0
            == pn_dns_parse_address(deps->dns_secondary,
                                    &t->user_servers[t->user_server_count])) {
            t->user_server_count++;
        }
    }

    /* Wire resolver to point at transport's parsed servers. */
    t->resolver.user_servers = t->user_servers;
    PUBNUB_ATOMIC_STORE_U8(&t->resolver.user_server_count, t->user_server_count);
    if (t->user_server_count > 0) {
        t->resolver.server_list_invalid = 1;
    }
#endif

    /* Initialize poll set. */
    rc = t->ops->poll_init(t->ops, &t->poll_set);
    if (0 != rc) {
        pn_dns_resolver_deinit(&t->resolver);
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    socket_init_dns_poll(t);
    socket_init_wake_pipe(t);

    /* Create TLS context if backend is available. */
    if (NULL != t->tls_backend) {
        t->tls_ctx = t->tls_backend->ctx_create(&t->tls_config, deps);
        if (NULL == t->tls_ctx) {
            socket_cleanup_wake_pipe(t);
            socket_cleanup_dns_poll(t);
            t->ops->poll_deinit(t->ops, &t->poll_set);
            pn_dns_resolver_deinit(&t->resolver);
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }

        /* Deep-copy ca_pem so the transport owns it. The setter
         * (set_tls_ca_bundle) frees the old value before replacing;
         * without this copy it would free the caller's borrowed
         * pointer. NULL ca_pem means system certs — no copy needed. */
        if (NULL != t->tls_config.ca_pem) {
            const char* owned = pn_strdup(t->tls_config.ca_pem, t->allocator);
            if (NULL == owned) {
                t->tls_backend->ctx_destroy(t->tls_ctx);
                t->tls_ctx = NULL;
                socket_cleanup_wake_pipe(t);
                socket_cleanup_dns_poll(t);
                t->ops->poll_deinit(t->ops, &t->poll_set);
                pn_dns_resolver_deinit(&t->resolver);
#ifdef _WIN32
                WSACleanup();
#endif
                return -1;
            }
            t->tls_config.ca_pem = owned;
        }
    }

    socket_init_proxy(t, deps);

    /* Initialize all connection slots to IDLE. */
    {
        int i;
        for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
            pn_connection_init(&t->connections[i]);
        }
    }

    t->initialized = 1;
    return 0;
}

static void socket_deinit(pubnub_transport_provider_t* self)
{
    if (NULL == self) {
        return;
    }

    pn_socket_transport_t* t = (pn_socket_transport_t*)self;
    if (!t->initialized) {
        return;
    }

    /* Cancel and close all in-flight connections. */
    {
        int i;
        for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
            pn_socket_connection_t* conn = &t->connections[i];
            if (PN_CONN_IDLE != conn->state) {
                if (!conn_is_terminal(conn->state)) {
                    pn_connection_cancel(conn, t);
                }
                pn_connection_reset(conn, t);
            }
        }
    }

    /* Destroy TLS context and free any strdup'd CA PEM from the
     * runtime setter (set_tls_ca_bundle). The original ca_pem from
     * init is a borrowed pointer, but the setter replaces it with
     * an owned copy via pn_strdup. pn_strfree is NULL-safe. */
    if (NULL != t->tls_backend && NULL != t->tls_ctx) {
        t->tls_backend->ctx_destroy(t->tls_ctx);
        t->tls_ctx = NULL;
    }
    pn_strfree(t->tls_config.ca_pem, t->allocator);
    t->tls_config.ca_pem = NULL;
    pn_strfree(t->pending_ca_pem, t->allocator);
    t->pending_ca_pem      = NULL;
    t->pending_ca_pem_set  = 0;
    t->pending_skip_verify = 0xFF;

    socket_cleanup_wake_pipe(t);
    socket_cleanup_dns_poll(t);

    /* Deinitialize DNS resolver and poll set. */
    pn_dns_resolver_deinit(&t->resolver);
    t->ops->poll_deinit(t->ops, &t->poll_set);

    /* Destroy proxy module BEFORE freeing config strings (module references them). */
    if (NULL != t->proxy_module) {
        t->proxy_module->destroy(t->proxy_module, t->allocator);
        t->proxy_module = NULL;
    }

    /* Free deep-copied proxy config strings. Username and password are
     * credentials, so scrub them before release. */
    pn_strfree(t->proxy_config_stored.host, t->allocator);
    pn_strfree_secure(t->proxy_config_stored.username, t->allocator);
    pn_strfree_secure(t->proxy_config_stored.password, t->allocator);
    memset(&t->proxy_config_stored, 0, sizeof(t->proxy_config_stored));

    t->initialized = 0;

#ifdef _WIN32
    WSACleanup();
#endif
}

static void socket_set_tls_ca_bundle(pubnub_transport_provider_t* self,
                                     const char*                  ca_pem)
{
    pn_socket_transport_t* t = (pn_socket_transport_t*)self;

    if (NULL == self || !t->initialized || NULL == t->tls_backend) {
        return;
    }

    /* Stage for poll-thread swap — avoids freeing ca_pem while
     * ctx_create may be reading it on the poll thread. */
    const char* new_pem = NULL;
    if (NULL != ca_pem) {
        new_pem = pn_strdup(ca_pem, t->allocator);
        if (NULL == new_pem) {
            return;
        }
    }

    /* Free any previous pending PEM that the poll thread hasn't
     * consumed yet (rapid successive calls). */
    pn_strfree(t->pending_ca_pem, t->allocator);
    t->pending_ca_pem     = new_pem;
    t->pending_ca_pem_set = 1;

    PUBNUB_ATOMIC_STORE_U8(&t->tls_ctx_stale, 1);
}

static void socket_set_tls_verify(pubnub_transport_provider_t* self,
                                  uint8_t                      skip_verify)
{
    pn_socket_transport_t* t = (pn_socket_transport_t*)self;

    if (NULL == self || !t->initialized || NULL == t->tls_backend) {
        return;
    }

    t->pending_skip_verify = (0 != skip_verify) ? 1 : 0;
    PUBNUB_ATOMIC_STORE_U8(&t->tls_ctx_stale, 1);
}

static pubnub_res_t socket_set_dns_servers(pubnub_transport_provider_t* self,
                                           const char*                  primary,
                                           const char* secondary)
{
#if PUBNUB_ENABLE_CUSTOM_DNS
    pn_socket_transport_t* t         = (pn_socket_transport_t*)self;
    pn_sockaddr_t          parsed[2] = {0};
    uint8_t                new_count = 0;

    /* Parse into temporaries first — a secondary parse failure must
     * not wipe a previously valid primary. */
    if (NULL != primary) {
        if (0 != pn_dns_parse_address(primary, &parsed[0])) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        new_count = 1;
    }
    if (NULL != secondary && new_count > 0) {
        if (0 != pn_dns_parse_address(secondary, &parsed[1])) {
            return PUBNUB_ERR_INVALID_ARGUMENT;
        }
        new_count = 2;
    }

    /* Release-store count=0: reader skips user_servers until publication. */
    PUBNUB_ATOMIC_STORE_U8(&t->resolver.user_server_count, 0);
    t->user_server_count = 0;

    if (new_count > 0) {
        t->user_servers[0] = parsed[0];
    }
    if (new_count > 1) {
        t->user_servers[1] = parsed[1];
    }
    t->resolver.server_list_invalid = (new_count > 0) ? 1 : 0;

    /* Release-store final count: all writes above (structs + invalid flag)
     * are visible to any core that observes this via acquire-load. */
    PUBNUB_ATOMIC_STORE_U8(&t->resolver.user_server_count, new_count);
    t->user_server_count = new_count;
    return PUBNUB_OK;
#else
    (void)self;
    (void)primary;
    (void)secondary;
    return PUBNUB_ERR_NOT_SUPPORTED;
#endif
}

/**
 * @brief Create a socket-based transport provider.
 *
 * The transport owns a fixed pool of connection slots (sized by
 * PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS). Each send() call acquires an
 * IDLE slot and drives it through the connection FSM. When a slot
 * reaches a terminal state (COMPLETE, FAILED, or CANCELLED), the
 * caller MUST invoke cancel() on the returned handle to return the
 * slot to IDLE. cancel() calls pn_connection_reset() unconditionally,
 * so every cancel() call — whether on an in-progress or terminal slot —
 * leaves the slot in PN_CONN_IDLE and ready for the next send().
 *
 * @param ops         Platform socket operations (poll, connect, etc.).
 * @param tls_backend TLS backend vtable (NULL disables TLS).
 * @param tls_config  TLS configuration (NULL uses defaults).
 * @param keepalive   TCP keep-alive configuration (NULL uses defaults).
 * @param allocator   Allocator for the transport struct itself.
 * @return Transport provider vtable pointer, or NULL on allocation
 *         failure.
 */
pubnub_transport_provider_t*
pn_socket_transport_create(const pn_socket_platform_ops_t*      ops,
                           pn_tls_backend_t*                    tls_backend,
                           const pn_tls_config_t*               tls_config,
                           const pubnub_tcp_keepalive_config_t* keepalive,
                           struct pubnub_allocator_provider*    allocator)
{
    if (NULL == ops || NULL == allocator) {
        return NULL;
    }

    pn_socket_transport_t* t = (pn_socket_transport_t*)PN_ALLOC(
        allocator, sizeof(pn_socket_transport_t), 8);
    if (NULL == t) {
        return NULL;
    }
    memset(t, 0, sizeof(*t));

    /* Populate vtable. */
    t->vtable.send              = socket_send;
    t->vtable.poll              = socket_poll;
    t->vtable.cancel            = socket_cancel;
    t->vtable.wake              = socket_wake;
    t->vtable.init              = socket_init;
    t->vtable.deinit            = socket_deinit;
    t->vtable.set_dns_servers   = socket_set_dns_servers;
    t->vtable.set_tls_ca_bundle = socket_set_tls_ca_bundle;
    t->vtable.set_tls_verify    = socket_set_tls_verify;

    /* Store construction-time references. */
    t->ops                 = ops;
    t->tls_backend         = tls_backend;
    t->allocator           = allocator;
    t->pending_skip_verify = 0xFF;

    if (NULL != tls_config) {
        t->tls_config = *tls_config;
    } else {
        pn_tls_config_t defaults = PN_TLS_CONFIG_INIT;
        t->tls_config            = defaults;
    }

    if (NULL != keepalive) {
        t->keepalive_config = *keepalive;
    } else {
        t->keepalive_config =
            (pubnub_tcp_keepalive_config_t)PUBNUB_TCP_KEEPALIVE_CONFIG_INIT;
    }

    return &t->vtable;
}

void pn_socket_transport_destroy(pubnub_transport_provider_t*      transport,
                                 struct pubnub_allocator_provider* allocator)
{
    if (NULL == transport || NULL == allocator) {
        return;
    }

    pn_socket_transport_t* t = (pn_socket_transport_t*)transport;

    if (t->initialized) {
        socket_deinit(transport);
    }

    PN_FREE(allocator, t);
}

/* Platform ops singleton — one per compiled platform. */
#if defined(PUBNUB_SOCKET_PLATFORM_OPS_CUSTOM)
extern const pn_socket_platform_ops_t pn_custom_socket_platform_ops;
#define PN_DEFAULT_PLATFORM_OPS pn_custom_socket_platform_ops
#elif defined(_WIN32)
extern const pn_socket_platform_ops_t pn_windows_socket_ops;
#define PN_DEFAULT_PLATFORM_OPS pn_windows_socket_ops
#elif defined(PUBNUB_PLATFORM_FREERTOS) || defined(ESP_PLATFORM) \
    || defined(LWIP_SOCKET)
extern const pn_socket_platform_ops_t pn_freertos_socket_ops;
#define PN_DEFAULT_PLATFORM_OPS pn_freertos_socket_ops
#elif defined(__ZEPHYR__)
extern const pn_socket_platform_ops_t pn_zephyr_socket_ops;
#define PN_DEFAULT_PLATFORM_OPS pn_zephyr_socket_ops
#else
extern const pn_socket_platform_ops_t pn_posix_socket_ops;
#define PN_DEFAULT_PLATFORM_OPS pn_posix_socket_ops
#endif

/* TLS backend singleton — one per compiled TLS backend. */
#if PUBNUB_ENABLE_SECURE_TRANSPORT
#if defined(PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS)
extern const pn_tls_backend_t pn_tls_mbedtls_backend;
#define PN_DEFAULT_TLS_BACKEND pn_tls_mbedtls_backend
#else
extern const pn_tls_backend_t pn_tls_openssl_backend;
#define PN_DEFAULT_TLS_BACKEND pn_tls_openssl_backend
#endif
#else
extern const pn_tls_backend_t pn_tls_none_backend;
#define PN_DEFAULT_TLS_BACKEND pn_tls_none_backend
#endif

/* NOLINTNEXTLINE(misc-use-internal-linkage) */
pubnub_transport_provider_t* pn_transport_default(pubnub_allocator_provider_t* alloc)
{
    if (NULL == alloc || NULL == alloc->alloc) {
        return NULL;
    }
    pn_socket_transport_t* t =
        (pn_socket_transport_t*)PN_ALLOC(alloc, sizeof(pn_socket_transport_t), 8);
    if (NULL == t) {
        return NULL;
    }
    memset(t, 0, sizeof(*t));

    t->vtable.send              = socket_send;
    t->vtable.poll              = socket_poll;
    t->vtable.cancel            = socket_cancel;
    t->vtable.wake              = socket_wake;
    t->vtable.init              = socket_init;
    t->vtable.deinit            = socket_deinit;
    t->vtable.set_dns_servers   = socket_set_dns_servers;
    t->vtable.set_tls_ca_bundle = socket_set_tls_ca_bundle;
    t->vtable.set_tls_verify    = socket_set_tls_verify;

    t->ops                 = &PN_DEFAULT_PLATFORM_OPS;
    t->tls_backend         = (pn_tls_backend_t*)&PN_DEFAULT_TLS_BACKEND;
    t->pending_skip_verify = 0xFF;

    pn_tls_config_t tls_defaults = PN_TLS_CONFIG_INIT;
    t->tls_config                = tls_defaults;
    t->keepalive_config =
        (pubnub_tcp_keepalive_config_t)PUBNUB_TCP_KEEPALIVE_CONFIG_INIT;

    return &t->vtable;
}
