/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file keepalive.c
 * @brief HTTP/1.1 connection keep-alive and reuse logic implementation.
 */

#include "keepalive.h"

#include "http_parser.h"

#include <string.h>

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

    if (target->secure != conn->secure) {
        return 0;
    }

    if (target->port != conn->port) {
        return 0;
    }

    if (0 != strcmp(conn->host, target->host)) {
        return 0;
    }

    if (conn->requests_served >= max_requests) {
        return 0;
    }

    if (now_ms - conn->idle_since_ms > max_idle_ms) {
        return 0;
    }

    return 1;
}

int pn_keepalive_should_close(uint8_t parser_flags)
{
    if (0 != (parser_flags & PN_HTTP_FLAG_CONNECTION_CLOSE)) {
        return 1;
    }

    return 0;
}

typedef int pn_nonempty_keepalive_t;
