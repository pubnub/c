/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file request.c
 * @brief Request descriptor state machine implementation.
 *
 * Pure state machine - no I/O, no timer registration. The caller
 * (context/process loop) is responsible for transport cancel and
 * timeout management.
 */

#include "request_internal.h"

#include "pn_format.h"
#include "pubnub/config.h"
#include "pubnub/providers/logger_types.h"

#include <string.h>

int pn_request_is_idle(const pn_request_t* req)
{
    return NULL != req && PN_REQUEST_IDLE == req->state;
}

int pn_request_is_ready(const pn_request_t* req)
{
    if (NULL == req) {
        return 0;
    }
    /* Acquire-load the publication gate FIRST: it pairs with the release-store
     * in the terminal-transition functions and establishes the happens-before
     * edge that makes state/result/parsed_body_tree safe to read lock-free.
     * The load does not mutate; cast away const for the atomic macro. */
    return PUBNUB_ATOMIC_LOAD_U8(&((pn_request_t*)req)->ready) != 0;
}

int pn_request_is_terminal(const pn_request_t* req)
{
    if (NULL == req) {
        return 0;
    }
    return req->state >= PN_REQUEST_COMPLETE;
}

void pn_request_init(pn_request_t* req, uint16_t slot_id)
{
    if (NULL == req) {
        return;
    }
    memset(req, 0, sizeof(*req));
    req->state      = PN_REQUEST_IDLE;
    req->slot_id    = slot_id;
    req->feature_id = (uint8_t)PUBNUB_FEATURE_COUNT;
}

void pn_request_reset(pn_request_t* req)
{
    if (NULL == req) {
        return;
    }
    uint16_t id  = req->slot_id;
    uint16_t gen = (uint16_t)(req->generation + 1);
    if (PN_GENERATION_ANY == gen) {
        gen++;
    }
    memset(req, 0, sizeof(*req));
    req->state      = PN_REQUEST_IDLE;
    req->slot_id    = id;
    req->generation = gen;
    req->feature_id = (uint8_t)PUBNUB_FEATURE_COUNT;
}

pubnub_res_t pn_request_enqueue(pn_request_t* req)
{
    if (NULL == req || PN_REQUEST_IDLE != req->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    req->state = PN_REQUEST_PENDING;
    return PUBNUB_OK;
}

/* These helpers exist only to format diagnostic log payloads. When no
 * DEBUG/WARNING/ERROR level is compiled in (embedded profiles strip all
 * logging), every call site is preprocessed out, so gate the definitions
 * with the union of their callers' guards to avoid unused-function
 * errors under -Werror. */
#if PUBNUB_LOG_ENABLED(DEBUG) || PUBNUB_LOG_ENABLED(WARNING) \
    || PUBNUB_LOG_ENABLED(ERROR)
static const char* pn_http_method_str_(pubnub_http_method_t method)
{
    switch (method) {
    case PUBNUB_HTTP_GET: return "GET";
    case PUBNUB_HTTP_POST: return "POST";
    case PUBNUB_HTTP_PATCH: return "PATCH";
    case PUBNUB_HTTP_DELETE: return "DELETE";
    default: return "??";
    }
}

/** @brief Build host + path + query URL into caller-provided buffer. */
static void pn_build_request_url_(const pn_request_t* req, char* buf, size_t buf_size)
{
    size_t       pos         = 0;
    const int    truncate_at = (int)buf_size - 4;
    unsigned int i;

    /* Protocol + host. */
    if (NULL != req->http_request.host) {
        const char* scheme = req->http_request.secure ? "https://" : "http://";
        int         written =
            pn_snprintf(buf, buf_size, "%s%s", scheme, req->http_request.host);
        if (written > 0) {
            pos = (size_t)written;
        }
    }

    /* Path segments. */
    for (i = 0; i < req->http_request.path_segment_count && (int)pos < truncate_at;
         ++i) {
        int written = pn_snprintf(buf + pos,
                                  buf_size - pos,
                                  "/%.*s",
                                  (int)req->http_request.path_segments[i].len,
                                  req->http_request.path_segments[i].ptr);
        if (written > 0) {
            pos += (size_t)written;
        }
    }

    /* Query parameters. */
    for (i = 0; i < req->http_request.query_param_count && (int)pos < truncate_at;
         ++i) {
        const char* sep     = (0 == i) ? "?" : "&";
        int         written = pn_snprintf(buf + pos,
                                  buf_size - pos,
                                  "%s%.*s=%.*s",
                                  sep,
                                  (int)req->http_request.query_params[i].key.len,
                                  req->http_request.query_params[i].key.ptr,
                                  (int)req->http_request.query_params[i].value.len,
                                  req->http_request.query_params[i].value.ptr);
        if (written > 0) {
            pos += (size_t)written;
        }
    }

    /* Truncation indicator when buffer was nearly exhausted. */
    if (pos >= buf_size - 4) {
        buf[buf_size - 4] = '.';
        buf[buf_size - 3] = '.';
        buf[buf_size - 2] = '.';
        buf[buf_size - 1] = '\0';
    }
}
#endif /* PUBNUB_LOG_ENABLED(DEBUG|WARNING|ERROR) */

void pn_request_log_net_terminal(const pn_request_t*       req,
                                 pubnub_logger_provider_t* logger,
                                 int                       canceled,
                                 int                       failed,
                                 pubnub_res_t              result,
                                 pubnub_log_level_t        level,
                                 const char*               caller_file,
                                 int                       caller_line)
{
#if PUBNUB_LOG_ENABLED(DEBUG) || PUBNUB_LOG_ENABLED(WARNING) \
    || PUBNUB_LOG_ENABLED(ERROR)
    char                           url_buf[512] = {0};
    pubnub_log_entry_net_request_t log_req      = {0};
    pubnub_log_value_t             hdr_vals[PUBNUB_CFG_HTTP_MAX_HEADERS];
    pubnub_log_value_t             hdr_entries[PUBNUB_CFG_HTTP_MAX_HEADERS];
    pubnub_log_value_t*            hdr_map = NULL;
    unsigned int                   hc      = 0;

    if (NULL == req || NULL == logger || NULL == logger->log) {
        return;
    }

    pn_build_request_url_(req, url_buf, sizeof(url_buf));

    log_req.base.type  = PUBNUB_LOG_ENTRY_NET_REQ;
    log_req.base.level = level;
    log_req.base.file  = caller_file;
    log_req.base.line  = caller_line;
    log_req.canceled   = canceled;
    log_req.failed     = failed;
    log_req.result     = result;
    log_req.slot_id    = req->slot_id;
    log_req.method     = pn_http_method_str_(req->http_request.method);
    log_req.url        = url_buf;

    hc = req->http_request.header_count;
    if (hc > 0) {
        unsigned int h;
        for (h = hc; h > 0; --h) {
            unsigned int idx = h - 1;
            hdr_vals[idx]    = pubnub_log_value_string_n(
                req->http_request.headers[idx].value.ptr,
                req->http_request.headers[idx].value.len);
            hdr_entries[idx] = (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY(
                req->http_request.headers[idx].key.ptr, &hdr_vals[idx], hdr_map);
            hdr_map = &hdr_entries[idx];
        }
        log_req.headers = hdr_map;
    }

    logger->log(logger, (const pubnub_log_entry_t*)&log_req);
#else
    (void)req;
    (void)logger;
    (void)canceled;
    (void)failed;
    (void)result;
    (void)level;
    (void)caller_file;
    (void)caller_line;
#endif
}

pubnub_res_t pn_request_accept_handle(pn_request_t* req,
                                      pubnub_transport_handle_t* transport_handle)
{
    if (NULL == req || PN_REQUEST_PENDING != req->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    if (NULL == transport_handle) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    req->transport_handle = transport_handle;
    req->state            = PN_REQUEST_IN_FLIGHT;

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (NULL != req->logger && NULL != req->logger->log) {
        char url_buf[512] = {0};
        pn_build_request_url_(req, url_buf, sizeof(url_buf));

        pubnub_log_entry_net_request_t log_req = {0};
        log_req.base.type                      = PUBNUB_LOG_ENTRY_NET_REQ;
        log_req.base.level                     = PUBNUB_LOG_LEVEL_DEBUG;
        log_req.base.file                      = __FILE__;
        log_req.base.line                      = __LINE__;
        log_req.failed                         = 0;
        log_req.slot_id                        = req->slot_id;
        log_req.method = pn_http_method_str_(req->http_request.method);
        log_req.url    = url_buf;

        /* Request header keys are NUL-terminated literals set by middleware. */
        pubnub_log_value_t  hdr_vals[PUBNUB_CFG_HTTP_MAX_HEADERS];
        pubnub_log_value_t  hdr_entries[PUBNUB_CFG_HTTP_MAX_HEADERS];
        pubnub_log_value_t* hdr_map = NULL;
        unsigned int        hc      = req->http_request.header_count;
        if (hc > 0) {
            for (unsigned int h = hc; h > 0; --h) {
                unsigned int idx = h - 1;
                hdr_vals[idx]    = pubnub_log_value_string_n(
                    req->http_request.headers[idx].value.ptr,
                    req->http_request.headers[idx].value.len);
                hdr_entries[idx] = (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY(
                    req->http_request.headers[idx].key.ptr, &hdr_vals[idx], hdr_map);
                hdr_map = &hdr_entries[idx];
            }
            log_req.headers = hdr_map;
        }

        req->logger->log(req->logger, (const pubnub_log_entry_t*)&log_req);
    }
#endif /* PUBNUB_LOG_ENABLED(DEBUG) */

    return PUBNUB_OK;
}

pubnub_res_t pn_request_on_success(pn_request_t* req, pubnub_res_t status)
{
    if (NULL == req || PN_REQUEST_IN_FLIGHT != req->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

#if PUBNUB_LOG_ENABLED(DEBUG)
    if (NULL != req->logger && NULL != req->logger->log) {
        char url_buf[512] = {0};
        pn_build_request_url_(req, url_buf, sizeof(url_buf));

        pubnub_log_entry_net_response_t log_resp = {0};
        log_resp.base.type                       = PUBNUB_LOG_ENTRY_NET_RESP;
        log_resp.base.level                      = PUBNUB_LOG_LEVEL_DEBUG;
        log_resp.base.file                       = __FILE__;
        log_resp.base.line                       = __LINE__;
        log_resp.url                             = url_buf;
        log_resp.status_code = (int)req->http_response.status_code;
        log_resp.body        = req->http_response.body;
        log_resp.body_len    = req->http_response.body_len;

        /* Response header keys are NUL-terminated (set by parser). */
        pubnub_log_value_t  hdr_vals[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
        pubnub_log_value_t  hdr_entries[PUBNUB_CFG_HTTP_MAX_RESP_HEADERS];
        pubnub_log_value_t* hdr_map = NULL;
        unsigned int        hc      = req->http_response.header_count;
        if (hc > 0) {
            for (unsigned int h = hc; h > 0; --h) {
                unsigned int idx = h - 1;
                hdr_vals[idx]    = pubnub_log_value_string_n(
                    req->http_response.headers[idx].value.ptr,
                    req->http_response.headers[idx].value.len);
                hdr_entries[idx] = (pubnub_log_value_t)PUBNUB_LOG_MAP_ENTRY(
                    req->http_response.headers[idx].key.ptr, &hdr_vals[idx], hdr_map);
                hdr_map = &hdr_entries[idx];
            }
            log_resp.headers = hdr_map;
        }

        req->logger->log(req->logger, (const pubnub_log_entry_t*)&log_resp);
    }
#endif /* PUBNUB_LOG_ENABLED(DEBUG) */

    req->result = status;

    /* Keep transport_handle live on success: response->body aliases the
     * transport's rx buffer, which the handle owns. Clearing it here would
     * strand the handle (no later cancel reaches it) and dangle the body
     * before the caller reads it. pubnub_future_release cancels the handle
     * (freeing rx_buf) once the caller is done. The failure path clears it
     * because that handle carries no readable body. */

    /* Defer callback delivery: enter COMPLETING if a callback is
     * registered so the caller can release the lock first. */
    req->state = (NULL != req->on_complete) ? PN_REQUEST_COMPLETING
                                            : PN_REQUEST_COMPLETE;

    /* Release-store the publication gate LAST: it makes result, state, and
     * (via the earlier preparse pass on this same poll tick) parsed_body_tree
     * visible to the lock-free reader in pn_request_is_ready. */
    PUBNUB_ATOMIC_STORE_U8(&req->ready, 1);
    return PUBNUB_OK;
}

pubnub_res_t pn_request_on_failure_impl(pn_request_t* req,
                                        pubnub_res_t  status,
                                        const char*   caller_file,
                                        int           caller_line)
{
    if (NULL == req || PN_REQUEST_IN_FLIGHT != req->state) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

#if PUBNUB_LOG_ENABLED(ERROR)
    pn_request_log_net_terminal(
        req, req->logger, 0, 1, status, PUBNUB_LOG_LEVEL_ERROR, caller_file, caller_line);
#else
    (void)caller_file;
    (void)caller_line;
#endif

    req->result           = status;
    req->transport_handle = NULL;

    req->state =
        (NULL != req->on_complete) ? PN_REQUEST_COMPLETING : PN_REQUEST_FAILED;

    /* Release-store the publication gate LAST: it makes result, state, and
     * transport_handle=NULL visible to the lock-free reader in
     * pn_request_is_ready. */
    PUBNUB_ATOMIC_STORE_U8(&req->ready, 1);
    return PUBNUB_OK;
}

void pn_request_deliver_notification(pn_request_t* req)
{
    if (NULL == req || PN_REQUEST_COMPLETING != req->state) {
        return;
    }

    /* Fire the callback outside the lock. */
    if (NULL != req->on_complete) {
        req->on_complete(req, req->result, req->user_data);
    }

    /* Transition to the final terminal state — but only if the
     * callback did not re-purpose the slot (multi-step state machines
     * like send_file reset state to PENDING and re-dispatch within
     * the callback). */
    if (PN_REQUEST_COMPLETING == req->state) {
        req->state = (PUBNUB_OK == req->result) ? PN_REQUEST_COMPLETE
                                                : PN_REQUEST_FAILED;
    }
}

pubnub_json_value_t* pn_request_get_parsed_body(pn_request_t* req,
                                                pubnub_serialization_provider_t* serial)
{
    if (NULL == req) {
        return NULL;
    }
    /* Fast path: already parsed (or already attempted and produced
     * NULL). No work needed. */
    if (req->parsed_body_attempted) {
        return req->parsed_body_tree;
    }

    /* Mark "attempted" up front: every exit path below leaves the
     * cache in a stable state, and the flag distinguishes "never
     * tried" from "tried and got NULL" for future readers. */
    req->parsed_body_attempted = 1;

    if (NULL == serial || NULL == serial->parse) {
        return NULL;
    }
    if (PUBNUB_HTTP_COMPLETE != req->http_response.completion) {
        return NULL;
    }
    if (NULL == req->http_response.body || 0 == req->http_response.body_len) {
        return NULL;
    }

    pubnub_json_value_t* tree =
        serial->parse(serial, req->http_response.body, req->http_response.body_len);
    if (NULL == tree) {
        return NULL;
    }

    req->parsed_body_tree  = tree;
    req->parsed_body_owner = serial;
    return tree;
}
