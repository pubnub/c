/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_backend.h"

static void* pn_tls_none_ctx_create(const pn_tls_config_t*             cfg,
                                    const struct pubnub_provider_deps* deps)
{
    (void)cfg;
    (void)deps;
    return NULL;
}

static void pn_tls_none_ctx_destroy(void* ctx)
{
    (void)ctx;
}

static int pn_tls_none_session_create(void**      out_session,
                                      void*       ctx,
                                      pn_socket_t sock,
                                      const struct pn_socket_platform_ops* ops,
                                      const char* hostname)
{
    (void)out_session;
    (void)ctx;
    (void)sock;
    (void)ops;
    (void)hostname;
    return -1;
}

static int pn_tls_none_handshake(void* session)
{
    (void)session;
    return -1;
}

static int pn_tls_none_send(void* session, const void* buf, size_t len)
{
    (void)session;
    (void)buf;
    (void)len;
    return -1;
}

static int pn_tls_none_recv(void* session, void* buf, size_t len)
{
    (void)session;
    (void)buf;
    (void)len;
    return -1;
}

static void pn_tls_none_session_destroy(void* session)
{
    (void)session;
}

/**
 * @brief Null TLS backend — all operations fail.
 *
 * Used when `PUBNUB_ENABLE_SECURE_TRANSPORT == 0`. All operations return
 * errors or no-ops, ensuring the transport knows TLS is unavailable without
 * runtime checks.
 */
// NOLINTNEXTLINE(misc-use-internal-linkage)
const pn_tls_backend_t pn_tls_none_backend = {
    .ctx_create        = pn_tls_none_ctx_create,
    .ctx_destroy       = pn_tls_none_ctx_destroy,
    .session_create    = pn_tls_none_session_create,
    .handshake         = pn_tls_none_handshake,
    .send              = pn_tls_none_send,
    .recv              = pn_tls_none_recv,
    .session_destroy   = pn_tls_none_session_destroy,
    .get_session_error = NULL,
    .session_error_str = NULL,
};
