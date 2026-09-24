/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_cert_loader.h"

#if defined(__linux__) || defined(__FreeBSD__)

#if defined(PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS)
#include <mbedtls/x509_crt.h>
#ifndef MBEDTLS_FS_IO
#error "certs_linux.c requires MBEDTLS_FS_IO — use certs_none.c for builds without filesystem support"
#endif
#elif defined(PUBNUB_SOCKET_TLS_BACKEND_OPENSSL)
#include <openssl/ssl.h>
#endif

static const char* const s_ca_paths[] = {
    "/etc/ssl/certs/ca-certificates.crt", /* Debian/Ubuntu */
    "/etc/pki/tls/certs/ca-bundle.crt",   /* RHEL/Fedora */
    "/etc/ssl/cert.pem",                  /* Alpine */
    NULL};

static int pn_tls_certs_linux(void* ca_chain, void* ssl_conf, void* user_data)
{
    const char* const* p;

    (void)ssl_conf;
    (void)user_data;
    for (p = s_ca_paths; NULL != *p; ++p) {
#if defined(PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS)
        if (0 == mbedtls_x509_crt_parse_file((mbedtls_x509_crt*)ca_chain, *p)) {
            return 0;
        }
#elif defined(PUBNUB_SOCKET_TLS_BACKEND_OPENSSL)
        if (1 == SSL_CTX_load_verify_locations((SSL_CTX*)ca_chain, *p, NULL)) {
            return 0;
        }
#endif
    }
    return -1;
}

pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void)
{
    return pn_tls_certs_linux;
}

#endif /* __linux__ || __FreeBSD__ */
