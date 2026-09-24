/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_cert_loader.h"

#if defined(_WIN32)

#if defined(PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS)
#include <mbedtls/x509_crt.h>
#elif defined(PUBNUB_SOCKET_TLS_BACKEND_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#endif

#include <windows.h>
#include <wincrypt.h>

static int pn_tls_certs_windows(void* ca_chain, void* ssl_conf, void* user_data)
{
    HCERTSTORE     store  = CertOpenSystemStoreA(0, "ROOT");
    int            loaded = 0;
    PCCERT_CONTEXT cert   = NULL;

    (void)ssl_conf;
    (void)user_data;

    if (NULL == store) {
        return -1;
    }
    while (NULL != (cert = CertEnumCertificatesInStore(store, cert))) {
#if defined(PUBNUB_SOCKET_TLS_BACKEND_MBEDTLS)
        if (0
            == mbedtls_x509_crt_parse_der((mbedtls_x509_crt*)ca_chain,
                                          cert->pbCertEncoded,
                                          (size_t)cert->cbCertEncoded)) {
            ++loaded;
        }
#elif defined(PUBNUB_SOCKET_TLS_BACKEND_OPENSSL)
        {
            X509_STORE* store_x509 = SSL_CTX_get_cert_store((SSL_CTX*)ca_chain);
            const uint8_t* der_ptr = cert->pbCertEncoded;
            X509* x509 = d2i_X509(NULL, &der_ptr, (long)cert->cbCertEncoded);
            if (NULL != x509) {
                X509_STORE_add_cert(store_x509, x509);
                X509_free(x509);
                ++loaded;
            }
        }
#endif
    }
    CertCloseStore(store, 0);
    return (loaded > 0) ? 0 : -1;
}

pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void)
{
    return pn_tls_certs_windows;
}

#endif /* _WIN32 */
