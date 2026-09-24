/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_cert_loader.h"

#if defined(ESP_PLATFORM)

#include <mbedtls/ssl.h>

#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
#include "esp_crt_bundle.h"
#endif

static int pn_tls_certs_esp(void* ca_chain, void* ssl_conf, void* user_data)
{
    (void)ca_chain;
    (void)user_data;
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
    return (ESP_OK == esp_crt_bundle_attach(ssl_conf)) ? 0 : -1;
#else
    (void)ssl_conf;
    return -1;
#endif
}

pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void)
{
    return pn_tls_certs_esp;
}

#endif /* ESP_PLATFORM */
