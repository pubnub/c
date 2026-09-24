/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_TLS_CERT_LOADER_H
#define PN_TLS_CERT_LOADER_H

/**
 * @brief Platform certificate loader interface.
 *
 * Provides the cert loader function type and the platform default
 * selector. Each platform file (certs_linux.c, certs_macos.c, etc.)
 * implements pn_tls_get_default_cert_loader() returning the
 * appropriate function. CMake selects exactly one platform file per
 * build.
 */

/**
 * @brief Platform certificate loader callback type.
 *
 * Loads root CA certificates into the TLS backend's trust store.
 * Called by both the mbedTLS and OpenSSL backends when
 * use_system_certs=1.
 *
 * @param ca_chain  Backend-specific trust store handle cast to void*.
 *                  - mbedTLS: mbedtls_x509_crt*
 *                  - OpenSSL: SSL_CTX*
 * @param ssl_conf  Backend-specific config handle cast to void*.
 *                  - mbedTLS: mbedtls_ssl_config*
 *                  - OpenSSL: unused (pass NULL)
 * @param user_data Opaque pointer from
 *                  pn_tls_config_t.system_cert_user_data.
 * @return 0 if at least one certificate was loaded, non-zero on
 *         failure.
 */
typedef int (*pn_tls_system_cert_fn_t)(void* ca_chain, void* ssl_conf, void* user_data);

/**
 * @brief Return the platform default certificate loader for this
 *        build.
 *
 * Implemented in one of the certs_*.c files selected by CMake.
 * Returns NULL on platforms with no built-in trust store.
 *
 * @return Platform cert loader function, or NULL if unavailable.
 */
pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void);

#endif /* PN_TLS_CERT_LOADER_H */
