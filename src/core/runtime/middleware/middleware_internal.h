/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file middleware_internal.h
 * @brief Middleware base types and shared query-param helper.
 *
 * A middleware IS a pubnub_transport_provider_t (decorator pattern).
 * It wraps the next transport in the chain, enriches the request
 * (e.g. adds query parameters), then delegates to the inner
 * transport.
 *
 * Each middleware struct embeds pubnub_transport_provider_t as its
 * first member so it can be cast to/from the transport interface.
 * The `next` pointer holds the wrapped (inner) transport.
 *
 * Middleware does not own the inner transport - the context manages
 * lifetimes.  poll() and cancel() are always delegated to the inner
 * transport unchanged.
 */

#ifndef PN_MIDDLEWARE_INTERNAL_H
#define PN_MIDDLEWARE_INTERNAL_H

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/crypto.h"
#include "pubnub/providers/logger.h"
#include "pubnub/providers/platform.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/transport_types.h"

#ifndef PN_ENCODE_NONE
/** @brief Do not percent-encode the value; copy verbatim. */
#define PN_ENCODE_NONE 0
/** @brief Percent-encode the entire value (RFC 3986). */
#define PN_ENCODE_FULL 1
/** @brief Percent-encode but preserve literal commas as delimiters. */
#define PN_ENCODE_KEEP_COMMAS 2
#endif

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief PubNub SDK identification middleware.
 *
 * Appends `pnsdk=PubNub-C/<version>[ suffix]` query parameter to
 * every request. Always present in the chain.
 */
typedef struct pn_middleware_pnsdk {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t base;

    /** Next transport in the chain (borrowed). */
    pubnub_transport_provider_t* next;

    /**
     * Optional suffix appended space-separated to the base identifier.
     * NULL or empty string means no suffix.
     */
    const char* suffix;

    /**
     * Optional override for the base SDK identifier. When non-NULL
     * and non-empty, completely replaces PUBNUB_SDK_IDENTIFIER.
     */
    const char* pnsdk_override;
} pn_middleware_pnsdk_t;

/**
 * @brief Initialize the pnsdk middleware.
 *
 * Populates the vtable and state. Does not allocate.
 *
 * @param mw             Middleware struct to initialize (caller-owned).
 * @param pnsdk_override Optional base identifier override (borrowed,
 *                       may be NULL).
 * @param suffix         Optional suffix (borrowed, may be NULL).
 * @param next           Inner transport to wrap (borrowed).
 */
void pn_middleware_pnsdk_init(pn_middleware_pnsdk_t*       mw,
                              const char*                  pnsdk_override,
                              const char*                  suffix,
                              pubnub_transport_provider_t* next);

/**
 * @brief Allocate and initialize a pnsdk middleware instance.
 *
 * Allocates a pn_middleware_pnsdk_t via @p allocator, initializes
 * it, and returns it cast to the generic transport interface. The
 * returned pointer is owned by the caller and must be released with
 * pn_middleware_pnsdk_destroy() once the chain is torn down.
 *
 * @param pnsdk_override Optional base identifier override (borrowed,
 *                       may be NULL).
 * @param suffix         Optional SDK suffix (borrowed, may be NULL).
 * @param next           Inner transport to wrap (borrowed).
 * @param allocator      Allocator provider (borrowed, must be non-NULL).
 * @return Transport-typed pointer on success, NULL on allocation
 *         failure or invalid arguments.
 */
pubnub_transport_provider_t*
pn_middleware_pnsdk_create(const char*                  pnsdk_override,
                           const char*                  suffix,
                           pubnub_transport_provider_t* next,
                           pubnub_allocator_provider_t* allocator);

/**
 * @brief Release a pnsdk middleware instance previously returned by
 *        pn_middleware_pnsdk_create().
 *
 * Safe to call with NULL @p mw (no-op).  @p allocator must be the
 * same allocator that produced @p mw.
 *
 * @param mw        Middleware to release (may be NULL).
 * @param allocator Allocator provider (borrowed).
 */
void pn_middleware_pnsdk_destroy(pubnub_transport_provider_t* mw,
                                 pubnub_allocator_provider_t* allocator);

/**
 * @brief User ID middleware.
 *
 * Appends `uuid=<user_id>` to every request. NULL/empty user_id is
 * a hard error (PubNub requires it on every request).
 */
typedef struct pn_middleware_user_id {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t base;

    /** Next transport in the chain (borrowed). */
    pubnub_transport_provider_t* next;

    /** Pointer-to-pointer to user_id (dereferenced at send time). */
    const char* const* user_id;
} pn_middleware_user_id_t;

/**
 * @brief Initialize the user_id middleware.
 *
 * @param mw      Middleware struct to initialize (caller-owned).
 * @param user_id Pointer to the user_id pointer (borrowed, must not
 *                be NULL at init time).
 * @param next    Inner transport to wrap (borrowed).
 */
void pn_middleware_userid_init(pn_middleware_user_id_t*     mw,
                               const char* const*           user_id,
                               pubnub_transport_provider_t* next);

/**
 * @brief Allocate and initialize a user_id middleware instance.
 *
 * Must be released with pn_middleware_userid_destroy() once the
 * chain is torn down.
 *
 * @param user_id   Pointer to the user_id pointer (borrowed, must
 *                  not be NULL).
 * @param next      Inner transport to wrap (borrowed).
 * @param allocator Allocator provider (borrowed, must be non-NULL).
 * @return Transport-typed pointer on success, NULL on allocation
 *         failure or invalid arguments.
 */
pubnub_transport_provider_t*
pn_middleware_userid_create(const char* const*           user_id,
                            pubnub_transport_provider_t* next,
                            pubnub_allocator_provider_t* allocator);

/**
 * @brief Release a user_id middleware instance previously returned
 *        by pn_middleware_userid_create().
 *
 * Safe to call with NULL @p mw (no-op).  @p allocator must be the
 * same allocator that produced @p mw.
 *
 * @param mw        Middleware to release (may be NULL).
 * @param allocator Allocator provider (borrowed).
 */
void pn_middleware_userid_destroy(pubnub_transport_provider_t* mw,
                                  pubnub_allocator_provider_t* allocator);

/**
 * @brief Auth token middleware.
 *
 * Appends `auth=<token>` when set; passthrough when NULL. Uses heap
 * allocation for percent-encoding because PAM tokens can exceed the
 * scratch buffer capacity (tokens grow with granted resources and may
 * reach 10KB+).
 *
 * The encoded buffer is cached and shared by all in-flight requests.
 * Re-encoding happens only when the raw token pointer changes (i.e.,
 * pubnub_set_auth_token was called). This is safe because config
 * mutations are caller-serialized and cannot race with in-flight
 * requests on the same context.
 */
typedef struct pn_middleware_auth {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t base;

    /** Next transport in the chain (borrowed). */
    pubnub_transport_provider_t* next;

    /** Pointer-to-pointer to auth token (dereferenced at send time). */
    const char* const* auth_token;

    /** Allocator for heap-encoding large tokens (borrowed). */
    pubnub_allocator_provider_t* allocator;

    /** Logger for auth diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;

    /** Owned NUL-terminated copy of the token bytes at time of last
     *  encoding. Compared by content (strcmp) to detect changes; a
     *  bare pointer compare would miss an ABA reuse of the same
     *  address with different token content. */
    char* cached_raw_str;

    /** Heap-encoded result shared by all in-flight requests. */
    char* cached_encoded;
} pn_middleware_auth_t;

/**
 * @brief Initialize the auth middleware.
 *
 * @param mw         Middleware struct to initialize (caller-owned).
 * @param auth_token Pointer to the auth token pointer (borrowed).
 * @param next       Inner transport to wrap (borrowed).
 * @param allocator  Allocator for heap-encoding large tokens
 *                   (borrowed, must be non-NULL).
 */
void pn_middleware_auth_init(pn_middleware_auth_t*        mw,
                             const char* const*           auth_token,
                             pubnub_transport_provider_t* next,
                             pubnub_allocator_provider_t* allocator);

/**
 * @brief Release the heap-owned caches held by a caller-owned auth
 *        middleware.
 *
 * Frees @c cached_encoded and @c cached_raw_str using the middleware's
 * stored allocator and clears both pointers. Does NOT free @p mw itself,
 * so it pairs with pn_middleware_auth_init() for stack-allocated instances.
 * Safe to call with NULL @p mw (no-op).
 *
 * @param mw Middleware to deinitialize (may be NULL).
 */
void pn_middleware_auth_deinit(pn_middleware_auth_t* mw);

/**
 * @brief Allocate and initialize an auth middleware instance.
 *
 * Must be released with pn_middleware_auth_destroy() once the
 * chain is torn down.
 *
 * @param auth_token Pointer to the auth token pointer (borrowed).
 *                   May be NULL to disable auth.
 * @param next       Inner transport to wrap (borrowed).
 * @param allocator  Allocator provider (borrowed, must be non-NULL).
 * @param logger     Logger for auth diagnostics (borrowed, may be
 *                   NULL).
 * @return Transport-typed pointer on success, NULL on allocation
 *         failure or invalid arguments.
 */
pubnub_transport_provider_t*
pn_middleware_auth_create(const char* const*           auth_token,
                          pubnub_transport_provider_t* next,
                          pubnub_allocator_provider_t* allocator,
                          pubnub_logger_provider_t*    logger);

/**
 * @brief Release an auth middleware instance previously returned by
 *        pn_middleware_auth_create().
 *
 * Safe to call with NULL @p mw (no-op).  @p allocator must be the
 * same allocator that produced @p mw.
 *
 * @param mw        Middleware to release (may be NULL).
 * @param allocator Allocator provider (borrowed).
 */
void pn_middleware_auth_destroy(pubnub_transport_provider_t* mw,
                                pubnub_allocator_provider_t* allocator);

/**
 * @brief PAMv3 request-signing middleware.
 *
 * Appends `signature=v2.<base64url(hmac-sha256)>` when secret_key,
 * publish_key, and crypto are all set; passthrough otherwise.
 * Must be innermost in the chain (signs the complete query set).
 */
typedef struct pn_middleware_signature {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t base;

    /** Next transport in the chain (borrowed). */
    pubnub_transport_provider_t* next;

    /** Publisher key (borrowed; null-terminated, may be NULL). */
    const char* publish_key;

    /** Pointer-to-pointer to secret key (dereferenced at send time). */
    const char* const* secret_key;

    /** Crypto provider supplying HMAC-SHA256 (borrowed, may be NULL). */
    pubnub_crypto_provider_t* crypto;

    /** Allocator used for the transient signing buffer (borrowed). */
    pubnub_allocator_provider_t* allocator;

    /** Platform provider for PAMv3 wall-clock timestamp (borrowed, may be NULL). */
    pubnub_platform_provider_t* platform;

    /** Logger for signature diagnostics (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;
} pn_middleware_signature_t;

/**
 * @brief Initialize the signature middleware.
 *
 * @param mw          Middleware struct to initialize (caller-owned).
 * @param publish_key Publisher key (borrowed, may be NULL).
 * @param secret_key  Pointer-to-pointer to the secret key (borrowed,
 *                    may be NULL to disable signing).
 * @param crypto      Crypto provider (borrowed, may be NULL - when
 *                    NULL the middleware passes through even if a
 *                    secret_key is configured; an error is logged
 *                    by a future wiring layer).
 * @param allocator   Allocator used for the transient signing
 *                    buffer (borrowed, must be non-NULL).
 * @param platform    Platform provider whose @c wall_clock_ms yields
 *                    the PAMv3 timestamp (borrowed, may be NULL to
 *                    disable signing).
 * @param next        Inner transport to wrap (borrowed).
 */
void pn_middleware_signature_init(pn_middleware_signature_t*   mw,
                                  const char*                  publish_key,
                                  const char* const*           secret_key,
                                  pubnub_crypto_provider_t*    crypto,
                                  pubnub_allocator_provider_t* allocator,
                                  pubnub_platform_provider_t*  platform,
                                  pubnub_transport_provider_t* next);

/**
 * @brief Allocate and initialize a signature middleware instance.
 *
 * Must be released with pn_middleware_signature_destroy() once the
 * chain is torn down.
 *
 * @param publish_key Publisher key (borrowed).
 * @param secret_key  Pointer-to-pointer to the secret key (borrowed).
 * @param crypto      Crypto provider (borrowed).
 * @param next        Inner transport to wrap (borrowed).
 * @param allocator   Allocator provider (borrowed, must be non-NULL).
 * @param platform    Platform provider supplying @c wall_clock_ms for
 *                    the PAMv3 timestamp (borrowed, may be NULL to
 *                    disable signing).
 * @param logger      Logger for signature diagnostics (borrowed, may
 *                    be NULL).
 * @return Transport-typed pointer on success, NULL on allocation
 *         failure or invalid arguments.
 */
pubnub_transport_provider_t*
pn_middleware_signature_create(const char*                  publish_key,
                               const char* const*           secret_key,
                               pubnub_crypto_provider_t*    crypto,
                               pubnub_transport_provider_t* next,
                               pubnub_allocator_provider_t* allocator,
                               pubnub_platform_provider_t*  platform,
                               pubnub_logger_provider_t*    logger);

/**
 * @brief Release a signature middleware instance previously
 *        returned by pn_middleware_signature_create().
 *
 * Safe to call with NULL @p mw (no-op).  @p allocator must be the
 * same allocator that produced @p mw.
 *
 * @param mw        Middleware to release (may be NULL).
 * @param allocator Allocator provider (borrowed).
 */
void pn_middleware_signature_destroy(pubnub_transport_provider_t* mw,
                                     pubnub_allocator_provider_t* allocator);

/**
 * @brief Retry middleware (full transport decorator).
 *
 * Intercepts transport failures, schedules non-blocking backoff, and
 * re-dispatches through the inner chain. Unlike the simpler
 * request-enrichment middlewares, this one manages per-slot retry state
 * and implements all three transport vtable operations (send/poll/cancel).
 *
 * Created only when PUBNUB_ENABLE_RETRY == 1 and the user-configured
 * policy is not PUBNUB_RETRY_NONE.
 */
typedef struct pn_middleware_retry pn_middleware_retry_t;

/**
 * @brief Initialize a retry middleware struct.
 *
 * Populates the vtable, resolves configuration defaults, and zeroes
 * slot tracking state. Does not allocate.
 *
 * @param mw       Middleware struct to initialize (caller-owned).
 * @param config   Retry configuration (copied, must not be NULL).
 * @param platform Platform provider for timers and random (borrowed,
 *                 may be NULL - timers and jitter degrade gracefully).
 * @param next     Inner transport to wrap (borrowed, must not be NULL).
 */
void pn_middleware_retry_init(pn_middleware_retry_t*              mw,
                              const pubnub_retry_configuration_t* config,
                              pubnub_platform_provider_t*         platform,
                              pubnub_transport_provider_t*        next);

/**
 * @brief Allocate and initialize a retry middleware instance.
 *
 * Returns NULL without allocating when @p config->policy is
 * PUBNUB_RETRY_NONE (caller should skip the layer entirely).
 *
 * @param config    Retry configuration (copied).
 * @param platform  Platform provider (borrowed, may be NULL).
 * @param next      Inner transport to wrap (borrowed).
 * @param allocator Allocator provider (borrowed, must be non-NULL).
 * @param logger    Logger for retry diagnostics (borrowed, may be
 *                  NULL).
 * @return Transport-typed pointer on success, NULL on allocation
 *         failure, invalid arguments, or NONE policy.
 */
pubnub_transport_provider_t*
pn_middleware_retry_create(const pubnub_retry_configuration_t* config,
                           pubnub_platform_provider_t*         platform,
                           pubnub_transport_provider_t*        next,
                           pubnub_allocator_provider_t*        allocator,
                           pubnub_logger_provider_t*           logger);

/**
 * @brief Release a retry middleware instance previously returned by
 *        pn_middleware_retry_create().
 *
 * Safe to call with NULL @p mw (no-op). @p allocator must be the
 * same allocator that produced @p mw.
 *
 * @param mw        Middleware to release (may be NULL).
 * @param allocator Allocator provider (borrowed).
 */
void pn_middleware_retry_destroy(pubnub_transport_provider_t* mw,
                                 pubnub_allocator_provider_t* allocator);

/**
 * @brief Copy the host string (with NUL terminator) into the request
 *        scratch buffer and point @c request->host at the copy.
 *
 * Makes the request self-contained with respect to the host field.
 * The NUL terminator is required because @c host is a @c const @c char*
 * consumed with @c %s formatting in URL builders and log messages.
 *
 * @note Consumes strlen(host)+1 bytes of scratch (typically 13B for
 *       the default origin @c ps.pndsn.com).
 *
 * @param request Request whose scratch buffer stores the copy.
 * @param host    NUL-terminated host string to copy (must not be NULL).
 * @return PUBNUB_OK on success, PUBNUB_ERR_BUFFER_TOO_SMALL when the
 *         scratch buffer cannot accommodate strlen(host)+1 bytes, or
 *         PUBNUB_ERR_INVALID_ARGUMENT when either argument is NULL.
 */
pubnub_res_t pn_request_set_host(pubnub_http_request_t* request, const char* host);

/**
 * @brief Encode (or copy verbatim) a string into the request scratch
 *        buffer.
 *
 * Universal scratch-encode primitive. Handles all encoding modes:
 * PN_ENCODE_NONE copies verbatim, PN_ENCODE_FULL and
 * PN_ENCODE_KEEP_COMMAS percent-encode via pn_url_encode().
 * All-or-nothing: on failure the scratch is unchanged.
 *
 * @param request Request whose scratch buffer stores the result.
 * @param raw     NUL-terminated string to encode or copy.
 * @param out     Output view populated on success; points into scratch.
 * @param encode  Encoding mode: PN_ENCODE_NONE (0), PN_ENCODE_FULL (1),
 *                or PN_ENCODE_KEEP_COMMAS (2).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_scratch_encode(pubnub_http_request_t* request,
                                       const char*            raw,
                                       pubnub_string_view_t*  out,
                                       int                    encode);

/**
 * @brief Encode (or copy verbatim) exactly @p len bytes into the
 *        request scratch buffer.
 *
 * Length-specified variant of @ref pn_request_scratch_encode. Accepts
 * `const uint8_t*` to match serialized output from the serialization
 * provider without requiring a cast at the call site. The input need
 * not be NUL-terminated; embedded NUL bytes are encoded as `%00` when
 * percent-encoding is active.
 *
 * All-or-nothing: on failure the scratch is unchanged.
 *
 * @param request Request whose scratch buffer stores the result.
 * @param raw     Input bytes (may contain NUL).
 * @param len     Number of bytes to process from @p raw.
 * @param out     Output view populated on success; points into scratch.
 * @param encode  Encoding mode: PN_ENCODE_NONE (0), PN_ENCODE_FULL (1),
 *                or PN_ENCODE_KEEP_COMMAS (2).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_scratch_encode_n(pubnub_http_request_t* request,
                                         const uint8_t*         raw,
                                         size_t                 len,
                                         pubnub_string_view_t*  out,
                                         int                    encode);

/**
 * @brief Append a query parameter to a request.
 *
 * All-or-nothing: on failure the request is unchanged.
 *
 * @param request Request to modify (borrowed).
 * @param key     Parameter key (null-terminated).
 * @param value   Parameter value (null-terminated).
 * @param encode  Encoding mode: PN_ENCODE_NONE (0) copies verbatim,
 *                PN_ENCODE_FULL (1) percent-encodes all reserved
 *                characters per RFC 3986, PN_ENCODE_KEEP_COMMAS (2)
 *                percent-encodes but preserves commas for
 *                comma-separated lists.
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_add_query_param(pubnub_http_request_t* request,
                                        const char*            key,
                                        const char*            value,
                                        int                    encode);

/**
 * @brief Append a query parameter with a caller-owned value view.
 *
 * The key is copied into scratch (always short). The value view is
 * assigned directly — the caller must ensure the backing memory
 * outlives the request (e.g., stored in feature_state).
 *
 * @param request Request to append to.
 * @param key     Parameter name (NUL-terminated, copied to scratch).
 * @param value   Pre-encoded value view (borrowed, NOT copied).
 * @return PUBNUB_OK on success, or an error code.
 */
pubnub_res_t pn_request_add_query_param_view(pubnub_http_request_t* request,
                                             const char*            key,
                                             pubnub_string_view_t   value);

/**
 * @brief Append a Content-Type: application/json header to a request.
 *
 * @param req Request to modify (borrowed, must not be NULL).
 * @return PUBNUB_OK on success, PUBNUB_ERR_BUFFER_TOO_SMALL when the
 *         header array is full.
 */
static inline pubnub_res_t pn_request_add_content_type_json(pubnub_http_request_t* req)
{
    pubnub_kv_t* h;
    if (req->header_count >= PUBNUB_CFG_HTTP_MAX_HEADERS) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }
    h            = &req->headers[req->header_count++];
    h->key.ptr   = "Content-Type";
    h->key.len   = 12;
    h->value.ptr = "application/json";
    h->value.len = 16;
    return PUBNUB_OK;
}

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_MIDDLEWARE_INTERNAL_H */
