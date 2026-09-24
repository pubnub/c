/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file signature_middleware.c
 * @brief PAMv3 request-signing middleware.
 *
 * Runs last in the enrichment stage: sorts every query parameter
 * added by outer middlewares alphabetically (in place), builds the
 * canonical signing string, HMAC-SHA256s it with the secret key,
 * base64url-encodes the digest (no padding), prepends `v2.`, and
 * appends `signature=v2.<...>` as the final query parameter.
 *
 * Passthrough when any of secret_key/publish_key/crypto is unset -
 * matches legacy `pbcc_sign_url` which only runs when
 * `secret_key != NULL`.
 */

#include "middleware_internal.h"

#include "core/pn_format.h"
#include "core/protocol_common/pn_base64url.h"
#include "signature_middleware/pn_signing_string.h"

#include <inttypes.h>
#include <string.h>

/** HMAC-SHA256 output length in bytes. */
#define PN_SIG_HMAC_LEN 32

/**
 * @brief Maximum size of the encoded signature value.
 *
 *   "v2." (3) + base64url(32 bytes) (43) + NUL (1) = 47.
 */
#define PN_SIG_ENCODED_MAX 47

/**
 * @brief Prefix marking PAMv3 signatures.
 *
 * Legacy format: `signature=v2.<base64url>`. The bare signature
 * value without the `v2.` prefix is PAMv2 (no longer used).
 */
static const char kSignaturePrefix[] = "v2.";

/**
 * @brief Lexicographic compare of two non-NUL-terminated string views.
 *
 * Order matches memcmp over the shorter prefix; ties resolved by the
 * shorter view sorting first. Matches c-core's SORT_URL_PARAMETERS.
 */
static int kv_key_cmp(const pubnub_kv_t* a, const pubnub_kv_t* b)
{
    const size_t n = a->key.len < b->key.len ? a->key.len : b->key.len;
    int          c = memcmp(a->key.ptr, b->key.ptr, n);

    if (0 != c) {
        return c;
    }

    if (a->key.len < b->key.len) {
        return -1;
    }

    if (a->key.len > b->key.len) {
        return 1;
    }

    return 0;
}

/**
 * @brief Stable insertion sort on the query parameter array.
 *
 * n is tiny (capped at PUBNUB_CFG_HTTP_MAX_QUERY_PARAMS, typically
 * 16); insertion sort is both simpler and faster than qsort with
 * a function-pointer comparator at this scale.
 */
static void sort_query_params(pubnub_http_request_t* request)
{
    for (unsigned int i = 1; i < request->query_param_count; i++) {
        pubnub_kv_t  tmp = request->query_params[i];
        unsigned int j   = i;
        while (j > 0 && kv_key_cmp(&request->query_params[j - 1], &tmp) > 0) {
            request->query_params[j] = request->query_params[j - 1];
            j--;
        }
        request->query_params[j] = tmp;
    }
}

/**
 * @brief Compute the signature and append `signature=v2.<...>` to the
 *        request's query parameters.
 *
 * Allocates a transient buffer for the canonical signing string via
 * @c mw->allocator, runs HMAC-SHA256 into a stack buffer, base64url
 * encodes the digest, builds the final "v2.<base64url>" string, and
 * stores it as a query parameter via the shared helper (which
 * URL-encodes the value - a no-op for base64url characters).
 */
static pubnub_res_t sign_and_append(pn_middleware_signature_t* mw,
                                    pubnub_http_request_t*     request)
{
    const char*                  publish_key = mw->publish_key;
    const char*                  secret_key  = *mw->secret_key;
    pubnub_crypto_provider_t*    crypto      = mw->crypto;
    pubnub_allocator_provider_t* alloc       = mw->allocator;

    if (NULL == crypto->hmac_sha256) {
        return PUBNUB_ERR_NOT_SUPPORTED;
    }

    const size_t str_len = pn_signing_string_len(request, publish_key);
    if (0 == str_len) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }

    uint8_t* sign_buf = (uint8_t*)PN_ALLOC(alloc, str_len, 0);
    if (NULL == sign_buf) {
        return PUBNUB_ERR_OUT_OF_MEMORY;
    }

    size_t       written = 0;
    pubnub_res_t rc =
        pn_signing_string_build(request, publish_key, sign_buf, str_len, &written);
    if (PUBNUB_OK != rc) {
        PN_FREE(alloc, sign_buf);
        return rc;
    }

    uint8_t digest[PN_SIG_HMAC_LEN];
    size_t  digest_len = sizeof(digest);
    rc                 = crypto->hmac_sha256(crypto,
                             (const uint8_t*)secret_key,
                             strlen(secret_key),
                             sign_buf,
                             written,
                             digest,
                             &digest_len);
    PN_FREE(alloc, sign_buf);
    if (PUBNUB_OK != rc) {
        return rc;
    }
    if (PN_SIG_HMAC_LEN != digest_len) {
        return PUBNUB_ERR_CRYPTO;
    }

    char encoded[PN_SIG_ENCODED_MAX];
    memcpy(encoded, kSignaturePrefix, sizeof(kSignaturePrefix) - 1);
    rc = pn_base64url_encode(digest,
                             digest_len,
                             encoded + (sizeof(kSignaturePrefix) - 1),
                             sizeof(encoded) - (sizeof(kSignaturePrefix) - 1));
    if (PUBNUB_OK != rc) {
        return rc;
    }

    rc = pn_request_add_query_param(request, "signature", encoded, PN_ENCODE_FULL);
    if (PUBNUB_OK == rc) {
        PUBNUB_LOG_TEXT(mw->logger, PUBNUB_LOG_LEVEL_TRACE, "Request signed");
    }
    return rc;
}

/**
 * @brief Append `timestamp=<unix_seconds>` to the request's query
 *        parameters using the platform provider's wall-clock time.
 *
 * PAMv3 requires an explicit timestamp in the signed query string.
 * The value is the current Unix epoch time in seconds, obtained
 * from @c wall_clock_ms. Returns @c PUBNUB_ERR_NO_WALL_CLOCK when
 * the vtable entry is NULL or the provider returns 0 (no RTC / not
 * yet NTP-synchronized).
 *
 * Pre: caller guaranteed platform is non-NULL via the can_sign
 * check below.
 */
static pubnub_res_t add_timestamp_query_param(pn_middleware_signature_t* mw,
                                              pubnub_http_request_t* request)
{
    if (NULL == mw->platform->wall_clock_ms) {
        return PUBNUB_ERR_NO_WALL_CLOCK;
    }

    const pubnub_milliseconds_t wall_ms = mw->platform->wall_clock_ms(mw->platform);
    if (0 == wall_ms) {
        return PUBNUB_ERR_NO_WALL_CLOCK;
    }

    const uint64_t now_s = (uint64_t)wall_ms / 1000U;
    char           buf[21];
    int            written = pn_snprintf(buf, sizeof(buf), "%" PRIu64, now_s);
    if (written <= 0 || (size_t)written >= sizeof(buf)) {
        return PUBNUB_ERR_INVALID_ARGUMENT;
    }
    return pn_request_add_query_param(request, "timestamp", buf, PN_ENCODE_NONE);
}

static pubnub_transport_handle_t* signature_send(pubnub_transport_provider_t* self,
                                                 pubnub_http_request_t* request,
                                                 pubnub_http_response_t* response)
{
    if (NULL == self || NULL == response) {
        return NULL;
    }
    pn_middleware_signature_t* mw = (pn_middleware_signature_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Skip decoration for external requests (e.g., S3 uploads). */
    if (request->external) {
        return mw->next->send(mw->next, request, response);
    }

    /* Passthrough when not fully configured. This mirrors legacy
     * c-core which only signs when secret_key != NULL. The crypto
     * provider and publish_key are additionally required for the
     * HMAC computation; the platform provider is required for the
     * PAMv3 timestamp query parameter (wall_clock_ms supplies the
     * epoch time). Any missing piece means "don't sign". */
    const int can_sign = NULL != mw->publish_key && NULL != mw->secret_key
                      && NULL != *mw->secret_key && NULL != mw->crypto
                      && NULL != mw->allocator && NULL != mw->platform;

    if (can_sign) {
        if (PUBNUB_OK != add_timestamp_query_param(mw, request)) {
            response->completion = PUBNUB_HTTP_ERROR;
            return NULL;
        }
        sort_query_params(request);
        if (PUBNUB_OK != sign_and_append(mw, request)) {
            response->completion = PUBNUB_HTTP_ERROR;
            return NULL;
        }
    }

    return mw->next->send(mw->next, request, response);
}

static int signature_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }
    pn_middleware_signature_t* mw = (pn_middleware_signature_t*)self;
    if (NULL == mw->next) {
        return -1;
    }
    return mw->next->poll(mw->next, timeout_ms);
}

static void signature_cancel(pubnub_transport_provider_t* self,
                             pubnub_transport_handle_t*   transport_handle)
{
    if (NULL == self) {
        return;
    }
    pn_middleware_signature_t* mw = (pn_middleware_signature_t*)self;
    if (NULL == mw->next) {
        return;
    }
    mw->next->cancel(mw->next, transport_handle);
}

void pn_middleware_signature_init(pn_middleware_signature_t*   mw,
                                  const char*                  publish_key,
                                  const char* const*           secret_key,
                                  pubnub_crypto_provider_t*    crypto,
                                  pubnub_allocator_provider_t* allocator,
                                  pubnub_platform_provider_t*  platform,
                                  pubnub_transport_provider_t* next)
{
    if (NULL == mw || NULL == next) {
        return;
    }

    mw->base.send   = signature_send;
    mw->base.poll   = signature_poll;
    mw->base.cancel = signature_cancel;
    mw->base.init   = NULL;
    mw->base.deinit = NULL;
    mw->next        = next;
    mw->publish_key = publish_key;
    mw->secret_key  = secret_key;
    mw->crypto      = crypto;
    mw->allocator   = allocator;
    mw->platform    = platform;
    mw->logger      = NULL;
}

pubnub_transport_provider_t*
pn_middleware_signature_create(const char*                  publish_key,
                               const char* const*           secret_key,
                               pubnub_crypto_provider_t*    crypto,
                               pubnub_transport_provider_t* next,
                               pubnub_allocator_provider_t* allocator,
                               pubnub_platform_provider_t*  platform,
                               pubnub_logger_provider_t*    logger)
{
    if (NULL == allocator || NULL == allocator->alloc || NULL == next) {
        return NULL;
    }

    pn_middleware_signature_t* mw =
        (pn_middleware_signature_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }
    pn_middleware_signature_init(
        mw, publish_key, secret_key, crypto, allocator, platform, next);
    mw->logger = logger;

    return (pubnub_transport_provider_t*)mw;
}

void pn_middleware_signature_destroy(pubnub_transport_provider_t* mw,
                                     pubnub_allocator_provider_t* allocator)
{
    if (NULL == mw) {
        return;
    }
    if (NULL == allocator || NULL == allocator->free) {
        return;
    }
    PN_FREE(allocator, mw);
}
