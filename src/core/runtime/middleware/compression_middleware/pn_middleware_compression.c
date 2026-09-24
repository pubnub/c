/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_middleware_compression.h"

#include "pubnub/config.h"
#include "pubnub/providers/logger.h"

#if PUBNUB_ENABLE_REQUEST_COMPRESSION

#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport_types.h"

#include "core/runtime/request_internal.h"

#include <stddef.h>
#include <string.h>
#include <zlib.h>

#define PN_COMPRESSION_CONTAINER_OF(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

/** Content-Encoding header key. */
static const char kContentEncodingKey[] = "Content-Encoding";

/** Content-Encoding header value for gzip. */
static const char kContentEncodingGzip[] = "gzip";

/**
 * @brief Per-request compression slot.
 *
 * Tracks the purpose-tagged buffer holding compressed data alongside
 * the transport handle and response pointer so the middleware can
 * reclaim the buffer when the request completes or is cancelled.
 * Also stores original body/header state for in-place restoration
 * (needed for retry middleware which re-dispatches through the chain).
 */
typedef struct pn_compression_slot {
    /** Purpose-tagged buffer holding compressed body (from buf_acquire). */
    pubnub_buffer_t buf;
    /** Transport handle returned by next->send(); for cancel lookup. */
    pubnub_transport_handle_t* handle;
    /** Generation of the owning pn_request_t at send time; prevents
     *  stale-handle matches when pool slots are recycled. */
    uint16_t handle_generation;
    /** Borrowed response pointer; completion field drives reclamation. */
    pubnub_http_response_t* response;
    /** Borrowed request pointer; for body/header restoration. */
    pubnub_http_request_t* request;
    /** Original body pointer saved before in-place mutation. */
    const uint8_t* original_body;
    /** Original body length saved before in-place mutation. */
    size_t original_body_len;
    /** Original header count saved before adding Content-Encoding. */
    unsigned int original_header_count;
} pn_compression_slot_t;

/**
 * @brief Compression middleware state.
 *
 * First member is the transport vtable (decorator pattern). Holds
 * N slots (one per max in-flight request) to avoid use-after-free
 * when multiple concurrent POST requests compress bodies.
 */
typedef struct pn_middleware_compression {
    /** Transport vtable (must be first member). */
    pubnub_transport_provider_t vtable;

    /** Next transport in the chain (borrowed). */
    pubnub_transport_provider_t* next;

    /** Allocator for compressed buffers (borrowed). */
    pubnub_allocator_provider_t* allocator;

    /** Logger for diagnostic messages (borrowed, may be NULL). */
    pubnub_logger_provider_t* logger;

    /** Per-request compression slots. */
    pn_compression_slot_t slots[PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS];
} pn_middleware_compression_t;

/**
 * @brief Sweep completed slots, releasing their buffers.
 *
 * Iterates all slots, restoring and releasing the buffer for any
 * completed request. Validates identity via generation counter — a
 * recycled slot can reuse the same response address for a new request.
 */
static void sweep_completed_slots(pn_middleware_compression_t* mw)
{
    int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_compression_slot_t* slot = &mw->slots[i];
        pn_request_t*          req;
        if (NULL == slot->buf.data || NULL == slot->request) {
            continue;
        }
        /* Generation mismatch: slot was recycled; release buffer, skip. */
        req = PN_COMPRESSION_CONTAINER_OF(slot->request, pn_request_t, http_request);
        if (slot->handle_generation != req->generation) {
            mw->allocator->buf_release(mw->allocator, &slot->buf);
            memset(slot, 0, sizeof(*slot));
            continue;
        }
        if (NULL == slot->response) {
            continue;
        }
        if (PUBNUB_HTTP_PENDING != slot->response->completion) {
            slot->request->body         = slot->original_body;
            slot->request->body_len     = slot->original_body_len;
            slot->request->header_count = slot->original_header_count;
            mw->allocator->buf_release(mw->allocator, &slot->buf);
            memset(slot, 0, sizeof(*slot));
        }
    }
}

/**
 * @brief Find an empty compression slot.
 *
 * @return Pointer to the empty slot, or NULL if all are occupied.
 */
static pn_compression_slot_t* find_empty_slot(pn_middleware_compression_t* mw)
{
    int i;
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        if (NULL == mw->slots[i].buf.data) {
            return &mw->slots[i];
        }
    }
    return NULL;
}

/**
 * @brief Compress data into a purpose-tagged buffer using gzip.
 *
 * @param buf       Acquired buffer with sufficient capacity.
 * @param input     Input data to compress.
 * @param input_len Length of input data.
 * @return PUBNUB_OK on success, error code on failure.
 */
static pubnub_res_t compress_gzip_into(pubnub_buffer_t* buf,
                                       const uint8_t*   input,
                                       size_t           input_len)
{
    z_stream stream  = {0};
    stream.next_in   = (Bytef*)input;
    stream.avail_in  = (uInt)input_len;
    stream.next_out  = buf->data;
    stream.avail_out = (uInt)buf->cap;

    /* 16 + MAX_WBITS = gzip format with default window size. */
    int rc = deflateInit2(
        &stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    if (Z_OK != rc) {
        return PUBNUB_ERR_INTERNAL;
    }

    rc = deflate(&stream, Z_FINISH);
    if (Z_STREAM_END != rc) {
        deflateEnd(&stream);
        return PUBNUB_ERR_INTERNAL;
    }

    buf->len = stream.total_out;
    deflateEnd(&stream);

    return PUBNUB_OK;
}

/**
 * @brief Add Content-Encoding: gzip header to the request.
 *
 * @param request Request to modify (borrowed).
 * @return PUBNUB_OK on success, error code if header array is full.
 */
static pubnub_res_t add_content_encoding_header(pubnub_http_request_t* request)
{
    if (request->header_count >= PUBNUB_CFG_HTTP_MAX_HEADERS) {
        return PUBNUB_ERR_BUFFER_TOO_SMALL;
    }

    pubnub_kv_t* h = &request->headers[request->header_count];
    h->key.ptr     = kContentEncodingKey;
    h->key.len     = sizeof(kContentEncodingKey) - 1;
    h->value.ptr   = kContentEncodingGzip;
    h->value.len   = sizeof(kContentEncodingGzip) - 1;
    request->header_count++;

    return PUBNUB_OK;
}

static pubnub_transport_handle_t* compression_send(pubnub_transport_provider_t* self,
                                                   pubnub_http_request_t* request,
                                                   pubnub_http_response_t* response)
{
    if (NULL == self || NULL == request || NULL == response) {
        return NULL;
    }

    pn_middleware_compression_t* mw = (pn_middleware_compression_t*)self;
    if (NULL == mw->next) {
        response->completion = PUBNUB_HTTP_ERROR;
        return NULL;
    }

    /* Passthrough when compression is not requested or body is absent. */
    if (0 == request->compress_body || NULL == request->body
        || 0 == request->body_len) {
        return mw->next->send(mw->next, request, response);
    }

    /* Reclaim buffers from completed requests. */
    sweep_completed_slots(mw);

    /* Find a free slot. Degrade gracefully if none available. */
    pn_compression_slot_t* slot = find_empty_slot(mw);
    if (NULL == slot) {
#if PUBNUB_LOG_ENABLED(DEBUG)
        if (NULL != mw->logger && NULL != mw->logger->log) {
            pubnub_log_entry_text_t log_e = {0};
            log_e.base.type               = PUBNUB_LOG_ENTRY_TEXT;
            log_e.base.level              = PUBNUB_LOG_LEVEL_DEBUG;
            log_e.base.file               = __FILE__;
            log_e.base.line               = __LINE__;
            log_e.message                 = "compression: no free"
                                            " slot, sending"
                                            " uncompressed";
            mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
        }
#endif
        return mw->next->send(mw->next, request, response);
    }

    /* Acquire a second OBJ-purpose buffer for the compressed body.
     * Allocator pool sizing must account for 2x OBJ slots per
     * in-flight request when compression is enabled. */
    pubnub_buffer_t buf = mw->allocator->buf_acquire(mw->allocator, PUBNUB_BUF_OBJ);
    if (NULL == buf.data || 0 == buf.cap) {
#if PUBNUB_LOG_ENABLED(DEBUG)
        if (NULL != mw->logger && NULL != mw->logger->log) {
            pubnub_log_entry_text_t log_e = {0};
            log_e.base.type               = PUBNUB_LOG_ENTRY_TEXT;
            log_e.base.level              = PUBNUB_LOG_LEVEL_DEBUG;
            log_e.base.file               = __FILE__;
            log_e.base.line               = __LINE__;
            log_e.message                 = "compression: OBJ buffer"
                                            " pool exhausted,"
                                            " sending uncompressed";
            mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
        }
#endif
        return mw->next->send(mw->next, request, response);
    }

    /* Check capacity: need compressBound(body_len) + 16 bytes of headroom.
     * Falls through when the OBJ buffer (PUBNUB_CFG_OBJECT_BUFFER_SIZE) is
     * too small — the maximum compressible body length is approximately
     * buf.cap - 16 - (buf.cap >> 12) - (buf.cap >> 14) - (buf.cap >> 25) - 13
     * per zlib's compressBound formula. */
    const size_t needed = (size_t)compressBound((uLong)request->body_len) + 16;
    if (buf.cap < needed) {
#if PUBNUB_LOG_ENABLED(DEBUG)
        if (NULL != mw->logger && NULL != mw->logger->log) {
            pubnub_log_entry_text_t log_e = {0};
            log_e.base.type               = PUBNUB_LOG_ENTRY_TEXT;
            log_e.base.level              = PUBNUB_LOG_LEVEL_DEBUG;
            log_e.base.file               = __FILE__;
            log_e.base.line               = __LINE__;
            log_e.message                 = "compression: OBJ buffer"
                                            " too small for"
                                            " compressed output,"
                                            " sending uncompressed";
            mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
        }
#endif
        mw->allocator->buf_release(mw->allocator, &buf);
        return mw->next->send(mw->next, request, response);
    }

    /* Compress the body into the acquired buffer. */
    pubnub_res_t rc = compress_gzip_into(&buf, request->body, request->body_len);
    if (PUBNUB_OK != rc) {
#if PUBNUB_LOG_ENABLED(DEBUG)
        if (NULL != mw->logger && NULL != mw->logger->log) {
            pubnub_log_entry_text_t log_e = {0};
            log_e.base.type               = PUBNUB_LOG_ENTRY_TEXT;
            log_e.base.level              = PUBNUB_LOG_LEVEL_DEBUG;
            log_e.base.file               = __FILE__;
            log_e.base.line               = __LINE__;
            log_e.message                 = "compression: gzip"
                                            " deflate failed,"
                                            " sending uncompressed";
            mw->logger->log(mw->logger, (const pubnub_log_entry_t*)&log_e);
        }
#endif
        mw->allocator->buf_release(mw->allocator, &buf);
        return mw->next->send(mw->next, request, response);
    }

    /* Save original body/header state for restoration after completion. */
    slot->request               = request;
    slot->original_body         = request->body;
    slot->original_body_len     = request->body_len;
    slot->original_header_count = request->header_count;

    /* Mutate request in-place (pool-owned, lives for request lifetime). */
    request->body     = buf.data;
    request->body_len = buf.len;

    rc = add_content_encoding_header(request);
    if (PUBNUB_OK != rc) {
        request->body         = slot->original_body;
        request->body_len     = slot->original_body_len;
        request->header_count = slot->original_header_count;
        slot->request         = NULL;
        mw->allocator->buf_release(mw->allocator, &buf);
        return mw->next->send(mw->next, request, response);
    }

    /* Send through the next layer. */
    pubnub_transport_handle_t* handle = mw->next->send(mw->next, request, response);
    if (NULL == handle) {
        request->body         = slot->original_body;
        request->body_len     = slot->original_body_len;
        request->header_count = slot->original_header_count;
        slot->request         = NULL;
        mw->allocator->buf_release(mw->allocator, &buf);
        return NULL;
    }

    /* Record in the slot for later reclamation. */
    slot->buf    = buf;
    slot->handle = handle;
    slot->handle_generation =
        PN_COMPRESSION_CONTAINER_OF(request, pn_request_t, http_request)->generation;
    slot->response = response;

    return handle;
}

static int compression_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    if (NULL == self) {
        return -1;
    }
    pn_middleware_compression_t* mw = (pn_middleware_compression_t*)self;
    if (NULL == mw->next) {
        return -1;
    }
    return mw->next->poll(mw->next, timeout_ms);
}

static void compression_cancel(pubnub_transport_provider_t* self,
                               pubnub_transport_handle_t*   transport_handle)
{
    if (NULL == self || NULL == transport_handle) {
        return;
    }

    pn_middleware_compression_t* mw = (pn_middleware_compression_t*)self;
    int                          i;

    /* Restore body/header state and release buffer for the cancelled request.
     * Match by handle pointer AND generation to avoid stale-handle hazard
     * when pool slots are recycled with the same address. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_compression_slot_t* slot = &mw->slots[i];
        if (slot->handle == transport_handle && NULL != slot->buf.data
            && NULL != slot->request
            && slot->handle_generation
                   == PN_COMPRESSION_CONTAINER_OF(slot->request, pn_request_t, http_request)
                          ->generation) {
            if (NULL != slot->request) {
                slot->request->body         = slot->original_body;
                slot->request->body_len     = slot->original_body_len;
                slot->request->header_count = slot->original_header_count;
            }
            mw->allocator->buf_release(mw->allocator, &slot->buf);
            memset(slot, 0, sizeof(*slot));
            break;
        }
    }

    if (NULL != mw->next) {
        mw->next->cancel(mw->next, transport_handle);
    }
}

pubnub_transport_provider_t*
pn_middleware_compression_create(pubnub_transport_provider_t* next,
                                 pubnub_allocator_provider_t* allocator,
                                 pubnub_logger_provider_t*    logger)
{
    if (NULL == allocator || NULL == allocator->alloc || NULL == next) {
        return NULL;
    }

    pn_middleware_compression_t* mw =
        (pn_middleware_compression_t*)PN_ALLOC(allocator, sizeof(*mw), 0);
    if (NULL == mw) {
        return NULL;
    }

    memset(mw, 0, sizeof(*mw));

    mw->vtable.send   = compression_send;
    mw->vtable.poll   = compression_poll;
    mw->vtable.cancel = compression_cancel;
    mw->vtable.init   = NULL;
    mw->vtable.deinit = NULL;

    mw->next      = next;
    mw->allocator = allocator;
    mw->logger    = logger;

    return (pubnub_transport_provider_t*)mw;
}

void pn_middleware_compression_destroy(pubnub_transport_provider_t* mw,
                                       pubnub_allocator_provider_t* allocator)
{
    if (NULL == mw) {
        return;
    }
    if (NULL == allocator || NULL == allocator->free) {
        return;
    }

    pn_middleware_compression_t* comp_mw = (pn_middleware_compression_t*)mw;
    int                          i;

    /* Restore body/header state and release all outstanding buffers. */
    for (i = 0; i < PUBNUB_CFG_MAX_IN_FLIGHT_REQUESTS; ++i) {
        pn_compression_slot_t* slot = &comp_mw->slots[i];
        if (NULL != slot->buf.data) {
            if (NULL != slot->request) {
                slot->request->body         = slot->original_body;
                slot->request->body_len     = slot->original_body_len;
                slot->request->header_count = slot->original_header_count;
            }
            allocator->buf_release(allocator, &slot->buf);
        }
    }

    PN_FREE(allocator, mw);
}

#else  /* !PUBNUB_ENABLE_REQUEST_COMPRESSION */

pubnub_transport_provider_t*
pn_middleware_compression_create(pubnub_transport_provider_t* next,
                                 pubnub_allocator_provider_t* allocator,
                                 pubnub_logger_provider_t*    logger)
{
    (void)allocator;
    (void)logger;
    return next; /* Pass-through: no compression layer. */
}

void pn_middleware_compression_destroy(pubnub_transport_provider_t* mw,
                                       pubnub_allocator_provider_t* allocator)
{
    (void)mw;
    (void)allocator;
}

#endif /* PUBNUB_ENABLE_REQUEST_COMPRESSION */
