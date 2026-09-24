/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_service_error.c
 * @brief libFuzzer harness for service error envelope classification.
 *
 * Creates a minimal SDK context with a real cJSON serialization
 * provider, injects arbitrary fuzz data as the HTTP response body of
 * a request slot, and exercises the full pubnub_response_service_error()
 * classification and extraction path.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/future.h"
#include "pubnub/service_error.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/transport.h"
#include "pubnub/providers/platform.h"
#include "core/core_internal.h"
#include "core/runtime/request_internal.h"
#include "core/runtime/request_pool_internal.h"

/* Real serialization provider (cJSON) wired through the build. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

/* Allocator: stdlib pass-through so we never hit pn_allocator_default
 * (avoids static-library link-order issues on Linux/GNU ld). */
static void* fuzz_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return malloc(size);
}

static void fuzz_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static pubnub_buffer_t fuzz_buf_acquire(pubnub_allocator_provider_t* self,
                                        pubnub_buf_purpose_t         purpose)
{
    (void)self;
    pubnub_buffer_t buf = {0};
    buf.data            = (uint8_t*)malloc(4096);
    buf.cap             = buf.data ? 4096 : 0;
    buf.len             = 0;
    buf.purpose         = purpose;
    return buf;
}

static void fuzz_buf_release(pubnub_allocator_provider_t* self, pubnub_buffer_t* buf)
{
    (void)self;
    if (NULL != buf && NULL != buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->cap  = 0;
    }
}

static pubnub_allocator_provider_t s_allocator = {
    .alloc       = fuzz_alloc,
    .realloc     = NULL,
    .free        = fuzz_free,
    .buf_acquire = fuzz_buf_acquire,
    .buf_release = fuzz_buf_release,
    .buf_grow    = NULL,
};

/* Minimal transport: send returns a dummy handle; never actually
 * used because we bypass dispatch entirely. */
static char s_handle_backing;

static pubnub_transport_handle_t* fuzz_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*  request,
                                            pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    (void)response;
    return (pubnub_transport_handle_t*)&s_handle_backing;
}

static int fuzz_poll(pubnub_transport_provider_t* self, uint32_t timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void fuzz_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send              = fuzz_send,
    .poll              = fuzz_poll,
    .cancel            = fuzz_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/* Platform: minimal monotonic clock, no sync primitives. */
static pubnub_milliseconds_t fuzz_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 1000;
}

static void fuzz_sleep(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int fuzz_random(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0xAB, len);
    return 0;
}

static pubnub_platform_provider_t s_platform = {
    .monotonic_ms  = fuzz_monotonic,
    .sleep_ms      = fuzz_sleep,
    .random_bytes  = fuzz_random,
    .secure_zero   = NULL,
    .lock_size     = NULL,
    .lock_init     = NULL,
    .lock_destroy  = NULL,
    .lock_acquire  = NULL,
    .lock_release  = NULL,
    .thread_create = NULL,
    .thread_join   = NULL,
};

static pubnub_context_t* s_ctx;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;

    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "fuzz-sub";
    cfg.publish_key     = "fuzz-pub";
    cfg.user_id         = "fuzz-user";
    cfg.transport       = &s_transport;
    cfg.platform        = &s_platform;
    cfg.allocator       = &s_allocator;
    cfg.serialization   = pn_serialization_default();

    s_ctx = pubnub_create(&cfg);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (NULL == s_ctx || 0 == size || size > 65536) {
        return 0;
    }

    /* Acquire a request slot from the pool. */
    pn_request_pool_t* pool = pn_context_request_pool(s_ctx);
    if (NULL == pool) {
        return 0;
    }

    pn_request_pool_lock(pool);
    pubnub_future_t future;
    pubnub_res_t    rc = pn_request_pool_acquire(pool, s_ctx, &future);
    if (PUBNUB_OK != rc) {
        pn_request_pool_unlock(pool);
        return 0;
    }

    /* Inject fuzz data as the HTTP response body and force the slot
     * into COMPLETE state (bypassing transport dispatch). */
    pn_request_t* slot = pn_request_pool_get(pool, future.slot_id);

    slot->state                     = PN_REQUEST_COMPLETE;
    slot->result                    = PUBNUB_OK;
    slot->http_response.completion  = PUBNUB_HTTP_COMPLETE;
    slot->http_response.status_code = 200;
    slot->http_response.body        = data;
    slot->http_response.body_len    = size;
    slot->parsed_body_tree          = NULL;
    slot->parsed_body_attempted     = 0;
    slot->svc_error_kind            = 0;
    slot->svc_error_classified      = 0;
    /* Publish the readiness gate: result accessors resolve through
     * pn_ready_slot_for_future, which gates on this atomic latch. */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);
    pn_request_pool_unlock(pool);

    /* Update the future status to reflect completion. */
    future.status = PUBNUB_OK;

    /* Exercise the full service error classification path. */
    pubnub_service_error_t err = {0};
    pubnub_response_service_error(future, &err);

    /* Exercise detail and channel accessors. */
    size_t detail_count = pubnub_service_error_detail_count(future);
    for (size_t i = 0; i < detail_count && i < 8; ++i) {
        pubnub_service_error_detail_t detail = {0};
        pubnub_service_error_detail_at(future, i, &detail);
    }

    size_t ch_count = pubnub_service_error_channel_count(future);
    for (size_t i = 0; i < ch_count && i < 8; ++i) {
        pubnub_string_view_t ch = pubnub_service_error_channel_at(future, i);
        (void)ch;
    }

    /* Clean up: NULL out the borrowed body pointer before release
     * so the pool reset does not attempt to interpret stale data
     * on future reuse. */
    pn_request_pool_lock(pool);
    slot->http_response.body     = NULL;
    slot->http_response.body_len = 0;
    pn_request_pool_release(pool, future.slot_id);
    pn_request_pool_unlock(pool);

    return 0;
}
