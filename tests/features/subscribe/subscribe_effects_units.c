/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file subscribe_effects_units.c
 * @brief White-box unit tests for subscribe cursor-preservation effects.
 *
 * Includes subscribe_effects.c directly to reach the static completion
 * callback (pn_subscribe_on_complete) and the message-emit effect
 * (emit_messages). The tests pin the cursor-storage invariant: a
 * transport error must never mutate mgr->cursor, a parse failure that
 * yields no recoverable cursor must leave it intact, and only a real
 * parse (or a raw-cursor scrape from a partially-readable body) may
 * advance it.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

/* White-box: pull the static effect implementations into this TU. */
#include "features/subscribe/subscribe_effects.c"

#include "pubnub/client.h"

#include "support/test_allocator.h"

/* Provided by the linked cJSON serialization provider — parsing the
 * subscribe envelope requires a real tree-traversal vtable. */
extern pubnub_serialization_provider_t* pn_serialization_default(void);

#if !PUBNUB_CFG_NO_HEAP

static uint64_t mock_monotonic(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static uint64_t mock_wall_clock_ms(pubnub_platform_provider_t* self)
{
    (void)self;
    return 0;
}

static void mock_sleep(pubnub_platform_provider_t* self, uint32_t ms)
{
    (void)self;
    (void)ms;
}

static int mock_random(pubnub_platform_provider_t* self, uint8_t* buf, size_t len)
{
    (void)self;
    memset(buf, 0, len);
    return 0;
}

static pubnub_platform_provider_t s_mock_platform = {
    .monotonic_ms  = mock_monotonic,
    .wall_clock_ms = mock_wall_clock_ms,
    .sleep_ms      = mock_sleep,
    .random_bytes  = mock_random,
};

static pubnub_transport_handle_t* mock_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return NULL;
}

static int mock_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void mock_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_mock_transport = {
    .send              = mock_send,
    .poll              = mock_poll,
    .cancel            = mock_cancel,
    .set_tls_ca_bundle = NULL,
    .set_tls_verify    = NULL,
};

/**
 * Build a heap context wired to a real serialization provider so the
 * response parser can traverse the envelope tree.
 */
static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "sub-test";
    cfg.user_id         = "test-user";
    cfg.allocator       = pn_test_allocator();
    cfg.transport       = &s_mock_transport;
    cfg.serialization   = pn_serialization_default();
    cfg.platform        = &s_mock_platform;
    return pubnub_create(&cfg);
}

/** Overwrite the manager cursor with a known timetoken and region. */
static void seed_cursor(pn_subscribe_manager_t* mgr,
                        const char*             timetoken,
                        uint32_t                region)
{
    size_t len = strlen(timetoken);

    memset(&mgr->cursor, 0, sizeof(mgr->cursor));
    memcpy(mgr->cursor.timetoken, timetoken, len);
    mgr->cursor.timetoken[len] = '\0';
    mgr->cursor.timetoken_len  = (uint8_t)len;
    mgr->cursor.region         = region;
    mgr->restore_cursor_valid  = 0;
}

/**
 * Acquire a pool slot, mark it ready, and attach a borrowed response
 * body so emit_messages() sees a completed request.
 */
static uint16_t attach_ready_slot(pubnub_context_t*       ctx,
                                  pn_subscribe_manager_t* mgr,
                                  const char*             body,
                                  size_t                  body_len)
{
    pn_request_pool_t* pool   = pn_context_request_pool(ctx);
    pubnub_future_t    future = {0};
    pn_request_t*      slot;
    pubnub_res_t       rc;

    assert_non_null(pool);
    rc = pn_request_pool_acquire(pool, ctx, &future);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_not_equal(PUBNUB_SLOT_ID_INVALID, future.slot_id);

    slot = pn_request_pool_get(pool, future.slot_id);
    assert_non_null(slot);
    slot->state                  = PN_REQUEST_COMPLETE;
    slot->http_response.body     = (uint8_t*)body;
    slot->http_response.body_len = body_len;
    /* Publish the readiness gate: pn_request_is_ready now gates on this
     * atomic latch, not on state alone. A slot forced to COMPLETE without
     * publishing the gate reads as not-ready (which is the correct
     * production behaviour). */
    PUBNUB_ATOMIC_STORE_U8(&slot->ready, 1);

    mgr->active_slot_id = future.slot_id;
    return future.slot_id;
}

/*
 * These tests assert the cursor STORAGE invariant on transport error:
 * pn_subscribe_on_complete must not mutate mgr->cursor when the request
 * failed. A subsequent reconnect issues a fresh handshake at tt=0, so
 * "cursor storage preserved" is distinct from "the next wire request
 * replays that token" — the latter is a state-machine concern proven
 * elsewhere. Here we only prove the bytes survive the failure callback.
 */

static void transport_error_handshake_preserves_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_HANDSHAKING;
    seed_cursor(mgr, "17001234567890123", 42);

    pn_subscribe_cursor_t before = mgr->cursor;

    pn_request_t request              = {0};
    request.http_response.status_code = 500;

    pn_subscribe_on_complete(&request, PUBNUB_ERR_TRANSPORT, mgr);

    assert_memory_equal(&before, &mgr->cursor, sizeof(before));

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

static void transport_error_receive_preserves_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_RECEIVING;
    seed_cursor(mgr, "17001234567890123", 42);

    pn_subscribe_cursor_t before = mgr->cursor;

    pn_request_t request              = {0};
    request.http_response.status_code = 0;

    pn_subscribe_on_complete(&request, PUBNUB_ERR_TRANSPORT, mgr);

    assert_memory_equal(&before, &mgr->cursor, sizeof(before));

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * A body that fails the full parse AND has no raw-scrapeable cursor must
 * leave the stored cursor untouched — the emit path pushes a failure
 * event instead of guessing a token.
 */
static void parse_failure_non_recoverable_preserves_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_RECEIVING;
    seed_cursor(mgr, "17001234567890123", 42);

    pn_subscribe_cursor_t before = mgr->cursor;

    static const char body[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    attach_ready_slot(ctx, mgr, body, sizeof(body) - 1);

    emit_messages(mgr);

    assert_memory_equal(&before, &mgr->cursor, sizeof(before));

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Distinct from preservation: when the full parse fails but a raw cursor
 * IS scrapeable from the body, the emit path advances the cursor so the
 * next request does not replay the dropped batch.
 */
static void raw_cursor_fallback_advances_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_RECEIVING;
    seed_cursor(mgr, "17001234567890123", 42);

    /* Invalid JSON (leading junk) but carries the "t":{"t":" needle
     * followed by exactly 17 digits, a closing quote, and a region. */
    static const char body[] =
        "!! not json !! \"t\":{\"t\":\"17009999999999999\",\"r\":7} tail";
    attach_ready_slot(ctx, mgr, body, sizeof(body) - 1);

    emit_messages(mgr);

    assert_int_equal(17, mgr->cursor.timetoken_len);
    assert_memory_equal("17009999999999999", mgr->cursor.timetoken, 17);
    assert_int_equal(7, mgr->cursor.region);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Happy control (receive path): a well-formed envelope advances the
 * cursor to the parsed timetoken and region.
 */
static void well_formed_receive_advances_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_RECEIVING;
    seed_cursor(mgr, "17001234567890123", 42);

    static const char body[] =
        "{\"t\":{\"t\":\"17009999999999999\",\"r\":7},\"m\":[]}";
    attach_ready_slot(ctx, mgr, body, sizeof(body) - 1);

    emit_messages(mgr);

    assert_int_equal(17, mgr->cursor.timetoken_len);
    assert_memory_equal("17009999999999999", mgr->cursor.timetoken, 17);
    assert_int_equal(7, mgr->cursor.region);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

/*
 * Happy control (handshake path): a successful handshake with a
 * well-formed body applies the parsed cursor via on_complete.
 */
static void handshake_success_applies_cursor(void** state)
{
    (void)state;
    pubnub_context_t* ctx = create_ctx();
    assert_non_null(ctx);

    pn_subscribe_manager_t* mgr =
        pn_subscribe_manager_create(ctx, pn_test_allocator());
    assert_non_null(mgr);

    mgr->ee_state = PN_SUBSCRIBE_STATE_HANDSHAKING;
    seed_cursor(mgr, "17001234567890123", 42);

    static const char body[] =
        "{\"t\":{\"t\":\"17009999999999999\",\"r\":7},\"m\":[]}";

    pn_request_t request              = {0};
    request.http_response.status_code = 200;
    request.http_response.body        = (uint8_t*)body;
    request.http_response.body_len    = sizeof(body) - 1;

    pn_subscribe_on_complete(&request, PUBNUB_OK, mgr);

    assert_int_equal(17, mgr->cursor.timetoken_len);
    assert_memory_equal("17009999999999999", mgr->cursor.timetoken, 17);
    assert_int_equal(7, mgr->cursor.region);

    pn_subscribe_manager_cleanup(mgr, pn_test_allocator());
    pubnub_destroy(ctx);
}

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
#if !PUBNUB_CFG_NO_HEAP
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(transport_error_handshake_preserves_cursor),
        cmocka_unit_test(transport_error_receive_preserves_cursor),
        cmocka_unit_test(parse_failure_non_recoverable_preserves_cursor),
        cmocka_unit_test(raw_cursor_fallback_advances_cursor),
        cmocka_unit_test(well_formed_receive_advances_cursor),
        cmocka_unit_test(handshake_success_applies_cursor),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}
