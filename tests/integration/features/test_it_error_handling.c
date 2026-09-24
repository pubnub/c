/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/*
 * G-012: Server-side and client-side error surfacing.
 *
 * When an operation is rejected — by client-side validation or by a
 * server 4xx response — the SDK must surface a coherent, typed error
 * (never PUBNUB_OK, never a crash) and keep the diagnostic accessors
 * (pubnub_response_status_code / pubnub_response_error_message) usable.
 *
 * Note on tolerance: whether a malformed or oversized request is caught
 * client-side (PUBNUB_ERR_INVALID_ARGUMENT, no HTTP exchange) or by the
 * server (PUBNUB_ERR_SERVER + HTTP 4xx) is a legitimately
 * deployment-dependent classification. These tests assert the failure is
 * surfaced coherently and pin the exact code only for the branch that
 * actually reached the server (HTTP status present).
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#if PUBNUB_ENABLE_SUBSCRIBE
#include "pubnub/features/subscribe.h"
#include "pubnub/features/subscribe_types.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

/** Payload size that exceeds the PubNub 32KiB publish limit. */
#define EH_OVERSIZED_BYTES 40000U

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_KEYS(env);
    it_test_state_t* s = it_state_create(env);
    if (NULL == s) {
        return -1;
    }
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    it_state_destroy((it_test_state_t*)*state);
    return 0;
}

/*
 * Test 1: publishing to an empty channel name is rejected.
 *
 * Accepts EITHER a client-side PUBNUB_ERR_INVALID_ARGUMENT or a server
 * error — both are correct ways to refuse an empty channel. The only
 * failure the test rejects is a false success or a crash.
 */
static void publish_empty_channel_rejected(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  fut;
    pubnub_res_t     st;

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = "",
                             .message = "\"eh-empty-channel\"",
                         });
    st  = pubnub_await(fut);

    print_message("empty-channel result: %s (http=%d)",
                  pubnub_res_str(st),
                  pubnub_response_status_code(fut));
    assert_int_not_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

/*
 * Test 2: publishing an invalid channel name is rejected.
 *
 * A channel name containing a comma is not a valid single publish
 * target. Same tolerance as the empty-channel case.
 */
static void publish_invalid_channel_name_rejected(void** state)
{
    it_test_state_t* s = *state;
    pubnub_future_t  fut;
    pubnub_res_t     st;

    fut = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                             .channel = "bad,channel,name",
                             .message = "\"eh-invalid-channel\"",
                         });
    st  = pubnub_await(fut);

    print_message("invalid-channel result: %s (http=%d)",
                  pubnub_res_str(st),
                  pubnub_response_status_code(fut));
    assert_int_not_equal(PUBNUB_OK, st);
    pubnub_future_release(fut);
}

/*
 * Test 3: an oversized (> 32KiB) message is rejected.
 *
 * The payload exceeds the PubNub 32KiB publish limit, so it must be
 * refused — never PUBNUB_OK. If the request reached the server (HTTP
 * status present) the rejection must be classified as PUBNUB_ERR_SERVER
 * carrying HTTP 400; a client-side rejection before any HTTP exchange
 * (http == 0) is an equally valid refusal.
 */
static void publish_oversized_message_rejected(void** state)
{
    it_test_state_t* s   = *state;
    char*            msg = (char*)malloc(EH_OVERSIZED_BYTES + 3U);
    pubnub_future_t  fut;
    pubnub_res_t     st;
    int              http;

    assert_non_null(msg);

    /* Build a valid JSON string literal that is too large to publish. */
    msg[0] = '"';
    memset(msg + 1, 'a', EH_OVERSIZED_BYTES);
    msg[EH_OVERSIZED_BYTES + 1U] = '"';
    msg[EH_OVERSIZED_BYTES + 2U] = '\0';

    fut  = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                              .channel = s->channel,
                              .message = msg,
                         });
    st   = pubnub_await(fut);
    http = pubnub_response_status_code(fut);

    print_message("oversized result: %s (http=%d)", pubnub_res_str(st), http);
    assert_int_not_equal(PUBNUB_OK, st);

    /* When the server answered, the rejection is a server error; the HTTP
     * status is 400 (Bad Request) or 414 (URI Too Long) depending on
     * the server and CDN layer. */
    if (0 != http) {
        assert_true(400 == http || 414 == http);
        assert_int_equal(PUBNUB_ERR_SERVER, st);
    }

    pubnub_future_release(fut);
    free(msg);
}

/*
 * Test 4: the error message is accessible on a failed request.
 *
 * Reuses the oversized-payload rejection; when the server answered with
 * HTTP 400 the SDK must expose a non-empty diagnostic message alongside
 * it. If the payload was refused client-side there is no server message
 * to retrieve, so the accessor check is skipped.
 */
static void error_message_accessible_on_failure(void** state)
{
    it_test_state_t*     s   = *state;
    char*                msg = (char*)malloc(EH_OVERSIZED_BYTES + 3U);
    pubnub_future_t      fut;
    pubnub_res_t         st;
    int                  http;
    pubnub_string_view_t errmsg;

    assert_non_null(msg);

    msg[0] = '"';
    memset(msg + 1, 'b', EH_OVERSIZED_BYTES);
    msg[EH_OVERSIZED_BYTES + 1U] = '"';
    msg[EH_OVERSIZED_BYTES + 2U] = '\0';

    fut    = pubnub_publish(s->ctx,
                         &(pubnub_publish_opts_t){
                                .channel = s->channel,
                                .message = msg,
                         });
    st     = pubnub_await(fut);
    http   = pubnub_response_status_code(fut);
    errmsg = pubnub_response_error_message(fut);

    print_message("error-message result: %s (http=%d msg=%.*s)",
                  pubnub_res_str(st),
                  http,
                  (int)errmsg.len,
                  (NULL != errmsg.ptr) ? errmsg.ptr : "");
    assert_int_not_equal(PUBNUB_OK, st);

    /* When the server answered with 400, a human-readable reason must be
     * retrievable — an empty message here means the accessor lost it. */
    if (400 == http) {
        assert_true(errmsg.len > 0U);
        assert_non_null(errmsg.ptr);
    }

    pubnub_future_release(fut);
    free(msg);
}

#if PUBNUB_ENABLE_SUBSCRIBE

/** Records the first status delivered so the test can prove the subscribe
 *  path neither hangs nor crashes on a questionable channel. */
typedef struct eh_status_probe {
    volatile int              got;
    pubnub_subscribe_status_t last;
} eh_status_probe_t;

static int eh_status_arrived(void* arg)
{
    return ((eh_status_probe_t*)arg)->got;
}

static void on_eh_status_cb(const pubnub_subscribe_status_event_t* ev, void* user_data)
{
    eh_status_probe_t* p = (eh_status_probe_t*)user_data;
    p->last              = ev->status;
    p->got               = 1;
}

/*
 * Test 5: subscribing to a questionable channel surfaces a status without
 * hanging or crashing.
 *
 * Whether the server accepts the name (CONNECTED) or rejects it
 * (CONNECTION_ERROR) is deployment-dependent; the invariant is that some
 * status is delivered within the connect budget and the SDK stays usable.
 */
static void subscribe_invalid_channel_no_hang(void** state)
{
    it_test_state_t*            s        = *state;
    eh_status_probe_t           probe    = {0};
    pubnub_subscribe_listener_t listener = {0};
    pubnub_listener_handle_t    lh;
    pubnub_entity_t             entity;
    pubnub_subscription_t       sub;
    int                         waited;

    listener.on_status = on_eh_status_cb;
    listener.user_data = &probe;
    lh                 = pubnub_add_listener(s->ctx, &listener);

    /* This test uses ctx only for subscribe (no pubnub_await on ctx), so
     * let the process driver pump it to advance the subscribe handshake. */
#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 1;
#endif

    entity = pubnub_channel(s->ctx, "bad,channel,name");
    sub    = pubnub_subscription_create(entity, NULL);
    pubnub_entity_destroy(entity);
    pubnub_subscription_subscribe(sub);

    waited = pn_test_wait_until(
        eh_status_arrived, &probe, IT_SUBSCRIBE_CONNECT_MAX_MS, 50U);

#if !PUBNUB_CFG_THREAD_SAFETY
    s->pump_ctx = 0;
#endif
    pubnub_subscription_unsubscribe(sub);
    pubnub_subscription_destroy(sub);
    pubnub_remove_listener(s->ctx, lh);

    print_message("subscribe-invalid status arrived=%d category=%d",
                  waited,
                  (int)probe.last);
    assert_true(waited);
}

#endif /* PUBNUB_ENABLE_SUBSCRIBE */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            publish_empty_channel_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_invalid_channel_name_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_oversized_message_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(
            error_message_accessible_on_failure, setup, teardown),
#if PUBNUB_ENABLE_SUBSCRIBE
        cmocka_unit_test_setup_teardown(
            subscribe_invalid_channel_no_hang, setup, teardown),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
