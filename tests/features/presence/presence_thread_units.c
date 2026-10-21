/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/* Lazy presence manager registration must be race-free under TSan. */

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "features/presence/presence_api.h"
#include "providers/provider_internal.h"
#include "pubnub/client.h"
#include "pubnub/config.h"
#include "support/test_threads.h"

#if PUBNUB_CFG_THREAD_SAFETY && PUBNUB_ENABLE_PRESENCE && !PUBNUB_CFG_NO_HEAP

#define PRESENCE_RACE_ITERATIONS 300

static int s_handle_token;

static pubnub_transport_handle_t* race_send(pubnub_transport_provider_t* self,
                                            pubnub_http_request_t*       req,
                                            pubnub_http_response_t*      resp)
{
    (void)self;
    (void)req;
    (void)resp;
    return (pubnub_transport_handle_t*)&s_handle_token;
}

static int race_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void race_cancel(pubnub_transport_provider_t* self,
                        pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send   = race_send,
    .poll   = race_poll,
    .cancel = race_cancel,
};

static pubnub_context_t* s_ctx;
static pn_test_atomic_t  s_stop;

static void joiner_thread(void* arg)
{
    int i;

    (void)arg;
    for (i = 0; i < PRESENCE_RACE_ITERATIONS; i++) {
        pn_presence_api_joined(s_ctx, "ch", NULL);
    }
    pn_test_atomic_store(&s_stop, 1);
}

static void test_lookup_races_first_join_cleanly(void** state)
{
    pubnub_config_t  config = pubnub_config_defaults();
    pn_test_thread_t th;

    (void)state;
    config.publish_key   = "pub";
    config.subscribe_key = "sub";
    config.user_id       = "presence-race";
    config.transport     = &s_transport;
    s_ctx                = pubnub_create(&config);
    assert_non_null(s_ctx);
    pn_test_atomic_store(&s_stop, 0);

    assert_int_equal(0, pn_test_thread_create(&th, joiner_thread, NULL));
    while (0 == pn_test_atomic_load(&s_stop)) {
        pn_presence_api_disconnect(s_ctx);
        pn_presence_api_reconnect(s_ctx);
        pn_presence_api_left(s_ctx, NULL, NULL, "ch", NULL, 0);
        pn_presence_api_left_all(s_ctx);
    }
    assert_int_equal(0, pn_test_thread_join(&th));

    pubnub_destroy(s_ctx);
}

#endif

int main(void)
{
#if PUBNUB_CFG_THREAD_SAFETY && PUBNUB_ENABLE_PRESENCE && !PUBNUB_CFG_NO_HEAP
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lookup_races_first_join_cleanly),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}
