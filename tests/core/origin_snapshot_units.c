/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

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

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/providers/transport.h"

#include "core/core_internal.h"
#include "providers/provider_internal.h"
#include "support/test_allocator.h"
#include "support/test_threads.h"

#if !PUBNUB_CFG_NO_HEAP

/** Host length used by the race test; fits every hosted hostname limit. */
#define RACE_HOST_LEN 60
/** Origin switches performed by the writer thread. */
#define RACE_SWITCHES 20000

static pubnub_transport_handle_t* quiet_send(pubnub_transport_provider_t* self,
                                             pubnub_http_request_t*  request,
                                             pubnub_http_response_t* response)
{
    (void)self;
    (void)request;
    (void)response;
    return NULL;
}

static int quiet_poll(pubnub_transport_provider_t* self, unsigned int timeout_ms)
{
    (void)self;
    (void)timeout_ms;
    return 0;
}

static void quiet_cancel(pubnub_transport_provider_t* self,
                         pubnub_transport_handle_t*   handle)
{
    (void)self;
    (void)handle;
}

static pubnub_transport_provider_t s_transport = {
    .send   = quiet_send,
    .poll   = quiet_poll,
    .cancel = quiet_cancel,
};

static pubnub_context_t* create_ctx(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();

    cfg.subscribe_key = "sub";
    cfg.publish_key   = "pub";
    cfg.user_id       = "snapshot";
    cfg.allocator     = pn_test_allocator();
    cfg.transport     = &s_transport;
    cfg.platform      = pn_platform_default();
    return pubnub_create(&cfg);
}

static void snapshot_returns_host_and_generation(void** state)
{
    char              host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
    uint16_t          generation = 99;
    pubnub_context_t* ctx;

    (void)state;
    ctx = create_ctx();
    assert_non_null(ctx);

    assert_int_equal(
        PUBNUB_OK, pn_context_origin_snapshot(ctx, host, sizeof(host), &generation));
    assert_string_equal(pubnub_get_origin(ctx), host);
    assert_int_equal(0, generation);

    assert_int_equal(PUBNUB_OK, pubnub_set_origin(ctx, "alt.example.com"));
    assert_int_equal(
        PUBNUB_OK, pn_context_origin_snapshot(ctx, host, sizeof(host), &generation));
    assert_string_equal("alt.example.com", host);
    assert_int_equal(1, generation);

    assert_int_equal(PUBNUB_OK,
                     pn_context_origin_snapshot(ctx, host, sizeof(host), NULL));

    pubnub_destroy(ctx);
}

static void snapshot_rejects_bad_arguments(void** state)
{
    char              host[8]    = "stale";
    uint16_t          generation = 7;
    pubnub_context_t* ctx;

    (void)state;
    ctx = create_ctx();
    assert_non_null(ctx);

    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_context_origin_snapshot(ctx, NULL, 8, &generation));
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT,
                     pn_context_origin_snapshot(ctx, host, 0, &generation));

    /* The default origin is longer than 8 bytes: nothing is copied. */
    assert_int_equal(
        PUBNUB_ERR_BUFFER_TOO_SMALL,
        pn_context_origin_snapshot(ctx, host, sizeof(host), &generation));
    assert_string_equal("", host);

    assert_int_equal(
        PUBNUB_ERR_NOT_INITIALIZED,
        pn_context_origin_snapshot(NULL, host, sizeof(host), &generation));
    assert_string_equal("", host);
    assert_int_equal(0, generation);

    pubnub_destroy(ctx);
}

#if PUBNUB_CFG_THREAD_SAFETY
typedef struct switcher {
    pubnub_context_t* ctx;
} switcher_t;

static void switch_origin_thread(void* arg)
{
    switcher_t* sw = (switcher_t*)arg;
    char        a[RACE_HOST_LEN + 1];
    char        b[RACE_HOST_LEN + 1];
    int         i;

    memset(a, 'a', RACE_HOST_LEN);
    memset(b, 'b', RACE_HOST_LEN);
    a[RACE_HOST_LEN] = '\0';
    b[RACE_HOST_LEN] = '\0';

    for (i = 0; i < RACE_SWITCHES; i++) {
        (void)pubnub_set_origin(sw->ctx, (0 == (i & 1)) ? a : b);
    }
}

/* Entries are built while another thread keeps switching the origin: every
 * host must be one whole value, never a mix of the two. */
static void concurrent_set_origin_never_yields_torn_host(void** state)
{
    switcher_t        sw;
    pn_test_thread_t  thread;
    pubnub_context_t* ctx;
    int               built = 0;
    int               done  = 0;

    (void)state;
    ctx = create_ctx();
    assert_non_null(ctx);
    sw.ctx = ctx;
    assert_int_equal(0, pn_test_thread_create(&thread, switch_origin_thread, &sw));

    while (!done) {
        pn_pending_entry_t* entry = pn_prep_acquire(ctx);
        char                host[PUBNUB_CFG_MAX_HOSTNAME_LEN];
        uint16_t            generation = 0;

        assert_non_null(entry);
        assert_int_equal(PUBNUB_OK,
                         pn_pending_entry_init(entry,
                                               (uint8_t)PUBNUB_FEATURE_TIME,
                                               NULL,
                                               NULL,
                                               NULL,
                                               PUBNUB_HTTP_GET,
                                               ctx,
                                               0));
        assert_non_null(entry->http_request.host);
        {
            const char* h = entry->http_request.host;
            size_t      n = strlen(h);

            if (n == RACE_HOST_LEN) {
                size_t k;

                for (k = 1; k < n; k++) {
                    assert_true(h[k] == h[0]);
                }
            } else {
                /* Only the default origin precedes the first switch. */
                assert_string_equal(PUBNUB_CFG_ORIGIN, h);
            }
        }
        pn_prep_release(ctx, entry);

        assert_int_equal(
            PUBNUB_OK,
            pn_context_origin_snapshot(ctx, host, sizeof(host), &generation));
        done = (generation >= RACE_SWITCHES - 1);
        built++;
    }

    assert_int_equal(0, pn_test_thread_join(&thread));
    assert_true(built > 0);
    pubnub_destroy(ctx);
}

#endif /* PUBNUB_CFG_THREAD_SAFETY */

#endif /* !PUBNUB_CFG_NO_HEAP */

int main(void)
{
#if !PUBNUB_CFG_NO_HEAP
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(snapshot_returns_host_and_generation),
        cmocka_unit_test(snapshot_rejects_bad_arguments),
#if PUBNUB_CFG_THREAD_SAFETY
        cmocka_unit_test(concurrent_set_origin_never_yields_torn_host),
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
#else
    return 0;
#endif
}
