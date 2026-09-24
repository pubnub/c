/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/push.h"
#include "pubnub/future.h"

#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

#define PN_TEST_GCM_TOKEN                                                      \
    "f7Y_X3zR2EC5Q9V-zN_7mP:APA91bH4W8vK6L2M9oP_"                              \
    "x3qR7sT5uV1wX2yZ3aB4cC5dE6fG7hI8"                                         \
    "jK9lL0mN1oP2qR3sT4uV5wX6yZ7aB8cC9dE0fG1hI2jK3lL4mN5oP6qR7sT8uV9wX0yZ1aB2" \
    "cC3"                                                                      \
    "dE4fG5hI6"
#define PN_TEST_APNS_TOKEN \
    "6652cff7f17536c86bc353527017741ec07a91699661abaf68c5977a83013091"
#define PN_TEST_APNS2_TOPIC "com.pubnub.ctest"

/** @brief Per-test state for push notification integration tests. */
typedef struct {
    /** Base state with contexts, channels, and cleanup queue. */
    it_test_state_t* base;
    /** GCM/FCM device token for this test run. */
    char gcm_token[256];
    /** APNS2 device token for this test run. */
    char apns_token[128];
} push_state_t;

static int channel_in_push_list(pubnub_future_t fut, uint32_t count, const char* name)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < (size_t)count; ++i) {
        pubnub_string_view_t v =
            pubnub_push_list_channels_result_channel_at(fut, i);
        if (v.len == name_len && 0 == memcmp(v.ptr, name, v.len)) {
            return 1;
        }
    }
    return 0;
}

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    push_state_t*   s;

    SKIP_IF_NO_KEYS(env);
    s = calloc(1, sizeof(*s));
    if (NULL == s) {
        return -1;
    }
    s->base = it_state_create(env);
    if (NULL == s->base) {
        free(s);
        return -1;
    }
    snprintf(s->gcm_token, sizeof(s->gcm_token), "%s", PN_TEST_GCM_TOKEN);
    snprintf(s->apns_token, sizeof(s->apns_token), "%s", PN_TEST_APNS_TOKEN);
    /* Splice a per-run unique 4-char hex segment into both tokens so that
     * concurrent CI jobs cannot interfere through `remove_device` cleanup
     * calls on a shared device identifier.  `it_unique_name` returns a string
     * of the form "pn-it-XXXXXXXX-push" where XXXXXXXX is 8 lowercase hex
     * chars — valid for APNS and acceptable for GCM. */
    {
        const char* run_id = it_unique_name("push");
        memcpy(s->apns_token, run_id + 6, 4);
        memcpy(s->gcm_token, run_id + 6, 4);
    }
    /* FCM: b=NULL → gateway=FCM; APNS2: b=topic → gateway=APNS2. */
    it_cleanup_add(
        &s->base->cleanup, IT_CLEANUP_REMOVE_PUSH_DEVICE, s->gcm_token, NULL);
    it_cleanup_add(&s->base->cleanup,
                   IT_CLEANUP_REMOVE_PUSH_DEVICE,
                   s->apns_token,
                   PN_TEST_APNS2_TOPIC);
    *state = s;
    return 0;
}

static int teardown(void** state)
{
    push_state_t* s = *state;
    it_state_destroy(s->base);
    free(s);
    return 0;
}

static void push_add_channels_gcm_returns_ok(void** state)
{
    push_state_t*                   s    = *state;
    pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_future_t                 fut;

    print_message("gcm channel: %s", s->base->channel);

    opts.device   = s->gcm_token;
    opts.gateway  = PUBNUB_PUSH_FCM;
    opts.channels = s->base->channel;
    fut           = pubnub_push_add_channels(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void push_list_channels_gcm_returns_added(void** state)
{
    push_state_t*                      s  = *state;
    pubnub_push_add_channels_opts_t    ao = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_opts_t   lo = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_result_t res;
    pubnub_future_t                    fut;
    char                               both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("gcm channels: %s", both);

    ao.device   = s->gcm_token;
    ao.gateway  = PUBNUB_PUSH_FCM;
    ao.channels = both;
    fut         = pubnub_push_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_PUSH_MS);

    lo.device  = s->gcm_token;
    lo.gateway = PUBNUB_PUSH_FCM;
    fut        = pubnub_push_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_push_list_channels_result(fut);
    assert_int_not_equal(0, (int)res.channel_count);
    assert_int_not_equal(
        0, channel_in_push_list(fut, res.channel_count, s->base->channel));
    assert_int_not_equal(
        0, channel_in_push_list(fut, res.channel_count, s->base->channel2));
    pubnub_future_release(fut);
}

static void push_remove_channels_gcm_returns_ok(void** state)
{
    push_state_t*                   s  = *state;
    pubnub_push_add_channels_opts_t ao = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_push_remove_channels_opts_t ro = PUBNUB_PUSH_REMOVE_CHANNELS_OPTS_INIT;
    pubnub_future_t fut;
    char            both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("gcm remove: %s", s->base->channel);

    ao.device   = s->gcm_token;
    ao.gateway  = PUBNUB_PUSH_FCM;
    ao.channels = both;
    fut         = pubnub_push_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ro.device   = s->gcm_token;
    ro.gateway  = PUBNUB_PUSH_FCM;
    ro.channels = s->base->channel;
    fut         = pubnub_push_remove_channels(s->base->ctx, &ro);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void push_list_after_remove_gcm_reflects_removal(void** state)
{
    push_state_t*                   s  = *state;
    pubnub_push_add_channels_opts_t ao = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_push_remove_channels_opts_t ro = PUBNUB_PUSH_REMOVE_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_opts_t   lo = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_result_t res;
    pubnub_future_t                    fut;
    char                               both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("gcm remove: %s", s->base->channel);

    ao.device   = s->gcm_token;
    ao.gateway  = PUBNUB_PUSH_FCM;
    ao.channels = both;
    fut         = pubnub_push_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    ro.device   = s->gcm_token;
    ro.gateway  = PUBNUB_PUSH_FCM;
    ro.channels = s->base->channel;
    fut         = pubnub_push_remove_channels(s->base->ctx, &ro);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_PUSH_MS);

    lo.device  = s->gcm_token;
    lo.gateway = PUBNUB_PUSH_FCM;
    fut        = pubnub_push_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_push_list_channels_result(fut);
    assert_int_equal(
        0, channel_in_push_list(fut, res.channel_count, s->base->channel));
    assert_int_not_equal(
        0, channel_in_push_list(fut, res.channel_count, s->base->channel2));
    pubnub_future_release(fut);
}

static void push_remove_device_gcm_clears_all(void** state)
{
    push_state_t*                      s  = *state;
    pubnub_push_add_channels_opts_t    ao = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_push_remove_device_opts_t   rd = PUBNUB_PUSH_REMOVE_DEVICE_OPTS_INIT;
    pubnub_push_list_channels_opts_t   lo = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_result_t res;
    pubnub_future_t                    fut;
    char                               both[200];

    snprintf(both, sizeof(both), "%s,%s", s->base->channel, s->base->channel2);
    print_message("gcm remove device");

    ao.device   = s->gcm_token;
    ao.gateway  = PUBNUB_PUSH_FCM;
    ao.channels = both;
    fut         = pubnub_push_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    rd.device  = s->gcm_token;
    rd.gateway = PUBNUB_PUSH_FCM;
    fut        = pubnub_push_remove_device(s->base->ctx, &rd);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_PUSH_MS);

    lo.device  = s->gcm_token;
    lo.gateway = PUBNUB_PUSH_FCM;
    fut        = pubnub_push_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_push_list_channels_result(fut);
    assert_int_equal(0, (int)res.channel_count);
    pubnub_future_release(fut);
}

static void push_add_channels_apns_returns_ok(void** state)
{
    push_state_t*                   s    = *state;
    pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_future_t                 fut;

    print_message("apns2 channel: %s", s->base->channel);

    opts.device   = s->apns_token;
    opts.gateway  = PUBNUB_PUSH_APNS2;
    opts.channels = s->base->channel;
    opts.topic    = PN_TEST_APNS2_TOPIC;
    fut           = pubnub_push_add_channels(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

static void push_list_channels_apns_returns_added(void** state)
{
    push_state_t*                      s  = *state;
    pubnub_push_add_channels_opts_t    ao = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_opts_t   lo = PUBNUB_PUSH_LIST_CHANNELS_OPTS_INIT;
    pubnub_push_list_channels_result_t res;
    pubnub_future_t                    fut;

    print_message("apns2 channel: %s", s->base->channel);

    ao.device   = s->apns_token;
    ao.gateway  = PUBNUB_PUSH_APNS2;
    ao.channels = s->base->channel;
    ao.topic    = PN_TEST_APNS2_TOPIC;
    fut         = pubnub_push_add_channels(s->base->ctx, &ao);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);

    pn_test_sleep_ms(IT_DELAY_PUSH_MS);

    lo.device  = s->apns_token;
    lo.gateway = PUBNUB_PUSH_APNS2;
    lo.topic   = PN_TEST_APNS2_TOPIC;
    fut        = pubnub_push_list_channels(s->base->ctx, &lo);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    res = pubnub_push_list_channels_result(fut);
    assert_int_not_equal(0, (int)res.channel_count);
    assert_int_not_equal(
        0, channel_in_push_list(fut, res.channel_count, s->base->channel));
    pubnub_future_release(fut);
}

static void push_add_channels_apns2_returns_ok(void** state)
{
    push_state_t*                   s    = *state;
    pubnub_push_add_channels_opts_t opts = PUBNUB_PUSH_ADD_CHANNELS_OPTS_INIT;
    pubnub_future_t                 fut;

    print_message("apns2+env channel: %s", s->base->channel);

    opts.device      = s->apns_token;
    opts.gateway     = PUBNUB_PUSH_APNS2;
    opts.channels    = s->base->channel;
    opts.topic       = PN_TEST_APNS2_TOPIC;
    opts.environment = PUBNUB_PUSH_ENV_DEVELOPMENT;
    fut              = pubnub_push_add_channels(s->base->ctx, &opts);
    assert_int_equal(PUBNUB_OK, (int)pubnub_await(fut));
    pubnub_future_release(fut);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            push_add_channels_gcm_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_list_channels_gcm_returns_added, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_remove_channels_gcm_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_list_after_remove_gcm_reflects_removal, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_remove_device_gcm_clears_all, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_add_channels_apns_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_list_channels_apns_returns_added, setup, teardown),
        cmocka_unit_test_setup_teardown(
            push_add_channels_apns2_returns_ok, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
