/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "pubnub/features/channel_groups.h"

static void add_channels_should_reject_null_ctx(void** state)
{
    (void)state;
    pubnub_channel_group_add_opts_t opts = {
        .channel_group = "grp",
        .channels      = "ch1,ch2",
    };
    pubnub_future_t fut = pubnub_channel_group_add_channels(NULL, &opts);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void add_channels_should_reject_null_opts(void** state)
{
    (void)state;
    pubnub_future_t fut = pubnub_channel_group_add_channels(NULL, NULL);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void remove_channels_should_reject_null_opts(void** state)
{
    (void)state;
    pubnub_future_t fut = pubnub_channel_group_remove_channels(NULL, NULL);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void list_channels_should_reject_null_opts(void** state)
{
    (void)state;
    pubnub_future_t fut = pubnub_channel_group_list_channels(NULL, NULL);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

static void remove_group_should_reject_null_opts(void** state)
{
    (void)state;
    pubnub_future_t fut = pubnub_channel_group_remove(NULL, NULL);
    assert_int_equal(pubnub_future_status(fut), PUBNUB_ERR_INVALID_ARGUMENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(add_channels_should_reject_null_ctx),
        cmocka_unit_test(add_channels_should_reject_null_opts),
        cmocka_unit_test(remove_channels_should_reject_null_opts),
        cmocka_unit_test(list_channels_should_reject_null_opts),
        cmocka_unit_test(remove_group_should_reject_null_opts),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
