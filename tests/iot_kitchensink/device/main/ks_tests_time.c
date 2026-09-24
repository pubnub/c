/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "ks_test_runner.h"

#include "pubnub/client.h"
#include "pubnub/features/time.h"
#include "pubnub/future.h"

#include "sdkconfig.h"

#include <string.h>

/**
 * time/basic: call pubnub_time(), verify PUBNUB_OK and a 17-char
 * timetoken string.
 */
static ks_result_t test_time_basic(ks_runner_t* runner)
{
    char               tt_buf[24] = {0};
    pubnub_future_t    fut;
    pubnub_res_t       rc;
    pubnub_timetoken_t tt;
    size_t             copy;

    fut = pubnub_time(runner->ctx);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("pubnub_time failed: %s", pubnub_res_str(rc));
    }

    tt = pubnub_time_result_timetoken(fut);
    if (NULL == tt.ptr || 0 == tt.len) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("timetoken is empty");
    }

    copy = tt.len < sizeof(tt_buf) - 1U ? tt.len : sizeof(tt_buf) - 1U;
    memcpy(tt_buf, tt.ptr, copy);
    tt_buf[copy] = '\0';
    pubnub_future_release(fut);

    if (17 != tt.len) {
        KS_RETURN_FAIL("timetoken length %u, expected 17", (unsigned)tt.len);
    }

    KS_RETURN_PASS();
}

/**
 * time/server_reachable: call pubnub_time() and verify the returned
 * timetoken is a plausible Unix epoch (> year 2020 in PubNub
 * 10MHz ticks).
 */
static ks_result_t test_time_server_reachable(ks_runner_t* runner)
{
    char               tt_buf[24] = {0};
    pubnub_future_t    fut;
    pubnub_res_t       rc;
    pubnub_timetoken_t tt;
    size_t             copy;
    uint64_t           val = 0;
    size_t             i;

    fut = pubnub_time(runner->ctx);
    rc = ks_pump_until_ready(runner->ctx, fut, CONFIG_PUBNUB_KS_TEST_TIMEOUT_MS);

    if (PUBNUB_OK != rc) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("pubnub_time failed: %s", pubnub_res_str(rc));
    }

    tt = pubnub_time_result_timetoken(fut);
    if (NULL == tt.ptr || 0 == tt.len) {
        pubnub_future_release(fut);
        KS_RETURN_FAIL("timetoken is empty");
    }

    copy = tt.len < sizeof(tt_buf) - 1U ? tt.len : sizeof(tt_buf) - 1U;
    memcpy(tt_buf, tt.ptr, copy);
    tt_buf[copy] = '\0';
    pubnub_future_release(fut);

    /* PubNub timetokens are Unix epoch in 10MHz units (10^-7 s).
     * 2020-01-01T00:00:00Z = 1577836800 seconds
     * = 15778368000000000 in PubNub ticks (16 digits).
     * A valid current timetoken should exceed this. */
    for (i = 0; i < copy; i++) {
        char c = tt_buf[i];
        if (c < '0' || c > '9') {
            KS_RETURN_FAIL("timetoken contains non-digit at pos %u", (unsigned)i);
        }
        val = val * 10 + (uint64_t)(c - '0');
    }

    /* 15778368000000000 = ~1.58e16 */
    if (val < 15778368000000000ULL) {
        KS_RETURN_FAIL("timetoken %s is before 2020", tt_buf);
    }

    KS_RETURN_PASS();
}

const ks_test_entry_t ks_time_tests[] = {
    {"time/basic",            test_time_basic,            0},
    {"time/server_reachable", test_time_server_reachable, 0},
};

const size_t ks_time_test_count = sizeof(ks_time_tests) / sizeof(ks_time_tests[0]);
