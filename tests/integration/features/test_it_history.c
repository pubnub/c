/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/history.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/response.h"

#if PUBNUB_ENABLE_CRYPTO
#include "pubnub/features/crypto.h"
#endif

#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

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

/** Publish @p count messages from @p msgs to @p channel in sequence.
 *  When @p out_tt_bufs is non-NULL, the server-assigned publish
 *  timetoken for each message is copied into @p out_tt_bufs[i] as a
 *  NUL-terminated 17-digit string before the future is released. */
static void publish_n_messages(pubnub_context_t* ctx,
                               const char*       channel,
                               const char* const msgs[],
                               size_t            count,
                               char (*out_tt_bufs)[18])
{
    for (size_t i = 0U; i < count; ++i) {
        pubnub_future_t fut = pubnub_publish(
            ctx, &(pubnub_publish_opts_t){.channel = channel, .message = msgs[i]});
        pubnub_res_t st = pubnub_await(fut);
        assert_int_equal(PUBNUB_OK, st);
        if (NULL != out_tt_bufs) {
            pubnub_timetoken_t tt = pubnub_publish_result_timetoken(fut);
            size_t             n  = tt.len < 17U ? tt.len : 17U;
            memcpy(out_tt_bufs[i], tt.ptr, n);
            out_tt_bufs[i][n] = '\0';
        }
        pubnub_future_release(fut);
    }
}

static void fetch_messages_returns_published_messages(void** state)
{
    it_test_state_t*  s       = *state;
    const char* const msgs[3] = {"\"A\"", "\"B\"", "\"C\""};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 3U, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = s->channel;
    opts.count                        = 10U;

    pubnub_future_t fut = pubnub_fetch_messages(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(fut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(fut, 0U);
    assert_int_equal(3, (int)ch.message_count);

    for (size_t i = 0U; i < ch.message_count; ++i) {
        pubnub_history_message_result_t msg =
            pubnub_fetch_messages_result_message_at(fut, 0U, i);
        assert_non_null(msg.message);
    }
    pubnub_future_release(fut);
}

static void fetch_messages_with_start_end_returns_range(void** state)
{
    it_test_state_t* s = *state;
    const char* const msgs[5] = {"\"M0\"", "\"M1\"", "\"M2\"", "\"M3\"", "\"M4\""};
    char tt_bufs[5][18] = {0};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 5U, tt_bufs);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* start=tt_bufs[4] (exclusive upper): return messages older than
     * tt_bufs[4].  end=tt_bufs[1] (inclusive lower): return messages
     * newer than or equal to tt_bufs[1].  Combined range matches M1,
     * M2, M3 (three messages). */
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = s->channel;
    opts.count                        = 10U;
    opts.start                        = tt_bufs[4];
    opts.end                          = tt_bufs[1];

    pubnub_future_t fut = pubnub_fetch_messages(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(fut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(fut, 0U);
    assert_int_equal(3, (int)ch.message_count);
    pubnub_future_release(fut);
}

static void message_counts_returns_correct_count(void** state)
{
    it_test_state_t*  s       = *state;
    const char* const msgs[4] = {"\"pre\"", "\"one\"", "\"two\"", "\"three\""};
    char              tt_bufs[4][18] = {0};
    print_message("channel: %s", s->channel);

    /* Publish four messages and capture all timetokens.  The first
     * timetoken (tt_bufs[0]) serves as the reference boundary:
     * message_counts returns the count of messages published strictly
     * after it, which equals three. */
    publish_n_messages(s->ctx, s->channel, msgs, 4U, tt_bufs);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_message_counts_opts_t copts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    copts.channels                     = s->channel;
    copts.timetoken                    = tt_bufs[0];

    pubnub_future_t fut = pubnub_message_counts(s->ctx, &copts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("message_counts failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_message_counts_result_t res = pubnub_message_counts_result(fut);
    assert_true(0U < res.channel_count);

    pubnub_message_counts_channel_result_t ch =
        pubnub_message_counts_result_channel_at(fut, 0U);
    assert_true(3U <= ch.count);
    pubnub_future_release(fut);
}

static void delete_messages_removes_from_history(void** state)
{
    it_test_state_t*  s       = *state;
    const char* const msgs[2] = {"\"del-a\"", "\"del-b\""};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 2U, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_delete_messages_opts_t dopts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    dopts.channel                       = s->channel;

    pubnub_future_t dfut = pubnub_delete_messages(s->ctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("delete_messages failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, dst);
    pubnub_future_release(dfut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t fopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    fopts.channels                     = s->channel;
    fopts.count                        = 10U;

    pubnub_future_t ffut = pubnub_fetch_messages(s->ctx, &fopts);
    pubnub_res_t    fst  = pubnub_await(ffut);
    if (PUBNUB_OK != fst) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(fst),
                    pubnub_response_status_code(ffut));
    }
    assert_int_equal(PUBNUB_OK, fst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(ffut);
    uint32_t                       msg_count = 0U;
    if (0U < res.channel_count) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(ffut, 0U);
        msg_count = ch.message_count;
    }
    pubnub_future_release(ffut);
    assert_int_equal(0, (int)msg_count);
}

static void fetch_messages_with_include_uuid_returns_publisher(void** state)
{
    it_test_state_t*  s       = *state;
    const char* const msgs[1] = {"\"uuid-probe\""};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 1U, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* include_uuid defaults to 1 via PUBNUB_FETCH_MESSAGES_OPTS_INIT. */
    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = s->channel;
    opts.count                        = 1U;

    pubnub_future_t fut = pubnub_fetch_messages(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(fut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(fut, 0U);
    assert_true(0U < ch.message_count);

    pubnub_history_message_result_t msg =
        pubnub_fetch_messages_result_message_at(fut, 0U, 0U);
    assert_true(0U < msg.uuid.len);
    assert_int_equal((int)strlen(s->user_id), (int)msg.uuid.len);
    assert_memory_equal(s->user_id, msg.uuid.ptr, msg.uuid.len);
    pubnub_future_release(fut);
}

static void fetch_messages_with_custom_message_type_round_trips(void** state)
{
    it_test_state_t* s = *state;
    print_message("channel: %s", s->channel);

    pubnub_publish_opts_t popts = PUBNUB_PUBLISH_OPTS_INIT;
    popts.channel               = s->channel;
    popts.message               = "\"typed-msg\"";
    popts.custom_message_type   = "hist-type";

    pubnub_future_t pfut = pubnub_publish(s->ctx, &popts);
    pubnub_res_t    pst  = pubnub_await(pfut);
    if (PUBNUB_OK != pst) {
        print_error("publish failed: %s (http=%d)",
                    pubnub_res_str(pst),
                    pubnub_response_status_code(pfut));
    }
    assert_int_equal(PUBNUB_OK, pst);
    pubnub_future_release(pfut);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t fopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    fopts.channels                     = s->channel;
    fopts.count                        = 1U;
    fopts.include_custom_message_type  = 1U;

    pubnub_future_t ffut = pubnub_fetch_messages(s->ctx, &fopts);
    pubnub_res_t    fst  = pubnub_await(ffut);
    if (PUBNUB_OK != fst) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(fst),
                    pubnub_response_status_code(ffut));
    }
    assert_int_equal(PUBNUB_OK, fst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(ffut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(ffut, 0U);
    assert_true(0U < ch.message_count);

    pubnub_history_message_result_t msg =
        pubnub_fetch_messages_result_message_at(ffut, 0U, 0U);
    assert_true(0U < msg.custom_message_type.len);
    assert_int_equal(9, (int)msg.custom_message_type.len);
    assert_memory_equal("hist-type", msg.custom_message_type.ptr, 9U);
    pubnub_future_release(ffut);
}

static void fetch_messages_with_crypto_decrypts_transparently(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    it_test_state_t*        s    = *state;
    pubnub_crypto_module_t* cm   = NULL;
    pubnub_context_t*       cctx = NULL;
    print_message("channel: %s", s->channel);

    cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->env->subscribe_key;
    cfg.publish_key                = s->env->publish_key;
    cfg.user_id                    = s->user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.crypto_module              = cm;

    cctx = pubnub_create(&cfg);
    if (NULL == cctx) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create crypto context");
    }

    pubnub_future_t pfut = pubnub_publish(
        cctx,
        &(pubnub_publish_opts_t){.channel = s->channel, .message = "\"secret\""});
    pubnub_res_t pst = pubnub_await(pfut);
    if (PUBNUB_OK != pst) {
        print_error("publish failed: %s (http=%d)",
                    pubnub_res_str(pst),
                    pubnub_response_status_code(pfut));
    }
    assert_int_equal(PUBNUB_OK, pst);
    pubnub_future_release(pfut);

    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t fopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    fopts.channels                     = s->channel;
    fopts.count                        = 1U;

    pubnub_future_t ffut = pubnub_fetch_messages(cctx, &fopts);
    pubnub_res_t    fst  = pubnub_await(ffut);
    if (PUBNUB_OK != fst) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(fst),
                    pubnub_response_status_code(ffut));
    }
    assert_int_equal(PUBNUB_OK, fst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(ffut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(ffut, 0U);
    assert_true(0U < ch.message_count);

    pubnub_history_message_result_t msg =
        pubnub_fetch_messages_result_message_at(ffut, 0U, 0U);
    assert_non_null(msg.message);

    pubnub_serialization_provider_t* serial = pubnub_serialization(cctx);
    assert_non_null(serial);
    size_t      slen = 0U;
    const char* sptr = serial->value_as_string(msg.message, &slen);
    assert_non_null(sptr);
    assert_int_equal(6, (int)slen);
    assert_memory_equal("secret", sptr, 6U);
    pubnub_future_release(ffut);

    pubnub_destroy(cctx);
    pubnub_crypto_module_destroy(cm);
#else
    (void)state;
    skip();
#endif
}

static void fetch_messages_reverse_order(void** state)
{
    it_test_state_t*  s       = *state;
    const char* const msgs[3] = {"\"A\"", "\"B\"", "\"C\""};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 3U, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = s->channel;
    opts.count                        = 10U;
    opts.reverse                      = 1U;

    pubnub_future_t fut = pubnub_fetch_messages(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(fut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(fut, 0U);
    assert_int_equal(3, (int)ch.message_count);

    /* reverse=1 returns oldest first: index 0="A", 1="B", 2="C". */
    static const char* const         expected[3] = {"A", "B", "C"};
    pubnub_serialization_provider_t* serial      = pubnub_serialization(s->ctx);
    assert_non_null(serial);

    for (size_t i = 0U; i < 3U; ++i) {
        pubnub_history_message_result_t msg =
            pubnub_fetch_messages_result_message_at(fut, 0U, i);
        assert_non_null(msg.message);
        size_t      slen = 0U;
        const char* sptr = serial->value_as_string(msg.message, &slen);
        assert_non_null(sptr);
        assert_int_equal(1, (int)slen);
        assert_memory_equal(expected[i], sptr, 1U);
    }
    pubnub_future_release(fut);
}

static void unencrypted_message_with_crypto_configured_surfaces_error(void** state)
{
#if PUBNUB_ENABLE_CRYPTO
    it_test_state_t*        s    = *state;
    pubnub_crypto_module_t* cm   = NULL;
    pubnub_context_t*       cctx = NULL;
    print_message("channel: %s", s->channel);

    /* Publish a plain (unencrypted) message using the base context. */
    pubnub_future_t pfut = pubnub_publish(
        s->ctx,
        &(pubnub_publish_opts_t){.channel = s->channel, .message = "\"plain\""});
    pubnub_res_t pst = pubnub_await(pfut);
    if (PUBNUB_OK != pst) {
        print_error("publish failed: %s (http=%d)",
                    pubnub_res_str(pst),
                    pubnub_response_status_code(pfut));
    }
    assert_int_equal(PUBNUB_OK, pst);
    pubnub_future_release(pfut);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* Create a context with a crypto module — the stored message is plain. */
    cm = pubnub_crypto_module_aes_cbc("enigma", 1, NULL);
    assert_non_null(cm);

    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->env->subscribe_key;
    cfg.publish_key                = s->env->publish_key;
    cfg.user_id                    = s->user_id;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;
    cfg.crypto_module              = cm;

    cctx = pubnub_create(&cfg);
    if (NULL == cctx) {
        pubnub_crypto_module_destroy(cm);
        fail_msg("failed to create crypto context");
    }

    pubnub_fetch_messages_opts_t fopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    fopts.channels                     = s->channel;
    fopts.count                        = 1U;

    pubnub_future_t ffut = pubnub_fetch_messages(cctx, &fopts);
    pubnub_res_t    fst  = pubnub_await(ffut);
    if (PUBNUB_OK != fst) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(fst),
                    pubnub_response_status_code(ffut));
    }
    assert_int_equal(PUBNUB_OK, fst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(ffut);
    assert_true(0U < res.channel_count);

    pubnub_fetch_messages_channel_result_t ch =
        pubnub_fetch_messages_result_channel_at(ffut, 0U);
    assert_true(0U < ch.message_count);

    pubnub_history_message_result_t msg =
        pubnub_fetch_messages_result_message_at(ffut, 0U, 0U);
    assert_int_equal(PUBNUB_ERR_CRYPTO, (int)msg.crypto_result);
    assert_non_null(msg.message);

    pubnub_future_release(ffut);
    pubnub_destroy(cctx);
    pubnub_crypto_module_destroy(cm);
#else
    (void)state;
    skip();
#endif
}

static void delete_messages_range_removes_subset(void** state)
{
    it_test_state_t*  s              = *state;
    const char* const msgs[4]        = {"\"M0\"", "\"M1\"", "\"M2\"", "\"M3\""};
    char              tt_bufs[4][18] = {0};
    print_message("channel: %s", s->channel);

    publish_n_messages(s->ctx, s->channel, msgs, 4U, tt_bufs);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* Delete messages M1 and M2 using a half-open range [start, end):
     * start is inclusive on the server — M1 (at tt_bufs[1]) is included
     * in the deletion.  end is exclusive — M3 (at tt_bufs[3]) is kept.
     * M0 is below start, so it is kept. */
    pubnub_delete_messages_opts_t dopts = PUBNUB_DELETE_MESSAGES_OPTS_INIT;
    dopts.channel                       = s->channel;
    dopts.start                         = tt_bufs[1];
    dopts.end                           = tt_bufs[3];

    pubnub_future_t dfut = pubnub_delete_messages(s->ctx, &dopts);
    pubnub_res_t    dst  = pubnub_await(dfut);
    if (PUBNUB_OK != dst) {
        print_error("delete_messages failed: %s (http=%d)",
                    pubnub_res_str(dst),
                    pubnub_response_status_code(dfut));
    }
    assert_int_equal(PUBNUB_OK, dst);
    pubnub_future_release(dfut);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* After deletion M0 and M3 remain — expect exactly 2 messages. */
    pubnub_fetch_messages_opts_t fopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    fopts.channels                     = s->channel;
    fopts.count                        = 10U;

    pubnub_future_t ffut = pubnub_fetch_messages(s->ctx, &fopts);
    pubnub_res_t    fst  = pubnub_await(ffut);
    if (PUBNUB_OK != fst) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(fst),
                    pubnub_response_status_code(ffut));
    }
    assert_int_equal(PUBNUB_OK, fst);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(ffut);
    pubnub_fetch_messages_channel_result_t ch = {0};
    if (0U < res.channel_count) {
        ch = pubnub_fetch_messages_result_channel_at(ffut, 0U);
    }
    pubnub_future_release(ffut);
    assert_int_equal(2, (int)ch.message_count);
}

static void fetch_messages_multi_channel_returns_per_channel_results(void** state)
{
    it_test_state_t*  s             = *state;
    const char* const msgs_ch1[2]   = {"\"MC-A\"", "\"MC-B\""};
    const char* const msgs_ch2[1]   = {"\"MC-C\""};
    char              ch_combo[160] = {0};
    const size_t      ch1_len       = strlen(s->channel);
    const size_t      ch2_len       = strlen(s->channel2);
    uint32_t          ch1_count     = 0U;
    uint32_t          ch2_count     = 0U;
    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);

    publish_n_messages(s->ctx, s->channel, msgs_ch1, 2U, NULL);
    publish_n_messages(s->ctx, s->channel2, msgs_ch2, 1U, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel2, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    snprintf(ch_combo, sizeof(ch_combo), "%s,%s", s->channel, s->channel2);

    pubnub_fetch_messages_opts_t opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts.channels                     = ch_combo;
    opts.count                        = 10U;

    pubnub_future_t fut = pubnub_fetch_messages(s->ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("fetch_messages failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_fetch_messages_result_t res = pubnub_fetch_messages_result(fut);
    assert_int_equal(2, (int)res.channel_count);

    for (size_t i = 0U; i < (size_t)res.channel_count; ++i) {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(fut, i);
        if (ch1_len == ch.name.len && 0 == memcmp(s->channel, ch.name.ptr, ch1_len)) {
            ch1_count = ch.message_count;
        } else if (ch2_len == ch.name.len
                   && 0 == memcmp(s->channel2, ch.name.ptr, ch2_len)) {
            ch2_count = ch.message_count;
        }
    }
    assert_int_equal(2, (int)ch1_count);
    assert_int_equal(1, (int)ch2_count);
    pubnub_future_release(fut);
}

static void message_counts_multi_channel_returns_per_channel_counts(void** state)
{
    it_test_state_t*  s                = *state;
    const char* const before_msg[1]    = {"\"before\""};
    const char* const ch1_extra[2]     = {"\"cnt-B\"", "\"cnt-C\""};
    const char* const ch2_msgs[1]      = {"\"cnt-D\""};
    char              before_tt[1][18] = {0};
    char              ch_combo[160]    = {0};
    const size_t      ch1_len          = strlen(s->channel);
    const size_t      ch2_len          = strlen(s->channel2);
    uint32_t          ch1_count        = 0U;
    uint32_t          ch2_count        = 0U;
    print_message("ch1: %s  ch2: %s", s->channel, s->channel2);

    /* Publish the boundary message to ch1 and capture its timetoken.
     * message_counts counts messages published strictly after before_tt:
     * ch1 gets 2 more, ch2 gets 1. */
    publish_n_messages(s->ctx, s->channel, before_msg, 1U, before_tt);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel2, NULL);

    publish_n_messages(s->ctx, s->channel, ch1_extra, 2U, NULL);
    publish_n_messages(s->ctx, s->channel2, ch2_msgs, 1U, NULL);

    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    snprintf(ch_combo, sizeof(ch_combo), "%s,%s", s->channel, s->channel2);

    pubnub_message_counts_opts_t copts = PUBNUB_MESSAGE_COUNTS_OPTS_INIT;
    copts.channels                     = ch_combo;
    copts.timetoken                    = before_tt[0];

    pubnub_future_t fut = pubnub_message_counts(s->ctx, &copts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        print_error("message_counts failed: %s (http=%d)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut));
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_message_counts_result_t res = pubnub_message_counts_result(fut);
    assert_int_equal(2, (int)res.channel_count);

    for (size_t i = 0U; i < (size_t)res.channel_count; ++i) {
        pubnub_message_counts_channel_result_t ch =
            pubnub_message_counts_result_channel_at(fut, i);
        if (ch1_len == ch.name.len && 0 == memcmp(s->channel, ch.name.ptr, ch1_len)) {
            ch1_count = ch.count;
        } else if (ch2_len == ch.name.len
                   && 0 == memcmp(s->channel2, ch.name.ptr, ch2_len)) {
            ch2_count = ch.count;
        }
    }
    assert_true(2U <= ch1_count);
    assert_true(1U <= ch2_count);
    pubnub_future_release(fut);
}

static void fetch_messages_pagination_returns_all_pages(void** state)
{
    it_test_state_t* s = *state;
    const char* const msgs[5] = {"\"P1\"", "\"P2\"", "\"P3\"", "\"P4\"", "\"P5\""};
    print_message("channel: %s", s->channel);
    publish_n_messages(s->ctx, s->channel, msgs, 5U, NULL);
    it_cleanup_add(&s->cleanup, IT_CLEANUP_DELETE_MESSAGES, s->channel, NULL);
    pn_test_sleep_ms(IT_DELAY_HISTORY_MS);

    /* Page 1: fetch 3 messages (leaves 2 older ones in history). */
    pubnub_fetch_messages_opts_t opts1 = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts1.channels                     = s->channel;
    opts1.count                        = 3;
    pubnub_future_t fut1               = pubnub_fetch_messages(s->ctx, &opts1);
    assert_int_equal(PUBNUB_OK, pubnub_await(fut1));

    pubnub_fetch_messages_result_t r1 = pubnub_fetch_messages_result(fut1);
    pubnub_fetch_messages_channel_result_t ch1 =
        pubnub_fetch_messages_result_channel_at(fut1, 0);
    assert_int_equal(3, (int)ch1.message_count);

    /* The next-page cursor is a server-optional field. When the server
     * includes a "more" object the cursor is ready-to-use. When not,
     * derive a cursor from the oldest timetoken in the current page. */
    char next_tt[18] = {0};
    if (0 < r1.next.len) {
        print_message("server returned cursor (len=%zu)", r1.next.len);
        size_t n = r1.next.len < 17U ? r1.next.len : 17U;
        memcpy(next_tt, r1.next.ptr, n);
    } else {
        print_message("no server cursor; using oldest timetoken from page 1");
        /* Messages are returned in ascending timetoken order: index 0 is
         * the oldest of the returned batch, so use it as an exclusive
         * upper bound (start=) to reach the prior messages. */
        pubnub_history_message_result_t oldest =
            pubnub_fetch_messages_result_message_at(fut1, 0, 0);
        size_t n = oldest.timetoken.len < 17U ? oldest.timetoken.len : 17U;
        memcpy(next_tt, oldest.timetoken.ptr, n);
    }
    pubnub_future_release(fut1);
    assert_true(0 < (int)strlen(next_tt));

    /* Page 2: use the cursor as start= to retrieve the older messages. */
    pubnub_fetch_messages_opts_t opts2 = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    opts2.channels                     = s->channel;
    opts2.count                        = 10;
    opts2.start                        = next_tt;
    pubnub_future_t fut2               = pubnub_fetch_messages(s->ctx, &opts2);
    assert_int_equal(PUBNUB_OK, pubnub_await(fut2));

    pubnub_fetch_messages_channel_result_t ch2 =
        pubnub_fetch_messages_result_channel_at(fut2, 0);
    assert_true(0 < (int)ch2.message_count);
    pubnub_future_release(fut2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            fetch_messages_returns_published_messages, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_with_start_end_returns_range, setup, teardown),
        cmocka_unit_test_setup_teardown(
            message_counts_returns_correct_count, setup, teardown),
        cmocka_unit_test_setup_teardown(
            delete_messages_removes_from_history, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_with_include_uuid_returns_publisher, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_with_custom_message_type_round_trips, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_with_crypto_decrypts_transparently, setup, teardown),
        cmocka_unit_test_setup_teardown(fetch_messages_reverse_order, setup, teardown),
        cmocka_unit_test_setup_teardown(
            unencrypted_message_with_crypto_configured_surfaces_error, setup, teardown),
        cmocka_unit_test_setup_teardown(
            delete_messages_range_removes_subset, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_multi_channel_returns_per_channel_results, setup, teardown),
        cmocka_unit_test_setup_teardown(
            message_counts_multi_channel_returns_per_channel_counts, setup, teardown),
        cmocka_unit_test_setup_teardown(
            fetch_messages_pagination_returns_all_pages, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
