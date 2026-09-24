/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "pubnub/client.h"
#include "pubnub/config.h"
#include "pubnub/error.h"
#include "pubnub/features/access.h"
#include "pubnub/features/app_context.h"
#include "pubnub/features/channel_groups.h"
#include "pubnub/features/files.h"
#include "pubnub/features/history.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/presence.h"
#include "pubnub/features/publish.h"
#include "pubnub/features/signal.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#include "it_channel.h"
#include "it_cleanup.h"
#include "it_context.h"
#include "it_env.h"
#include "it_wait.h"

typedef struct pam_state {
    it_test_state_t* base;
    char             token[512];
} pam_state_t;

static int setup(void** state)
{
    const it_env_t* env = it_env_load();
    SKIP_IF_NO_PAM_KEYS(env);
    SKIP_IF_NO_KEYS(env);

    it_test_state_t* base = it_state_create(env);
    if (NULL == base) {
        return -1;
    }
    it_state_add_pam_ctx(base);
    if (NULL == base->pam_ctx) {
        it_state_destroy(base);
        return -1;
    }

    pam_state_t* s = calloc(1U, sizeof(*s));
    if (NULL == s) {
        it_state_destroy(base);
        return -1;
    }
    s->base = base;
    *state  = s;
    return 0;
}

static int teardown(void** state)
{
    pam_state_t* s = *state;
    if (NULL != s) {
        it_state_destroy(s->base);
        free(s);
    }
    return 0;
}

static void grant_token_returns_non_empty_token(void** state)
{
    pam_state_t* s = *state;

    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE,
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 1;
    opts.channels                  = &ch;
    opts.channel_count             = 1;

    pubnub_future_t fut = pubnub_grant_token(s->base->pam_ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("grant_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_grant_token_result_t res = pubnub_grant_token_result(fut);
    assert_true(20 < (int)res.token.len);
    pubnub_future_release(fut);
}

static void parse_token_round_trips_permissions(void** state)
{
    pam_state_t* s = *state;

    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("grant_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t gres = pubnub_grant_token_result(gfut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)gres.token.len, gres.token.ptr);
    pubnub_future_release(gfut);

    pubnub_parse_token_opts_t popts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    popts.token                     = s->token;

    pubnub_parsed_token_t tok = {0};
    pubnub_res_t pst = pubnub_parse_token(s->base->pam_ctx, &popts, &tok);
    if (PUBNUB_OK != pst) {
        print_error("parse_token failed: %s", pubnub_res_str(pst));
    }
    assert_int_equal(PUBNUB_OK, pst);
    assert_int_equal(1, (int)tok.ttl);
    assert_true(0 < (int)tok.channel_count);

    pubnub_parsed_token_resource_t r =
        pubnub_parsed_token_channel_at(s->base->pam_ctx, 0);
    assert_true(0 != (r.permissions & PUBNUB_ACCESS_READ));
    assert_true(0 != (r.permissions & PUBNUB_ACCESS_WRITE));
}

static void publish_with_token_on_pam_channel_succeeds(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("grant_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t gres = pubnub_grant_token_result(gfut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)gres.token.len, gres.token.ptr);
    pubnub_future_release(gfut);

    snprintf(uid, sizeof(uid), "%s", it_unique_name("tok-pub"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* tok_ctx = pubnub_create(&cfg);
    assert_non_null(tok_ctx);

    pubnub_set_auth_token(tok_ctx, s->token);

    pubnub_future_t pfut = pubnub_publish(tok_ctx,
                                          &(pubnub_publish_opts_t){
                                              .channel = s->base->channel,
                                              .message = "\"token-test\"",
                                          });
    pubnub_res_t    pst  = pubnub_await(pfut);
    if (PUBNUB_OK != pst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(pfut);
        print_error("publish with token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(pst),
                    pubnub_response_status_code(pfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    pubnub_future_release(pfut);
    pubnub_destroy(tok_ctx);

    assert_int_equal(PUBNUB_OK, pst);
}

static void publish_without_token_on_pam_channel_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut         = pubnub_publish(unauth_ctx,
                                         &(pubnub_publish_opts_t){
                                                     .channel = s->base->channel,
                                                     .message = "\"unauthorized\"",
                                         });
    pubnub_res_t    st          = pubnub_await(fut);
    int             http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void grant_token_with_pattern_permission_returns_ok(void** state)
{
    pam_state_t* s = *state;

    pubnub_access_resource_permission_t pat = {
        .name        = "test-.*",
        .permissions = PUBNUB_ACCESS_READ,
    };
    pubnub_grant_token_opts_t opts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    opts.ttl                       = 1;
    opts.channel_patterns          = &pat;
    opts.channel_pattern_count     = 1;

    pubnub_future_t fut = pubnub_grant_token(s->base->pam_ctx, &opts);
    pubnub_res_t    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(fut);
        print_error("grant_token pattern failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, st);

    pubnub_grant_token_result_t res = pubnub_grant_token_result(fut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)res.token.len, res.token.ptr);
    pubnub_future_release(fut);

    pubnub_parse_token_opts_t popts = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    popts.token                     = s->token;

    pubnub_parsed_token_t tok = {0};
    pubnub_res_t pst = pubnub_parse_token(s->base->pam_ctx, &popts, &tok);
    if (PUBNUB_OK != pst) {
        print_error("parse_token failed: %s", pubnub_res_str(pst));
    }
    assert_int_equal(PUBNUB_OK, pst);
    assert_true(0 < (int)tok.channel_pattern_count);

    pubnub_parsed_token_resource_t r =
        pubnub_parsed_token_channel_pattern_at(s->base->pam_ctx, 0);
    assert_true(0 != (r.permissions & PUBNUB_ACCESS_READ));
}

static void revoke_token_returns_ok(void** state)
{
    pam_state_t* s = *state;

    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("grant_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t gres = pubnub_grant_token_result(gfut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)gres.token.len, gres.token.ptr);
    pubnub_future_release(gfut);

    pubnub_revoke_token_opts_t ropts = PUBNUB_REVOKE_TOKEN_OPTS_INIT;
    ropts.token                      = s->token;

    pubnub_future_t rfut = pubnub_revoke_token(s->base->pam_ctx, &ropts);
    pubnub_res_t    rst  = pubnub_await(rfut);
    if (PUBNUB_OK != rst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(rfut);
        print_error("revoke_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(rst),
                    pubnub_response_status_code(rfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    pubnub_future_release(rfut);
    assert_int_equal(PUBNUB_OK, rst);
}

static void signal_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-sig"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_signal(
        unauth_ctx,
        &(pubnub_signal_opts_t){.channel = s->base->channel, .message = "\"x\""});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void history_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-hist"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_fetch_messages(
        unauth_ctx,
        &(pubnub_fetch_messages_opts_t){.channels = s->base->channel, .count = 1});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void here_now_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-hn"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_here_now(
        unauth_ctx, &(pubnub_here_now_opts_t){.channels = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void get_state_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-gs"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_get_state(
        unauth_ctx,
        &(pubnub_get_state_opts_t){.channels = s->base->channel, .uuid = uid});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void get_uuid_metadata_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-um"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_get_uuid_metadata(
        unauth_ctx, &(pubnub_get_uuid_metadata_opts_t){.uuid = uid});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void get_channel_metadata_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-cm"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_get_channel_metadata(
        unauth_ctx,
        &(pubnub_get_channel_metadata_opts_t){.channel = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void list_channel_groups_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-cg"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_channel_group_list_channels(
        unauth_ctx,
        &(pubnub_channel_group_list_opts_t){.channel_group = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void get_message_actions_without_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-ma"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_get_message_actions(
        unauth_ctx,
        &(pubnub_get_message_actions_opts_t){.channel = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void list_files_without_token_on_pam_keyset_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    snprintf(uid, sizeof(uid), "%s", it_unique_name("no-tok-fl"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* unauth_ctx = pubnub_create(&cfg);
    assert_non_null(unauth_ctx);

    pubnub_future_t fut = pubnub_list_files(
        unauth_ctx, &(pubnub_list_files_opts_t){.channel = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(unauth_ctx);

    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void history_with_expired_token_returns_error(void** state)
{
    pam_state_t* s = *state;

    /* Grant a token with TTL=1 minute (minimum). */
    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    if (PUBNUB_OK != gst) {
        pubnub_string_view_t errmsg = pubnub_response_error_message(gfut);
        print_error("grant_token failed: %s (http=%d msg=%.*s)",
                    pubnub_res_str(gst),
                    pubnub_response_status_code(gfut),
                    (int)errmsg.len,
                    errmsg.ptr ? errmsg.ptr : "");
    }
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t res = pubnub_grant_token_result(gfut);
    char                        tok[512];
    snprintf(tok, sizeof(tok), "%.*s", (int)res.token.len, res.token.ptr);
    pubnub_future_release(gfut);

    /* Create a context using the token. */
    char uid[80];
    snprintf(uid, sizeof(uid), "%s", it_unique_name("exp-tok"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.auth_token                 = tok;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* ctx = pubnub_create(&cfg);
    assert_non_null(ctx);

    /* Wait for the token to expire (TTL=1 minute + margin). */
    print_message("Waiting 65s for token expiry...\n");
    pn_test_sleep_ms(65000);

    pubnub_future_t fut = pubnub_fetch_messages(
        ctx, &(pubnub_fetch_messages_opts_t){.channels = s->base->channel});
    pubnub_res_t st          = pubnub_await(fut);
    int          http_status = pubnub_response_status_code(fut);
    pubnub_future_release(fut);
    pubnub_destroy(ctx);

    /* Expired token should result in a 403. */
    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void publish_with_read_only_token_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    /* Grant a token with READ permission only (no WRITE). */
    pubnub_access_resource_permission_t ch = {
        .name        = s->base->channel,
        .permissions = PUBNUB_ACCESS_READ,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t gres = pubnub_grant_token_result(gfut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)gres.token.len, gres.token.ptr);
    pubnub_future_release(gfut);

    /* Create context with the read-only token. */
    snprintf(uid, sizeof(uid), "%s", it_unique_name("ro-tok"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* tok_ctx = pubnub_create(&cfg);
    assert_non_null(tok_ctx);
    pubnub_set_auth_token(tok_ctx, s->token);

    pubnub_future_t pfut =
        pubnub_publish(tok_ctx,
                       &(pubnub_publish_opts_t){.channel = s->base->channel,
                                                .message = "\"should-fail\""});
    pubnub_res_t st          = pubnub_await(pfut);
    int          http_status = pubnub_response_status_code(pfut);
    pubnub_future_release(pfut);
    pubnub_destroy(tok_ctx);

    /* Publish requires WRITE permission; read-only token should be 403. */
    assert_int_equal(PUBNUB_ERR_SERVER, st);
    assert_int_equal(403, http_status);
}

static void history_with_token_for_wrong_channel_returns_403(void** state)
{
    pam_state_t* s = *state;
    char         uid[80];

    /* Grant a token scoped to channel "allowed-ch" only. */
    pubnub_access_resource_permission_t ch = {
        .name        = "allowed-ch-that-differs",
        .permissions = PUBNUB_ACCESS_READ | PUBNUB_ACCESS_WRITE,
    };
    pubnub_grant_token_opts_t gopts = PUBNUB_GRANT_TOKEN_OPTS_INIT;
    gopts.ttl                       = 1;
    gopts.channels                  = &ch;
    gopts.channel_count             = 1;

    pubnub_future_t gfut = pubnub_grant_token(s->base->pam_ctx, &gopts);
    pubnub_res_t    gst  = pubnub_await(gfut);
    assert_int_equal(PUBNUB_OK, gst);

    pubnub_grant_token_result_t gres = pubnub_grant_token_result(gfut);
    snprintf(s->token, sizeof(s->token), "%.*s", (int)gres.token.len, gres.token.ptr);
    pubnub_future_release(gfut);

    /* Create context with the mismatched-channel token. */
    snprintf(uid, sizeof(uid), "%s", it_unique_name("wrong-ch"));
    pubnub_config_t cfg            = pubnub_config_defaults();
    cfg.subscribe_key              = s->base->env->pam_subscribe_key;
    cfg.publish_key                = s->base->env->pam_publish_key;
    cfg.user_id                    = uid;
    cfg.retry_configuration.policy = PUBNUB_RETRY_NONE;

    pubnub_context_t* tok_ctx = pubnub_create(&cfg);
    assert_non_null(tok_ctx);
    pubnub_set_auth_token(tok_ctx, s->token);

    /* Query history on a DIFFERENT channel than what the token covers. */
    pubnub_fetch_messages_opts_t hopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    hopts.channels                     = s->base->channel;

    pubnub_future_t hfut = pubnub_fetch_messages(tok_ctx, &hopts);
    pubnub_res_t    hst  = pubnub_await(hfut);
    int             http = pubnub_response_status_code(hfut);
    pubnub_future_release(hfut);
    pubnub_destroy(tok_ctx);

    /* Token does not cover this channel; server should return 403. */
    assert_int_equal(PUBNUB_ERR_SERVER, hst);
    assert_int_equal(403, http);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            grant_token_returns_non_empty_token, setup, teardown),
        cmocka_unit_test_setup_teardown(
            parse_token_round_trips_permissions, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_token_on_pam_channel_succeeds, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_without_token_on_pam_channel_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            signal_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            history_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            here_now_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_state_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_uuid_metadata_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_channel_metadata_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            list_channel_groups_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            get_message_actions_without_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            grant_token_with_pattern_permission_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(revoke_token_returns_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(
            list_files_without_token_on_pam_keyset_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            history_with_expired_token_returns_error, setup, teardown),
        cmocka_unit_test_setup_teardown(
            publish_with_read_only_token_returns_403, setup, teardown),
        cmocka_unit_test_setup_teardown(
            history_with_token_for_wrong_channel_returns_403, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
