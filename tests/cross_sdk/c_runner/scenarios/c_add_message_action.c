/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/message_actions.h"
#include "pubnub/features/publish.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#include <string.h>

static pubnub_context_t* make_ctx(const xs_context_t* xctx)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = xctx->sub_key;
    cfg.publish_key     = xctx->pub_key;
    cfg.user_id         = "xs-c-runner";
    return pubnub_create(&cfg);
}

xs_result_t run_c_add_message_action(const xs_context_t* ctx)
{
    xs_result_t           r     = {0};
    pubnub_context_t*     pn    = make_ctx(ctx);
    pubnub_publish_opts_t popts = PUBNUB_PUBLISH_OPTS_INIT;
    pubnub_add_message_action_opts_t aopts = PUBNUB_ADD_MESSAGE_ACTION_OPTS_INIT;
    pubnub_future_t                    fut;
    pubnub_res_t                       st;
    pubnub_timetoken_t                 tt;
    pubnub_add_message_action_result_t ares;
    char                               tt_buf[32];

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    /* Publish a sentinel message to get a timetoken. */
    popts.channel = ctx->channel;
    popts.message = "\"xs-reaction-target\"";

    fut = pubnub_publish(pn, &popts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "publish failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    tt = pubnub_publish_result_timetoken(fut);
    if (NULL == tt.ptr || 0 == tt.len) {
        pn_snprintf(r.detail, sizeof(r.detail), "publish returned no timetoken");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    /* Copy timetoken to NUL-terminated buffer. */
    if (tt.len >= sizeof(tt_buf)) {
        tt.len = sizeof(tt_buf) - 1;
    }
    memcpy(tt_buf, tt.ptr, tt.len);
    tt_buf[tt.len] = '\0';
    pubnub_future_release(fut);

    /* Add a message action to the published message. */
    aopts.channel           = ctx->channel;
    aopts.message_timetoken = tt_buf;
    aopts.type              = "reaction";
    aopts.value             = "thumbsup";

    fut = pubnub_add_message_action(pn, &aopts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "add_action failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    ares = pubnub_add_message_action_result(fut);
    pn_snprintf(r.detail,
                sizeof(r.detail),
                "action_tt=%.*s",
                (int)(NULL != ares.action.action_timetoken.ptr
                          ? ares.action.action_timetoken.len
                          : 0U),
                NULL != ares.action.action_timetoken.ptr
                    ? ares.action.action_timetoken.ptr
                    : "");

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = 1;
    return r;
}
