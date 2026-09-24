/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
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

xs_result_t run_c_publish(const xs_context_t* ctx)
{
    xs_result_t           r             = {0};
    pubnub_context_t*     pn            = make_ctx(ctx);
    pubnub_publish_opts_t opts          = PUBNUB_PUBLISH_OPTS_INIT;
    char                  json_msg[300] = {0};
    pubnub_future_t       fut;
    pubnub_res_t          st;
    pubnub_timetoken_t    tt;

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    opts.channel = ctx->channel;
    if (NULL != ctx->content) {
        pn_snprintf(json_msg, sizeof(json_msg), "\"%s\"", ctx->content);
        opts.message = json_msg;
    } else {
        opts.message = "\"hello-from-c\"";
    }

    fut = pubnub_publish(pn, &opts);
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
    pn_snprintf(r.detail,
                sizeof(r.detail),
                "published tt=%.*s",
                (int)(NULL != tt.ptr ? tt.len : 0U),
                NULL != tt.ptr ? tt.ptr : "");

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = 1;
    return r;
}
