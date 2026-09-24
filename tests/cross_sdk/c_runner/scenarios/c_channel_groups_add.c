/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/channel_groups.h"
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

xs_result_t run_c_channel_groups_add(const xs_context_t* ctx)
{
    xs_result_t       r  = {0};
    pubnub_context_t* pn = make_ctx(ctx);
    pubnub_future_t   fut;
    pubnub_res_t      st;
    char              channels[256];

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    /* Build 3 channel names derived from the test channel. */
    pn_snprintf(channels,
                sizeof(channels),
                "%s-a,%s-b,%s-c",
                ctx->channel,
                ctx->channel,
                ctx->channel);

    pubnub_channel_group_add_opts_t opts = PUBNUB_CHANNEL_GROUP_ADD_OPTS_INIT;
    opts.channel_group                   = ctx->channel;
    opts.channels                        = channels;

    fut = pubnub_channel_group_add_channels(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "add_channels failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    pn_snprintf(
        r.detail, sizeof(r.detail), "added 3 channels to group %s", ctx->channel);
    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = 1;
    return r;
}
