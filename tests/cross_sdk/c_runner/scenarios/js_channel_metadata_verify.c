/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/app_context.h"
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

xs_result_t run_js_channel_metadata_verify(const xs_context_t* ctx)
{
    xs_result_t       r  = {0};
    pubnub_context_t* pn = make_ctx(ctx);
    pubnub_get_channel_metadata_opts_t opts = PUBNUB_GET_CHANNEL_METADATA_OPTS_INIT;
    pubnub_future_t           fut;
    pubnub_res_t              st;
    pubnub_channel_metadata_t meta;
    size_t                    clen;
    int                       match;

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    opts.channel = ctx->channel;

    fut = pubnub_get_channel_metadata(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "get_channel_metadata failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    meta  = pubnub_get_channel_metadata_result(fut);
    clen  = NULL != ctx->content ? strlen(ctx->content) : 0U;
    match = (NULL != meta.name.ptr && meta.name.len == clen
             && 0 == memcmp(meta.name.ptr, ctx->content, clen))
              ? 1
              : 0;

    if (0 != match) {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "channel name='%.*s' matches",
                    (int)meta.name.len,
                    NULL != meta.name.ptr ? meta.name.ptr : "");
    } else {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "expected name='%s' got='%.*s'",
                    NULL != ctx->content ? ctx->content : "<null>",
                    (int)meta.name.len,
                    NULL != meta.name.ptr ? meta.name.ptr : "");
    }

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = match;
    return r;
}
