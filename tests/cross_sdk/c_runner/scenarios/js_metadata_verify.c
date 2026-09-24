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

xs_result_t run_js_metadata_verify(const xs_context_t* ctx)
{
    xs_result_t                     r    = {0};
    pubnub_context_t*               pn   = make_ctx(ctx);
    pubnub_get_uuid_metadata_opts_t opts = PUBNUB_GET_UUID_METADATA_OPTS_INIT;
    pubnub_future_t                 fut;
    pubnub_res_t                    st;
    pubnub_uuid_metadata_t          meta;
    const char*                     content;

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    content   = NULL != ctx->content ? ctx->content : "";
    opts.uuid = NULL != ctx->uuid ? ctx->uuid : "xs-uuid";

    fut = pubnub_get_uuid_metadata(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "get_uuid_metadata failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    meta = pubnub_get_uuid_metadata_result(fut);
    if (NULL == meta.name.ptr || 0 == meta.name.len) {
        pn_snprintf(r.detail, sizeof(r.detail), "metadata name is empty");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    if (meta.name.len == strlen(content)
        && 0 == strncmp(meta.name.ptr, content, meta.name.len)) {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "name matches: %.*s",
                    (int)meta.name.len,
                    meta.name.ptr);
        r.pass = 1;
    } else {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "name mismatch: expected '%s' got '%.*s'",
                    content,
                    (int)meta.name.len,
                    meta.name.ptr);
    }

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    return r;
}
