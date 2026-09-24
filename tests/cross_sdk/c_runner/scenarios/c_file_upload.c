/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/files.h"
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

xs_result_t run_c_file_upload(const xs_context_t* ctx)
{
    xs_result_t               r             = {0};
    pubnub_context_t*         pn            = make_ctx(ctx);
    pubnub_send_file_opts_t   opts          = PUBNUB_SEND_FILE_OPTS_INIT;
    char                      msg_json[300] = {0};
    pubnub_future_t           fut;
    pubnub_res_t              st;
    pubnub_send_file_result_t res;
    const char* content = NULL != ctx->content ? ctx->content : "Hello from C";

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    /* Attach the content as the file notification message so the JS side
     * can independently verify both the binary content and the message. */
    pn_snprintf(msg_json, sizeof(msg_json), "\"%s\"", content);

    opts.channel      = ctx->channel;
    opts.file_name    = "xs-test.txt";
    opts.data         = (const uint8_t*)content;
    opts.data_len     = strlen(content);
    opts.content_type = "text/plain";
    opts.message      = msg_json;

    fut = pubnub_send_file(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "send_file failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    res = pubnub_send_file_result(fut);
    pn_snprintf(r.detail,
                sizeof(r.detail),
                "file_id=%.*s",
                (int)(NULL != res.id.ptr ? res.id.len : 0U),
                NULL != res.id.ptr ? res.id.ptr : "");

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = 1;
    return r;
}
