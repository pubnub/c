/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/features/files.h"
#include "pubnub/future.h"
#include "pubnub/response.h"

#include <string.h>

xs_result_t run_c_encrypted_file_upload(const xs_context_t* ctx)
{
    xs_result_t               r   = {0};
    pubnub_crypto_module_t*   cm  = NULL;
    pubnub_config_t           cfg = pubnub_config_defaults();
    pubnub_context_t*         pn;
    pubnub_send_file_opts_t   opts          = PUBNUB_SEND_FILE_OPTS_INIT;
    char                      msg_json[300] = {0};
    pubnub_future_t           fut;
    pubnub_res_t              st;
    pubnub_send_file_result_t res;
    const char* content = NULL != ctx->content ? ctx->content : "Hello from C";

    cfg.subscribe_key = ctx->sub_key;
    cfg.publish_key   = ctx->pub_key;
    cfg.user_id       = "xs-c-runner";

    if (NULL != ctx->cipher) {
        cm = pubnub_crypto_module_aes_cbc(ctx->cipher, 1, NULL);
        if (NULL != cm) {
            cfg.crypto_module = cm;
        }
    }

    pn = pubnub_create(&cfg);
    if (NULL == pn) {
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

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
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
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
    if (NULL != cm) {
        pubnub_crypto_module_destroy(cm);
    }
    r.pass = 1;
    return r;
}
