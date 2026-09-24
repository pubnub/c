/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/message_actions.h"
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

xs_result_t run_js_message_action_verify(const xs_context_t* ctx)
{
    xs_result_t       r  = {0};
    pubnub_context_t* pn = make_ctx(ctx);
    pubnub_get_message_actions_opts_t opts = PUBNUB_GET_MESSAGE_ACTIONS_OPTS_INIT;
    pubnub_future_t                     fut;
    pubnub_res_t                        st;
    pubnub_get_message_actions_result_t res;
    uint32_t                            i;
    int                                 found = 0;

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    opts.channel = ctx->channel;

    fut = pubnub_get_message_actions(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "get_message_actions failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    res = pubnub_get_message_actions_result(fut);
    for (i = 0U; i < res.count && 0 == found; ++i) {
        pubnub_message_action_t a =
            pubnub_get_message_actions_result_action_at(fut, (size_t)i);
        if (8U == a.type.len && NULL != a.type.ptr
            && 0 == memcmp(a.type.ptr, "reaction", 8U) && 8U == a.value.len
            && NULL != a.value.ptr && 0 == memcmp(a.value.ptr, "thumbsup", 8U)) {
            found = 1;
        }
    }

    if (0 != found) {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "reaction:thumbsup found in %u actions",
                    res.count);
    } else {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "reaction:thumbsup not found in %u actions",
                    res.count);
    }

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = found;
    return r;
}
