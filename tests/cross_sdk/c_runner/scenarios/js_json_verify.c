/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/history.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
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

xs_result_t run_js_json_verify(const xs_context_t* ctx)
{
    xs_result_t                    r    = {0};
    pubnub_context_t*              pn   = make_ctx(ctx);
    pubnub_fetch_messages_opts_t   opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    pubnub_future_t                fut;
    pubnub_res_t                   st;
    pubnub_fetch_messages_result_t fres;
    pubnub_fetch_messages_channel_result_t ch;
    pubnub_serialization_provider_t*       serial;
    size_t                                 i;
    int                                    found = 0;

    if (NULL == pn) {
        pn_snprintf(r.detail, sizeof(r.detail), "context creation failed");
        return r;
    }

    opts.channels = ctx->channel;
    opts.count    = 10;

    fut = pubnub_fetch_messages(pn, &opts);
    st  = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "fetch_messages failed: %s (http=%d %.*s)",
                    pubnub_res_str(st),
                    pubnub_response_status_code(fut),
                    (int)(NULL != em.ptr ? em.len : 0U),
                    NULL != em.ptr ? em.ptr : "");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    fres = pubnub_fetch_messages_result(fut);
    if (0U == fres.channel_count) {
        pn_snprintf(r.detail, sizeof(r.detail), "no channels in response");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        return r;
    }

    ch     = pubnub_fetch_messages_result_channel_at(fut, 0U);
    serial = pubnub_serialization(pn);

    for (i = 0U; i < (size_t)ch.message_count && 0 == found; ++i) {
        pubnub_history_message_result_t msg =
            pubnub_fetch_messages_result_message_at(fut, 0U, i);
        const pubnub_json_value_t* from_val;
        const pubnub_json_value_t* value_val;
        size_t                     flen = 0U;
        const char*                fptr;
        int                        num = 0;
        pubnub_res_t               vres;

        if (NULL == msg.message || NULL == serial) {
            continue;
        }
        from_val  = serial->object_get(msg.message, "from", 4U);
        value_val = serial->object_get(msg.message, "value", 5U);
        if (NULL == from_val || NULL == value_val) {
            continue;
        }
        fptr = serial->value_as_string(from_val, &flen);
        vres = serial->value_as_int(value_val, &num);
        if (NULL != fptr && 6U == flen && 0 == memcmp(fptr, "js-sdk", 6U)
            && PUBNUB_OK == vres && 42 == num) {
            found = 1;
        }
    }

    if (0 != found) {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "JSON {from:js-sdk,value:42} found in %d messages",
                    (int)ch.message_count);
    } else {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "JSON {from:js-sdk,value:42} not found in %d messages",
                    (int)ch.message_count);
    }

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    r.pass = found;
    return r;
}
