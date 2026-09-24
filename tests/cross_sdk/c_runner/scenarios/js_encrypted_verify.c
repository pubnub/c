/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/features/history.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/response.h"

#include <string.h>

xs_result_t run_js_encrypted_verify(const xs_context_t* ctx)
{
    xs_result_t                      r   = {0};
    pubnub_crypto_module_t*          cm  = NULL;
    pubnub_config_t                  cfg = pubnub_config_defaults();
    pubnub_context_t*                pn;
    pubnub_fetch_messages_opts_t     opts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    pubnub_future_t                  fut;
    pubnub_res_t                     st;
    pubnub_fetch_messages_result_t   fres;
    pubnub_serialization_provider_t* serial;
    const char*                      content;

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

    content = NULL != ctx->content ? ctx->content : "";

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
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        return r;
    }

    fres = pubnub_fetch_messages_result(fut);
    if (0 == fres.channel_count) {
        pn_snprintf(r.detail, sizeof(r.detail), "no channels in response");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        return r;
    }

    serial = pubnub_serialization(pn);

    {
        pubnub_fetch_messages_channel_result_t ch =
            pubnub_fetch_messages_result_channel_at(fut, 0U);
        size_t clen = strlen(content);
        size_t i;

        for (i = 0U; i < (size_t)ch.message_count; ++i) {
            pubnub_history_message_result_t msg =
                pubnub_fetch_messages_result_message_at(fut, 0U, i);
            size_t      mlen = 0U;
            const char* mptr = NULL;

            /* Skip messages where decryption failed. */
            if (PUBNUB_OK != msg.crypto_result) {
                continue;
            }
            if (NULL != msg.message && NULL != serial) {
                mptr = serial->value_as_string(msg.message, &mlen);
            }
            /* Exact match proves decryption round-tripped correctly. */
            if (NULL != mptr && mlen == clen && 0 == memcmp(mptr, content, clen)) {
                pn_snprintf(r.detail,
                            sizeof(r.detail),
                            "exact decrypted message '%s' found at index %d",
                            content,
                            (int)i);
                pubnub_future_release(fut);
                pubnub_destroy(pn);
                if (NULL != cm) {
                    pubnub_crypto_module_destroy(cm);
                }
                r.pass = 1;
                return r;
            }
        }

        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "exact decrypted message '%s' not found in %d messages",
                    content,
                    (int)ch.message_count);
    }

    pubnub_future_release(fut);
    pubnub_destroy(pn);
    if (NULL != cm) {
        pubnub_crypto_module_destroy(cm);
    }
    return r;
}
