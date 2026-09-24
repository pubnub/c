/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"
#include "pubnub/client.h"
#include "pubnub/error.h"
#include "pubnub/features/crypto.h"
#include "pubnub/features/files.h"
#include "pubnub/features/history.h"
#include "pubnub/future.h"
#include "pubnub/providers/serialization.h"
#include "pubnub/response.h"
#include "pubnub/types.h"

#include <string.h>

xs_result_t run_js_encrypted_file_verify(const xs_context_t* ctx)
{
    xs_result_t                   r   = {0};
    pubnub_crypto_module_t*       cm  = NULL;
    pubnub_config_t               cfg = pubnub_config_defaults();
    pubnub_context_t*             pn;
    pubnub_list_files_opts_t      lopts = PUBNUB_LIST_FILES_OPTS_INIT;
    pubnub_download_file_opts_t   dopts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    pubnub_fetch_messages_opts_t  hopts = PUBNUB_FETCH_MESSAGES_OPTS_INIT;
    pubnub_future_t               fut;
    pubnub_res_t                  st;
    pubnub_list_files_result_t    lr;
    pubnub_file_info_t            fi;
    pubnub_download_file_result_t dr;
    char                          id_buf[128]   = {0};
    char                          name_buf[256] = {0};
    const char*                   content;
    size_t                        clen;
    int                           content_ok = 0;
    int                           notif_ok   = 0;

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
    clen    = strlen(content);

    lopts.channel = ctx->channel;
    fut           = pubnub_list_files(pn, &lopts);
    st            = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "list_files failed: %s (http=%d %.*s)",
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

    lr = pubnub_list_files_result(fut);
    if (0U == lr.count) {
        pn_snprintf(r.detail, sizeof(r.detail), "no files on channel");
        pubnub_future_release(fut);
        pubnub_destroy(pn);
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        return r;
    }

    fi = pubnub_list_files_result_file_at(fut, (size_t)(lr.count - 1U));
    {
        size_t id_len = (NULL != fi.id.ptr && fi.id.len < sizeof(id_buf) - 1U)
                          ? fi.id.len
                          : 0U;
        size_t nm_len = (NULL != fi.name.ptr && fi.name.len < sizeof(name_buf) - 1U)
                          ? fi.name.len
                          : 0U;
        if (0U < id_len) {
            memcpy(id_buf, fi.id.ptr, id_len);
        }
        if (0U < nm_len) {
            memcpy(name_buf, fi.name.ptr, nm_len);
        }
    }
    pubnub_future_release(fut);

    if ('\0' == id_buf[0]) {
        pn_snprintf(r.detail, sizeof(r.detail), "file id empty");
        pubnub_destroy(pn);
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        return r;
    }

    /* Download and verify decrypted content (exact match). */
    dopts.channel   = ctx->channel;
    dopts.file_id   = id_buf;
    dopts.file_name = name_buf;
    fut             = pubnub_download_file(pn, &dopts);
    st              = pubnub_await(fut);
    if (PUBNUB_OK != st) {
        pubnub_string_view_t em = pubnub_response_error_message(fut);
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "download failed: %s (http=%d %.*s)",
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

    dr         = pubnub_download_file_result(fut);
    content_ok = (NULL != dr.data && dr.data_len == clen
                  && 0 == memcmp(dr.data, content, clen))
                   ? 1
                   : 0;
    pubnub_future_release(fut);

    if (0 == content_ok) {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "decrypted content mismatch: expected '%s' (%d bytes)",
                    content,
                    (int)clen);
        pubnub_destroy(pn);
        if (NULL != cm) {
            pubnub_crypto_module_destroy(cm);
        }
        return r;
    }

    /* Fetch history to verify the file notification message. */
    hopts.channels = ctx->channel;
    hopts.count    = 10;
    fut            = pubnub_fetch_messages(pn, &hopts);
    st             = pubnub_await(fut);
    if (PUBNUB_OK == st) {
        pubnub_fetch_messages_result_t fres = pubnub_fetch_messages_result(fut);
        if (0U < fres.channel_count) {
            pubnub_fetch_messages_channel_result_t ch =
                pubnub_fetch_messages_result_channel_at(fut, 0U);
            pubnub_serialization_provider_t* serial = pubnub_serialization(pn);
            size_t                           i;
            for (i = 0U; i < (size_t)ch.message_count && 0 == notif_ok; ++i) {
                pubnub_history_message_result_t msg =
                    pubnub_fetch_messages_result_message_at(fut, 0U, i);
                if (PUBNUB_EVENT_TYPE_FILE != msg.event_type
                    || NULL == msg.message || NULL == serial) {
                    continue;
                }
                {
                    const pubnub_json_value_t* msg_val =
                        serial->object_get(msg.message, "message", 7U);
                    if (NULL != msg_val) {
                        size_t nlen = 0U;
                        const char* nptr = serial->value_as_string(msg_val, &nlen);
                        if (NULL != nptr && nlen == clen
                            && 0 == memcmp(nptr, content, clen)) {
                            notif_ok = 1;
                        }
                    }
                }
            }
        }
    }
    pubnub_future_release(fut);

    if (0 != notif_ok) {
        pn_snprintf(
            r.detail,
            sizeof(r.detail),
            "decrypted file content and notification message both match '%s'",
            content);
    } else {
        pn_snprintf(r.detail,
                    sizeof(r.detail),
                    "decrypted content matches but notification '%s' not found",
                    content);
    }

    pubnub_destroy(pn);
    if (NULL != cm) {
        pubnub_crypto_module_destroy(cm);
    }
    r.pass = (0 != notif_ok) ? 1 : 0;
    return r;
}
