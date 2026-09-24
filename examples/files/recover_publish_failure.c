/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/recover_publish_failure.c
 * @brief Recover a partially-successful send_file without re-uploading.
 *
 * pubnub_send_file() can fail after the upload succeeded. The result
 * struct distinguishes the two cases: a non-empty id means the bytes
 * reached storage and only the announcing publish failed, so retrying
 * with pubnub_publish_file_message() costs no second upload. An empty id
 * means the failure happened before or during the upload and there is
 * nothing to recover.
 *
 * Build: cmake --build build/full --target example_files_recover_publish_failure
 * Run:   ./build/full/examples/files/example_files_recover_publish_failure
 */

// snippet.filesRecoverPublishFailure

#include "pubnub/pubnub.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-recover";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. Attempt the upload. */
    static const char content[] = "Hello PubNub Files!";

    pubnub_send_file_opts_t send_opts = PUBNUB_SEND_FILE_OPTS_INIT;
    send_opts.channel                 = "demo_channel";
    send_opts.file_name               = "greeting.txt";
    send_opts.data                    = (const uint8_t*)content;
    send_opts.data_len                = strlen(content);
    send_opts.content_type            = "text/plain";

    pubnub_future_t send_fut = pubnub_send_file(ctx, &send_opts);
    while (!pubnub_future_is_ready(send_fut)) {
        pubnub_process(ctx);
    }

    const pubnub_res_t        send_status = pubnub_future_status(send_fut);
    pubnub_send_file_result_t sent        = pubnub_send_file_result(send_fut);

    if (PUBNUB_OK == send_status) {
        printf("Sent OK at %.*s\n", (int)sent.timetoken.len, sent.timetoken.ptr);
        pubnub_future_release(send_fut);
        pubnub_destroy(ctx);
        return 0;
    }

    /* 2. Failed. An empty id means the upload itself never landed. */
    if (0 == sent.id.len) {
        printf("Upload failed before storage: %s. Retry the whole send.\n",
               pubnub_res_str(send_status));
        pubnub_future_release(send_fut);
        pubnub_destroy(ctx);
        return 1;
    }

    /* 3. Partial success: the file exists, only the publish failed.
     * Copy id and name out of the result before releasing the future —
     * both views alias future-owned memory. */
    char id_buf[128];
    char name_buf[256];
    if (sent.id.len >= sizeof(id_buf) || sent.name.len >= sizeof(name_buf)) {
        printf("Identifiers longer than the local buffers\n");
        pubnub_future_release(send_fut);
        pubnub_destroy(ctx);
        return 1;
    }
    memcpy(id_buf, sent.id.ptr, sent.id.len);
    id_buf[sent.id.len] = '\0';
    memcpy(name_buf, sent.name.ptr, sent.name.len);
    name_buf[sent.name.len] = '\0';
    pubnub_future_release(send_fut);

    printf("Upload succeeded but publish failed. Re-announcing %s (%s).\n",
           name_buf,
           id_buf);

    /* 4. Publish only the file message. No bytes are re-sent. */
    pubnub_publish_file_message_opts_t pub_opts =
        PUBNUB_PUBLISH_FILE_MESSAGE_OPTS_INIT;
    pub_opts.channel   = "demo_channel";
    pub_opts.file_id   = id_buf;
    pub_opts.file_name = name_buf;
    pub_opts.message   = "{\"caption\":\"recovered\"}";

    pubnub_future_t pub_fut = pubnub_publish_file_message(ctx, &pub_opts);
    while (!pubnub_future_is_ready(pub_fut)) {
        pubnub_process(ctx);
    }

    if (PUBNUB_OK == pubnub_future_status(pub_fut)) {
        pubnub_publish_file_message_result_t r =
            pubnub_publish_file_message_result(pub_fut);
        printf("Recovered, published at %.*s\n",
               (int)r.timetoken.len,
               r.timetoken.ptr);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(pub_fut);
        printf("Re-publish failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(pub_fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
