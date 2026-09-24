/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/download_file.c
 * @brief Download a file from a channel using cooperative polling.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see send_file_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_files_download_file
 * Run:   ./build/full/examples/files/example_files_download_file
 */

// snippet.filesDownloadFile

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-download";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Download a known file. */
    pubnub_download_file_opts_t opts = PUBNUB_DOWNLOAD_FILE_OPTS_INIT;
    opts.channel                     = "demo_channel";
    opts.file_id                     = "abc-123";
    opts.file_name                   = "greeting.txt";

    pubnub_future_t fut = pubnub_download_file(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_download_file_result_t r = pubnub_download_file_result(fut);
        printf("Downloaded %zu bytes\n", r.data_len);
        printf("Content: %.*s\n", (int)r.data_len, (const char*)r.data);
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("download failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
