/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/list_files.c
 * @brief List files on a channel using cooperative polling.
 *
 * This example uses cooperative polling. Async callbacks
 * (pubnub_async) and blocking await (pubnub_await) work the same
 * way — see send_file_async.c and publish/sync.c for those patterns.
 *
 * Build: cmake --build build/full --target example_files_list_files
 * Run:   ./build/full/examples/files/example_files_list_files
 */

// snippet.filesListFiles

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-list";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. List files on a channel. */
    pubnub_list_files_opts_t opts = PUBNUB_LIST_FILES_OPTS_INIT;
    opts.channel                  = "demo_channel";
    opts.limit                    = 10;

    pubnub_future_t fut = pubnub_list_files(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        pubnub_list_files_result_t r = pubnub_list_files_result(fut);
        printf("Files on channel (%u):\n", r.count);
        for (uint32_t i = 0; i < r.count; ++i) {
            pubnub_file_info_t f = pubnub_list_files_result_file_at(fut, i);
            printf("  %.*s  id=%.*s  %u bytes\n",
                   (int)f.name.len,
                   f.name.ptr,
                   (int)f.id.len,
                   f.id.ptr,
                   f.size);
        }
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("list_files failed: %.*s\n", (int)err.len, err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
