/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/delete_file.c
 * @brief Delete a stored file from a channel.
 *
 * Deleting the file removes the stored object. It does not remove the
 * file message that announced it, so subscribers and history readers can
 * still see a reference to a file that no longer downloads.
 *
 * Build: cmake --build build/full --target example_files_delete_file
 * Run:   ./build/full/examples/files/example_files_delete_file
 */

// snippet.filesDeleteFile

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-delete";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. All three identifiers are required. Take file_id and file_name
     * from pubnub_send_file_result_t or pubnub_file_info_t — the server
     * may have altered the name you originally uploaded. */
    pubnub_delete_file_opts_t opts = PUBNUB_DELETE_FILE_OPTS_INIT;
    opts.channel                   = "demo_channel";
    opts.file_id                   = "d7d5f0e0-0d1a-4f4c-8b1e-6a9f0c2b3d4e";
    opts.file_name                 = "greeting.txt";

    pubnub_future_t fut = pubnub_delete_file(ctx, &opts);

    /* 3. Drive I/O until the future is ready. */
    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Delete returns no payload, so the status is the whole result. */
    const pubnub_res_t status = pubnub_future_status(fut);
    if (PUBNUB_OK == status) {
        printf("File deleted.\n");
    } else {
        pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("delete_file failed: %s (%.*s)\n",
               pubnub_res_str(status),
               (int)err.len,
               err.ptr);
    }

    /* 5. Cleanup. */
    pubnub_future_release(fut);
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
