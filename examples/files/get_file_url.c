/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/files/get_file_url.c
 * @brief Build the direct download URL for a stored file.
 *
 * pubnub_get_file_url() is pure local string construction from the
 * context's origin and subscribe key. It issues no request, never
 * blocks, and returns a pubnub_res_t rather than a future.
 *
 * Build: cmake --build build/full --target example_files_get_file_url
 * Run:   ./build/full/examples/files/example_files_get_file_url
 */

// snippet.filesGetFileUrl

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure the client. The URL is derived from cfg.subscribe_key
     * and the context origin, so both must be set before the call. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-files-url";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Identify the file. Take file_id and file_name from a
     * pubnub_send_file_result_t or a pubnub_file_info_t. */
    pubnub_get_file_url_opts_t opts = PUBNUB_GET_FILE_URL_OPTS_INIT;
    opts.channel                    = "demo_channel";
    opts.file_id                    = "d7d5f0e0-0d1a-4f4c-8b1e-6a9f0c2b3d4e";
    opts.file_name                  = "greeting.txt";

    /* 3. Write the URL into a caller-owned buffer. On
     * PUBNUB_ERR_BUFFER_TOO_SMALL, out_len reports the size needed. */
    char   url[512];
    size_t url_len = 0;
    pubnub_res_t rc = pubnub_get_file_url(ctx, &opts, url, sizeof(url), &url_len);

    if (PUBNUB_OK == rc) {
        printf("URL (%zu bytes): %.*s\n", url_len, (int)url_len, url);
    } else if (PUBNUB_ERR_BUFFER_TOO_SMALL == rc) {
        printf("Buffer too small, need %zu bytes\n", url_len);
    } else {
        printf("get_file_url failed: %s\n", pubnub_res_str(rc));
    }

    /* 4. Cleanup. There is no future to release. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
