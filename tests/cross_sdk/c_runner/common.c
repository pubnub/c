/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "common.h"

#include <stdio.h>
#include <string.h>

int xs_parse_args(int argc, char* argv[], xs_context_t* ctx)
{
    for (int i = 1; i < (argc - 1); ++i) {
        if (0 == strcmp(argv[i], "--sub-key")) {
            ctx->sub_key = argv[++i];
        } else if (0 == strcmp(argv[i], "--pub-key")) {
            ctx->pub_key = argv[++i];
        } else if (0 == strcmp(argv[i], "--channel")) {
            ctx->channel = argv[++i];
        } else if (0 == strcmp(argv[i], "--scenario")) {
            ctx->scenario = argv[++i];
        } else if (0 == strcmp(argv[i], "--cipher")) {
            ctx->cipher = argv[++i];
        } else if (0 == strcmp(argv[i], "--uuid")) {
            ctx->uuid = argv[++i];
        } else if (0 == strcmp(argv[i], "--content")) {
            ctx->content = argv[++i];
        } else if (0 == strcmp(argv[i], "--output")) {
            ctx->output = argv[++i];
        }
    }

    if (NULL == ctx->sub_key || NULL == ctx->pub_key || NULL == ctx->channel
        || NULL == ctx->scenario) {
        return -1;
    }
    return 0;
}

void xs_write_result(const xs_context_t* ctx, const xs_result_t* result)
{
    /* snprintf is acceptable here — this is non-SDK tool code. */
    char json[512];
    (void)snprintf(json,
                   sizeof(json),
                   "{\"pass\":%s,\"detail\":\"%s\"}\n",
                   result->pass ? "true" : "false",
                   result->detail);

    if (NULL != ctx->output) {
        FILE* f = fopen(ctx->output, "w");
        if (NULL != f) {
            (void)fputs(json, f);
            (void)fclose(f);
            return;
        }
    }
    (void)fputs(json, stdout);
}
