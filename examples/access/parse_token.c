/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/access/parse_token.c
 * @brief Parse and inspect an access token locally (no network).
 *
 * pubnub_parse_token is purely local — it decodes the base64url CBOR
 * structure and caches the result on the context. Use it to inspect
 * tokens received from any source (grant response, auth flow,
 * external key server).
 *
 * Build: cmake --build build/full --target example_access_parse_token
 * Run:   ./build/full/examples/access/example_access_parse_token
 */

// snippet.accessParseToken

#include "pubnub/pubnub.h"

#include <stdio.h>

int main(void)
{
    /* 1. Configure and create the client. */
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-parse";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 2. Parse the token locally (no network call). */
    /* Token received from a server-side grant or auth flow. */
    const char* token =
        "qEF2AkF0GmFLd-NDdHRsGQWgQ3Jlc6VEY2hhbqFjY2gxGP9DZ3JwoWNj"
        "ZzEY_0N1c3KgQ3NwY6BEdXVpZKFldXVpZDEY_0NwYXSlRGNoYW6gQ2dycK"
        "BDdXNyoENzcGOgRHV1aWShYl4kAURtZXRho2VzY29yZRhkZWNvbG9yY3Jl"
        "ZGZhdXRob3JlcGFuZHVEdXVpZGtteWF1dGh1dWlkMUNzaWdYIP2vlxHik0"
        "EPZwtgYxAW3-LsBaX_WgWdYvtAXpYbKll3";

    pubnub_parsed_token_t     result = {0};
    pubnub_parse_token_opts_t opts   = PUBNUB_PARSE_TOKEN_OPTS_INIT;
    opts.token                       = token;

    pubnub_res_t rc = pubnub_parse_token(ctx, &opts, &result);
    if (PUBNUB_OK != rc) {
        printf("Parse failed: %s\n", pubnub_res_str(rc));
        pubnub_destroy(ctx);
        return 1;
    }

    /* 3. Print the decoded token contents. */
    printf("version=%d ttl=%u min timestamp=%llu\n",
           result.version,
           result.ttl,
           (unsigned long long)result.timestamp);

    if (0 < result.authorized_uuid.len) {
        printf("authorized_uuid=%.*s\n",
               (int)result.authorized_uuid.len,
               result.authorized_uuid.ptr);
    }

    printf("channels=%u groups=%u uuids=%u\n",
           result.channel_count,
           result.group_count,
           result.uuid_count);

    for (size_t i = 0; i < result.channel_count; ++i) {
        pubnub_parsed_token_resource_t r = pubnub_parsed_token_channel_at(ctx, i);
        printf("  chan[%zu]: %.*s perms=0x%x\n",
               i,
               (int)r.name.len,
               r.name.ptr,
               r.permissions);
    }

    for (size_t i = 0; i < result.uuid_pattern_count; ++i) {
        pubnub_parsed_token_resource_t r =
            pubnub_parsed_token_uuid_pattern_at(ctx, i);
        printf("  uuid_pat[%zu]: %.*s perms=0x%x\n",
               i,
               (int)r.name.len,
               r.name.ptr,
               r.permissions);
    }

    /* 4. Cleanup. */
    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
