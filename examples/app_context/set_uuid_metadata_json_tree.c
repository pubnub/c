/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file examples/app_context/set_uuid_metadata_json_tree.c
 * @brief Set UUID metadata with custom data built as a JSON value tree,
 *        and apply a conditional update with if_match.
 *
 * Two snippets live here:
 *
 *   appContextSetUuidMetadataJsonTree -- custom_value instead of custom,
 *       built with the PUBNUB_JSON_* macros. Use this when the values
 *       come from variables rather than a literal, so no hand-rolled
 *       string escaping is needed.
 *   appContextConditionalUpdate -- if_match, using the etag returned by
 *       a prior read.
 *
 * App Context is the one place where a JSON tree is CONSUMED rather than
 * borrowed: publish, signal, and set_state borrow the tree, but
 * custom_value transfers ownership to the SDK. Do not touch or free the
 * tree after the call returns.
 *
 * See set_uuid_metadata.c for the simpler raw-JSON-string variant.
 *
 * Build: cmake --build build/full --target example_app_context_set_uuid_metadata_json_tree
 * Run: ./build/full/examples/app_context/example_app_context_set_uuid_metadata_json_tree
 */

#include "pubnub/pubnub.h"

#include "pubnub/json_macros.h"

#include <stdio.h>
#include <string.h>

// snippet.appContextSetUuidMetadataJsonTree

int main(void)
{
    pubnub_config_t cfg = pubnub_config_defaults();
    cfg.publish_key     = "demo";
    cfg.subscribe_key   = "demo";
    cfg.user_id         = "example-app-context";

    pubnub_context_t* ctx = pubnub_create(&cfg);
    if (NULL == ctx) {
        printf("pubnub_create failed\n");
        return 1;
    }

    /* 1. Build the custom object. Each PUBNUB_JSON_KV_* expands to a
     * key plus a freshly constructed node; PUBNUB_JSON_OBJ appends the
     * NULL sentinel and takes ownership of every child. On failure it
     * frees them all, so a NULL return leaks nothing. */
    pubnub_serialization_provider_t* serial = pubnub_serialization(ctx);
    const int                        level  = 42;

    pubnub_json_value_t* custom =
        PUBNUB_JSON_OBJ(serial,
                        PUBNUB_JSON_KV_STR(serial, "role", "developer"),
                        PUBNUB_JSON_KV_INT(serial, "level", level),
                        PUBNUB_JSON_KV_BOOL(serial, "beta", 1));
    if (NULL == custom) {
        printf("Failed to build the custom JSON tree\n");
        pubnub_destroy(ctx);
        return 1;
    }

    /* 2. Hand the tree over via custom_value. Setting both custom and
     * custom_value is PUBNUB_ERR_INVALID_ARGUMENT, so pick one. */
    pubnub_set_uuid_metadata_opts_t opts = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
    opts.uuid                            = "user-alice";
    opts.name                            = "Alice Example";
    opts.email                           = "alice@example.com";
    opts.custom_value                    = custom;

    pubnub_future_t fut = pubnub_set_uuid_metadata(ctx, &opts);

    /* 3. The SDK now owns `custom`. Do not read it, reuse it, or pass it
     * to pubnub_json_destroy(). Only a tree that was never handed to a
     * feature needs that call. */
    custom = NULL;

    while (!pubnub_future_is_ready(fut)) {
        pubnub_process(ctx);
    }

    /* 4. Read the result, including the etag for a later conditional
     * update. */
    char etag_buf[64] = {0};
    if (PUBNUB_OK == pubnub_future_status(fut)) {
        const pubnub_uuid_metadata_t m = pubnub_set_uuid_metadata_result(fut);
        printf("Set %.*s, etag %.*s\n",
               (int)m.id.len,
               m.id.ptr,
               (int)m.etag.len,
               m.etag.ptr);
        if (m.etag.len < sizeof(etag_buf)) {
            memcpy(etag_buf, m.etag.ptr, m.etag.len);
        }
    } else {
        const pubnub_string_view_t err = pubnub_response_error_message(fut);
        printf("set_uuid_metadata failed: %.*s\n", (int)err.len, err.ptr);
    }
    pubnub_future_release(fut);

    // snippet.appContextConditionalUpdate

    /* 5. Conditional update. if_match carries the etag from the read
     * above, so the write is rejected with a 412-class error if another
     * writer changed the object in the meantime. */
    if ('\0' != etag_buf[0]) {
        pubnub_set_uuid_metadata_opts_t cond = PUBNUB_SET_UUID_METADATA_OPTS_INIT;
        cond.uuid     = "user-alice";
        cond.name     = "Alice Example (v2)";
        cond.if_match = etag_buf;

        pubnub_future_t    cond_fut = pubnub_set_uuid_metadata(ctx, &cond);
        const pubnub_res_t rc       = pubnub_await(cond_fut);
        if (PUBNUB_OK == rc) {
            printf("Conditional update applied.\n");
        } else {
            printf("Conditional update rejected: %s\n", pubnub_res_str(rc));
        }
        pubnub_future_release(cond_fut);
    }

    pubnub_destroy(ctx);
    return 0;
}

// snippet.end
