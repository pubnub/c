/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_publish_response.c
 * @brief libFuzzer harness for publish response validation and parsing.
 *
 * Feeds arbitrary bytes as the HTTP response body to the publish
 * response validator and, when the validator accepts, drives the parse
 * path through the serialization provider.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pubnub/error.h"
#include "pubnub/providers/serialization.h"
#include "features/publish/publish_internal.h"
#include "providers/provider_internal.h"

static pubnub_serialization_provider_t* s_serial;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    s_serial = pn_serialization_default();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (0 == size || size > 65536) {
        return 0;
    }

    /* Test the response validator with various HTTP status codes. */
    static const int statuses[] = {200, 400, 403, 404, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        pubnub_res_t vrc = pn_publish_response_validator(data, size, statuses[i]);

        /* If validator passes and we have a serialization provider,
         * attempt to parse the response as a publish array. */
        if (PUBNUB_OK == vrc && NULL != s_serial) {
            pubnub_json_value_t* tree = s_serial->parse(s_serial, data, size);
            if (NULL != tree) {
                pn_publish_parsed_t parsed = {0};
                pn_publish_parse_response(s_serial, tree, &parsed);
                s_serial->value_destroy(s_serial, tree);
            }
        }
    }

    return 0;
}
