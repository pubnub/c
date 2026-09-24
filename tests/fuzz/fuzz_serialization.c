/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_serialization.c
 * @brief libFuzzer harness for JSON serialization round-trip.
 *
 * Feeds arbitrary bytes to the cJSON serialization provider's parse()
 * entry, then round-trips any successfully parsed tree through
 * serialize() and destroys it.  Exercises the parser, serializer, and
 * value_destroy lifecycle under adversarial input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pubnub/providers/serialization.h"
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
    if (NULL == s_serial || 0 == size || size > 1048576) {
        return 0;
    }

    /* Attempt to parse arbitrary bytes as JSON. */
    pubnub_json_value_t* tree = s_serial->parse(s_serial, data, size);
    if (NULL == tree) {
        return 0;
    }

    /* Round-trip: serialize the parsed tree back to bytes. */
    if (NULL != s_serial->serialize) {
        uint8_t buf[4096];
        size_t  out_len = 0;
        s_serial->serialize(s_serial, tree, buf, sizeof(buf), &out_len);
    }

    /* Exercise type query if available. */
    if (NULL != s_serial->value_type) {
        (void)s_serial->value_type(tree);
    }

    /* Clean up. */
    s_serial->value_destroy(s_serial, tree);

    return 0;
}
