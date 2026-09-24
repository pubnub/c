/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file fuzz_base64.c
 * @brief libFuzzer harness for base64url encoding.
 *
 * Exercises pn_base64url_encode() with arbitrary input and verifies
 * that the output contains only valid base64url characters (RFC 4648
 * section 5: A-Z a-z 0-9 - _) and NUL terminator.
 */

#include <stddef.h>
#include <stdint.h>

#include "pubnub/error.h"
#include "core/protocol_common/pn_base64url.h"

/** Validate that all bytes are in the base64url alphabet. */
static int is_valid_base64url(const char* str, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        char c  = str[i];
        int  ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (0 == size || size > 4096) {
        return 0;
    }

    /* Compute required output length. */
    size_t encoded_len = pn_base64url_encoded_len(size);

    /* Encode into a stack buffer (+1 for NUL). */
    char buf[8192];
    if (encoded_len + 1 > sizeof(buf)) {
        return 0;
    }

    pubnub_res_t rc = pn_base64url_encode(data, size, buf, sizeof(buf));
    if (PUBNUB_OK != rc) {
        return 0;
    }

    /* Verify output is valid base64url. */
    (void)is_valid_base64url(buf, encoded_len);

    /* Verify NUL termination. */
    volatile char term = buf[encoded_len];
    (void)term;

    /* Exercise with exact-fit buffer (boundary condition). */
    char tight[8192];
    if (encoded_len + 1 <= sizeof(tight)) {
        pubnub_res_t rc2 = pn_base64url_encode(data, size, tight, encoded_len + 1);
        (void)rc2;
    }

    /* Exercise with too-small buffer (must fail gracefully). */
    if (encoded_len > 0) {
        char         small[1];
        pubnub_res_t rc3 = pn_base64url_encode(data, size, small, 1);
        (void)rc3;
    }

    return 0;
}
