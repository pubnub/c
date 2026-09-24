/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#ifndef PN_JSON_UNESCAPE_H
#define PN_JSON_UNESCAPE_H

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Decode JSON escape sequences in place.
 *
 * Processes standard JSON escapes (\\", \\\\, \\/, \\b, \\f, \\n,
 * \\r, \\t) and \\uXXXX sequences (including surrogate pairs for
 * code points above U+FFFF) into their UTF-8 byte equivalents.
 *
 * The decoded result is always <= the input length, so in-place
 * transformation is safe. A NUL terminator is written at the index
 * given by the returned length, so the buffer must have one writable
 * byte beyond the escaped content (see @p str).
 *
 * Malformed escape sequences are preserved literally (no data loss).
 * Lone surrogate halves are encoded as-is (invalid UTF-8 but
 * lossless).
 *
 * @param str  Mutable buffer containing the JSON string content
 *             (without surrounding quotes). Must have at least
 *             @p *len + 1 writable bytes: when the content carries no
 *             escapes the decoded length equals @p *len and the NUL
 *             terminator lands at index @p *len. May be NULL only
 *             when @p *len is zero.
 * @param len  [in/out] On entry, byte length of the escaped string.
 *             On return, byte length after unescaping. Must not be
 *             NULL.
 */
void pn_json_unescape_inplace(char* str, size_t* len);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_JSON_UNESCAPE_H */
