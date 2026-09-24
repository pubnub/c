/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_json_unescape.h"

#include <stdint.h>
#include <string.h>

/** @brief Convert a single hex character to 0..15, or -1. */
static int pn_hex_val(char c)
{
    if ('0' <= c && c <= '9') {
        return c - '0';
    }
    if ('a' <= c && c <= 'f') {
        return 10 + (c - 'a');
    }
    if ('A' <= c && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

/**
 * @brief Parse exactly four hex digits into a 16-bit value.
 *
 * @param s      Pointer to the first hex digit.
 * @param avail  Remaining bytes in the buffer starting at @p s.
 * @param out    Receives the parsed value on success.
 * @retval 1     Success.
 * @retval 0     Fewer than 4 bytes available or a non-hex digit found.
 */
static int pn_parse_hex4(const char* s, size_t avail, uint32_t* out)
{
    int d0;
    int d1;
    int d2;
    int d3;

    if (avail < 4) {
        return 0;
    }
    d0 = pn_hex_val(s[0]);
    d1 = pn_hex_val(s[1]);
    d2 = pn_hex_val(s[2]);
    d3 = pn_hex_val(s[3]);
    if (0 > d0 || 0 > d1 || 0 > d2 || 0 > d3) {
        return 0;
    }
    *out = (uint32_t)((d0 << 12) | (d1 << 8) | (d2 << 4) | d3);
    return 1;
}

/**
 * @brief Encode a Unicode code point as 1..4 UTF-8 bytes.
 *
 * Invalid code points (> U+10FFFF) produce U+FFFD (3 bytes).
 *
 * @param cp   Code point to encode.
 * @param out  Destination buffer (must have room for 4 bytes).
 * @return     Number of bytes written.
 */
static size_t pn_utf8_encode(uint32_t cp, char* out)
{
    if (cp <= 0x7FU) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp <= 0x7FFU) {
        out[0] = (char)(0xC0U | (cp >> 6));
        out[1] = (char)(0x80U | (cp & 0x3FU));
        return 2;
    }
    if (cp <= 0xFFFFU) {
        out[0] = (char)(0xE0U | (cp >> 12));
        out[1] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[2] = (char)(0x80U | (cp & 0x3FU));
        return 3;
    }
    if (cp <= 0x10FFFFU) {
        out[0] = (char)(0xF0U | (cp >> 18));
        out[1] = (char)(0x80U | ((cp >> 12) & 0x3FU));
        out[2] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[3] = (char)(0x80U | (cp & 0x3FU));
        return 4;
    }
    /* Invalid code point: emit U+FFFD replacement character. */
    out[0] = (char)0xEFU;
    out[1] = (char)0xBFU;
    out[2] = (char)0xBDU;
    return 3;
}

/**
 * @brief Decode a `\uXXXX` escape (with optional surrogate pair) to UTF-8.
 *
 * @p r must point at the first hex digit (the caller has already consumed
 * the leading `\u`). Parses four hex digits and, when they form a high
 * surrogate followed by `\uXXXX` low surrogate, combines both into one
 * code point before encoding.
 *
 * @param str       Buffer being unescaped.
 * @param r         Index of the first hex digit within @p str.
 * @param n         Total valid length of @p str.
 * @param out_buf   Destination for the encoded UTF-8 bytes (room for 4).
 * @param consumed  Receives the number of input chars consumed from @p r
 *                  (4 for a single escape, 10 for a surrogate pair).
 * @return Number of UTF-8 bytes written to @p out_buf, or 0 when the
 *         sequence is malformed (in which case @p consumed is 0).
 */
static size_t pn_decode_unicode_escape(const char* str,
                                       size_t      r,
                                       size_t      n,
                                       char*       out_buf,
                                       size_t*     consumed)
{
    uint32_t cp = 0;

    *consumed = 0;
    if (0 == pn_parse_hex4(str + r, n - r, &cp)) {
        return 0;
    }
    *consumed = 4;
    /* High surrogate (U+D800..U+DBFF): look for a paired low surrogate
     * immediately following. */
    if (0xD800U <= cp && cp <= 0xDBFFU) {
        uint32_t lo = 0;
        if (r + 5 < n && '\\' == str[r + 4] && 'u' == str[r + 5]
            && 0 != pn_parse_hex4(str + r + 6, n - r - 6, &lo) && 0xDC00U <= lo
            && lo <= 0xDFFFU) {
            cp        = 0x10000U + ((cp - 0xD800U) << 10) + (lo - 0xDC00U);
            *consumed = 10;
        }
        /* Lone high surrogate: encode as-is (invalid UTF-8 but
         * data-preserving). */
    }
    return pn_utf8_encode(cp, out_buf);
}

void pn_json_unescape_inplace(char* str, size_t* len)
{
    size_t r;
    size_t w;
    size_t n;

    if (NULL == str || NULL == len) {
        return;
    }

    n = *len;
    w = 0;

    for (r = 0; r < n; /* advanced in body */) {
        if ('\\' != str[r] || r + 1 >= n) {
            str[w++] = str[r++];
            continue;
        }
        /* Skip the backslash. */
        r++;
        switch (str[r]) {
        case '"':
            str[w++] = '"';
            r++;
            break;
        case '\\':
            str[w++] = '\\';
            r++;
            break;
        case '/':
            str[w++] = '/';
            r++;
            break;
        case 'b':
            str[w++] = '\b';
            r++;
            break;
        case 'f':
            str[w++] = '\f';
            r++;
            break;
        case 'n':
            str[w++] = '\n';
            r++;
            break;
        case 'r':
            str[w++] = '\r';
            r++;
            break;
        case 't':
            str[w++] = '\t';
            r++;
            break;
        case 'u': {
            size_t consumed = 0;
            size_t written;
            r++; /* skip 'u' */
            written = pn_decode_unicode_escape(str, r, n, str + w, &consumed);
            if (0 == written) {
                /* Malformed: emit the backslash-u literally. */
                str[w++] = '\\';
                str[w++] = 'u';
                break;
            }
            w += written;
            r += consumed;
            break;
        }
        default:
            /* Unknown escape: preserve literally. */
            str[w++] = '\\';
            str[w++] = str[r++];
            break;
        }
    }

    str[w] = '\0';
    *len   = w;
}
