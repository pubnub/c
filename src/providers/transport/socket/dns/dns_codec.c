/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file dns_codec.c
 * @brief DNS wire format codec implementation (RFC 1035).
 */

#include "dns_codec.h"

#include <string.h>

/** DNS header size (fixed 12 bytes). */
#define DNS_HEADER_SIZE 12

/** Maximum hostname length per RFC 1035. */
#define DNS_MAX_HOSTNAME_LEN 253

/** Maximum label length per RFC 1035. */
#define DNS_MAX_LABEL_LEN 63

/** DNS CLASS IN (Internet). */
#define DNS_CLASS_IN 1

/** DNS RCODE mask (bits 0-3 of flags2). */
#define DNS_RCODE_MASK 0x0F

/** DNS RCODE NXDOMAIN. */
#define DNS_RCODE_NXDOMAIN 3

/** Max compression pointer jumps (prevents infinite loops). */
#define DNS_MAX_POINTER_JUMPS 8

/** DNS CNAME record type (canonical name alias). */
#define DNS_TYPE_CNAME 5

/** Compression pointer marker (top 2 bits = 11). */
#define DNS_COMPRESSION_MASK 0xC0

/**
 * @brief Write 16-bit value in network byte order.
 */
static void write_u16(uint8_t* buf, uint16_t val)
{
    buf[0] = (uint8_t)((val >> 8) & 0xFF);
    buf[1] = (uint8_t)(val & 0xFF);
}

/**
 * @brief Read 16-bit value from network byte order.
 *
 * Uses uint32_t arithmetic throughout to avoid MSVC Release-mode
 * optimizer issues where uint16_t intermediate values get optimized
 * in unexpected ways with shift operations.
 */
static uint16_t read_u16(const uint8_t* buf)
{
    return (uint16_t)(((uint32_t)buf[0] << 8) | (uint32_t)buf[1]);
}

/**
 * @brief Read 32-bit value from network byte order.
 */
static uint32_t read_u32(const uint8_t* buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[3]);
}

/**
 * @brief Encode hostname as DNS labels.
 *
 * Splits hostname on '.' and writes length-prefixed segments.
 * "ps.pndsn.com" → \x02ps\x05pndsn\x03com\x00
 *
 * @param hostname  NUL-terminated hostname.
 * @param buf       Output buffer.
 * @param buf_size  Buffer capacity.
 * @param out_len   Encoded length on success.
 * @retval PN_DNS_OK on success.
 * @retval PN_DNS_ERR_INVALID on validation error.
 * @retval PN_DNS_ERR_OVERFLOW if the buffer is too small.
 */
static int encode_labels(const char* hostname,
                         uint8_t*    buf,
                         size_t      buf_size,
                         size_t*     out_len)
{
    if (NULL == hostname || NULL == buf || NULL == out_len) {
        return PN_DNS_ERR_INVALID;
    }

    size_t hostname_len = strlen(hostname);
    if (0 == hostname_len || DNS_MAX_HOSTNAME_LEN < hostname_len) {
        return PN_DNS_ERR_INVALID;
    }

    size_t      pos         = 0;
    const char* label_start = hostname;
    const char* p           = hostname;

    while (1) {
        if ('.' == *p || '\0' == *p) {
            size_t label_len = (size_t)(p - label_start);
            if (0 == label_len || DNS_MAX_LABEL_LEN < label_len) {
                return PN_DNS_ERR_INVALID;
            }
            if (pos + 1 + label_len > buf_size) {
                return PN_DNS_ERR_OVERFLOW;
            }

            buf[pos++] = (uint8_t)label_len;
            memcpy(buf + pos, label_start, label_len);
            pos += label_len;

            if ('\0' == *p) {
                break;
            }

            label_start = p + 1;
        }
        ++p;
    }

    if (pos + 1 > buf_size) {
        return PN_DNS_ERR_OVERFLOW;
    }
    buf[pos++] = 0x00;

    *out_len = pos;
    return PN_DNS_OK;
}

int pn_dns_encode_query(const char* hostname,
                        uint16_t    qtype,
                        uint16_t    txn_id,
                        uint8_t*    buf,
                        size_t      buf_size,
                        size_t*     out_len)
{
    if (NULL == hostname || NULL == buf || NULL == out_len) {
        return PN_DNS_ERR_INVALID;
    }
    if (DNS_HEADER_SIZE > buf_size) {
        return PN_DNS_ERR_OVERFLOW;
    }

    size_t labels_len = 0;
    int    rc         = encode_labels(
        hostname, buf + DNS_HEADER_SIZE, buf_size - DNS_HEADER_SIZE, &labels_len);
    if (PN_DNS_OK != rc) {
        return rc;
    }

    size_t question_len = labels_len + 4;
    size_t total_len    = DNS_HEADER_SIZE + question_len;
    if (total_len > buf_size) {
        return PN_DNS_ERR_OVERFLOW;
    }

    memset(buf, 0, DNS_HEADER_SIZE);
    write_u16(buf + 0, txn_id);
    write_u16(buf + 2, 0x0100);
    write_u16(buf + 4, 1);

    size_t qtype_offset = DNS_HEADER_SIZE + labels_len;
    write_u16(buf + qtype_offset, qtype);
    write_u16(buf + qtype_offset + 2, DNS_CLASS_IN);

    *out_len = total_len;
    return PN_DNS_OK;
}

/**
 * @brief Case-insensitive ASCII equality for DNS label bytes (RFC 4343).
 */
static int dns_char_eq_ci(uint8_t a, uint8_t b)
{
    if (a >= 'A' && a <= 'Z') {
        a = (uint8_t)(a - 'A' + 'a');
    }
    if (b >= 'A' && b <= 'Z') {
        b = (uint8_t)(b - 'A' + 'a');
    }

    return a == b;
}

/**
 * @brief Walk a DNS name, advancing *offset, optionally matching a hostname.
 *
 * Follows compression pointers with a bounded jump count and advances *offset
 * past the name using the same rule as a plain name skip. When expected is
 * non-NULL, the walked name is compared case-insensitively against it and the
 * verdict is written to *out_matched (1 = equal, 0 = differs). When expected
 * is NULL, matching is skipped and *out_matched is left untouched.
 *
 * @param buf         Response buffer start.
 * @param len         Response buffer length.
 * @param offset      Starting offset (updated to position after the name).
 * @param expected    Expected NUL-terminated hostname, or NULL to skip match.
 * @param out_matched Match verdict output (written only when expected != NULL).
 * @retval PN_DNS_OK on a well-formed name.
 * @retval PN_DNS_ERR_INVALID on malformed wire data.
 */
/** Advance *exp past one label in buf[pos+1..pos+label_len], returns 0 on mismatch. */
static int match_label(const uint8_t* buf,
                       size_t         pos,
                       uint8_t        label_len,
                       const char**   exp,
                       const char*    expected)
{
    size_t k;
    if (*exp != expected) {
        if ('.' != **exp) {
            return 0;
        }
        ++(*exp);
    }
    for (k = 0; k < label_len; ++k) {
        if ('\0' == **exp || 0 == dns_char_eq_ci(buf[pos + 1 + k], (uint8_t)**exp)) {
            return 0;
        }
        ++(*exp);
    }
    return 1;
}

static int decode_name(const uint8_t* buf,
                       size_t         len,
                       size_t*        offset,
                       const char*    expected,
                       int*           out_matched)
{
    size_t pos           = *offset;
    int    jumps         = 0;
    size_t end_after_ptr = 0; /* position after first compression pointer */
    int    followed_ptr  = 0;
    int    matched       = (NULL != expected);
    const char* exp      = expected;

    while (pos < len) {
        uint8_t label_len = buf[pos];

        if (DNS_COMPRESSION_MASK == (label_len & DNS_COMPRESSION_MASK)) {
            if (pos + 1 >= len) {
                return PN_DNS_ERR_INVALID;
            }
            /* Record end position on the first pointer we follow. */
            if (!followed_ptr) {
                end_after_ptr = pos + 2;
                followed_ptr  = 1;
            }
            uint16_t ptr = (uint16_t)(((uint16_t)(label_len & 0x3FU) << 8)
                                      | (uint16_t)buf[pos + 1]);
            if (ptr >= len) {
                return PN_DNS_ERR_INVALID;
            }
            if (DNS_MAX_POINTER_JUMPS <= ++jumps) {
                return PN_DNS_ERR_INVALID;
            }
            pos = ptr;
        } else if (0 == label_len) {
            /* Name ended: advance past the terminating byte, or past the
             * first pointer (whichever comes last in the wire stream). */
            *offset = followed_ptr ? end_after_ptr : pos + 1;
            if (matched && '\0' != *exp) {
                matched = 0;
            }
            if (NULL != out_matched) {
                *out_matched = matched;
            }
            return PN_DNS_OK;
        } else {
            if (pos + 1 + (size_t)label_len > len) {
                return PN_DNS_ERR_INVALID;
            }
            if (matched) {
                matched = match_label(buf, pos, label_len, &exp, expected);
            }
            pos += 1 + (size_t)label_len;
        }
    }

    return PN_DNS_ERR_INVALID;
}

/**
 * @brief Materialize a DNS name at offset into a dotted hostname string.
 *
 * Follows compression pointers with a bounded jump count. Does not advance a
 * caller offset — used to capture a CNAME target for later owner matching.
 * Truncation (name longer than out_size - 1) is reported as failure so that a
 * partial name is never matched against subsequent records.
 *
 * @param buf      Response buffer start.
 * @param len      Response buffer length.
 * @param offset   Offset of the name to materialize.
 * @param out      Output buffer for the NUL-terminated dotted name.
 * @param out_size Capacity of out in bytes.
 * @retval PN_DNS_OK on success.
 * @retval PN_DNS_ERR_INVALID on malformed input or truncation.
 */
static int decode_name_str(const uint8_t* buf,
                           size_t         len,
                           size_t         offset,
                           char*          out,
                           size_t         out_size)
{
    size_t pos    = offset;
    int    jumps  = 0;
    size_t outpos = 0;

    while (pos < len) {
        uint8_t label_len = buf[pos];

        if (DNS_COMPRESSION_MASK == (label_len & DNS_COMPRESSION_MASK)) {
            if (pos + 1 >= len) {
                return PN_DNS_ERR_INVALID;
            }
            uint16_t ptr = (uint16_t)(((uint16_t)(label_len & 0x3FU) << 8)
                                      | (uint16_t)buf[pos + 1]);
            if (ptr >= len) {
                return PN_DNS_ERR_INVALID;
            }
            if (DNS_MAX_POINTER_JUMPS <= ++jumps) {
                return PN_DNS_ERR_INVALID;
            }
            pos = ptr;
        } else if (0 == label_len) {
            if (outpos >= out_size) {
                return PN_DNS_ERR_INVALID;
            }
            out[outpos] = '\0';
            return PN_DNS_OK;
        } else {
            size_t k;
            if (pos + 1 + (size_t)label_len > len) {
                return PN_DNS_ERR_INVALID;
            }
            if (0 != outpos) {
                if (outpos + 1 >= out_size) {
                    return PN_DNS_ERR_INVALID;
                }
                out[outpos++] = '.';
            }
            if (outpos + (size_t)label_len >= out_size) {
                return PN_DNS_ERR_INVALID;
            }
            for (k = 0; k < label_len; ++k) {
                out[outpos++] = (char)buf[pos + 1 + k];
            }
            pos += 1 + (size_t)label_len;
        }
    }

    return PN_DNS_ERR_INVALID;
}

int pn_dns_decode_response(const uint8_t* buf,
                           size_t         len,
                           uint16_t       expected_txn_id,
                           const char*    expected_hostname,
                           pn_sockaddr_t* addrs_out,
                           size_t         max_addrs,
                           size_t*        out_count,
                           uint32_t*      out_ttl)
{
    /* Mutable copy of the name we currently accept as an answer owner. Starts
     * as the queried hostname and advances along any CNAME chain. Sized to the
     * RFC 1035 name limit (+1 for the NUL terminator). */
    char        owner_name[DNS_MAX_HOSTNAME_LEN + 1];
    const char* expected = expected_hostname;

    if (NULL == buf || NULL == addrs_out || NULL == out_count || NULL == out_ttl) {
        return PN_DNS_ERR_INVALID;
    }
    if (DNS_HEADER_SIZE > len) {
        return PN_DNS_ERR_INVALID;
    }

    if (NULL != expected_hostname) {
        size_t hlen = strlen(expected_hostname);
        if (hlen >= sizeof(owner_name)) {
            return PN_DNS_ERR_INVALID;
        }
        memcpy(owner_name, expected_hostname, hlen + 1);
        expected = owner_name;
    }

    /* Read txn_id directly from bytes for maximum MSVC compatibility. */
    uint16_t txn_id = (uint16_t)(((uint32_t)buf[0] << 8) | (uint32_t)buf[1]);
    if (expected_txn_id != txn_id) {
        return PN_DNS_ERR_TXN_ID;
    }

    /* QR bit is bit 7 of the flags high byte (buf[2]).
     * Read directly from the raw byte to avoid any MSVC optimizer
     * interference with the 16-bit flags word reconstruction. */
    if (0 == (buf[2] & 0x80U)) {
        return PN_DNS_ERR_INVALID;
    }

    uint8_t rcode = (uint8_t)(buf[3] & DNS_RCODE_MASK);
    if (0 != rcode) {
        return PN_DNS_ERR_RCODE;
    }

    uint16_t qdcount = read_u16(buf + 4);
    uint16_t ancount = read_u16(buf + 6);

    size_t offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < qdcount; ++i) {
        int q_matched = 0;
        if (PN_DNS_OK != decode_name(buf, len, &offset, expected, &q_matched)) {
            return PN_DNS_ERR_INVALID;
        }
        /* Reject a reply whose question echoes a name we never queried. */
        if (NULL != expected && 0 == q_matched) {
            return PN_DNS_ERR_INVALID;
        }
        if (offset + 4 > len) {
            return PN_DNS_ERR_INVALID;
        }
        offset += 4;
    }

    uint32_t min_ttl    = UINT32_MAX;
    size_t   addr_count = 0;

    for (uint16_t i = 0; i < ancount; ++i) {
        int owner_matched = 0;
        if (PN_DNS_OK != decode_name(buf, len, &offset, expected, &owner_matched)) {
            return PN_DNS_ERR_INVALID;
        }
        if (offset + 10 > len) {
            return PN_DNS_ERR_INVALID;
        }

        uint16_t rtype    = read_u16(buf + offset);
        uint32_t ttl      = read_u32(buf + offset + 4);
        uint16_t rdlength = read_u16(buf + offset + 8);
        offset += 10;

        if (offset + rdlength > len) {
            return PN_DNS_ERR_INVALID;
        }

        /* When a hostname is supplied, accept only records whose owner name
         * matches the name we are currently resolving (the query name, or the
         * canonical target reached through a CNAME chain). Records for any
         * other owner are skipped. */
        if (NULL == expected || 0 != owner_matched) {
            if (NULL != expected && DNS_TYPE_CNAME == rtype) {
                /* Adopt the canonical name as the owner accepted for the
                 * remaining answer records. */
                if (PN_DNS_OK
                    == decode_name_str(
                        buf, len, offset, owner_name, sizeof(owner_name))) {
                    expected = owner_name;
                }
            } else if (PN_DNS_TYPE_A == rtype && 4 == rdlength) {
                if (addr_count < max_addrs) {
                    pn_sockaddr_t* addr = &addrs_out[addr_count];
                    addr->family        = PN_AF_INET;
                    addr->port          = 0;
                    memcpy(addr->addr.ipv4, buf + offset, 4);
                    ++addr_count;
                }

                if (ttl < min_ttl) {
                    min_ttl = ttl;
                }
            } else if (PN_DNS_TYPE_AAAA == rtype && 16 == rdlength) {
                if (addr_count < max_addrs) {
                    pn_sockaddr_t* addr = &addrs_out[addr_count];
                    addr->family        = PN_AF_INET6;
                    addr->port          = 0;
                    memcpy(addr->addr.ipv6, buf + offset, 16);
                    ++addr_count;
                }

                if (ttl < min_ttl) {
                    min_ttl = ttl;
                }
            }
        }

        offset += rdlength;
    }

    *out_count = addr_count;
    *out_ttl   = (UINT32_MAX == min_ttl) ? 0 : min_ttl;
    return PN_DNS_OK;
}
