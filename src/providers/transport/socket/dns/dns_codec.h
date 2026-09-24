/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file dns_codec.h
 * @brief DNS wire format codec (RFC 1035).
 */

#ifndef PN_DNS_CODEC_H
#define PN_DNS_CODEC_H

#include "providers/transport/socket/platform/pn_socket_types.h"

#include <stddef.h>
#include <stdint.h>

/** Query type for IPv4 address (A record). */
#define PN_DNS_TYPE_A 1

/** Query type for IPv6 address (AAAA record). */
#define PN_DNS_TYPE_AAAA 28

/** @brief Return code: success (both functions). */
#define PN_DNS_OK 0
/** @brief Return code: validation error — NULL args, invalid hostname,
 *  or malformed wire data (both functions). */
#define PN_DNS_ERR_INVALID (-1)
/** @brief Return code: output buffer too small (pn_dns_encode_query only). */
#define PN_DNS_ERR_OVERFLOW (-2)
/** @brief Return code: transaction ID mismatch (pn_dns_decode_response only).
 *  Same value as PN_DNS_ERR_OVERFLOW — valid only in the decode context. */
#define PN_DNS_ERR_TXN_ID (-2)
/** @brief Return code: DNS error RCODE != 0, e.g. NXDOMAIN or SERVFAIL
 *  (pn_dns_decode_response only). */
#define PN_DNS_ERR_RCODE (-3)

/**
 * @brief Encode a DNS query for a hostname.
 *
 * Produces an RFC 1035 §4.1 wire-format query with a single question
 * section. The query is non-recursive (RD bit clear), uses CLASS=IN,
 * and requests the specified record type.
 *
 * @param hostname  NUL-terminated hostname (e.g., "ps.pndsn.com").
 * @param qtype     Query type (PN_DNS_TYPE_A or PN_DNS_TYPE_AAAA).
 * @param txn_id    16-bit transaction ID (must be unique per query).
 * @param buf       Output buffer for wire-format query.
 * @param buf_size  Buffer capacity in bytes.
 * @param out_len   Written length on success (valid only when return
 *                  is PN_DNS_OK).
 * @retval PN_DNS_OK on success.
 * @retval PN_DNS_ERR_INVALID on validation/encoding error.
 * @retval PN_DNS_ERR_OVERFLOW on buffer too small.
 */
int pn_dns_encode_query(const char* hostname,
                        uint16_t    qtype,
                        uint16_t    txn_id,
                        uint8_t*    buf,
                        size_t      buf_size,
                        size_t*     out_len);

/**
 * @brief Decode a DNS response, extracting addresses and TTL.
 *
 * Parses an RFC 1035 §4.1 wire-format response. Validates transaction ID,
 * checks RCODE, validates the question and answer names against the queried
 * hostname, and extracts A/AAAA records from the answer section. Name
 * compression pointers are followed with a max-jump limit to prevent infinite
 * loops. CNAME chains are followed so that A/AAAA records published under a
 * canonical name are still accepted.
 *
 * @param buf               Response buffer.
 * @param len               Response length in bytes.
 * @param expected_txn_id   Expected transaction ID (rejects mismatches).
 * @param expected_hostname Queried NUL-terminated hostname used to validate
 *                          the question QNAME and answer owner names. Pass
 *                          NULL to skip name matching (extract every A/AAAA
 *                          record regardless of owner).
 * @param addrs_out         Output array for resolved addresses.
 * @param max_addrs         Capacity of addrs_out.
 * @param out_count         Number of addresses written (valid only when
 *                          return is PN_DNS_OK).
 * @param out_ttl           Minimum TTL across all answer records in seconds
 *                          (valid only when return is PN_DNS_OK).
 * @retval PN_DNS_OK on success.
 * @retval PN_DNS_ERR_INVALID on format error (truncated packet, invalid
 *                          structure, or a question QNAME that does not match
 *                          expected_hostname).
 * @retval PN_DNS_ERR_TXN_ID on transaction ID mismatch.
 * @retval PN_DNS_ERR_RCODE on DNS error (NXDOMAIN, SERVFAIL, or other RCODE != 0).
 */
int pn_dns_decode_response(const uint8_t* buf,
                           size_t         len,
                           uint16_t       expected_txn_id,
                           const char*    expected_hostname,
                           pn_sockaddr_t* addrs_out,
                           size_t         max_addrs,
                           size_t*        out_count,
                           uint32_t*      out_ttl);

#endif /* PN_DNS_CODEC_H */
