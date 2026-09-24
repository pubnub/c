/**
 * @file test_dns_codec.c
 * @brief DNS codec unit tests.
 */

#include "dns_codec.h"

#include <cmocka.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void test_encode_a_query(void** state)
{
    (void)state;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_dns_encode_query(
        "ps.pndsn.com", PN_DNS_TYPE_A, 0x1234, buf, sizeof(buf), &len);

    assert_int_equal(0, rc);
    assert_true(len > 12);

    assert_int_equal(0x12, buf[0]);
    assert_int_equal(0x34, buf[1]);
    assert_int_equal(0x01, buf[2]);
    assert_int_equal(0x00, buf[3]);
    assert_int_equal(0x00, buf[4]);
    assert_int_equal(0x01, buf[5]);

    size_t offset = 12;
    assert_int_equal(2, buf[offset++]);
    assert_int_equal('p', buf[offset++]);
    assert_int_equal('s', buf[offset++]);
    assert_int_equal(5, buf[offset++]);
    assert_int_equal('p', buf[offset++]);
    assert_int_equal('n', buf[offset++]);
    assert_int_equal('d', buf[offset++]);
    assert_int_equal('s', buf[offset++]);
    assert_int_equal('n', buf[offset++]);
    assert_int_equal(3, buf[offset++]);
    assert_int_equal('c', buf[offset++]);
    assert_int_equal('o', buf[offset++]);
    assert_int_equal('m', buf[offset++]);
    assert_int_equal(0x00, buf[offset++]);

    assert_int_equal(0x00, buf[offset++]);
    assert_int_equal(PN_DNS_TYPE_A, buf[offset++]);
    assert_int_equal(0x00, buf[offset++]);
    assert_int_equal(0x01, buf[offset++]);

    assert_int_equal(len, offset);
}

static void test_encode_aaaa_query(void** state)
{
    (void)state;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_dns_encode_query(
        "example.com", PN_DNS_TYPE_AAAA, 0xABCD, buf, sizeof(buf), &len);

    assert_int_equal(0, rc);
    assert_true(len > 12);

    assert_int_equal(0xAB, buf[0]);
    assert_int_equal(0xCD, buf[1]);

    size_t qtype_offset = 12 + (1 + 7) + (1 + 3) + 1; /* header + label bytes */
    assert_int_equal(0x00, buf[qtype_offset]);
    assert_int_equal(PN_DNS_TYPE_AAAA, buf[qtype_offset + 1]);
}

static void test_encode_long_hostname(void** state)
{
    (void)state;

    uint8_t buf[512];
    size_t  len = 0;
    int     rc  = pn_dns_encode_query(
        "sub.domain.example.co.uk", PN_DNS_TYPE_A, 0x5678, buf, sizeof(buf), &len);

    assert_int_equal(0, rc);
    assert_true(len > 12);

    size_t offset = 12;
    assert_int_equal(3, buf[offset++]);
    assert_int_equal('s', buf[offset++]);
    assert_int_equal('u', buf[offset++]);
    assert_int_equal('b', buf[offset++]);
    assert_int_equal(6, buf[offset++]);
    assert_int_equal('d', buf[offset++]);
    assert_int_equal('o', buf[offset++]);
    assert_int_equal('m', buf[offset++]);
    assert_int_equal('a', buf[offset++]);
    assert_int_equal('i', buf[offset++]);
    assert_int_equal('n', buf[offset++]);
    assert_int_equal(7, buf[offset++]);
    assert_int_equal('e', buf[offset++]);
    assert_int_equal('x', buf[offset++]);
    assert_int_equal('a', buf[offset++]);
    assert_int_equal('m', buf[offset++]);
    assert_int_equal('p', buf[offset++]);
    assert_int_equal('l', buf[offset++]);
    assert_int_equal('e', buf[offset++]);
    assert_int_equal(2, buf[offset++]);
    assert_int_equal('c', buf[offset++]);
    assert_int_equal('o', buf[offset++]);
    assert_int_equal(2, buf[offset++]);
    assert_int_equal('u', buf[offset++]);
    assert_int_equal('k', buf[offset++]);
    assert_int_equal(0x00, buf[offset++]);
}

static void test_encode_buffer_too_small(void** state)
{
    (void)state;

    uint8_t buf[20];
    size_t  len = 0;
    int     rc  = pn_dns_encode_query(
        "ps.pndsn.com", PN_DNS_TYPE_A, 0x1234, buf, sizeof(buf), &len);

    assert_int_equal(-2, rc);
}

/**
 * @brief Minimal A-record response with qdcount=0 to isolate skip_name.
 *
 * If this passes on Windows but test_decode_a_response fails, skip_name
 * is the culprit. Header-only validation + direct answer without question
 * section skip.
 */
static void test_decode_a_response_no_question(void** state)
{
    (void)state;

    /* qdcount=0, ancount=1, direct A record (no name compression) */
    static const uint8_t response[] = {
        0x12, 0x34,              /* TXN=0x1234           */
        0x81, 0x80,              /* QR=1 RCODE=0         */
        0x00, 0x00,              /* qdcount=0            */
        0x00, 0x01,              /* ancount=1            */
        0x00, 0x00, 0x00, 0x00,  /* nscount=0 arcount=0  */
        0x00,                    /* NAME: root label (0) */
        0x00, 0x01,              /* TYPE=A               */
        0x00, 0x01,              /* CLASS=IN             */
        0x00, 0x00, 0x00, 0x3C,  /* TTL=60               */
        0x00, 0x04,              /* RDLENGTH=4           */
        0xC0, 0xA8, 0x01, 0x01}; /* 192.168.1.1          */

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    /* NULL hostname: skip name matching so this root-owner answer (used to
     * isolate the name walker) is still extracted. */
    int rc = pn_dns_decode_response(
        response, sizeof(response), 0x1234, NULL, addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(1, count);
    assert_int_equal(60, ttl);
    assert_int_equal(PN_AF_INET, addrs[0].family);
    assert_int_equal(0xC0, addrs[0].addr.ipv4[0]);
    assert_int_equal(0xA8, addrs[0].addr.ipv4[1]);
    assert_int_equal(0x01, addrs[0].addr.ipv4[2]);
    assert_int_equal(0x01, addrs[0].addr.ipv4[3]);
}

static void test_decode_a_response(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',  0x03,
        'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0xC0, 0xA8,
        0x01, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x04, 0xC0, 0xA8, 0x01, 0x02};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(2, count);
    assert_int_equal(60, ttl);

    assert_int_equal(PN_AF_INET, addrs[0].family);
    assert_int_equal(0xC0, addrs[0].addr.ipv4[0]);
    assert_int_equal(0xA8, addrs[0].addr.ipv4[1]);
    assert_int_equal(0x01, addrs[0].addr.ipv4[2]);
    assert_int_equal(0x01, addrs[0].addr.ipv4[3]);

    assert_int_equal(PN_AF_INET, addrs[1].family);
    assert_int_equal(0xC0, addrs[1].addr.ipv4[0]);
    assert_int_equal(0xA8, addrs[1].addr.ipv4[1]);
    assert_int_equal(0x01, addrs[1].addr.ipv4[2]);
    assert_int_equal(0x02, addrs[1].addr.ipv4[3]);
}

static void test_decode_aaaa_response(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x1C, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x2C, 0x00, 0x10, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0xABCD, "example.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(1, count);
    assert_int_equal(300, ttl);

    assert_int_equal(PN_AF_INET6, addrs[0].family);
    assert_int_equal(0x20, addrs[0].addr.ipv6[0]);
    assert_int_equal(0x01, addrs[0].addr.ipv6[1]);
    assert_int_equal(0x0D, addrs[0].addr.ipv6[2]);
    assert_int_equal(0xB8, addrs[0].addr.ipv6[3]);
    assert_int_equal(0x00, addrs[0].addr.ipv6[4]);
    assert_int_equal(0x01, addrs[0].addr.ipv6[15]);
}

static void test_decode_txn_id_mismatch(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',
        'n',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0xFFFF, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(-2, rc);
}

static void test_decode_nxdomain(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',
        'n',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(-3, rc);
}

static void test_decode_compressed_name(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',  0x03, 'c',  'o',
        'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0xC0, 0xA8, 0x01, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(1, count);
}

static void test_decode_truncated(void** state)
{
    (void)state;

    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(-1, rc);
}

/**
 * @brief Test: NOERROR response with 0 AAAA answers (IPv4-only host).
 *
 * Real-world scenario: the resolver sends both A and AAAA queries. For
 * a host that has no AAAA record (IPv4-only), the server returns NOERROR
 * with ancount=0 for the AAAA query. The decoder must return 0 (success)
 * with count=0, NOT -3 (which is only for NXDOMAIN/SERVFAIL).
 * This matches the behavior expected from h2.pubnubapi.com when queried
 * for AAAA on networks where it has no IPv6 address.
 */
static void test_decode_aaaa_nodata_response(void** state)
{
    (void)state;

    /* NOERROR with QDCOUNT=1, ANCOUNT=0 — server has no AAAA record. */
    static const uint8_t response[] = {
        0xAB, 0xCD, 0x81, 0x80, /* TXN=0xABCD, flags QR+AA+RD+RA */
        0x00, 0x01, 0x00, 0x00, /* qdcount=1, ancount=0          */
        0x00, 0x00, 0x00, 0x00, /* nscount=0, arcount=0          */
        0x02, 'h',  '2',  0x09, /* QNAME: "h2.pubnubapi.com"     */
        'p',  'u',  'b',  'n',  /*   label "h2"                  */
        'u',  'b',  'a',  'p',  /*   label "pubnubapi"           */
        'i',  0x03, 'c',  'o',  /*   label "com"                 */
        'm',  0x00, 0x00, 0x1C, /* QNAME terminator, QTYPE=AAAA  */
        0x00, 0x01};            /* QCLASS=IN                     */

    pn_sockaddr_t addrs[10];
    size_t        count = 99; /* non-zero to verify it's cleared */
    uint32_t      ttl   = 99;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0xABCD, "h2.pubnubapi.com", addrs, 10, &count, &ttl);

    /* NOERROR with 0 answers: success, 0 addresses, ttl=0 */
    assert_int_equal(0, rc);
    assert_int_equal(0, count);
    assert_int_equal(0, ttl);
}

/**
 * @brief Test: NOERROR response with mixed A and AAAA records.
 *
 * Verifies that when querying with txn_id_a (for A records), only A
 * records are extracted even if the response also contains AAAA records
 * in the additional section. The decoder ignores record types other than
 * the requested one.
 */
static void test_decode_mixed_record_types(void** state)
{
    (void)state;

    /* Response contains 1 A record and 1 AAAA record in answers.
     * When decoded looking for A records (type=1), only the A is counted. */
    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, /* TXN=0x1234, QR+RD+RA, RCODE=0 */
        0x00, 0x01, 0x00, 0x02, /* qdcount=1, ancount=2           */
        0x00, 0x00, 0x00, 0x00, 0x02, 'h',  '2',  0x09, 'p',
        'u',  'b',  'n',  'u',  'b',  'a',  'p',  'i',  0x03,
        'c',  'o',  'm',  0x00, 0x00, 0x01, /* QTYPE=A (0x0001)               */
        0x00, 0x01,                         /* QCLASS=IN                      */
        0xC0, 0x0C,                         /* Answer 1 NAME: ptr to offset 12*/
        0x00, 0x01,                         /* TYPE=A                         */
        0x00, 0x01,                         /* CLASS=IN                       */
        0x00, 0x00, 0x00, 0x3C,             /* TTL=60                         */
        0x00, 0x04,                         /* RDLENGTH=4                     */
        0x68, 0x6F, 0x73, 0x74,             /* 104.111.115.116                */
        0xC0, 0x0C,                         /* Answer 2 NAME: ptr to offset 12*/
        0x00, 0x1C,                         /* TYPE=AAAA                      */
        0x00, 0x01,                         /* CLASS=IN                       */
        0x00, 0x00, 0x00, 0x3C,             /* TTL=60                         */
        0x00, 0x10,                         /* RDLENGTH=16                    */
        0x20, 0x01, 0x0D, 0xB8,             /* IPv6 2001:db8::1               */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;

    /* Decoder collects both A and AAAA records from the answer section. */
    int rc = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "h2.pubnubapi.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(2, count); /* 1 A + 1 AAAA */
    assert_int_equal(60, ttl);
    assert_int_equal(PN_AF_INET, addrs[0].family);
    assert_int_equal(0x68, addrs[0].addr.ipv4[0]);
    assert_int_equal(0x6F, addrs[0].addr.ipv4[1]);
    assert_int_equal(0x73, addrs[0].addr.ipv4[2]);
    assert_int_equal(0x74, addrs[0].addr.ipv4[3]);
    assert_int_equal(PN_AF_INET6, addrs[1].family);
    assert_int_equal(0x20, addrs[1].addr.ipv6[0]);
    assert_int_equal(0x01, addrs[1].addr.ipv6[1]);
}

/**
 * @brief Test: question QNAME that differs from the queried hostname is
 *        rejected (defends against off-path answer injection).
 */
static void test_decode_question_name_mismatch(void** state)
{
    (void)state;

    /* Valid A response whose QNAME is "ps.pndsn.com". */
    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',  0x03, 'c',  'o',
        'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0xC0, 0xA8, 0x01, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    /* We queried "evil.example", the reply answers "ps.pndsn.com". */
    int rc = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "evil.example", addrs, 10, &count, &ttl);

    assert_int_equal(-1, rc);
}

/**
 * @brief Test: an answer whose owner name differs from the queried hostname is
 *        skipped rather than extracted (defends against cache-poisoning-style
 *        piggybacked answers).
 */
static void test_decode_answer_owner_mismatch(void** state)
{
    (void)state;

    /* Question is "ps.pndsn.com" (matches), but the single answer's owner is
     * the unrelated inline name "ev.pndsn.com". */
    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',  0x03, 'c',  'o',
        'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 'e',  'v',  0x05, 'p',  'n',
        'd',  's',  'n',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 99;
    uint32_t      ttl   = 99;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    /* Well-formed packet, but the mismatched answer is ignored. */
    assert_int_equal(0, rc);
    assert_int_equal(0, count);
    assert_int_equal(0, ttl);
}

/**
 * @brief Test: a CNAME chain is followed so that A records published under the
 *        canonical name are still accepted (no regression for CNAME hosts).
 */
static void test_decode_cname_chain(void** state)
{
    (void)state;

    /* Question "www.pndsn.com"; answer 1 is CNAME -> "ps.pndsn.com"; answer 2
     * is an A record owned by the canonical name "ps.pndsn.com". */
    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x03, 'w',  'w',  'w',  0x05, 'p',  'n',  'd',  's',  'n',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C,
        0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x0E, 0x02,
        'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',  0x03, 'c',  'o',
        'm',  0x00, 0x02, 'p',  's',  0x05, 'p',  'n',  'd',  's',  'n',
        0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x3C, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "www.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(1, count);
    assert_int_equal(PN_AF_INET, addrs[0].family);
    assert_int_equal(0x0A, addrs[0].addr.ipv4[0]);
    assert_int_equal(0x00, addrs[0].addr.ipv4[1]);
    assert_int_equal(0x00, addrs[0].addr.ipv4[2]);
    assert_int_equal(0x01, addrs[0].addr.ipv4[3]);
}

/**
 * @brief Test: name matching is case-insensitive per RFC 4343.
 */
static void test_decode_case_insensitive_match(void** state)
{
    (void)state;

    /* QNAME uses uppercase "PS.PNDSN.COM"; the resolver queried lowercase. */
    static const uint8_t response[] = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x02, 'P',  'S',  0x05, 'P',  'N',  'D',  'S',  'N',  0x03, 'C',  'O',
        'M',  0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x02};

    pn_sockaddr_t addrs[10];
    size_t        count = 0;
    uint32_t      ttl   = 0;
    int           rc    = pn_dns_decode_response(
        response, sizeof(response), 0x1234, "ps.pndsn.com", addrs, 10, &count, &ttl);

    assert_int_equal(0, rc);
    assert_int_equal(1, count);
    assert_int_equal(PN_AF_INET, addrs[0].family);
    assert_int_equal(0x02, addrs[0].addr.ipv4[3]);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_decode_a_response_no_question),
        cmocka_unit_test(test_encode_a_query),
        cmocka_unit_test(test_encode_aaaa_query),
        cmocka_unit_test(test_encode_long_hostname),
        cmocka_unit_test(test_encode_buffer_too_small),
        cmocka_unit_test(test_decode_a_response),
        cmocka_unit_test(test_decode_aaaa_response),
        cmocka_unit_test(test_decode_txn_id_mismatch),
        cmocka_unit_test(test_decode_nxdomain),
        cmocka_unit_test(test_decode_compressed_name),
        cmocka_unit_test(test_decode_truncated),
        cmocka_unit_test(test_decode_aaaa_nodata_response),
        cmocka_unit_test(test_decode_mixed_record_types),
        cmocka_unit_test(test_decode_question_name_mismatch),
        cmocka_unit_test(test_decode_answer_owner_mismatch),
        cmocka_unit_test(test_decode_cname_chain),
        cmocka_unit_test(test_decode_case_insensitive_match),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
