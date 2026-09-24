/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* cmocka must come after the std headers. */
#include <cmocka.h>

#include "features/access/access_internal.h"
#include "features/access/pn_cbor.h"

static void* real_alloc(pubnub_allocator_provider_t* self, size_t size, size_t align)
{
    (void)self;
    (void)align;
    return test_malloc(size);
}

static void* real_realloc(pubnub_allocator_provider_t* self,
                          void*                        ptr,
                          size_t                       old_size,
                          size_t                       new_size,
                          size_t                       align)
{
    (void)self;
    (void)old_size;
    (void)align;
    return test_realloc(ptr, new_size);
}

static void real_free(pubnub_allocator_provider_t* self, void* ptr)
{
    (void)self;
    test_free(ptr);
}

static pubnub_allocator_provider_t s_alloc = {
    .alloc   = real_alloc,
    .realloc = real_realloc,
    .free    = real_free,
};

/* ---------------------------------------------------------------
 * Group 1: CBOR Decoder Unit Tests
 * --------------------------------------------------------------- */

static void test_cbor_parse_null_input(void** state)
{
    (void)state;
    assert_null(pn_cbor_parse(NULL, 10, &s_alloc));
}

static void test_cbor_parse_null_allocator(void** state)
{
    (void)state;
    uint8_t input[] = {0x05};
    assert_null(pn_cbor_parse(input, sizeof(input), NULL));
}

static void test_cbor_parse_zero_length(void** state)
{
    (void)state;
    uint8_t input[] = {0x05};
    assert_null(pn_cbor_parse(input, 0, &s_alloc));
}

static void test_cbor_parse_uint_inline(void** state)
{
    (void)state;

    /* CBOR uint 5: major type 0, inline value 5. Byte: 0x05 */
    uint8_t          input[] = {0x05};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_int_equal(5, (int)root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_uint_zero(void** state)
{
    (void)state;

    /* CBOR uint 0: 0x00 */
    uint8_t          input[] = {0x00};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_int_equal(0, (int)root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_uint_23(void** state)
{
    (void)state;

    /* CBOR uint 23: 0x17 (max inline value) */
    uint8_t          input[] = {0x17};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_int_equal(23, (int)root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_uint_1byte(void** state)
{
    (void)state;

    /* CBOR uint 42: additional=24 (1-byte follows), value=42.
     * Bytes: 0x18 0x2A */
    uint8_t          input[] = {0x18, 0x2A};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_int_equal(42, (int)root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_uint_2byte(void** state)
{
    (void)state;

    /* CBOR uint 1000: additional=25 (2 bytes), 0x03E8.
     * Bytes: 0x19 0x03 0xE8 */
    uint8_t          input[] = {0x19, 0x03, 0xE8};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_int_equal(1000, (int)root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_uint_4byte(void** state)
{
    (void)state;

    /* CBOR uint 1632335843 (0x614B77E3): additional=26 (4 bytes).
     * Bytes: 0x1A 0x61 0x4B 0x77 0xE3 */
    uint8_t          input[] = {0x1A, 0x61, 0x4B, 0x77, 0xE3};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_UINT, root->type);
    assert_true(1632335843ULL == root->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_string(void** state)
{
    (void)state;

    /* CBOR text string "hello": 0x65 'h' 'e' 'l' 'l' 'o'
     * 0x65 = major type 3 (text), length 5 */
    uint8_t          input[] = {0x65, 'h', 'e', 'l', 'l', 'o'};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_STRING, root->type);
    assert_int_equal(5, (int)root->data.string.len);
    assert_memory_equal("hello", root->data.string.ptr, 5);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_string_empty(void** state)
{
    (void)state;

    /* CBOR text string "": 0x60 (major type 3, length 0) */
    uint8_t          input[] = {0x60};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_STRING, root->type);
    assert_int_equal(0, (int)root->data.string.len);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_bytes(void** state)
{
    (void)state;

    /* CBOR byte string (3 bytes): 0x43 0x01 0x02 0x03
     * 0x43 = major type 2 (bytes), length 3 */
    uint8_t          input[] = {0x43, 0x01, 0x02, 0x03};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_BYTES, root->type);
    assert_int_equal(3, (int)root->data.bytes.len);
    assert_int_equal(0x01, root->data.bytes.ptr[0]);
    assert_int_equal(0x02, root->data.bytes.ptr[1]);
    assert_int_equal(0x03, root->data.bytes.ptr[2]);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_bytes_empty(void** state)
{
    (void)state;

    /* CBOR byte string empty: 0x40 (major type 2, length 0) */
    uint8_t          input[] = {0x40};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_BYTES, root->type);
    assert_int_equal(0, (int)root->data.bytes.len);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_simple_map(void** state)
{
    (void)state;

    /* CBOR map {"a": 1}: 0xA1 0x61 'a' 0x01
     * 0xA1 = major type 5 (map), 1 entry
     * 0x61 = text(1)
     * 'a' = the key
     * 0x01 = uint(1) */
    uint8_t          input[] = {0xA1, 0x61, 'a', 0x01};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_MAP, root->type);
    assert_int_equal(1, (int)root->data.map.count);

    pn_cbor_value_t* val = pn_cbor_map_get(root, "a", 1);
    assert_non_null(val);
    assert_int_equal(PN_CBOR_UINT, val->type);
    assert_int_equal(1, (int)val->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_map_empty(void** state)
{
    (void)state;

    /* CBOR empty map: 0xA0 (map, 0 entries) */
    uint8_t          input[] = {0xA0};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_MAP, root->type);
    assert_int_equal(0, (int)root->data.map.count);
    assert_null(root->data.map.entries);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_map_multiple_entries(void** state)
{
    (void)state;

    /* CBOR map {"x": 10, "y": 20}:
     * 0xA2 = map(2)
     * 0x61 'x' = text(1) "x"
     * 0x0A = uint(10)
     * 0x61 'y' = text(1) "y"
     * 0x14 = uint(20) */
    uint8_t          input[] = {0xA2, 0x61, 'x', 0x0A, 0x61, 'y', 0x14};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_MAP, root->type);
    assert_int_equal(2, (int)root->data.map.count);

    pn_cbor_value_t* x_val = pn_cbor_map_get(root, "x", 1);
    assert_non_null(x_val);
    assert_int_equal(10, (int)x_val->data.uint_val);

    pn_cbor_value_t* y_val = pn_cbor_map_get(root, "y", 1);
    assert_non_null(y_val);
    assert_int_equal(20, (int)y_val->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_nested_map(void** state)
{
    (void)state;

    /* CBOR map {"x": {"y": 2}}:
     * 0xA1 = map(1)
     *   0x61 'x' = text(1) "x"
     *   0xA1 = map(1)
     *     0x61 'y' = text(1) "y"
     *     0x02 = uint(2) */
    uint8_t          input[] = {0xA1, 0x61, 'x', 0xA1, 0x61, 'y', 0x02};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_MAP, root->type);

    pn_cbor_value_t* inner = pn_cbor_map_get(root, "x", 1);
    assert_non_null(inner);
    assert_int_equal(PN_CBOR_MAP, inner->type);

    pn_cbor_value_t* y_val = pn_cbor_map_get(inner, "y", 1);
    assert_non_null(y_val);
    assert_int_equal(PN_CBOR_UINT, y_val->type);
    assert_int_equal(2, (int)y_val->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_map_with_string_value(void** state)
{
    (void)state;

    /* CBOR map {"k": "val"}:
     * 0xA1 = map(1)
     * 0x61 'k' = text(1) "k"
     * 0x63 'v' 'a' 'l' = text(3) "val" */
    uint8_t          input[] = {0xA1, 0x61, 'k', 0x63, 'v', 'a', 'l'};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    pn_cbor_value_t* val = pn_cbor_map_get(root, "k", 1);
    assert_non_null(val);
    assert_int_equal(PN_CBOR_STRING, val->type);
    assert_int_equal(3, (int)val->data.string.len);
    assert_memory_equal("val", val->data.string.ptr, 3);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_parse_deeply_nested(void** state)
{
    (void)state;

    /* 4 levels deep: {"a":{"b":{"c":{"d":99}}}}
     * max depth is 5, so 4 levels should succeed. */
    uint8_t input[] = {
        0xA1,
        0x61,
        'a', /* map(1), text(1) "a" */
        0xA1,
        0x61,
        'b', /* map(1), text(1) "b" */
        0xA1,
        0x61,
        'c', /* map(1), text(1) "c" */
        0xA1,
        0x61,
        'd',
        0x18, /* map(1), text(1) "d", uint1byte */
        0x63  /* value: 99 */
    };
    pn_cbor_value_t* root = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);

    pn_cbor_value_t* a = pn_cbor_map_get(root, "a", 1);
    assert_non_null(a);
    pn_cbor_value_t* b = pn_cbor_map_get(a, "b", 1);
    assert_non_null(b);
    pn_cbor_value_t* c = pn_cbor_map_get(b, "c", 1);
    assert_non_null(c);
    pn_cbor_value_t* d = pn_cbor_map_get(c, "d", 1);
    assert_non_null(d);
    assert_int_equal(PN_CBOR_UINT, d->type);
    assert_int_equal(99, (int)d->data.uint_val);

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_reject_array(void** state)
{
    (void)state;

    /* CBOR array [1, 2]: 0x82 0x01 0x02
     * Major type 4 (array) is not supported. */
    uint8_t          input[] = {0x82, 0x01, 0x02};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_negative_int(void** state)
{
    (void)state;

    /* CBOR negative integer -1: 0x20 (major type 1, value 0) */
    uint8_t          input[] = {0x20};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_tag(void** state)
{
    (void)state;

    /* CBOR tag(0) + uint(0): 0xC0 0x00 (major type 6) */
    uint8_t          input[] = {0xC0, 0x00};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_float(void** state)
{
    (void)state;

    /* CBOR false: 0xF4 (major type 7, special value) */
    uint8_t          input[] = {0xF4};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_oversized(void** state)
{
    (void)state;

    /* Input exceeding PN_CBOR_MAX_INPUT (4096 bytes). */
    uint8_t input[4097];
    memset(input, 0, sizeof(input));
    pn_cbor_value_t* root = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_truncated_string(void** state)
{
    (void)state;

    /* Claims text of length 5, but only 3 bytes available.
     * 0x65 = text(5), then only "he" */
    uint8_t          input[] = {0x65, 'h', 'e'};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_trailing_bytes(void** state)
{
    (void)state;

    /* uint 5 followed by garbage byte. Parser should reject. */
    uint8_t          input[] = {0x05, 0xFF};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_reject_truncated_uint(void** state)
{
    (void)state;

    /* additional=25 (2-byte uint), but only 1 byte present. */
    uint8_t          input[] = {0x19, 0x03};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_null(root);
}

static void test_cbor_map_get_not_found(void** state)
{
    (void)state;

    /* Map {"a": 1} — look up "b" which doesn't exist. */
    uint8_t          input[] = {0xA1, 0x61, 'a', 0x01};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_null(pn_cbor_map_get(root, "b", 1));

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_map_get_null_map(void** state)
{
    (void)state;
    assert_null(pn_cbor_map_get(NULL, "a", 1));
}

static void test_cbor_map_get_non_map(void** state)
{
    (void)state;

    /* Try map_get on a uint node (not a map). */
    uint8_t          input[] = {0x05};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_null(pn_cbor_map_get(root, "x", 1));

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_map_get_null_key(void** state)
{
    (void)state;

    uint8_t          input[] = {0xA1, 0x61, 'a', 0x01};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_null(pn_cbor_map_get(root, NULL, 1));

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_map_get_byte_string_key(void** state)
{
    (void)state;

    /* Map with byte-string key (PubNub token format):
     * 0xA1 = map(1)
     * 0x41 'v' = byte string(1) containing 'v'
     * 0x02 = uint(2)
     *
     * pn_cbor_map_get must match byte-string keys too. */
    uint8_t          input[] = {0xA1, 0x41, 'v', 0x02};
    pn_cbor_value_t* root    = pn_cbor_parse(input, sizeof(input), &s_alloc);

    assert_non_null(root);
    assert_int_equal(PN_CBOR_MAP, root->type);

    pn_cbor_value_t* val = pn_cbor_map_get(root, "v", 1);
    assert_non_null(val);
    assert_int_equal(PN_CBOR_UINT, val->type);
    assert_int_equal(2, (int)val->data.uint_val);

    /* Non-matching key should still return NULL. */
    assert_null(pn_cbor_map_get(root, "x", 1));

    pn_cbor_cleanup(root, &s_alloc);
}

static void test_cbor_cleanup_null_safe(void** state)
{
    (void)state;

    /* Should not crash with NULL arguments. */
    pn_cbor_cleanup(NULL, &s_alloc);
    pn_cbor_cleanup(NULL, NULL);
}

/* ---------------------------------------------------------------
 * Group 2: Token Parse Integration Tests
 * --------------------------------------------------------------- */

/**
 * @brief Real token from PubNub Python SDK test suite
 *        (tests/unit/test_pam_v3.py).
 *
 * Decodes to a CBOR map with:
 *   v=2, t=1632335843, ttl=1440,
 *   uuid="myauthuuid1",
 *   res.chan.ch1=255, res.grp.cg1=255, res.uuid.uuid1=255,
 *   pat.uuid.^$=1,
 *   meta={score:100, color:"red", author:"pandu"},
 *   sig=32-byte signature
 */
static const char* const TEST_TOKEN_PYTHON_SDK =
    "qEF2AkF0GmFLd-NDdHRsGQWgQ3Jlc6VEY2hhbqFjY2gxGP9DZ3JwoWNj"
    "ZzEY_0N1c3KgQ3NwY6BEdXVpZKFldXVpZDEY_0NwYXSlRGNoYW6gQ2dycK"
    "BDdXNyoENzcGOgRHV1aWShYl4kAURtZXRho2VzY29yZRhkZWNvbG9yY3Jl"
    "ZGZhdXRob3JlcGFuZHVEdXVpZGtteWF1dGh1dWlkMUNzaWdYIP2vlxHik0"
    "EPZwtgYxAW3-LsBaX_WgWdYvtAXpYbKll3";

static void test_parse_token_cross_sdk_top_level(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_access_parse_token_impl(TEST_TOKEN_PYTHON_SDK, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(out.parsed_tree);
    assert_non_null(out.decoded_buf);

    /* Top-level scalar fields. */
    assert_int_equal(2, out.result.version);
    assert_true(1632335843ULL == out.result.timestamp);
    assert_int_equal(1440, (int)out.result.ttl);

    /* Authorized UUID. */
    assert_int_equal(11, (int)out.result.authorized_uuid.len);
    assert_memory_equal("myauthuuid1", out.result.authorized_uuid.ptr, 11);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_cross_sdk_resources(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_access_parse_token_impl(TEST_TOKEN_PYTHON_SDK, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);

    /* Resource counts. */
    assert_int_equal(1, (int)out.result.channel_count);
    assert_int_equal(1, (int)out.result.group_count);
    assert_int_equal(1, (int)out.result.uuid_count);

    /* Verify resource permissions via CBOR tree. */
    pn_cbor_value_t* res = pn_cbor_map_get(out.parsed_tree, "res", 3);
    assert_non_null(res);
    assert_int_equal(PN_CBOR_MAP, res->type);

    /* res.chan.ch1 = 255 (all permissions). */
    pn_cbor_value_t* chan = pn_cbor_map_get(res, "chan", 4);
    assert_non_null(chan);
    pn_cbor_value_t* ch1 = pn_cbor_map_get(chan, "ch1", 3);
    assert_non_null(ch1);
    assert_int_equal(PN_CBOR_UINT, ch1->type);
    assert_int_equal(255, (int)ch1->data.uint_val);

    /* res.grp.cg1 = 255. */
    pn_cbor_value_t* grp = pn_cbor_map_get(res, "grp", 3);
    assert_non_null(grp);
    pn_cbor_value_t* cg1 = pn_cbor_map_get(grp, "cg1", 3);
    assert_non_null(cg1);
    assert_int_equal(PN_CBOR_UINT, cg1->type);
    assert_int_equal(255, (int)cg1->data.uint_val);

    /* res.uuid.uuid1 = 255. */
    pn_cbor_value_t* uuid_map = pn_cbor_map_get(res, "uuid", 4);
    assert_non_null(uuid_map);
    pn_cbor_value_t* uuid1 = pn_cbor_map_get(uuid_map, "uuid1", 5);
    assert_non_null(uuid1);
    assert_int_equal(PN_CBOR_UINT, uuid1->type);
    assert_int_equal(255, (int)uuid1->data.uint_val);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_cross_sdk_patterns(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_access_parse_token_impl(TEST_TOKEN_PYTHON_SDK, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);

    /* Pattern counts. */
    assert_int_equal(0, (int)out.result.channel_pattern_count);
    assert_int_equal(0, (int)out.result.group_pattern_count);
    assert_int_equal(1, (int)out.result.uuid_pattern_count);

    /* Verify pat.uuid.^$ = 1 (read only). */
    pn_cbor_value_t* pat = pn_cbor_map_get(out.parsed_tree, "pat", 3);
    assert_non_null(pat);
    pn_cbor_value_t* pat_uuid = pn_cbor_map_get(pat, "uuid", 4);
    assert_non_null(pat_uuid);
    pn_cbor_value_t* pattern = pn_cbor_map_get(pat_uuid, "^$", 2);
    assert_non_null(pattern);
    assert_int_equal(PN_CBOR_UINT, pattern->type);
    assert_int_equal(1, (int)pattern->data.uint_val);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_cross_sdk_meta(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_access_parse_token_impl(TEST_TOKEN_PYTHON_SDK, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);

    /* meta = {score: 100, color: "red", author: "pandu"} */
    pn_cbor_value_t* meta = pn_cbor_map_get(out.parsed_tree, "meta", 4);
    assert_non_null(meta);
    assert_int_equal(PN_CBOR_MAP, meta->type);
    assert_int_equal(3, (int)meta->data.map.count);

    /* meta.score = 100. */
    pn_cbor_value_t* score = pn_cbor_map_get(meta, "score", 5);
    assert_non_null(score);
    assert_int_equal(PN_CBOR_UINT, score->type);
    assert_int_equal(100, (int)score->data.uint_val);

    /* meta.color = "red". */
    pn_cbor_value_t* color = pn_cbor_map_get(meta, "color", 5);
    assert_non_null(color);
    assert_int_equal(PN_CBOR_STRING, color->type);
    assert_int_equal(3, (int)color->data.string.len);
    assert_memory_equal("red", color->data.string.ptr, 3);

    /* meta.author = "pandu". */
    pn_cbor_value_t* author = pn_cbor_map_get(meta, "author", 6);
    assert_non_null(author);
    assert_int_equal(PN_CBOR_STRING, author->type);
    assert_int_equal(5, (int)author->data.string.len);
    assert_memory_equal("pandu", author->data.string.ptr, 5);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_cross_sdk_signature(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc =
        pn_access_parse_token_impl(TEST_TOKEN_PYTHON_SDK, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);

    /* sig = 32-byte byte string (HMAC-SHA256 output). */
    pn_cbor_value_t* sig = pn_cbor_map_get(out.parsed_tree, "sig", 3);
    assert_non_null(sig);
    assert_int_equal(PN_CBOR_BYTES, sig->type);
    assert_int_equal(32, (int)sig->data.bytes.len);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_null_rejected(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_access_parse_token_impl(NULL, &s_alloc, &out);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void test_parse_token_empty_rejected(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_access_parse_token_impl("", &s_alloc, &out);
    assert_int_equal(PUBNUB_ERR_INVALID_ARGUMENT, rc);
}

static void test_parse_token_invalid_base64(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    /* '!' is not valid base64url. */
    pubnub_res_t rc = pn_access_parse_token_impl("!!!invalid!!!", &s_alloc, &out);
    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
    assert_null(out.parsed_tree);
    assert_null(out.decoded_buf);
}

static void test_parse_token_invalid_cbor(void** state)
{
    (void)state;
    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    /* "AAAA" decodes to 3 zero bytes — not a valid CBOR map. */
    pubnub_res_t rc = pn_access_parse_token_impl("AAAA", &s_alloc, &out);
    assert_int_equal(PUBNUB_ERR_SERIALIZATION, rc);
    assert_null(out.parsed_tree);
    assert_null(out.decoded_buf);
}

static void test_parse_token_minimal_valid(void** state)
{
    (void)state;

    /* Minimal CBOR map: {"v":2, "t":1000, "ttl":60}
     *
     * CBOR hex: A3 61 76 02 61 74 19 03 E8 63 74 74 6C 18 3C
     * base64url: o2F2AmF0GQPoY3R0bBg8 */
    static const char token_b64url[] = "o2F2AmF0GQPoY3R0bBg8";

    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_access_parse_token_impl(token_b64url, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_non_null(out.parsed_tree);
    assert_int_equal(2, out.result.version);
    assert_int_equal(1000, (int)out.result.timestamp);
    assert_int_equal(60, (int)out.result.ttl);
    assert_int_equal(0, (int)out.result.channel_count);
    assert_int_equal(0, (int)out.result.authorized_uuid.len);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_parse_token_no_resources(void** state)
{
    (void)state;

    /* Token with v=1, t=500, ttl=30, no res/pat/uuid.
     *
     * CBOR: A3 61 76 01 61 74 19 01 F4 63 74 74 6C 18 1E
     * base64url: o2F2AWF0GQH0Y3R0bBge */
    static const char token[] = "o2F2AWF0GQH0Y3R0bBge";

    pn_access_token_state_t out;
    memset(&out, 0, sizeof(out));

    pubnub_res_t rc = pn_access_parse_token_impl(token, &s_alloc, &out);
    assert_int_equal(PUBNUB_OK, rc);
    assert_int_equal(1, out.result.version);
    assert_int_equal(500, (int)out.result.timestamp);
    assert_int_equal(30, (int)out.result.ttl);
    assert_int_equal(0, (int)out.result.channel_count);
    assert_int_equal(0, (int)out.result.group_count);
    assert_int_equal(0, (int)out.result.uuid_count);
    assert_int_equal(0, (int)out.result.channel_pattern_count);
    assert_int_equal(0, (int)out.result.group_pattern_count);
    assert_int_equal(0, (int)out.result.uuid_pattern_count);

    pn_cbor_cleanup(out.parsed_tree, &s_alloc);
    real_free(&s_alloc, out.decoded_buf);
}

static void test_token_state_cleanup_null_safe(void** state)
{
    (void)state;
    pn_access_token_state_cleanup(NULL, NULL);
    pn_access_token_state_cleanup(NULL, &s_alloc);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Group 1: CBOR Decoder */
        cmocka_unit_test(test_cbor_parse_null_input),
        cmocka_unit_test(test_cbor_parse_null_allocator),
        cmocka_unit_test(test_cbor_parse_zero_length),
        cmocka_unit_test(test_cbor_parse_uint_inline),
        cmocka_unit_test(test_cbor_parse_uint_zero),
        cmocka_unit_test(test_cbor_parse_uint_23),
        cmocka_unit_test(test_cbor_parse_uint_1byte),
        cmocka_unit_test(test_cbor_parse_uint_2byte),
        cmocka_unit_test(test_cbor_parse_uint_4byte),
        cmocka_unit_test(test_cbor_parse_string),
        cmocka_unit_test(test_cbor_parse_string_empty),
        cmocka_unit_test(test_cbor_parse_bytes),
        cmocka_unit_test(test_cbor_parse_bytes_empty),
        cmocka_unit_test(test_cbor_parse_simple_map),
        cmocka_unit_test(test_cbor_parse_map_empty),
        cmocka_unit_test(test_cbor_parse_map_multiple_entries),
        cmocka_unit_test(test_cbor_parse_nested_map),
        cmocka_unit_test(test_cbor_parse_map_with_string_value),
        cmocka_unit_test(test_cbor_parse_deeply_nested),
        cmocka_unit_test(test_cbor_reject_array),
        cmocka_unit_test(test_cbor_reject_negative_int),
        cmocka_unit_test(test_cbor_reject_tag),
        cmocka_unit_test(test_cbor_reject_float),
        cmocka_unit_test(test_cbor_reject_oversized),
        cmocka_unit_test(test_cbor_reject_truncated_string),
        cmocka_unit_test(test_cbor_reject_trailing_bytes),
        cmocka_unit_test(test_cbor_reject_truncated_uint),
        cmocka_unit_test(test_cbor_map_get_not_found),
        cmocka_unit_test(test_cbor_map_get_null_map),
        cmocka_unit_test(test_cbor_map_get_non_map),
        cmocka_unit_test(test_cbor_map_get_null_key),
        cmocka_unit_test(test_cbor_map_get_byte_string_key),
        cmocka_unit_test(test_cbor_cleanup_null_safe),
        /* Group 2: Token Parse */
        cmocka_unit_test(test_parse_token_cross_sdk_top_level),
        cmocka_unit_test(test_parse_token_cross_sdk_resources),
        cmocka_unit_test(test_parse_token_cross_sdk_patterns),
        cmocka_unit_test(test_parse_token_cross_sdk_meta),
        cmocka_unit_test(test_parse_token_cross_sdk_signature),
        cmocka_unit_test(test_parse_token_null_rejected),
        cmocka_unit_test(test_parse_token_empty_rejected),
        cmocka_unit_test(test_parse_token_invalid_base64),
        cmocka_unit_test(test_parse_token_invalid_cbor),
        cmocka_unit_test(test_parse_token_minimal_valid),
        cmocka_unit_test(test_parse_token_no_resources),
        cmocka_unit_test(test_token_state_cleanup_null_safe),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
