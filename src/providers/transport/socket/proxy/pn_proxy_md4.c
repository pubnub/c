/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_proxy_md4.h"

#include <string.h>

/* MD4 round functions. */
#define PN_MD4_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define PN_MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define PN_MD4_H(x, y, z) ((x) ^ (y) ^ (z))

/* Left rotation. */
#define PN_MD4_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/** @brief Decode 4 bytes (little-endian) into a uint32_t. */
static uint32_t md4_decode_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/** @brief Encode a uint32_t into 4 bytes (little-endian). */
static void md4_encode_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
}

/** @brief Process a single 64-byte block. */
// NOLINTNEXTLINE(readability-function-size) - 48-round fixed crypto transform; cannot be split without passing working variables across call boundaries
static void md4_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    for (size_t i = 0; i < 16; ++i) {
        x[i] = md4_decode_u32(block + i * 4U);
    }

    /* Round 1 */
#define PN_MD4_R1(a, b, c, d, k, s)                                     \
    do {                                                                \
        (a) = PN_MD4_ROTL((a) + PN_MD4_F((b), (c), (d)) + x[(k)], (s)); \
    } while (0)

    PN_MD4_R1(a, b, c, d, 0, 3);
    PN_MD4_R1(d, a, b, c, 1, 7);
    PN_MD4_R1(c, d, a, b, 2, 11);
    PN_MD4_R1(b, c, d, a, 3, 19);
    PN_MD4_R1(a, b, c, d, 4, 3);
    PN_MD4_R1(d, a, b, c, 5, 7);
    PN_MD4_R1(c, d, a, b, 6, 11);
    PN_MD4_R1(b, c, d, a, 7, 19);
    PN_MD4_R1(a, b, c, d, 8, 3);
    PN_MD4_R1(d, a, b, c, 9, 7);
    PN_MD4_R1(c, d, a, b, 10, 11);
    PN_MD4_R1(b, c, d, a, 11, 19);
    PN_MD4_R1(a, b, c, d, 12, 3);
    PN_MD4_R1(d, a, b, c, 13, 7);
    PN_MD4_R1(c, d, a, b, 14, 11);
    PN_MD4_R1(b, c, d, a, 15, 19);

    /* Round 2 */
#define PN_MD4_R2(a, b, c, d, k, s)                                             \
    do {                                                                        \
        (a) = PN_MD4_ROTL((a) + PN_MD4_G((b), (c), (d)) + x[(k)] + 0x5a827999U, \
                          (s));                                                 \
    } while (0)

    PN_MD4_R2(a, b, c, d, 0, 3);
    PN_MD4_R2(d, a, b, c, 4, 5);
    PN_MD4_R2(c, d, a, b, 8, 9);
    PN_MD4_R2(b, c, d, a, 12, 13);
    PN_MD4_R2(a, b, c, d, 1, 3);
    PN_MD4_R2(d, a, b, c, 5, 5);
    PN_MD4_R2(c, d, a, b, 9, 9);
    PN_MD4_R2(b, c, d, a, 13, 13);
    PN_MD4_R2(a, b, c, d, 2, 3);
    PN_MD4_R2(d, a, b, c, 6, 5);
    PN_MD4_R2(c, d, a, b, 10, 9);
    PN_MD4_R2(b, c, d, a, 14, 13);
    PN_MD4_R2(a, b, c, d, 3, 3);
    PN_MD4_R2(d, a, b, c, 7, 5);
    PN_MD4_R2(c, d, a, b, 11, 9);
    PN_MD4_R2(b, c, d, a, 15, 13);

    /* Round 3 */
#define PN_MD4_R3(a, b, c, d, k, s)                                             \
    do {                                                                        \
        (a) = PN_MD4_ROTL((a) + PN_MD4_H((b), (c), (d)) + x[(k)] + 0x6ed9eba1U, \
                          (s));                                                 \
    } while (0)

    PN_MD4_R3(a, b, c, d, 0, 3);
    PN_MD4_R3(d, a, b, c, 8, 9);
    PN_MD4_R3(c, d, a, b, 4, 11);
    PN_MD4_R3(b, c, d, a, 12, 15);
    PN_MD4_R3(a, b, c, d, 2, 3);
    PN_MD4_R3(d, a, b, c, 10, 9);
    PN_MD4_R3(c, d, a, b, 6, 11);
    PN_MD4_R3(b, c, d, a, 14, 15);
    PN_MD4_R3(a, b, c, d, 1, 3);
    PN_MD4_R3(d, a, b, c, 9, 9);
    PN_MD4_R3(c, d, a, b, 5, 11);
    PN_MD4_R3(b, c, d, a, 13, 15);
    PN_MD4_R3(a, b, c, d, 3, 3);
    PN_MD4_R3(d, a, b, c, 11, 9);
    PN_MD4_R3(c, d, a, b, 7, 11);
    PN_MD4_R3(b, c, d, a, 15, 15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* Scrub local working state. */
    volatile uint32_t* vx = (volatile uint32_t*)x;
    for (int i = 0; i < 16; ++i) {
        vx[i] = 0;
    }
}

#undef PN_MD4_R1
#undef PN_MD4_R2
#undef PN_MD4_R3

void pn_proxy_md4(const uint8_t* data, size_t len, uint8_t digest[16])
{
    uint32_t state[4] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};

    /* Process complete 64-byte blocks. */
    size_t offset = 0;
    while (offset + 64 <= len) {
        md4_transform(state, data + offset);
        offset += 64;
    }

    /* Final block with padding. */
    uint8_t final_block[128];
    size_t  remaining = len - offset;
    memset(final_block, 0, sizeof(final_block));
    if (remaining > 0) {
        memcpy(final_block, data + offset, remaining);
    }
    final_block[remaining] = 0x80;

    /* If remaining + 1 + 8 > 64, we need two blocks. */
    size_t pad_blocks = (remaining >= 56) ? 2 : 1;

    /* Append bit length (little-endian 64-bit) at end of last block. */
    uint64_t bit_len            = (uint64_t)len * 8;
    size_t   len_offset         = pad_blocks * 64 - 8;
    final_block[len_offset]     = (uint8_t)(bit_len & 0xffU);
    final_block[len_offset + 1] = (uint8_t)((bit_len >> 8) & 0xffU);
    final_block[len_offset + 2] = (uint8_t)((bit_len >> 16) & 0xffU);
    final_block[len_offset + 3] = (uint8_t)((bit_len >> 24) & 0xffU);
    final_block[len_offset + 4] = (uint8_t)((bit_len >> 32) & 0xffU);
    final_block[len_offset + 5] = (uint8_t)((bit_len >> 40) & 0xffU);
    final_block[len_offset + 6] = (uint8_t)((bit_len >> 48) & 0xffU);
    final_block[len_offset + 7] = (uint8_t)((bit_len >> 56) & 0xffU);

    for (size_t i = 0; i < pad_blocks; ++i) {
        md4_transform(state, final_block + i * 64);
    }

    /* Encode state to output. */
    md4_encode_u32(digest, state[0]);
    md4_encode_u32(digest + 4, state[1]);
    md4_encode_u32(digest + 8, state[2]);
    md4_encode_u32(digest + 12, state[3]);

    /* Scrub working state: final_block holds the (credential-derived)
     * input tail and state holds the hash intermediates. Volatile
     * writes prevent the optimizer from eliding the clear. */
    {
        volatile uint8_t*  vb = (volatile uint8_t*)final_block;
        volatile uint32_t* vs = (volatile uint32_t*)state;
        size_t             i;
        for (i = 0; i < sizeof(final_block); ++i) {
            vb[i] = 0U;
        }
        for (i = 0; i < 4; ++i) {
            vs[i] = 0U;
        }
    }
}
