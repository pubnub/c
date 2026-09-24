/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_proxy_md5.h"

#include <string.h>

/* MD5 round functions. */
#define PN_MD5_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define PN_MD5_G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define PN_MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define PN_MD5_I(x, y, z) ((y) ^ ((x) | (~(z))))

/* Left rotation. */
#define PN_MD5_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Per-step additive constants: T[i] = floor(2^32 * abs(sin(i + 1))). */
static const uint32_t PN_MD5_T[64] = {
    0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU,
    0x4787c62aU, 0xa8304613U, 0xfd469501U, 0x698098d8U, 0x8b44f7afU,
    0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U, 0xa679438eU,
    0x49b40821U, 0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
    0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U, 0x21e1cde6U,
    0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U,
    0x676f02d9U, 0x8d2a4c8aU, 0xfffa3942U, 0x8771f681U, 0x6d9d6122U,
    0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
    0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U, 0xd9d4d039U,
    0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U, 0xf4292244U, 0x432aff97U,
    0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU,
    0x85845dd1U, 0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
    0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U};

/** @brief Decode 4 bytes (little-endian) into a uint32_t. */
static uint32_t md5_decode_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/** @brief Encode a uint32_t into 4 bytes (little-endian). */
static void md5_encode_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
}

/** @brief Process a single 64-byte block. */
// NOLINTNEXTLINE(readability-function-size) - 64-round fixed crypto transform; cannot be split without passing working variables across call boundaries
static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    for (size_t i = 0; i < 16; ++i) {
        x[i] = md5_decode_u32(block + i * 4U);
    }

    /* Round 1 */
#define PN_MD5_R1(a, b, c, d, k, s, i)                                          \
    do {                                                                        \
        (a) = (b)                                                               \
            + PN_MD5_ROTL(                                                      \
                  (a) + PN_MD5_F((b), (c), (d)) + x[(k)] + PN_MD5_T[(i)], (s)); \
    } while (0)

    PN_MD5_R1(a, b, c, d, 0, 7, 0);
    PN_MD5_R1(d, a, b, c, 1, 12, 1);
    PN_MD5_R1(c, d, a, b, 2, 17, 2);
    PN_MD5_R1(b, c, d, a, 3, 22, 3);
    PN_MD5_R1(a, b, c, d, 4, 7, 4);
    PN_MD5_R1(d, a, b, c, 5, 12, 5);
    PN_MD5_R1(c, d, a, b, 6, 17, 6);
    PN_MD5_R1(b, c, d, a, 7, 22, 7);
    PN_MD5_R1(a, b, c, d, 8, 7, 8);
    PN_MD5_R1(d, a, b, c, 9, 12, 9);
    PN_MD5_R1(c, d, a, b, 10, 17, 10);
    PN_MD5_R1(b, c, d, a, 11, 22, 11);
    PN_MD5_R1(a, b, c, d, 12, 7, 12);
    PN_MD5_R1(d, a, b, c, 13, 12, 13);
    PN_MD5_R1(c, d, a, b, 14, 17, 14);
    PN_MD5_R1(b, c, d, a, 15, 22, 15);

    /* Round 2 */
#define PN_MD5_R2(a, b, c, d, k, s, i)                                          \
    do {                                                                        \
        (a) = (b)                                                               \
            + PN_MD5_ROTL(                                                      \
                  (a) + PN_MD5_G((b), (c), (d)) + x[(k)] + PN_MD5_T[(i)], (s)); \
    } while (0)

    PN_MD5_R2(a, b, c, d, 1, 5, 16);
    PN_MD5_R2(d, a, b, c, 6, 9, 17);
    PN_MD5_R2(c, d, a, b, 11, 14, 18);
    PN_MD5_R2(b, c, d, a, 0, 20, 19);
    PN_MD5_R2(a, b, c, d, 5, 5, 20);
    PN_MD5_R2(d, a, b, c, 10, 9, 21);
    PN_MD5_R2(c, d, a, b, 15, 14, 22);
    PN_MD5_R2(b, c, d, a, 4, 20, 23);
    PN_MD5_R2(a, b, c, d, 9, 5, 24);
    PN_MD5_R2(d, a, b, c, 14, 9, 25);
    PN_MD5_R2(c, d, a, b, 3, 14, 26);
    PN_MD5_R2(b, c, d, a, 8, 20, 27);
    PN_MD5_R2(a, b, c, d, 13, 5, 28);
    PN_MD5_R2(d, a, b, c, 2, 9, 29);
    PN_MD5_R2(c, d, a, b, 7, 14, 30);
    PN_MD5_R2(b, c, d, a, 12, 20, 31);

    /* Round 3 */
#define PN_MD5_R3(a, b, c, d, k, s, i)                                          \
    do {                                                                        \
        (a) = (b)                                                               \
            + PN_MD5_ROTL(                                                      \
                  (a) + PN_MD5_H((b), (c), (d)) + x[(k)] + PN_MD5_T[(i)], (s)); \
    } while (0)

    PN_MD5_R3(a, b, c, d, 5, 4, 32);
    PN_MD5_R3(d, a, b, c, 8, 11, 33);
    PN_MD5_R3(c, d, a, b, 11, 16, 34);
    PN_MD5_R3(b, c, d, a, 14, 23, 35);
    PN_MD5_R3(a, b, c, d, 1, 4, 36);
    PN_MD5_R3(d, a, b, c, 4, 11, 37);
    PN_MD5_R3(c, d, a, b, 7, 16, 38);
    PN_MD5_R3(b, c, d, a, 10, 23, 39);
    PN_MD5_R3(a, b, c, d, 13, 4, 40);
    PN_MD5_R3(d, a, b, c, 0, 11, 41);
    PN_MD5_R3(c, d, a, b, 3, 16, 42);
    PN_MD5_R3(b, c, d, a, 6, 23, 43);
    PN_MD5_R3(a, b, c, d, 9, 4, 44);
    PN_MD5_R3(d, a, b, c, 12, 11, 45);
    PN_MD5_R3(c, d, a, b, 15, 16, 46);
    PN_MD5_R3(b, c, d, a, 2, 23, 47);

    /* Round 4 */
#define PN_MD5_R4(a, b, c, d, k, s, i)                                          \
    do {                                                                        \
        (a) = (b)                                                               \
            + PN_MD5_ROTL(                                                      \
                  (a) + PN_MD5_I((b), (c), (d)) + x[(k)] + PN_MD5_T[(i)], (s)); \
    } while (0)

    PN_MD5_R4(a, b, c, d, 0, 6, 48);
    PN_MD5_R4(d, a, b, c, 7, 10, 49);
    PN_MD5_R4(c, d, a, b, 14, 15, 50);
    PN_MD5_R4(b, c, d, a, 5, 21, 51);
    PN_MD5_R4(a, b, c, d, 12, 6, 52);
    PN_MD5_R4(d, a, b, c, 3, 10, 53);
    PN_MD5_R4(c, d, a, b, 10, 15, 54);
    PN_MD5_R4(b, c, d, a, 1, 21, 55);
    PN_MD5_R4(a, b, c, d, 8, 6, 56);
    PN_MD5_R4(d, a, b, c, 15, 10, 57);
    PN_MD5_R4(c, d, a, b, 6, 15, 58);
    PN_MD5_R4(b, c, d, a, 13, 21, 59);
    PN_MD5_R4(a, b, c, d, 4, 6, 60);
    PN_MD5_R4(d, a, b, c, 11, 10, 61);
    PN_MD5_R4(c, d, a, b, 2, 15, 62);
    PN_MD5_R4(b, c, d, a, 9, 21, 63);

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

#undef PN_MD5_R1
#undef PN_MD5_R2
#undef PN_MD5_R3
#undef PN_MD5_R4

void pn_proxy_md5_init(pn_proxy_md5_ctx_t* ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
    ctx->count    = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void pn_proxy_md5_update(pn_proxy_md5_ctx_t* ctx, const uint8_t* data, size_t len)
{
    /* Number of bytes already buffered from a previous partial block. */
    size_t buffered = (size_t)(ctx->count % 64);
    size_t offset   = 0;

    ctx->count += (uint64_t)len;

    /* Complete the pending partial block, if any. */
    if (buffered > 0) {
        size_t need = 64 - buffered;
        if (len < need) {
            memcpy(ctx->buffer + buffered, data, len);
            return;
        }
        memcpy(ctx->buffer + buffered, data, need);
        md5_transform(ctx->state, ctx->buffer);
        offset = need;
    }

    /* Process complete 64-byte blocks straight from the input. */
    while (offset + 64 <= len) {
        md5_transform(ctx->state, data + offset);
        offset += 64;
    }

    /* Buffer the trailing partial block for the next call. */
    if (offset < len) {
        memcpy(ctx->buffer, data + offset, len - offset);
    }
}

void pn_proxy_md5_final(pn_proxy_md5_ctx_t* ctx, uint8_t digest[16])
{
    uint64_t bit_len  = ctx->count * 8;
    size_t   buffered = (size_t)(ctx->count % 64);

    /* Append the 0x80 padding byte. */
    ctx->buffer[buffered] = 0x80;
    ++buffered;

    /* If there is no room for the 8-byte length, flush and start fresh. */
    if (buffered > 56) {
        memset(ctx->buffer + buffered, 0, 64 - buffered);
        md5_transform(ctx->state, ctx->buffer);
        buffered = 0;
    }
    memset(ctx->buffer + buffered, 0, 56 - buffered);

    /* Append the 64-bit little-endian bit length. */
    ctx->buffer[56] = (uint8_t)(bit_len & 0xffU);
    ctx->buffer[57] = (uint8_t)((bit_len >> 8) & 0xffU);
    ctx->buffer[58] = (uint8_t)((bit_len >> 16) & 0xffU);
    ctx->buffer[59] = (uint8_t)((bit_len >> 24) & 0xffU);
    ctx->buffer[60] = (uint8_t)((bit_len >> 32) & 0xffU);
    ctx->buffer[61] = (uint8_t)((bit_len >> 40) & 0xffU);
    ctx->buffer[62] = (uint8_t)((bit_len >> 48) & 0xffU);
    ctx->buffer[63] = (uint8_t)((bit_len >> 56) & 0xffU);

    md5_transform(ctx->state, ctx->buffer);

    md5_encode_u32(digest, ctx->state[0]);
    md5_encode_u32(digest + 4, ctx->state[1]);
    md5_encode_u32(digest + 8, ctx->state[2]);
    md5_encode_u32(digest + 12, ctx->state[3]);

    /* Scrub sensitive context state. */
    volatile uint8_t* vp = (volatile uint8_t*)ctx;
    for (size_t i = 0; i < sizeof(*ctx); ++i) {
        vp[i] = 0;
    }
}
