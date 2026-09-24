/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_inflate.h"

#include "pubnub/pubnub_compat.h"
#include "pubnub/providers/allocator.h"
#include "pubnub/providers/logger.h"

#if defined(PUBNUB_COMPRESSION_BACKEND_TINFL)

/* tinfl-based inflate: zero-alloc from tinfl's perspective; caller
 * provides ~11KB working memory via SDK allocator. NULL allocator is
 * not supported — returns PN_INFLATE_ERR_INVALID. */

#include "miniz_tinfl.h"

#include <string.h>

/** Working memory for tinfl: decompressor state only. The dict ring buffer
 *  is not needed because TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF directs
 *  tinfl to use the caller-provided output buffer as the sliding window. */
typedef struct pn_tinfl_workspace {
    tinfl_decompressor decomp;
} pn_tinfl_workspace_t;

PUBNUB_STATIC_ASSERT(
    sizeof(pn_tinfl_workspace_t) < 16384u,
    "tinfl workspace must fit within 16KB embedded arena pool");

/**
 * @brief Parse the gzip header and return offset to the raw deflate
 *        payload.
 *
 * @param input      Gzip data start.
 * @param input_len  Total gzip data length.
 * @param out_offset Populated with byte offset past the header.
 * @retval PN_INFLATE_OK on success
 * @retval PN_INFLATE_ERR_INVALID on invalid or truncated header.
 */
static int pn_gzip_header_skip(const uint8_t* input, size_t input_len, size_t* out_offset)
{
    /* Minimum gzip header: 10 bytes (magic+method+flags+mtime+xfl+os). */
    if (input_len < 10) {
        return PN_INFLATE_ERR_INVALID;
    }
    if (0x1F != input[0] || 0x8B != input[1]) {
        return PN_INFLATE_ERR_INVALID;
    }
    if (0x08 != input[2]) {
        return PN_INFLATE_ERR_INVALID; /* only deflate method supported */
    }

    uint8_t flags  = input[3];
    size_t  offset = 10;

    /* FEXTRA (bit 2): 2-byte length + that many bytes. */
    if (0 != (flags & 0x04)) {
        if (offset + 2 > input_len) {
            return PN_INFLATE_ERR_INVALID;
        }
        size_t xlen = (size_t)input[offset] | ((size_t)input[offset + 1] << 8);
        offset += 2 + xlen;
        if (offset > input_len) {
            return PN_INFLATE_ERR_INVALID;
        }
    }

    /* FNAME (bit 3): NUL-terminated string. */
    if (0 != (flags & 0x08)) {
        while (offset < input_len && 0 != input[offset]) {
            offset++;
        }
        offset++; /* skip the NUL */
        if (offset > input_len) {
            return PN_INFLATE_ERR_INVALID;
        }
    }

    /* FCOMMENT (bit 4): NUL-terminated string. */
    if (0 != (flags & 0x10)) {
        while (offset < input_len && 0 != input[offset]) {
            offset++;
        }
        offset++; /* skip the NUL */
        if (offset > input_len) {
            return PN_INFLATE_ERR_INVALID;
        }
    }

    /* FHCRC (bit 1): 2-byte CRC16 of the header. */
    if (0 != (flags & 0x02)) {
        offset += 2;
        if (offset > input_len) {
            return PN_INFLATE_ERR_INVALID;
        }
    }

    *out_offset = offset;
    return PN_INFLATE_OK;
}

/**
 * @brief Core tinfl inflate: raw deflate stream into output buffer.
 */
static int pn_tinfl_inflate_raw(const uint8_t*            deflate_data,
                                size_t                    deflate_len,
                                uint8_t*                  output,
                                size_t                    output_cap,
                                size_t*                   out_len,
                                pn_tinfl_workspace_t*     ws,
                                pubnub_logger_provider_t* logger)
{
    tinfl_init(&ws->decomp);

    size_t in_remaining  = deflate_len;
    size_t out_remaining = output_cap;

    /* Use non-wrapping output buffer mode when output is large enough
     * to hold all output in a single pass. */
    const mz_uint32 flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;

    size_t in_bytes  = in_remaining;
    size_t out_bytes = out_remaining;

    tinfl_status status = tinfl_decompress(
        &ws->decomp, deflate_data, &in_bytes, output, output, &out_bytes, flags);

    if (TINFL_STATUS_DONE == status) {
        if (in_bytes < in_remaining) {
            /* Deflate stream ended before consuming all input — trailing
             * bytes. */
            return PN_INFLATE_ERR_INVALID;
        }
        *out_len = out_bytes;
        return PN_INFLATE_OK;
    }

    if (TINFL_STATUS_HAS_MORE_OUTPUT == status) {
        return PN_INFLATE_ERR_OVERFLOW;
    }

    PUBNUB_LOG(logger,
               PUBNUB_LOG_LEVEL_WARNING,
               "inflate: tinfl status %d deflate_len=%u",
               (int)status,
               (unsigned)deflate_len);
    return PN_INFLATE_ERR_INVALID;
}

int pn_inflate_gzip(const uint8_t*                    input,
                    size_t                            input_len,
                    uint8_t*                          output,
                    size_t                            output_cap,
                    size_t*                           out_len,
                    struct pubnub_allocator_provider* allocator,
                    struct pubnub_logger_provider*    logger)
{
    if (NULL == input || NULL == output || NULL == out_len) {
        return PN_INFLATE_ERR_INVALID;
    }

    /* Parse gzip header to find the raw deflate payload. */
    size_t deflate_offset = 0;
    int    rc = pn_gzip_header_skip(input, input_len, &deflate_offset);
    if (PN_INFLATE_OK != rc) {
        return PN_INFLATE_ERR_INVALID;
    }

    /* Strip 8-byte gzip trailer (CRC32 + ISIZE). */
    if (input_len < deflate_offset + 8) {
        return PN_INFLATE_ERR_INVALID;
    }
    size_t deflate_len = input_len - deflate_offset - 8;

    /* Allocate working memory for decompressor state. */
    pn_tinfl_workspace_t* ws = NULL;
    if (NULL != allocator && NULL != allocator->alloc) {
        ws = (pn_tinfl_workspace_t*)PN_ALLOC(allocator, sizeof(*ws), sizeof(void*));
    }
    if (NULL == ws) {
        PUBNUB_LOG(logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "inflate: tinfl workspace alloc failed (%u bytes)",
                   (unsigned)sizeof(pn_tinfl_workspace_t));
        return PN_INFLATE_ERR_INVALID;
    }

    rc = pn_tinfl_inflate_raw(
        input + deflate_offset, deflate_len, output, output_cap, out_len, ws, logger);

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, ws);
    }

    return rc;
}

int pn_inflate_deflate(const uint8_t*                    input,
                       size_t                            input_len,
                       uint8_t*                          output,
                       size_t                            output_cap,
                       size_t*                           out_len,
                       struct pubnub_allocator_provider* allocator,
                       struct pubnub_logger_provider*    logger)
{
    if (NULL == input || NULL == output || NULL == out_len) {
        return PN_INFLATE_ERR_INVALID;
    }

    /* Allocate working memory for decompressor state. */
    pn_tinfl_workspace_t* ws = NULL;
    if (NULL != allocator && NULL != allocator->alloc) {
        ws = (pn_tinfl_workspace_t*)PN_ALLOC(allocator, sizeof(*ws), sizeof(void*));
    }
    if (NULL == ws) {
        PUBNUB_LOG(logger,
                   PUBNUB_LOG_LEVEL_ERROR,
                   "inflate: tinfl workspace alloc failed (%u bytes)",
                   (unsigned)sizeof(pn_tinfl_workspace_t));
        return PN_INFLATE_ERR_INVALID;
    }

    int rc = pn_tinfl_inflate_raw(
        input, input_len, output, output_cap, out_len, ws, logger);

    if (NULL != allocator && NULL != allocator->free) {
        PN_FREE(allocator, ws);
    }

    return rc;
}

#elif defined(PUBNUB_COMPRESSION_BACKEND_ZLIB)

/* zlib-based inflate: uses system zlib; allocator parameter ignored. */

#include <zlib.h>

int pn_inflate_gzip(const uint8_t*                    input,
                    size_t                            input_len,
                    uint8_t*                          output,
                    size_t                            output_cap,
                    size_t*                           out_len,
                    struct pubnub_allocator_provider* allocator,
                    struct pubnub_logger_provider*    logger)
{
    z_stream stream;
    int      ret;

    (void)allocator;
    (void)logger;

    if (NULL == input || NULL == output || NULL == out_len) {
        return PN_INFLATE_ERR_INVALID;
    }

    stream.zalloc   = Z_NULL;
    stream.zfree    = Z_NULL;
    stream.opaque   = Z_NULL;
    stream.next_in  = (Bytef*)input;
    stream.avail_in = (uInt)input_len;

    ret = inflateInit2(&stream, 16 + MAX_WBITS);
    if (Z_OK != ret) {
        return PN_INFLATE_ERR_INVALID;
    }

    stream.next_out  = output;
    stream.avail_out = (uInt)output_cap;

    ret = inflate(&stream, Z_FINISH);

    if (Z_STREAM_END == ret) {
        if (0 != stream.avail_in) {
            inflateEnd(&stream);
            return PN_INFLATE_ERR_INVALID;
        }
        *out_len = stream.total_out;
        inflateEnd(&stream);
        return PN_INFLATE_OK;
    }

    inflateEnd(&stream);

    if (Z_BUF_ERROR == ret) {
        return (0 == stream.avail_out) ? PN_INFLATE_ERR_OVERFLOW
                                       : PN_INFLATE_ERR_INVALID;
    }
    if (Z_OK == ret && 0 == stream.avail_out) {
        return PN_INFLATE_ERR_OVERFLOW;
    }

    return PN_INFLATE_ERR_INVALID;
}

int pn_inflate_deflate(const uint8_t*                    input,
                       size_t                            input_len,
                       uint8_t*                          output,
                       size_t                            output_cap,
                       size_t*                           out_len,
                       struct pubnub_allocator_provider* allocator,
                       struct pubnub_logger_provider*    logger)
{
    z_stream stream;
    int      ret;

    (void)allocator;
    (void)logger;

    if (NULL == input || NULL == output || NULL == out_len) {
        return PN_INFLATE_ERR_INVALID;
    }

    stream.zalloc   = Z_NULL;
    stream.zfree    = Z_NULL;
    stream.opaque   = Z_NULL;
    stream.next_in  = (Bytef*)input;
    stream.avail_in = (uInt)input_len;

    ret = inflateInit2(&stream, -MAX_WBITS);
    if (Z_OK != ret) {
        return PN_INFLATE_ERR_INVALID;
    }

    stream.next_out  = output;
    stream.avail_out = (uInt)output_cap;

    ret = inflate(&stream, Z_FINISH);

    if (Z_STREAM_END == ret) {
        if (0 != stream.avail_in) {
            inflateEnd(&stream);
            return PN_INFLATE_ERR_INVALID;
        }
        *out_len = stream.total_out;
        inflateEnd(&stream);
        return PN_INFLATE_OK;
    }

    inflateEnd(&stream);

    if (Z_BUF_ERROR == ret) {
        return (0 == stream.avail_out) ? PN_INFLATE_ERR_OVERFLOW
                                       : PN_INFLATE_ERR_INVALID;
    }
    if (Z_OK == ret && 0 == stream.avail_out) {
        return PN_INFLATE_ERR_OVERFLOW;
    }

    return PN_INFLATE_ERR_INVALID;
}

#else
#error "No compression backend defined: set PUBNUB_COMPRESSION_BACKEND_TINFL or PUBNUB_COMPRESSION_BACKEND_ZLIB"
#endif
