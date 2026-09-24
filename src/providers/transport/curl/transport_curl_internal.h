/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file transport_curl_internal.h
 * @brief Internal declarations shared between transport_curl.c and
 *        its unit tests.
 *
 * Not installed as a public header. Anything declared here is
 * subject to change between minor releases; custom provider
 * implementors should not include it. Its only purpose is to
 * make a small set of file-local-style helpers reachable from the
 * test translation unit so pure-logic code paths can be exercised
 * without standing up libcurl transfers.
 */

#ifndef PN_TRANSPORT_CURL_INTERNAL_H
#define PN_TRANSPORT_CURL_INTERNAL_H

#include "pubnub/providers/allocator.h"

#include <stddef.h>

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Append @p chunk_len bytes from @p chunk into @p buf,
 *        growing it via @p allocator->buf_grow when capacity is
 *        exceeded.
 *
 * Core of the libcurl write-callback logic, extracted so the
 * "respect NULL buf_grow per the allocator contract" behaviour
 * can be exercised directly in unit tests without a real
 * libcurl transfer.
 *
 * @param allocator  Allocator provider.  `buf_grow` may be NULL;
 *                   when it is, this function aborts the append
 *                   instead of dereferencing it.
 * @param buf        RX buffer receiving @p chunk. Capacity is
 *                   extended in place when @c buf_grow succeeds.
 * @param written    IN: current number of bytes already written
 *                   into @p buf. OUT: updated on success to
 *                   reflect the new write position.
 * @param chunk      Input bytes to append (borrowed).
 * @param chunk_len  Number of bytes in @p chunk.
 * @return @p chunk_len on success, 0 on failure (short-write
 *         signal that libcurl interprets as "abort the transfer").
 */
size_t pn_curl_rx_append_or_grow(pubnub_allocator_provider_t* allocator,
                                 pubnub_buffer_t*             buf,
                                 size_t*                      written,
                                 const char*                  chunk,
                                 size_t                       chunk_len);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_TRANSPORT_CURL_INTERNAL_H */
