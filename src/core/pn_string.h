/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @brief Internal allocator-aware string helpers (not installed).
 *
 * Returns NULL if no allocator is available.
 */

#ifndef PN_STRING_H
#define PN_STRING_H

#include "pubnub/providers/allocator.h"

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Duplicate a NUL-terminated string via the allocator.
 *
 * @param src    Source string (NULL returns NULL).
 * @param alloc  Allocator provider (must be non-NULL with valid alloc).
 * @return Owned copy on success. NULL if src is NULL, alloc is NULL,
 *         or allocation fails.
 */
char* pn_strdup(const char* src, pubnub_allocator_provider_t* alloc);

/**
 * @brief Duplicate exactly @p len bytes via the allocator.
 *
 * Copies @p len bytes from @p src and appends a NUL terminator.
 * Does NOT require @p src to be NUL-terminated.
 *
 * @param src    Source buffer (NULL returns NULL).
 * @param len    Number of bytes to copy.
 * @param alloc  Allocator provider (must be non-NULL with valid alloc).
 * @return Owned NUL-terminated copy on success. NULL on failure.
 */
char* pn_strndup(const char* src, size_t len, pubnub_allocator_provider_t* alloc);

/**
 * @brief Copy at most @p n - 1 bytes from @p src to @p dst, always
 *        NUL-terminating.
 *
 * @param dst   Destination buffer. Must be at least @p n bytes.
 * @param src   NUL-terminated source string.
 * @param n     Size of the destination buffer in bytes.
 * @return      Number of bytes that would have been written if @p dst
 *              were large enough (excluding the NUL terminator), i.e.
 *              @c strlen(src).
 */
size_t pn_strlcpy(char* dst, const char* src, size_t n);

/**
 * @brief Report whether a string contains a byte that would break an
 *        HTTP request line or header field.
 *
 * Scans for carriage return (0x0D), line feed (0x0A), or space (0x20) —
 * the bytes that let an attacker smuggle extra request lines or headers
 * (HTTP request/header injection). NUL is not scanned for because the
 * input is NUL-terminated. Use to validate host / origin values before
 * they are written into a @c Host: header.
 *
 * @param s NUL-terminated string to scan. NULL is treated as safe.
 * @retval 1 A CR, LF, or space byte is present.
 * @retval 0 No such byte is present (or @p s is NULL).
 */
int pn_str_has_header_unsafe_byte(const char* s);

/**
 * @brief Free a string via the allocator provider.
 *
 * @param ptr    String to free (may be NULL).
 * @param alloc  Allocator provider (may be NULL).
 *
 * @note Arena allocators typically no-op on free(); frequent runtime
 *       mutations on arena-backed contexts will exhaust the arena.
 */
void pn_strfree(const char* ptr, pubnub_allocator_provider_t* alloc);

/**
 * @brief Overwrite a buffer with zero bytes in a way the compiler may
 *        not optimize away.
 *
 * Ordinary @c memset before a free is a dead store the optimizer is
 * free to elide, leaving secrets recoverable from freed heap memory.
 * This helper writes through a @c volatile pointer, which the C
 * standard forbids the compiler from eliminating, so it is safe for
 * clearing key material before release. It has no external dependency
 * and needs no platform provider (unlike the optional
 * @c pubnub_platform_provider_t::secure_zero hook, which POSIX leaves
 * unset).
 *
 * @param ptr  Buffer to zeroize (NULL is ignored).
 * @param len  Number of bytes to clear (0 is ignored).
 */
void pn_secure_memzero(void* ptr, size_t len);

/**
 * @brief Zeroize a NUL-terminated secret string, then free it.
 *
 * Use for sensitive strings (secret key, auth token, proxy
 * credentials) so their bytes do not linger in freed memory. The
 * string length is taken with @c strlen before clearing, so @p ptr
 * must be NUL-terminated.
 *
 * @param ptr    Secret string to scrub and free (may be NULL).
 * @param alloc  Allocator provider (may be NULL).
 *
 * @note Arena allocators typically no-op on free(); the scrub still
 *       runs so the bytes are cleared even when the block is retained.
 */
void pn_strfree_secure(const char* ptr, pubnub_allocator_provider_t* alloc);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_STRING_H */
