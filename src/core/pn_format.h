/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

/**
 * @file pn_format.h
 * @brief Minimal printf subset for embedded targets.
 *
 * Standard libc snprintf/vsnprintf pull in locale tables, floating-point
 * formatting, and wide-char conversion on most embedded toolchains —
 * typically 10-30 KB of .text on Cortex-M. The SDK only needs integer
 * and string formatting, so this header provides a compile-time switch:
 *
 * - PUBNUB_CFG_MINIMAL_FORMATTER == 1 (embedded profile default):
 *   ~650-byte bundled formatter supporting %s, %d, %u, %x, %%, %.*s
 *   (precision-from-arg), and the `ll` length modifier on %d/%u/%x
 *   (i.e. %lld, %llu, %llx). Single `l` is accepted and treated as
 *   no-op (long is consumed via va_arg(int)/va_arg(unsigned int);
 *   correct on targets where long == int, narrowing on LP64 — the
 *   SDK does not pass bare `long` arguments to pn_snprintf).
 *   Unrecognized specifiers pass through as literal "%<chars>".
 *
 * - PUBNUB_CFG_MINIMAL_FORMATTER == 0 (hosted profile default):
 *   Delegates to libc vsnprintf (full specifier support, no code-size
 *   concern on hosted targets).
 *
 * All SDK code must call pn_snprintf/pn_vsnprintf instead of libc
 * snprintf/vsnprintf so that embedded builds benefit from the reduced
 * footprint automatically.
 */

#ifndef PN_FORMAT_H
#define PN_FORMAT_H

#include <stdarg.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define PN_PRINTF_ATTR(fmt_idx, first_arg) \
    __attribute__((format(printf, fmt_idx, first_arg)))
#else
#define PN_PRINTF_ATTR(fmt_idx, first_arg)
#endif

#ifdef __cplusplus
// clang-format off
extern "C" {
// clang-format on
#endif

/**
 * @brief Format a string into a buffer (va_list variant).
 *
 * @param buf   Destination buffer (may be NULL when size is 0).
 * @param size  Buffer capacity in bytes (including NUL terminator).
 * @param fmt   Format string (supports %s, %d, %u, %x, %%, %.*s,
 *              %lld, %llu, %llx).
 * @param args  Argument list.
 * @return Number of characters that would have been written (excluding
 *         NUL), or negative on encoding error. Output is always
 *         NUL-terminated when size > 0.
 */
int pn_vsnprintf(char* buf, size_t size, const char* fmt, va_list args);

/**
 * @brief Format a string into a buffer.
 *
 * @param buf   Destination buffer (may be NULL when size is 0).
 * @param size  Buffer capacity in bytes (including NUL terminator).
 * @param fmt   Format string (supports %s, %d, %u, %x, %%, %.*s,
 *              %lld, %llu, %llx).
 * @param ...   Format arguments.
 * @return Number of characters that would have been written (excluding
 *         NUL), or negative on encoding error. Output is always
 *         NUL-terminated when size > 0.
 */
int pn_snprintf(char* buf, size_t size, const char* fmt, ...) PN_PRINTF_ATTR(3, 4);

#ifdef __cplusplus
// clang-format off
}
// clang-format on
#endif

#endif /* PN_FORMAT_H */
