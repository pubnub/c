/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_format.h"

#include "pubnub/config.h"

#if PUBNUB_CFG_MINIMAL_FORMATTER

static int pn_fmt_emit(char* buf, size_t size, size_t pos, char ch)
{
    if (pos < size) {
        buf[pos] = ch;
    }
    return 1;
}

static int pn_fmt_str(char* buf, size_t size, size_t pos, const char* s)
{
    int written = 0;
    if (NULL == s) {
        s = "(null)";
    }
    while (*s != '\0') {
        if (pos + (size_t)written < size) {
            buf[pos + (size_t)written] = *s;
        }
        ++written;
        ++s;
    }
    return written;
}

static int
pn_fmt_uint(char* buf, size_t size, size_t pos, unsigned int val, unsigned int base)
{
    char tmp[sizeof(unsigned int) * 3 + 1];
    int  len     = 0;
    int  written = 0;

    if (0 == val) {
        return pn_fmt_emit(buf, size, pos, '0');
    }

    while (0 != val) {
        unsigned int digit = val % base;
        tmp[len++] = (digit < 10) ? (char)('0' + digit) : (char)('a' + digit - 10);
        val /= base;
    }

    /* Emit in reverse order. */
    while (len > 0) {
        --len;
        if (pos + (size_t)written < size) {
            buf[pos + (size_t)written] = tmp[len];
        }
        ++written;
    }
    return written;
}

/* Reverse-emit helper for unsigned long long values (base 10 or 16).
 * Stack frame: tmp[25] + scalars; matches pn_fmt_uint shape. */
static int pn_fmt_ull(char*              buf,
                      size_t             size,
                      size_t             pos,
                      unsigned long long val,
                      unsigned int       base)
{
    char tmp[sizeof(unsigned long long) * 3 + 1];
    int  len     = 0;
    int  written = 0;

    if (0ULL == val) {
        return pn_fmt_emit(buf, size, pos, '0');
    }

    while (0ULL != val) {
        unsigned int digit = (unsigned int)(val % (unsigned long long)base);
        tmp[len++] = (digit < 10) ? (char)('0' + digit) : (char)('a' + digit - 10);
        val /= (unsigned long long)base;
    }

    /* Emit in reverse order. */
    while (len > 0) {
        --len;
        if (pos + (size_t)written < size) {
            buf[pos + (size_t)written] = tmp[len];
        }
        ++written;
    }
    return written;
}

int pn_vsnprintf(char* buf, size_t size, const char* fmt, va_list args)
{
    size_t pos = 0;

    if (NULL == fmt) {
        if (size > 0) {
            buf[0] = '\0';
        }
        return 0;
    }

    while (*fmt != '\0') {
        if (*fmt != '%') {
            pos += (size_t)pn_fmt_emit(buf, size, pos, *fmt);
            ++fmt;
            continue;
        }

        ++fmt; /* skip '%' */

        /* Handle %.*s (precision-from-arg for strings only). */
        if ('.' == *fmt && '*' == *(fmt + 1) && 's' == *(fmt + 2)) {
            int         prec    = va_arg(args, int);
            const char* s       = va_arg(args, const char*);
            int         emitted = 0;

            if (prec < 0) {
                prec = 0;
            }
            if (NULL != s) {
                while (emitted < prec && '\0' != s[emitted]) {
                    if (pos + (size_t)emitted < size) {
                        buf[pos + (size_t)emitted] = s[emitted];
                    }
                    ++emitted;
                }
            }
            pos += (size_t)emitted;
            fmt += 3; /* skip ".*s" */
            continue;
        }

        /* Length modifiers: only 'll' is honored (always-on per Round 6
         * D-2). Single 'l' is treated as no-op — long is consumed via
         * va_arg(int)/va_arg(unsigned int), correct on targets where
         * sizeof(long) == sizeof(int) and accepted as the SDK does not
         * pass bare `long` arguments to pn_snprintf. The width_ll flag
         * is determined here BEFORE any va_arg call so that the call
         * site picks the matching argument width — closing the
         * va_list-misalignment hole flagged in Round 5 PF-R5-2. */
        int width_ll = 0;
        if ('l' == *fmt && 'l' == *(fmt + 1)) {
            width_ll = 1;
            fmt += 2;
        } else if ('l' == *fmt) {
            ++fmt;
        }

        switch (*fmt) {
        case '\0':
            /* Trailing '%' (with optional length modifier) at end of
             * format string. Emit literal '%' and any length modifier
             * that was peeled off; do NOT consume any va_arg. */
            pos += (size_t)pn_fmt_emit(buf, size, pos, '%');
            if (width_ll) {
                pos += (size_t)pn_fmt_emit(buf, size, pos, 'l');
                pos += (size_t)pn_fmt_emit(buf, size, pos, 'l');
            }
            goto done;

        case '%': pos += (size_t)pn_fmt_emit(buf, size, pos, '%'); break;

        case 's':
            /* %ls is not supported; treat as %s and consume one ptr. */
            pos += (size_t)pn_fmt_str(buf, size, pos, va_arg(args, const char*));
            break;

        case 'd':
            if (width_ll) {
                long long llval = va_arg(args, long long);
                /* Compute magnitude in unsigned domain to avoid signed
                 * overflow on LLONG_MIN (UB if we negated directly). */
                if (llval < 0) {
                    pos += (size_t)pn_fmt_emit(buf, size, pos, '-');
                    pos += (size_t)pn_fmt_ull(
                        buf, size, pos, 0ULL - (unsigned long long)llval, 10);
                } else {
                    pos += (size_t)pn_fmt_ull(
                        buf, size, pos, (unsigned long long)llval, 10);
                }
            } else {
                int val = va_arg(args, int);
                if (val < 0) {
                    pos += (size_t)pn_fmt_emit(buf, size, pos, '-');
                    /* Handle INT_MIN without overflow. */
                    pos += (size_t)pn_fmt_uint(
                        buf, size, pos, 0u - (unsigned int)val, 10);
                } else {
                    pos +=
                        (size_t)pn_fmt_uint(buf, size, pos, (unsigned int)val, 10);
                }
            }
            break;

        case 'u':
            if (width_ll) {
                pos += (size_t)pn_fmt_ull(
                    buf, size, pos, va_arg(args, unsigned long long), 10);
            } else {
                pos += (size_t)pn_fmt_uint(
                    buf, size, pos, va_arg(args, unsigned int), 10);
            }
            break;

        case 'x':
            if (width_ll) {
                pos += (size_t)pn_fmt_ull(
                    buf, size, pos, va_arg(args, unsigned long long), 16);
            } else {
                pos += (size_t)pn_fmt_uint(
                    buf, size, pos, va_arg(args, unsigned int), 16);
            }
            break;

        default:
            /* Unknown specifier: emit literal "%[ll]<char>" and consume
             * NOTHING from the va_list. A future 'll'-prefixed specifier
             * (e.g. %lln) must not silently misalign the va_list, so the
             * fallback path is intentionally bug-loud. */
            pos += (size_t)pn_fmt_emit(buf, size, pos, '%');
            if (width_ll) {
                pos += (size_t)pn_fmt_emit(buf, size, pos, 'l');
                pos += (size_t)pn_fmt_emit(buf, size, pos, 'l');
            }
            pos += (size_t)pn_fmt_emit(buf, size, pos, *fmt);
            break;
        }
        ++fmt;
    }

done:
    if (size > 0) {
        buf[pos < size ? pos : size - 1] = '\0';
    }
    return (int)pos;
}

int pn_snprintf(char* buf, size_t size, const char* fmt, ...)
{
    va_list args;
    int     ret;

    va_start(args, fmt);
    ret = pn_vsnprintf(buf, size, fmt, args);
    va_end(args);
    return ret;
}

#else /* !PUBNUB_CFG_MINIMAL_FORMATTER — delegate to libc */

#include <stdio.h>

/* Suppress format-nonliteral: these wrappers forward an already-checked
   format string — callers are validated via PN_PRINTF_ATTR on the header. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

int pn_vsnprintf(char* buf, size_t size, const char* fmt, va_list args)
{
    return vsnprintf(buf, size, fmt, args);
}

int pn_snprintf(char* buf, size_t size, const char* fmt, ...)
{
    va_list args;
    int     ret;

    va_start(args, fmt);
    ret = vsnprintf(buf, size, fmt, args);
    va_end(args);
    return ret;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#endif /* PUBNUB_CFG_MINIMAL_FORMATTER */
