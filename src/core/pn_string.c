/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_string.h"

#include <string.h>

char* pn_strdup(const char* src, pubnub_allocator_provider_t* alloc)
{
    if (!src) {
        return NULL;
    }

    if (!alloc || !alloc->alloc) {
        return NULL;
    }

    size_t len = strlen(src) + 1;
    if (len == 0) {
        return NULL;
    } /* size_t addition overflow */
    char* dst = (char*)PN_ALLOC(alloc, len, 1);
    if (dst) {
        memcpy(dst, src, len);
    }
    return dst;
}

char* pn_strndup(const char* src, size_t len, pubnub_allocator_provider_t* alloc)
{
    if (!src) {
        return NULL;
    }
    if (!alloc || !alloc->alloc) {
        return NULL;
    }

    char* dst = (char*)PN_ALLOC(alloc, len + 1, 1);
    if (dst) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

size_t pn_strlcpy(char* dst, const char* src, size_t n)
{
    const char* s = src;

    if (n > 0) {
        char*       d = dst;
        const char* e = dst + n - 1;
        while ('\0' != *s && d < e) {
            *d++ = *s++;
        }
        *d = '\0';
    }

    /* Count remaining characters to return full strlen(src). */
    while ('\0' != *s) {
        ++s;
    }

    return (size_t)(s - src);
}

int pn_str_has_header_unsafe_byte(const char* s)
{
    const char* p = s;

    if (NULL == s) {
        return 0;
    }
    while ('\0' != *p) {
        if ('\r' == *p || '\n' == *p || ' ' == *p) {
            return 1;
        }
        ++p;
    }
    return 0;
}

void pn_strfree(const char* ptr, pubnub_allocator_provider_t* alloc)
{
    if (ptr && alloc && alloc->free) {
        PN_FREE(alloc, (void*)ptr);
    }
}

void pn_secure_memzero(void* ptr, size_t len)
{
    volatile unsigned char* p = (volatile unsigned char*)ptr;

    if (NULL == ptr || 0 == len) {
        return;
    }

    /* Writing through a volatile pointer prevents the optimizer from
     * treating this as a dead store, unlike a plain memset. */
    while (len > 0) {
        *p++ = 0U;
        --len;
    }
}

void pn_strfree_secure(const char* ptr, pubnub_allocator_provider_t* alloc)
{
    if (NULL != ptr) {
        pn_secure_memzero((void*)ptr, strlen(ptr));
    }
    pn_strfree(ptr, alloc);
}
