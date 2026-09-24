/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "proxy_wpad.h"

#include <stddef.h>
#include <string.h>

int pn_proxy_wpad_resolve(const char* target_url, pn_proxy_config_t* out)
{
    (void)target_url;
    if (NULL != out) {
        memset(out, 0, sizeof(*out));
    }
    return -1;
}

void pn_proxy_wpad_free(pn_proxy_config_t* config)
{
    (void)config;
}
