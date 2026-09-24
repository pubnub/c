/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pn_tls_cert_loader.h"

#include <stddef.h>

pn_tls_system_cert_fn_t pn_tls_get_default_cert_loader(void)
{
    return NULL;
}
