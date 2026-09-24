/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "../common.h"

#include "core/pn_format.h"

xs_result_t run_cleanup(const xs_context_t* ctx)
{
    (void)ctx;
    xs_result_t r = {0};
    r.pass        = 1;
    pn_snprintf(r.detail, sizeof(r.detail), "ok");
    return r;
}
