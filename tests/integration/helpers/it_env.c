/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */
#include "it_env.h"
#include <stdlib.h>

static it_env_t s_env;
static int      s_loaded = 0;

const it_env_t* it_env_load(void)
{
    if (s_loaded) {
        return &s_env;
    }
    s_env.publish_key       = getenv("PUBNUB_PUBLISH_KEY");
    s_env.subscribe_key     = getenv("PUBNUB_SUBSCRIBE_KEY");
    s_env.pam_publish_key   = getenv("PAM_PUBLISH_KEY");
    s_env.pam_subscribe_key = getenv("PAM_SUBSCRIBE_KEY");
    s_env.pam_secret_key    = getenv("PAM_SECRET_KEY");
    s_loaded                = 1;
    return &s_env;
}
