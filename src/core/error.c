/* Copyright (c) PubNub Inc. */
/* See LICENSE in the root directory of this source tree. */

#include "pubnub/error.h"

#include "pubnub/config.h"

const char* pubnub_res_str(pubnub_res_t res)
{
#if PUBNUB_CFG_RES_STR
    switch (res) {
    case PUBNUB_OK: return "Success";
    case PUBNUB_IN_PROGRESS: return "Operation in progress";
    case PUBNUB_ERR_CANCELLED: return "Operation cancelled";
    case PUBNUB_ERR_INVALID_ARGUMENT: return "Invalid argument";
    case PUBNUB_ERR_NOT_INITIALIZED: return "Context not initialized";
    case PUBNUB_ERR_PROVIDER_MISSING: return "Required provider missing";
    case PUBNUB_ERR_NOT_SUPPORTED: return "Operation not supported";
    case PUBNUB_ERR_OUT_OF_MEMORY: return "Out of memory";
    case PUBNUB_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
    case PUBNUB_ERR_QUEUE_FULL: return "Request queue full";
    case PUBNUB_ERR_TIMEOUT: return "Operation timed out";
    case PUBNUB_ERR_NO_WALL_CLOCK: return "Wall-clock time unavailable";
    case PUBNUB_ERR_TRANSPORT: return "Transport failure";
    case PUBNUB_ERR_SERVER: return "Server returned error";
    case PUBNUB_ERR_SERIALIZATION: return "Serialization failure";
    case PUBNUB_ERR_CRYPTO: return "Crypto failure";
    case PUBNUB_ERR_INTERNAL: return "Internal SDK error";
    default: return "Unknown error";
    }
#else
    (void)res;
    return "";
#endif
}
