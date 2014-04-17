#ifndef PUBNUB__PubNub_http_libcurl_h
#define PUBNUB__PubNub_http_libcurl_h

#include <pubnub.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque objects. */
struct pubnub_http_libcurl;

/* Callback structure to pass pubnub_init(). */
extern const struct pubnub_http_callbacks pubnub_http_libcurl_callbacks;

#ifdef __cplusplus
}
#endif

#endif
