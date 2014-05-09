#ifndef PUBNUB__PubNub_http_curl_h
#define PUBNUB__PubNub_http_curl_h

/* This is a full-featured HTTP communication backend for PubNub that
 * uses the libcurl library. */

#include <curl/curl.h>
#include "pubnub.h"

struct json_object;
struct printbuf;
struct pubnub_http;

struct pubnub_http *http_init(struct pubnub *p);
void http_done(struct pubnub_http *http);

/* Issue an HTTP request within p->http context based on p->url, storing
 * the result in p->body and calling pubnub_connection_finished()
 * when ready. */
void http_request(struct pubnub *p, bool wait);
/* Tear down HTTP request context; any ongoing request is interrupted. */
void http_cleanup(struct pubnub_http *http);

void http_printbuf_urlappend(struct pubnub_http *http, struct printbuf *url, const char *urlelem);

#endif
