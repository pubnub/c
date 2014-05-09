#ifndef PUBNUB__PubNub_http_curl_h
#define PUBNUB__PubNub_http_curl_h

/* This is a full-featured HTTP communication backend for PubNub that
 * uses the libcurl library. */

#include <curl/curl.h>
#include "pubnub.h"

struct json_object;

typedef void (*pubnub_http_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);

struct pubnub_http {
	CURL *curl;
	CURLM *curlm;
	struct curl_slist *curl_headers;
	char curl_error[CURL_ERROR_SIZE];
};

struct pubnub_http *http_init(struct pubnub *p);
void http_done(struct pubnub_http *http);

/* Tear down HTTP request context; any ongoing request is interrupted. */
void http_cleanup(struct pubnub_http *http);

void pubnub_http_setup(struct pubnub *p, const char *urlelems[], const char **qparelems, long timeout);
void pubnub_http_request(struct pubnub *p, pubnub_http_cb cb, void *cb_data, bool cb_internal, bool wait);

#endif
