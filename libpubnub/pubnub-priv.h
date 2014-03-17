#ifndef PUBNUB__PubNub_priv_h
#define PUBNUB__PubNub_priv_h

#include <printbuf.h>
#include <curl/curl.h>

#include "pubnub.h"

struct json_object;

typedef void (*pubnub_http_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);

struct pubnub {
	char *publish_key, *subscribe_key;
	char *secret_key, *cipher_key;
	char *origin;
	char *uuid;

	char time_token[64];
	char **channelset;
	int channelset_n;

	const struct pubnub_callbacks *cb;
	void *cb_data;

	/* Name of method currently in progress; NULL if there is no
	 * method in progress currently. */
	const char *method;
	/* Callback information for the method currently
	 * in progress. Call this when we have received
	 * complete HTTP reply and the method should be
	 * completed. May be NULL in case of no notification
	 * required! */
	pubnub_http_cb finished_cb;
	void *finished_cb_data;
	/* True if finished_cb points to our internal handler;
	 * in that case, we can still call pubnub_handle_error()
	 * later and therefore shall not call stop_wait just yet. */
	bool finished_cb_internal;

	/* Error retry policy. */
	unsigned int error_retry_mask;
	bool error_print;

	bool nosignal;

	CURL *curl;
	CURLM *curlm;
	struct curl_slist *curl_headers;
	char curl_error[CURL_ERROR_SIZE];
	struct printbuf *url;
	struct printbuf *body;
	long timeout;
};

#ifdef DEBUG
#define DBGMSG(x...) do { fprintf(stderr, "[%d] ", __LINE__); fprintf(stderr, x); } while (0)
#define VERBOSE_VAL 1L
#else
#define DBGMSG(x...) do { } while (0)
#define VERBOSE_VAL 0L
#endif

#define PUBNUB_API __attribute__ ((visibility("default")))

#endif
