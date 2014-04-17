#ifndef PUBNUB__PubNub_priv_h
#define PUBNUB__PubNub_priv_h

#include <printbuf.h>

#include "pubnub.h"

struct json_object;

typedef void (*pubnub_http_cb)(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data);

struct channelset {
	const char **set;
	int n;
};

struct pubnub {
	char *publish_key, *subscribe_key;
	char *secret_key, *cipher_key;
	char *origin;
	char *uuid;

	char time_token[64];
	struct channelset channelset;
	bool resume_on_reconnect;

	const struct pubnub_callbacks *cb;
	void *cb_data;
	const struct pubnub_http_callbacks *http_cb;
	void *http_data;

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

	struct printbuf *url;
	struct printbuf *body;
	long timeout;
};

bool pubnub_handle_error_cb(struct pubnub *p, enum pubnub_res result, const char *msg, int num, bool is_num, bool stop_wait);
void pubnub_connection_cleanup(struct pubnub *p, bool stop_wait);
void pubnub_connection_finished(struct pubnub *p, const char *method);
size_t pubnub_http_inputcb(char *ptr, size_t size, size_t nmemb, void *userdata);

#ifdef DEBUG
#define DBGMSG(x, ...) do { fprintf(stderr, "[%d] ", __LINE__); fprintf(stderr, x, ##__VA_ARGS__); } while (0)
#define VERBOSE_VAL 1L
#else
#define DBGMSG(x, ...) do { } while (0)
#define VERBOSE_VAL 0L
#endif

#ifdef _MSC_VER
#define PUBNUB_API
#else
#define PUBNUB_API __attribute__ ((visibility("default")))
#endif

#endif
