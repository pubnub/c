#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <json.h>
#include <printbuf.h>

#include <curl/curl.h>

#include "crypto.h"
#include "pubnub.h"
#include "pubnub-priv.h"

/* TODO: Use curl shares. */

/* Due to all the callbacks for async safety, things may appear a bit tangled.
 * This diagram might help:
 *
 * pubnub_{publish,subscribe,history,here_now,time}
 *                 ||
 *                 vv
 *        pubnub_http_request => [pubnub_callbacks]
 *                 ||                   |
 *                 ||                   v
 *                 ||          pubnub_event_timeoutcb => pubnub.finished_cb
 *                 ||
 *             [libcurl] (we ask libcurl to issue the request)
 *                  |
 *                  v
 *         pubnub_http_sockcb (libcurl is interested in some socket events)
 *                 ||
 *          [pubnub_callbacks] (user code polls for socket events)
 *                  |
 *                  v
 *         pubnub_event_sockcb => [libcurl] (we notify curl about socket event)
 *                 ||                 ||
 *                 ||         pubnub_http_inputcb (new data arrived;
 *                 ||                              accumulated in pubnub.body)
 *                 ||
 *           pubnub.finished_cb (possibly, the request got completed)
 *
 * pubnub.finished_cb is the user-provided parameter
 * to pubnub_{publish,history,here_now,time} or a custom channel-parsing wrapper
 * around user-provided parameter to pubnub_subscribe()
 *
 * double lines (=, ||) are synchronous calls,
 * single lines (-, |) are asynchronous callbacks */

/* This is complex stuff, so let's provide yet another viewpoint,
 * a possible timeline (| denotes a sort of "context"):
 *
 * pubnub_publish
 *  pubnub_http_request
 *   curl_multi_add_handle
 *    pubnub_http_sockcb
 *     cb.add_socket    ---.
 *   cb.wait            ---+--.
 * <user's event loop>     |  |
 * pubnub_event_sockcb  ---'  |
 *  finished_cb               |
 *  cb.stop_wait        ------' (if not called in time,
 *                               wait triggers pubnub_timeout_cb)
 */


static void pubnub_http_request(struct pubnub *p, pubnub_http_cb cb, void *cb_data, bool cb_internal, bool wait);

static enum pubnub_res
pubnub_error_report(struct pubnub *p, enum pubnub_res result, json_object *msg, const char *method, bool retry)
{
	if (p->error_print) {
		static const char *pubnub_res_str[] = {
			[PNR_OK] = "Success",
			[PNR_OCCUPIED] = "Another method already in progress",
			[PNR_TIMEOUT] = "Timeout",
			[PNR_IO_ERROR] = "Communication error",
			[PNR_HTTP_ERROR] = "HTTP error",
			[PNR_FORMAT_ERROR] = "Unexpected input in received JSON",
		};
		if (msg) {
			fprintf(stderr, "pubnub %s result: %s [%s]%s\n",
				method, pubnub_res_str[result],
				json_object_get_string(msg),
				retry ? " (reissuing)" : "");
		} else {
			fprintf(stderr, "pubnub %s result: %s%s\n",
				method, pubnub_res_str[result],
				retry ? " (reissuing)" : "");
		}
	}
	return result;
}

static void
pubnub_error_retry(struct pubnub *p, void *cb_data)
{
	pubnub_http_request(p, p->finished_cb, p->finished_cb_data, p->finished_cb_internal, false);
}

/* Deal with errors. This will (i) print the error and (ii) either (a) retry
 * the request or (b) notify the user (if @cb is true).
 *
 * It will return true if the caller shall notify the user (i.e. (b) was
 * the case and @cb was false).
 *
 * Note that in case of notifying the user of an error, stop_wait is called
 * unconditionally, even in case of finished_cb_internal set or cb at false,
 * as it's certain there will be no retrying anymore. */
static bool
pubnub_handle_error(struct pubnub *p, enum pubnub_res result, json_object *msg, const char *method, bool cb)
{
	if (p->error_retry_mask & (1 << result)) {
		/* Retry ... */

		pubnub_error_report(p, result, msg, method, true);
		p->method = method; // restore after cleanup

		/* ... after a 250ms delay; this avoids hammering
		 * the PubNub service in case of a bug. */
		struct timespec timeout_ts = { .tv_nsec = 250*1000*1000 };
		p->cb->timeout(p, p->cb_data, &timeout_ts, pubnub_error_retry, p);

		return false;

	} else {
		/* No auto-retry, somehow notify the user. */

		pubnub_error_report(p, result, msg, method, false);
		p->cb->stop_wait(p, p->cb_data); // unconditional!

		if (cb)
			p->finished_cb(p, result, msg, p->cb_data, p->finished_cb_data);

		return !cb;
	}
}


static void pubnub_connection_cleanup(struct pubnub *p, bool stop_wait);

static void
pubnub_connection_finished(struct pubnub *p, CURLcode res, bool stop_wait)
{
	DBGMSG("DONE: (%d) %s\n", res, p->curl_error);

	/* pubnub_connection_cleanup() will clobber p->method */
	const char *method = p->method;

	/* Check against I/O errors */
	if (res != CURLE_OK) {
		pubnub_connection_cleanup(p, stop_wait);
		if (res == CURLE_OPERATION_TIMEDOUT) {
			pubnub_handle_error(p, PNR_TIMEOUT, NULL, method, true);
		} else {
			json_object *msgstr = json_object_new_string(curl_easy_strerror(res));
			pubnub_handle_error(p, PNR_IO_ERROR, msgstr, method, true);
			json_object_put(msgstr);
		}
		return;
	}

	/* Check HTTP code */
	long code = 599;
	curl_easy_getinfo(p->curl, CURLINFO_RESPONSE_CODE, &code);
	/* At this point, we can tear down the connection. */
	pubnub_connection_cleanup(p, stop_wait);
	if (code / 100 != 2) {
		json_object *httpcode = json_object_new_int(code);
		pubnub_handle_error(p, PNR_HTTP_ERROR, httpcode, method, true);
		json_object_put(httpcode);
		return;
	}

	/* Parse body */
	json_object *response = json_tokener_parse(p->body->buf);
	if (!response) {
		pubnub_handle_error(p, PNR_FORMAT_ERROR, NULL, method, true);
		return;
	}

	DBGMSG("DONE: Passed all traps! stop_wait %d\n", p->finished_cb_internal);

	/* The regular callback */
	if (!p->finished_cb_internal)
		p->cb->stop_wait(p, p->cb_data);
	p->finished_cb(p, PNR_OK, response, p->cb_data, p->finished_cb_data);
	json_object_put(response);
}

static void
pubnub_connection_cleanup(struct pubnub *p, bool stop_wait)
{
	p->method = NULL;

	curl_multi_remove_handle(p->curlm, p->curl);
	curl_easy_cleanup(p->curl);
	p->curl = NULL;
}

/* Let curl take care of the ongoing connections, then check for new events
 * and handle them (call the user callbacks etc.).  If stop_wait == true,
 * we have already called cb->wait and need to call cb->stop_wait if the
 * connection is over. Returns true if the connection has finished, otherwise
 * it is still running. */
static bool
pubnub_connection_check(struct pubnub *p, int fd, int bitmask, bool stop_wait)
{
	int running_handles = 0;
	CURLMcode rc = curl_multi_socket_action(p->curlm, fd, bitmask, &running_handles);
	DBGMSG("event_sockcb fd %d bitmask %d rc %d rh %d\n", fd, bitmask, rc, running_handles);
	if (rc != CURLM_OK) {
		const char *method = p->method;
		pubnub_connection_cleanup(p, stop_wait);
		json_object *msgstr = json_object_new_string(curl_multi_strerror(rc));
		pubnub_handle_error(p, PNR_IO_ERROR, msgstr, method, true);
		json_object_put(msgstr);
		return true;
	}

	CURLMsg *msg;
	int msgs_left;
	bool done = false;

	while ((msg = curl_multi_info_read(p->curlm, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Done! */
		pubnub_connection_finished(p, msg->data.result, stop_wait);
		done = true;
	}

	return done;
}

/* Socket callback for pubnub_callbacks event notification. */
static void
pubnub_event_sockcb(struct pubnub *p, int fd, int mode, void *cb_data)
{
	int ev_bitmask =
		(mode & 1 ? CURL_CSELECT_IN : 0) |
		(mode & 2 ? CURL_CSELECT_OUT : 0) |
		(mode & 4 ? CURL_CSELECT_ERR : 0);

	pubnub_connection_check(p, fd, ev_bitmask, true);
}

static void
pubnub_event_timeoutcb(struct pubnub *p, void *cb_data)
{
	pubnub_connection_check(p, CURL_SOCKET_TIMEOUT, 0, true);
}

/* Socket callback for libcurl setting up / tearing down watches. */
static int
pubnub_http_sockcb(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp)
{
	struct pubnub *p = userp;

	DBGMSG("http_sockcb: fd %d action %d sockdata %p\n", s, action, socketp);

	if (action == CURL_POLL_REMOVE) {
		p->cb->rem_socket(p, p->cb_data, s);

	} else if (action == CURL_POLL_NONE) {
		/* Nothing to do? */

	} else {
		/* We use the socketp pointer just as a marker of whether
		 * we have already been called on this socket (i.e. should
		 * issue rem_socket() first). The particular value does
		 * not matter, as long as it's not NULL. */
		if (socketp)
			p->cb->rem_socket(p, p->cb_data, s);
		curl_multi_assign(p->curlm, s, /* anything not NULL */ easy);
		/* add_socket()'s mode uses the same bit pattern as
		 * libcurl's action. What a coincidence! ;-) */
		p->cb->add_socket(p, p->cb_data, s, action, pubnub_event_sockcb, easy);
	}
	return 0;
}

/* Timer callback for libcurl setting up a timeout notification. */
static int
pubnub_http_timercb(CURLM *multi, long timeout_ms, void *userp)
{
	struct pubnub *p = userp;

	DBGMSG("http_timercb: %ld ms\n", timeout_ms);

	struct timespec timeout_ts;
	if (timeout_ms > 0) {
		timeout_ts.tv_sec = timeout_ms/1000;
		timeout_ts.tv_nsec = (timeout_ms%1000)*1000000L;
		p->cb->timeout(p, p->cb_data, &timeout_ts, pubnub_event_timeoutcb, p);
	} else {
		if (timeout_ms == 0) {
			/* Timeout already reached. Call cb directly. */
			pubnub_event_timeoutcb(p, p);
		} /* else no timeout at all. */
		timeout_ts.tv_sec = 0;
		timeout_ts.tv_nsec = 0;
		p->cb->timeout(p, p->cb_data, &timeout_ts, NULL, NULL);
	}
	return 0;
}

static char *
pubnub_gen_uuid(void)
{
	/* Template for version 4 (random) UUID. */
	char uuidbuf[] = "xxxxxxxx-xxxx-4xxx-9xxx-xxxxxxxxxxxx";

	unsigned int seed;
#if defined(__MINGW32__) || defined(__MACH__)
	seed = time(NULL);
	srand(seed);
#else
	/* About the best world-unique random seed we can manage without
	 * absurd measures... */
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	seed = ts.tv_nsec;
#endif
	char hex[] = "0123456789abcdef";
	for (int i = 0; i < strlen(uuidbuf); i++) {
		if (uuidbuf[i] != 'x')
			continue;
#if defined(__MINGW32__) || defined(__MACH__)
		uuidbuf[i] = hex[rand() % 16];
#else
		uuidbuf[i] = hex[rand_r(&seed) % 16];
#endif
	}

	return strdup(uuidbuf);
}

PUBNUB_API
struct pubnub *
pubnub_init(const char *publish_key, const char *subscribe_key,
		const struct pubnub_callbacks *cb, void *cb_data)
{
	struct pubnub *p = calloc(1, sizeof(*p));
	if (!p) return NULL;

	p->publish_key = strdup(publish_key);
	p->subscribe_key = strdup(subscribe_key);
	p->origin = strdup("http://pubsub.pubnub.com");
	p->uuid = pubnub_gen_uuid();
	strcpy(p->time_token, "0");

	p->cb = cb;
	p->cb_data = cb_data;

	p->url = printbuf_new();
	p->body = printbuf_new();

	p->error_retry_mask = ~0;
	p->error_print = true;

	p->nosignal = true;

	p->curlm = curl_multi_init();
	curl_multi_setopt(p->curlm, CURLMOPT_SOCKETFUNCTION, pubnub_http_sockcb);
	curl_multi_setopt(p->curlm, CURLMOPT_SOCKETDATA, p);
	curl_multi_setopt(p->curlm, CURLMOPT_TIMERFUNCTION, pubnub_http_timercb);
	curl_multi_setopt(p->curlm, CURLMOPT_TIMERDATA, p);

	p->curl_headers = curl_slist_append(p->curl_headers, "User-Agent: c-generic/0");
	p->curl_headers = curl_slist_append(p->curl_headers, "V: 3.4");

	return p;
}

PUBNUB_API
void
pubnub_done(struct pubnub *p)
{
	if (p->cb->done)
		p->cb->done(p, p->cb_data);

	if (p->curl) {
		curl_multi_remove_handle(p->curlm, p->curl);
		curl_easy_cleanup(p->curl);
	}
	curl_multi_cleanup(p->curlm);
	curl_slist_free_all(p->curl_headers);

	printbuf_free(p->body);
	printbuf_free(p->url);
	free(p->publish_key);
	free(p->subscribe_key);
	free(p->secret_key);
	free(p->cipher_key);
	free(p->origin);
	free(p->uuid);
	free(p);
}

PUBNUB_API
void
pubnub_set_secret_key(struct pubnub *p, const char *secret_key)
{
	free(p->secret_key);
	p->secret_key = secret_key ? strdup(secret_key) : NULL;
}

PUBNUB_API
void
pubnub_set_cipher_key(struct pubnub *p, const char *cipher_key)
{
	free(p->cipher_key);
	p->cipher_key = cipher_key ? strdup(cipher_key) : NULL;
}

PUBNUB_API
void
pubnub_set_origin(struct pubnub *p, const char *origin)
{
	free(p->origin);
	p->origin = strdup(origin);
}

PUBNUB_API
void
pubnub_set_nosignal(struct pubnub *p, bool nosignal)
{
	p->nosignal = nosignal;
}

PUBNUB_API
const char *
pubnub_current_uuid(struct pubnub *p)
{
	return p->uuid;
}

PUBNUB_API
void
pubnub_set_uuid(struct pubnub *p, const char *uuid)
{
	free(p->uuid);
	p->uuid = strdup(uuid);
}

PUBNUB_API
void
pubnub_error_policy(struct pubnub *p, unsigned int retry_mask, bool print)
{
	p->error_retry_mask = retry_mask;
	p->error_print = print;
}


static size_t
pubnub_http_inputcb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct pubnub *p = userdata;
	DBGMSG("http input: %zd bytes\n", size * nmemb);
	printbuf_memappend_fast(p->body, ptr, size * nmemb);
	return size * nmemb;
}

static void
pubnub_http_setup(struct pubnub *p, const char *urlelems[], const char **qparelems, long timeout)
{
	printbuf_reset(p->url);
	printbuf_memappend_fast(p->url, p->origin, strlen(p->origin));
	for (const char **urlelemp = urlelems; *urlelemp; urlelemp++) {
		/* Join urlemes by slashes, e.g.
		 *   { "v2", "time", NULL }
		 * means /v2/time */
		printbuf_memappend_fast(p->url, "/", 1);
		char *urlenc = curl_easy_escape(p->curl, *urlelemp, strlen(*urlelemp));
		printbuf_memappend_fast(p->url, urlenc, strlen(urlenc));
		curl_free(urlenc);
	}
	if (qparelems) {
		printbuf_memappend_fast(p->url, "?", 1);
		/* qparelemp elements are in pairs, e.g.
		 *   { "x", NULL, "UUID", "abc", "tt, "1", NULL }
		 * means ?x&UUID=abc&tt=1 */
		for (const char **qparelemp = qparelems; *qparelemp; qparelemp += 2) {
			if (qparelemp > qparelems)
				printbuf_memappend_fast(p->url, "?", 1);
			printbuf_memappend_fast(p->url, qparelemp[0], strlen(qparelemp[0]));
			if (qparelemp[1]) {
				printbuf_memappend_fast(p->url, "=", 1);
				printbuf_memappend_fast(p->url, qparelemp[1], strlen(qparelemp[1]));
			}
		}
	}
	printbuf_memappend_fast(p->url, "" /* \0 */, 1);

	p->timeout = timeout;
}

static void
pubnub_http_request(struct pubnub *p, pubnub_http_cb cb, void *cb_data, bool cb_internal, bool wait)
{
	p->curl = curl_easy_init();

	curl_easy_setopt(p->curl, CURLOPT_URL, p->url->buf);
	curl_easy_setopt(p->curl, CURLOPT_HTTPHEADER, p->curl_headers);
	curl_easy_setopt(p->curl, CURLOPT_WRITEFUNCTION, pubnub_http_inputcb);
	curl_easy_setopt(p->curl, CURLOPT_WRITEDATA, p);
	curl_easy_setopt(p->curl, CURLOPT_VERBOSE, VERBOSE_VAL);
	curl_easy_setopt(p->curl, CURLOPT_ERRORBUFFER, p->curl_error);
	curl_easy_setopt(p->curl, CURLOPT_PRIVATE, p);
	curl_easy_setopt(p->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(p->curl, CURLOPT_NOSIGNAL, (long) p->nosignal);
	curl_easy_setopt(p->curl, CURLOPT_TIMEOUT, p->timeout);

	printbuf_reset(p->body);
	p->finished_cb = cb;
	p->finished_cb_data = cb_data;
	p->finished_cb_internal = cb_internal;

	DBGMSG("add handle: pre\n");
	curl_multi_add_handle(p->curlm, p->curl);
	DBGMSG("add handle: post\n");

	if (!pubnub_connection_check(p, CURL_SOCKET_TIMEOUT, 0, false)) {
		/* Connection did not fail early, let's call wait and return. */
		DBGMSG("wait: pre\n");
		/* Call wait() only if this is not an error retry; wait
		 * and stop_wait should be paired 1:1 and we did not
		 * call stop_wait either. */
		if (wait)
			p->cb->wait(p, p->cb_data);
		DBGMSG("wait: post\n");
	}
}


PUBNUB_API
void
pubnub_publish(struct pubnub *p, const char *channel, struct json_object *message,
		long timeout, pubnub_publish_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->publish;

	if (p->method) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "publish", false),
				NULL, p->cb_data, cb_data);
		return;
	}
	p->method = "publish";

	if (timeout < 0)
		timeout = 5;

	bool put_message = false;
	if (p->cipher_key) {
		message = pubnub_encrypt(p->cipher_key, json_object_to_json_string(message));
		put_message = true;
	}

	const char *message_str = json_object_to_json_string(message);

	char *signature;
	if (p->secret_key) {
		signature = pubnub_signature(p, channel, message_str);
	} else {
		signature = strdup("0");
	}

	const char *urlelems[] = { "publish", p->publish_key, p->subscribe_key, signature, channel, "0", message_str, NULL };
	pubnub_http_setup(p, urlelems, NULL, timeout);
	free(signature);
	if (put_message)
		json_object_put(message);

	pubnub_http_request(p, (pubnub_http_cb) cb, cb_data, false, true);
}


struct pubnub_subscribe_http_cb {
	char *channelset;
	pubnub_subscribe_cb cb;
	void *call_data;
};

static void
pubnub_subscribe_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct pubnub_subscribe_http_cb *cb_http_data = call_data;
	char *channelset = cb_http_data->channelset;
	call_data = cb_http_data->call_data;
	pubnub_subscribe_cb cb = cb_http_data->cb;
	free(cb_http_data);

	if (result != PNR_OK) {
		/* pubnub_handle_error() has been already called along
		 * the way to here. */
		cb(p, result, NULL, response, ctx_data, call_data);
		free(channelset);
		return;
	}

	/* Response must be an array, and its first element also an array. */
	if (!json_object_is_type(response, json_type_array)) {
		result = PNR_FORMAT_ERROR;
error:
		if (pubnub_handle_error(p, result, response, "subscribe", false))
			cb(p, result, NULL, response, ctx_data, call_data);
		free(channelset);
		return;
	}
	json_object *msg = json_object_array_get_idx(response, 0);
	if (!json_object_is_type(msg, json_type_array)) {
		result = PNR_FORMAT_ERROR;
		goto error;
	}

	if (p->cipher_key) {
		/* Decrypt array elements, which must be strings. */
		struct json_object *msg_new = pubnub_decrypt_array(p->cipher_key, msg);
		if (!msg_new) {
			result = PNR_FORMAT_ERROR;
			goto error;
		}
		/* Replacing msg in the response[] array will make sure
		 * the refcounting is correct; this drops old msg and
		 * will drop msg_new when we drop the whole response. */
		json_object_array_put_idx(response, 0, msg_new);
		msg = msg_new;
	}

	/* Extract and save time token (mandatory). */
	json_object *time_token = json_object_array_get_idx(response, 1);
	if (!time_token || !json_object_is_type(time_token, json_type_string)) {
		result = PNR_FORMAT_ERROR;
		goto error;
	}
	strncpy(p->time_token, json_object_get_string(time_token), sizeof(p->time_token));
	p->time_token[sizeof(p->time_token) - 1] = 0;

	/* Extract and update channel name (not mandatory, present only
	 * when multiplexing). */
	json_object *channelset_json = json_object_array_get_idx(response, 2);
	int msg_n = json_object_array_length(msg);
	char **channels = malloc((msg_n + 1) * sizeof(channels[0]));
	if (channelset_json) {
		if (!json_object_is_type(channelset_json, json_type_string)) {
			result = PNR_FORMAT_ERROR;
			goto error;
		}
		free(channelset);
		channelset = strdup(json_object_get_string(channelset_json));

		/* Comma-split the channelset to channels[] array. */
		char *channelsetp = channelset;
#ifndef __MINGW32__
		char *channelsettok = NULL;
#endif
		for (int i = 0; i < msg_n; channelsetp = NULL, i++) {
#ifdef __MINGW32__			
			char *channelset1 = strtok(channelsetp, ",");
#else			
			char *channelset1 = strtok_r(channelsetp, ",", &channelsettok);
#endif
			if (!channelset1) {
				for (; i < msg_n; i++) {
					/* Fill the rest of the array with
					 * empty strings. */
					channels[i] = strdup("");
				}
				break;
			}
			channels[i] = strdup(channelset1);
		}
	} else {
		for (int i = 0; i < msg_n; i++) {
			channels[i] = strdup(channelset);
		}
	}
	channels[msg_n] = NULL;
	free(channelset);

	/* Finally call the user callback. */
	p->cb->stop_wait(p, p->cb_data);
	cb(p, result, channels, msg, ctx_data, call_data);
}

PUBNUB_API
void
pubnub_subscribe(struct pubnub *p, const char *channel,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->subscribe;

	if (p->method) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "subscribe", false),
				NULL, NULL, p->cb_data, cb_data);
		return;
	}
	p->method = "subscribe";

	if (timeout < 0)
		timeout = 310;

	struct pubnub_subscribe_http_cb *cb_http_data = malloc(sizeof(*cb_http_data));
	cb_http_data->channelset = strdup(channel);
	cb_http_data->cb = cb;
	cb_http_data->call_data = cb_data;

	const char *urlelems[] = { "subscribe", p->subscribe_key, channel, "0", p->time_token, NULL };
	const char *qparamelems[] = { "UUID", p->uuid, NULL };
	pubnub_http_setup(p, urlelems, qparamelems, timeout);
	pubnub_http_request(p, pubnub_subscribe_http_cb, cb_http_data, true, true);
}

PUBNUB_API
void
pubnub_subscribe_multi(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	struct printbuf *channelset = printbuf_new();
	for (int i = 0; i < channels_n; i++) {
		printbuf_memappend_fast(channelset, channels[i], strlen(channels[i]));
		if (i < channels_n - 1)
			printbuf_memappend_fast(channelset, ",", 1);
		else
			printbuf_memappend_fast(channelset, "" /* \0 */, 1);
	}
	pubnub_subscribe(p, channelset->buf, timeout, cb, cb_data);
	printbuf_free(channelset);
}


struct pubnub_history_http_cb {
	pubnub_history_cb cb;
	void *call_data;
};

static void
pubnub_history_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct pubnub_history_http_cb *cb_http_data = call_data;
	call_data = cb_http_data->call_data;
	pubnub_history_cb cb = cb_http_data->cb;
	free(cb_http_data);

	if (result != PNR_OK) {
		/* pubnub_handle_error() has been already called along
		 * the way to here. */
		cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Response must be an array. */
	if (!json_object_is_type(response, json_type_array)) {
		result = PNR_FORMAT_ERROR;
error:
		if (pubnub_handle_error(p, result, response, "history", false))
			cb(p, result, response, ctx_data, call_data);
		return;
	}

	bool put_response = false;
	if (p->cipher_key) {
		/* Decrypt array elements, which must be strings. */
		struct json_object *response_new = pubnub_decrypt_array(p->cipher_key, response);
		if (!response_new) {
			result = PNR_FORMAT_ERROR;
			goto error;
		}
		put_response = true;
		response = response_new;
	}

	/* Finally call the user callback. */
	p->cb->stop_wait(p, p->cb_data);
	cb(p, result, response, ctx_data, call_data);

	if (put_response)
		json_object_put(response);
}

PUBNUB_API
void
pubnub_history(struct pubnub *p, const char *channel, int limit,
		long timeout, pubnub_history_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->history;

	if (p->method) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "history", false),
				NULL, p->cb_data, cb_data);
		return;
	}
	p->method = "history";

	if (timeout < 0)
		timeout = 5;

	struct pubnub_history_http_cb *cb_http_data = malloc(sizeof(*cb_http_data));
	cb_http_data->cb = cb;
	cb_http_data->call_data = cb_data;

	char strlimit[64]; snprintf(strlimit, sizeof(strlimit), "%d", limit);
	const char *urlelems[] = { "history", p->subscribe_key, channel, "0", strlimit, NULL };
	pubnub_http_setup(p, urlelems, NULL, timeout);
	pubnub_http_request(p, pubnub_history_http_cb, cb_http_data, true, true);
}


PUBNUB_API
void
pubnub_here_now(struct pubnub *p, const char *channel,
		long timeout, pubnub_here_now_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->here_now;

	if (p->method) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "here_now", false),
				NULL, p->cb_data, cb_data);
		return;
	}
	p->method = "here_now";

	if (timeout < 0)
		timeout = 5;

	const char *urlelems[] = { "v2", "presence", "sub-key", p->subscribe_key, "channel", channel, NULL };
	pubnub_http_setup(p, urlelems, NULL, timeout);
	pubnub_http_request(p, (pubnub_http_cb) cb, cb_data, false, true);
}


struct pubnub_time_http_cb {
	pubnub_time_cb cb;
	void *call_data;
};

static void
pubnub_time_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct pubnub_time_http_cb *cb_http_data = call_data;
	call_data = cb_http_data->call_data;
	pubnub_history_cb cb = cb_http_data->cb;
	free(cb_http_data);

	if (result != PNR_OK) {
		/* pubnub_handle_error() has been already called along
		 * the way to here. */
		cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Response must be an array. */
	if (!json_object_is_type(response, json_type_array)) {
		result = PNR_FORMAT_ERROR;
		if (pubnub_handle_error(p, result, response, "time", false))
			cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Extract the first element. */
	json_object *ts = json_object_array_get_idx(response, 0);
	json_object_get(ts);

	/* Finally call the user callback. */
	p->cb->stop_wait(p, p->cb_data);
	cb(p, result, ts, ctx_data, call_data);

	json_object_put(ts);
}

PUBNUB_API
void
pubnub_time(struct pubnub *p, long timeout, pubnub_time_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->time;

	if (p->method) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "time", false),
				NULL, p->cb_data, cb_data);
		return;
	}
	p->method = "time";

	if (timeout < 0)
		timeout = 5;

	struct pubnub_time_http_cb *cb_http_data = malloc(sizeof(*cb_http_data));
	cb_http_data->cb = cb;
	cb_http_data->call_data = cb_data;

	const char *urlelems[] = { "time", "0", NULL };
	pubnub_http_setup(p, urlelems, NULL, timeout);
	pubnub_http_request(p, pubnub_time_http_cb, cb_http_data, true, true);
}
