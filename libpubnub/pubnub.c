#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <json/json.h>
#include <json/printbuf.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

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


#define SDK_INFO "c-generic/1.0"


static void pubnub_http_request(struct pubnub *p, pubnub_http_cb cb, void *cb_data, bool cb_internal, bool wait);

static enum pubnub_res
pubnub_error_report(struct pubnub *p, enum pubnub_res result, json_object *msg, const char *method, bool retry)
{
	if (p->error_print) {
		static const char *pubnub_res_str[] = {
			SFINIT( [PNR_OK] ,           "Success"),
			SFINIT( [PNR_OCCUPIED] ,     "Another method already in progress"),
			SFINIT( [PNR_TIMEOUT] ,      "Timeout"),
			SFINIT( [PNR_IO_ERROR] ,     "Communication error"),
			SFINIT( [PNR_HTTP_ERROR] ,   "HTTP error"),
			SFINIT( [PNR_FORMAT_ERROR] , "Unexpected input in received JSON"),
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

void
pubnub_finished_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response)
{
	/* In some places, e.g. resubscribe_http_init(), we look at whether
	 * p->finished_cb_data holds anything, and if there are leftovers
	 * from a previous call (e.g. here_now), things blow up.  Therefore,
	 * make sure that at the point when we issue the callback, there are
	 * no leftovers. */
	pubnub_http_cb finished_cb = p->finished_cb;
	void *finished_cb_data = p->finished_cb_data;
	p->finished_cb = NULL;
	p->finished_cb_data = NULL;

	finished_cb(p, result, response, p->cb_data, finished_cb_data);
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

		DBGMSG("error retry (%d %s)\n", result, method);

		pubnub_error_report(p, result, msg, method, true);
		p->method = method; // restore after cleanup

		/* ... after a 250ms delay; this avoids hammering
		 * the PubNub service in case of a bug. */
		struct timespec timeout_ts;
		timeout_ts.tv_nsec = 250*1000*1000;
		timeout_ts.tv_sec = 0;
		p->cb->timeout(p, p->cb_data, &timeout_ts, pubnub_error_retry, p);

		return false;

	} else {
		/* No auto-retry, somehow notify the user. */

		DBGMSG("error terminal fail (%d %s)\n", result, method);

		pubnub_error_report(p, result, msg, method, false);
		p->cb->stop_wait(p, p->cb_data); // unconditional!

		if (cb && p->finished_cb)
			pubnub_finished_cb(p, result, msg);

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
	if (p->finished_cb)
		pubnub_finished_cb(p, PNR_OK, response);
	json_object_put(response);
}

static void
pubnub_connection_cleanup(struct pubnub *p, bool stop_wait)
{
	p->method = NULL;

	if (p->curl) {
		curl_multi_remove_handle(p->curlm, p->curl);
		curl_easy_cleanup(p->curl);
		p->curl = NULL;
	}
}

/* Cancel ongoing HTTP connection, freeing all request resources and
 * invoking the relevant callbacks. */
static void
pubnub_connection_cancel(struct pubnub *p)
{
	pubnub_connection_cleanup(p, false);
	if (p->finished_cb)
		pubnub_finished_cb(p, PNR_CANCELLED, NULL);
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
	DBGMSG("event_sockcb fd %d bitmask %d rh %d...\n", fd, bitmask, running_handles);
	CURLMcode rc = curl_multi_socket_action(p->curlm, fd, bitmask, &running_handles);
	DBGMSG("event_sockcb ...rc %d\n", rc);
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
	struct pubnub *p = (struct pubnub *)userp;

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
	struct pubnub *p = (struct pubnub *)userp;

	DBGMSG("http_timercb: %ld ms\n", timeout_ms);

	struct timespec timeout_ts;
	if (timeout_ms > 0) {
		timeout_ts.tv_sec = timeout_ms/1000;
		timeout_ts.tv_nsec = (timeout_ms%1000)*1000000L;
		p->cb->timeout(p, p->cb_data, &timeout_ts, pubnub_event_timeoutcb, p);
	} else {
		timeout_ts.tv_sec = 0;
		timeout_ts.tv_nsec = 0;
		p->cb->timeout(p, p->cb_data, &timeout_ts, NULL, NULL);

		if (timeout_ms == 0) {
			/* Timeout already reached. Call cb directly. */
			pubnub_event_timeoutcb(p, p);
		} /* else no timeout at all. */
	}
	return 0;
}

static char *
pubnub_gen_uuid(void)
{
	/* Template for version 4 (random) UUID. */
	char uuidbuf[] = "xxxxxxxx-xxxx-4xxx-9xxx-xxxxxxxxxxxx";

	unsigned int seed;
#if defined(__MINGW32__) || defined(__MACH__) || defined(_MSC_VER)
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
#if defined(__MINGW32__) || defined(__MACH__) || defined(_MSC_VER)
		uuidbuf[i] = hex[rand() % 16];
#else
		uuidbuf[i] = hex[rand_r(&seed) % 16];
#endif
	}

	return strdup(uuidbuf);
}

static struct printbuf *
channelset_printbuf(const struct channelset *cs)
{
	struct printbuf *pb = printbuf_new();
	for (int i = 0; i < cs->n; i++) {
		printbuf_memappend_fast(pb, cs->set[i], strlen(cs->set[i]));
		if (i < cs->n - 1)
			printbuf_memappend_fast(pb, ",", 1);
		else
			printbuf_memappend_fast(pb, "" /* \0 */, 1);
	}
	return pb;
}

/* Add all items from |src| to |dst|, unless they are already in it.
 * Returns the number of channels actually added. */
static int
channelset_add(struct channelset *dst, const struct channelset *src)
{
#ifdef _MSC_VER
	bool *src_mask = (bool*)calloc(src->n , sizeof(bool));
#else
	bool src_mask[src->n];
	memset(&src_mask, 0, sizeof(src_mask));
#endif
	int src_new_n = src->n;

	/* We anticipate small |channelset| and small (or singular) |channels|,
	 * therefore using just a trivial O(MN) algorithm here. */
	for (int i = 0; i < dst->n; i++) {
		for (int j = 0; j < src->n; j++) {
			if (src_mask[j])
				continue;
			if (!strcmp(dst->set[i], src->set[j])) {
				src_mask[j] = true;
				src_new_n--;
				break;
			}
		}
	}

	if (src_new_n != 0) {
		int i = dst->n;
		dst->n += src_new_n;
		dst->set = (const char**)realloc(dst->set, dst->n * sizeof(dst->set[0]));
		for (int j = 0; j < src->n; j++) {
			if (src_mask[j])
				continue;
			dst->set[i++] = strdup(src->set[j]);
		}
	}
#ifdef _MSC_VER
	free(src_mask);
#endif
	return src_new_n;
}

static void channelset_done(struct channelset *cs);

/* Remove all items from |channels| from the channelset (if they are listed).
 * Returns the number of channels actually removed. */
static int
channelset_rm(struct channelset *dst, const struct channelset *src)
{
#ifdef _MSC_VER
	bool *src_mask = (bool*)calloc(src->n , sizeof(bool));
#else
	bool src_mask[src->n];
	memset(&src_mask, 0, sizeof(src_mask));
#endif
	int src_new_n = src->n;

	/* We anticipate small |channelset| and small (or singular) |channels|,
	 * therefore using just a trivial O(MN) algorithm here. */
	for (int i = 0; i < dst->n; i++) {
		for (int j = 0; j < src->n; j++) {
			if (src_mask[j])
				continue;
			if (!strcmp(dst->set[i], src->set[j])) {
				src_mask[j] = true;
				src_new_n--;

				free((char *) dst->set[i]);
				/* Replace the free spot with the last channel
				 * and revisit the spot in next iteration. */
				dst->set[i] = dst->set[--dst->n];
				i--;
				break;
			}
		}
	}

	if (src_new_n != src->n) {
		if (dst->n == 0) {
			/* All channels removed. */
			channelset_done(dst);
		} else {
			dst->set = (const char**)realloc(dst->set, dst->n * sizeof(dst->set[0]));
		}
	}
#ifdef _MSC_VER
	free(src_mask);
#endif
	return src->n - src_new_n;
}

static void
channelset_done(struct channelset *cs)
{
	for (int i = 0; i < cs->n; i++) {
		/* XXX: The typecast here is a hack; we are dealing with
		 * a const char *channels everywhere else and rely on the
		 * fact that we are calling channelset_done() only on
		 * those channelsets where we strdup()'d all the strings. */
		free((char *) cs->set[i]);
	}
	cs->n = 0;
	free(cs->set);
	cs->set = NULL;
}

static void
pubnub_free_ssl_cacerts(struct pubnub *p)
{
	if (p->ssl_cacerts)
	{
		sk_X509_INFO_pop_free(p->ssl_cacerts, X509_INFO_free);
		p->ssl_cacerts = NULL;
	}
}

PUBNUB_API
struct pubnub *
pubnub_init(const char *publish_key, const char *subscribe_key,
		const struct pubnub_callbacks *cb, void *cb_data)
{
	struct pubnub *p = (struct pubnub *)calloc(1, sizeof(*p));
	if (!p) return NULL;

	p->publish_key = strdup(publish_key);
	p->subscribe_key = strdup(subscribe_key);
	p->origin = strdup("http://pubsub.pubnub.com");
	p->uuid = pubnub_gen_uuid();
	strcpy(p->time_token, "0");
	p->resume_on_reconnect = true;

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

	p->curl_headers = curl_slist_append(p->curl_headers, "User-Agent: " SDK_INFO);
	p->curl_headers = curl_slist_append(p->curl_headers, "V: 3.4");

	return p;
}

PUBNUB_API
void
pubnub_done(struct pubnub *p)
{
	if (p->method) {
		/* Ongoing request, cancel. */
		pubnub_connection_cancel(p);
		p->method = NULL;
	}
	assert(!p->curl);

	curl_multi_cleanup(p->curlm);
	curl_slist_free_all(p->curl_headers);

	if (p->cb->done)
		p->cb->done(p, p->cb_data);

	channelset_done(&p->channelset);

	pubnub_free_ssl_cacerts(p);
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
struct json_object *
pubnub_serialize(struct pubnub *p)
{
	json_object *obj = json_object_new_object();
	json_object_object_add(obj, "publish_key", json_object_new_string(p->publish_key));
	json_object_object_add(obj, "subscribe_key", json_object_new_string(p->subscribe_key));
	json_object_object_add(obj, "time_token", json_object_new_string(p->time_token));
	json_object_object_add(obj, "uuid", json_object_new_string(p->uuid));
	json_object_object_add(obj, "origin", json_object_new_string(p->origin));
	json_object_object_add(obj, "secret_key", json_object_new_string(p->secret_key));
	json_object_object_add(obj, "cipher_key", json_object_new_string(p->cipher_key));
	json_object_object_add(obj, "resume_on_reconnect", json_object_new_boolean(p->resume_on_reconnect));

	json_object *arr = json_object_new_array();
	for (int i = 0; i < p->channelset.n; i++) {
		json_object_array_add(arr, json_object_new_string(p->channelset.set[i]));
	}
	json_object_object_add(obj, "channels", arr);

	return obj;
}

PUBNUB_API
struct pubnub *
pubnub_init_serialized(struct json_object *obj,
	const struct pubnub_callbacks *cb, void *cb_data)
{
	const char *pub = json_object_get_string(json_object_object_get(obj, "publish_key"));
	const char *sub = json_object_get_string(json_object_object_get(obj, "subscribe_key"));
	struct pubnub *p = pubnub_init(pub, sub, cb, cb_data);

	int tt_size = sizeof(p->time_token);
	strncpy(p->time_token, json_object_get_string(json_object_object_get(obj, "time_token")), tt_size);
	p->time_token[tt_size - 1] = 0;

	pubnub_set_uuid(p, json_object_get_string(json_object_object_get(obj, "uuid")));
	pubnub_set_origin(p, json_object_get_string(json_object_object_get(obj, "origin")));
	pubnub_set_secret_key(p, json_object_get_string(json_object_object_get(obj, "secret_key")));
	pubnub_set_cipher_key(p, json_object_get_string(json_object_object_get(obj, "cipher_key")));
	pubnub_set_resume_on_reconnect(p, json_object_get_boolean(json_object_object_get(obj, "resume_on_reconnect")));

	json_object *arr = json_object_object_get(obj, "channels");

	int n = json_object_array_length(arr);
	if (n > 0) {
		const char **channels = (const char**)malloc(sizeof(char*) * n);
		for (int i = 0; i < n; i++) {
			channels[i] = json_object_get_string(json_object_array_get_idx(arr, i));
		}
		pubnub_subscribe_multi(p, channels, n, -1, NULL, NULL);
		free(channels);
	}

	return p;
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

PUBNUB_API
void
pubnub_set_ssl_cacerts(struct pubnub *p, const char *cacerts, size_t len)
{
	BIO *bio;

	pubnub_free_ssl_cacerts(p);

	bio = BIO_new_mem_buf((char *)cacerts, len);
	p->ssl_cacerts = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	BIO_free(bio);
}

PUBNUB_API
void
pubnub_set_resume_on_reconnect(struct pubnub *p, bool resume_on_reconnect)
{
	p->resume_on_reconnect = resume_on_reconnect;
}

static size_t
pubnub_http_inputcb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct pubnub *p = (struct pubnub *)userdata;
	DBGMSG("http input: %zd bytes\n", size * nmemb);
	printbuf_memappend_fast(p->body, ptr, size * nmemb);
	return size * nmemb;
}

static CURLcode
pubnub_ssl_contextcb(CURL *curl, void *context, void *userdata)
{
	SSL_CTX *ssl_context = (SSL_CTX *)context;
	struct pubnub *p = (struct pubnub *)userdata;

	if (p->ssl_cacerts)
	{
		X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_context);
		int i;

		for (i = 0; i < sk_X509_INFO_num(p->ssl_cacerts); i++)
		{
			X509_INFO *cert_info = sk_X509_INFO_value(p->ssl_cacerts, i);
			if (cert_info->x509)
				X509_STORE_add_cert(cert_store, cert_info->x509);
			if (cert_info->crl)
				X509_STORE_add_crl(cert_store, cert_info->crl);
		}
	}

	return CURLE_OK;
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

	printbuf_memappend_fast(p->url, "?pnsdk=", 7);
	printbuf_memappend_fast(p->url, SDK_INFO, strlen(SDK_INFO));

	if (qparelems) {
		/* qparelemp elements are in pairs, e.g.
		 *   { "x", NULL, "UUID", "abc", "tt, "1", NULL }
		 * means ?x&UUID=abc&tt=1 */
		for (const char **qparelemp = qparelems; *qparelemp; qparelemp += 2) {
			printbuf_memappend_fast(p->url, "&", 1);
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
	curl_easy_setopt(p->curl, CURLOPT_SSL_CTX_FUNCTION, pubnub_ssl_contextcb);
	curl_easy_setopt(p->curl, CURLOPT_SSL_CTX_DATA, p);

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


/* Subscribe/resubscribe/unsubscribe flow is super-tricky because we
 * have some intermediate spliced-in calls here - join (subscribe with
 * timetoken "0") and leave.
 *
 * On subscribe, if channelset changes, we issue a join call with
 * a resubscribe callback that will re-issue subscribe and this time,
 * it really means subscribe. (Also, it will use the original time
 * token if we have any, not the one from the join call.)
 *
 * On unsubscribe, if channelset changes, we issue a leave call.
 * If a subscribe was ongoing, it is cancelled and if anything remains
 * in the channelset, we use a resubscribe callback that will re-issue
 * subscribe with the original callback.
 *
 * TODO: Allow subscribe/unsubscribe during join/leave, queuing
 * the changes up (new callback wins, previous callbacks gets
 * PNR_CANCELLED). */

struct pubnub_subscribe_cb_http_data {
	/* XXX: We peek here from unsubscribe as well! */
	char *channelset;
	pubnub_subscribe_cb cb;
	void *call_data;
	bool cb_internal;
};


static void pubnub_subscribe_internal(struct pubnub *p, long timeout,
		pubnub_subscribe_cb cb, void *cb_data, bool is_retry);

struct resubscribe_cb_http_data {
	pubnub_unsubscribe_cb unsub_cb;
	void *unsub_call_data;

	pubnub_subscribe_cb sub_cb;
	void *sub_call_data;
	long sub_timeout;
	char sub_time_token[64];
};

static void
resubscribe_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct resubscribe_cb_http_data *cb_http_data = (struct resubscribe_cb_http_data *)call_data;
	p->finished_cb = NULL;
	p->finished_cb_data = NULL;

	/* Restart the subscribe first (to be sure the unsub callback
	 * cannot disturb it). Do it even in case of failed leave()/join(). */
	if (p->resume_on_reconnect && strcmp(cb_http_data->sub_time_token, "0"))
		strcpy(p->time_token, cb_http_data->sub_time_token);
	pubnub_subscribe_internal(p, cb_http_data->sub_timeout,
			cb_http_data->sub_cb, cb_http_data->sub_call_data,
			true);

	/* Now, re-issue the unsubscribe callback. */
	/* No stop_wait here, another subscribe ongoing. */
	if (cb_http_data->unsub_cb)
		cb_http_data->unsub_cb(p, result, response, ctx_data, cb_http_data->unsub_call_data);

	free(cb_http_data);
}

static void
resubscribe_sub_http_cb(struct pubnub *p, enum pubnub_res result, char **channels, struct json_object *response, void *ctx_data, void *call_data)
{
	assert(!(channels != NULL && channels[0] != NULL));
	free(channels);
	resubscribe_http_cb(p, result, response, ctx_data, call_data);
}

static struct resubscribe_cb_http_data *
resubscribe_http_init(struct pubnub *p)
{
	struct resubscribe_cb_http_data *cb_http_data = (struct resubscribe_cb_http_data *)calloc(1, sizeof(*cb_http_data));

	struct pubnub_subscribe_cb_http_data *subcb_http_data = (struct pubnub_subscribe_cb_http_data *)p->finished_cb_data;
	if (subcb_http_data) {
		cb_http_data->sub_cb = subcb_http_data->cb;
		cb_http_data->sub_call_data = subcb_http_data->call_data;

		free(subcb_http_data->channelset);
		free(subcb_http_data);
		p->finished_cb = NULL;
		p->finished_cb_data = NULL;
	}
	cb_http_data->sub_timeout = p->timeout;
	strcpy(cb_http_data->sub_time_token, p->time_token);

	return cb_http_data;
}

static enum pubnub_res
check_subscribe_response(struct pubnub *p, struct json_object *response)
{
	/* Response must be an array, and its first element also an array. */
	if (!response || !json_object_is_type(response, json_type_array)) {
		return PNR_FORMAT_ERROR;
	}
	json_object *msg = json_object_array_get_idx(response, 0);
	if (!msg || !json_object_is_type(msg, json_type_array)) {
		return PNR_FORMAT_ERROR;
	}
	if (p->cipher_key) {
		/* Decrypt array elements, which must be strings. */
		struct json_object *msg_new = pubnub_decrypt_array(p->cipher_key, msg);
		if (!msg_new) {
			return PNR_FORMAT_ERROR;
		}
		/* Replacing msg in the response[] array will make sure
		 * the refcounting is correct; this drops old msg and
		 * will drop msg_new when we drop the whole response. */
		json_object_array_put_idx(response, 0, msg_new);
	}

	/* Extract and save time token (mandatory). */
	json_object *time_token = json_object_array_get_idx(response, 1);
	if (!time_token || !json_object_is_type(time_token, json_type_string)) {
		return PNR_FORMAT_ERROR;
	}
	strncpy(p->time_token, json_object_get_string(time_token), sizeof(p->time_token));
	p->time_token[sizeof(p->time_token) - 1] = 0;

	json_object *channelset_json = json_object_array_get_idx(response, 2);
	if (channelset_json && !json_object_is_type(channelset_json, json_type_string)) {
		return PNR_FORMAT_ERROR;
	}

	return PNR_OK;
}

static void
parse_channels(char *channelset, int msg_n, char **channels)
{
	/* Comma-split the channelset to channels[] array. */
	char *channelsetp = channelset;
#ifndef __MINGW32__
	char *channelsettok = NULL;
#endif
	for (int i = 0; i < msg_n; channelsetp = NULL, i++) {
#if defined __MINGW32__ || defined _MSC_VER
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
}

static void
pubnub_subscribe_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct pubnub_subscribe_cb_http_data *cb_http_data = (struct pubnub_subscribe_cb_http_data *)call_data;
	char *channelset = cb_http_data->channelset;
	bool cb_internal = cb_http_data->cb_internal;
	call_data = cb_http_data->call_data;
	pubnub_subscribe_cb cb = cb_http_data->cb;
	free(cb_http_data);
	p->finished_cb = NULL;
	p->finished_cb_data = NULL;

	enum pubnub_res res = (result != PNR_OK ? result : check_subscribe_response(p, response));
	struct json_object *msg;
	char **channels = NULL;
	if (res == PNR_OK) {
		msg = json_object_array_get_idx(response, 0);

		/* Extract and update channel name (not mandatory, present only
		 * when multiplexing). */
		json_object *channelset_json = json_object_array_get_idx(response, 2);
		int msg_n = json_object_array_length(msg);
		channels = (char**)malloc((msg_n + 1) * sizeof(channels[0]));
		if (channelset_json) {
			free(channelset);
			channelset = strdup(json_object_get_string(channelset_json));
			parse_channels(channelset, msg_n, channels);
		} else {
			for (int i = 0; i < msg_n; i++) {
				channels[i] = strdup(channelset);
			}
		}
		channels[msg_n] = NULL;

		if (!cb_internal)
			p->cb->stop_wait(p, p->cb_data);

	} else {
		msg = response;
		if (result == PNR_OK /* pubnub_handle_error() has not been already called */
			&& !pubnub_handle_error(p, res, response, "subscribe", false)) {
			cb = NULL;
		}
	}
	free(channelset);
	/* Finally call the user callback. */
	if (cb) {
		cb(p, res, channels, msg, ctx_data, call_data);
	}
}

/* This is the common backend for subscribe HTTP API calls. */
static void
pubnub_subscribe_do(struct pubnub *p, const char *channelset, char *time_token,
		long timeout, pubnub_subscribe_cb cb, void *cb_data, bool cb_internal,
		bool is_retry)
{
	struct pubnub_subscribe_cb_http_data *cb_http_data = (struct pubnub_subscribe_cb_http_data *)malloc(sizeof(*cb_http_data));
	cb_http_data->channelset = strdup(channelset);
	cb_http_data->cb = cb;
	cb_http_data->call_data = cb_data;
	cb_http_data->cb_internal = cb_internal;

	const char *urlelems[] = { "subscribe", p->subscribe_key, channelset, "0", time_token, NULL };
	const char *qparamelems[] = { "uuid", p->uuid, NULL };
	pubnub_http_setup(p, urlelems, qparamelems, timeout);
	pubnub_http_request(p, pubnub_subscribe_http_cb, cb_http_data, true, !is_retry);
}

static void
pubnub_join(struct pubnub *p, const char *channelset, long timeout,
		pubnub_subscribe_cb cb, void *cb_data)
{
	/* As this is an internal API, we don't bother with
	 * the full-fledged PNR_OCCUPIED check and assume
	 * there is internal callback. */
	assert(!p->method);
	p->method = "join";

	timeout /= 60;
	if (timeout <= 0)
		timeout = 5;

	pubnub_subscribe_do(p, channelset, (char*)"0", timeout, cb, cb_data, true, false);
}

static void
pubnub_subscribe_internal(struct pubnub *p, long timeout,
		pubnub_subscribe_cb cb, void *cb_data, bool is_retry)
{
	p->method = "subscribe";
	if (timeout < 0)
		timeout = 310;

	struct printbuf *channelset = channelset_printbuf(&p->channelset);
	pubnub_subscribe_do(p, channelset->buf, p->time_token, timeout, cb, cb_data, false, is_retry);
	printbuf_free(channelset);
}

PUBNUB_API
void
pubnub_subscribe(struct pubnub *p, const char *channel,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	/* Simply defer to _multi(). */
	if (channel) {
		pubnub_subscribe_multi(p, &channel, 1, timeout, cb, cb_data);
	} else {
		pubnub_subscribe_multi(p, NULL, 0, timeout, cb, cb_data);
	}
}

PUBNUB_API
void
pubnub_subscribe_multi(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->subscribe;

	if (p->method && strcmp(p->method, "subscribe")) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "subscribe", false),
				NULL, NULL, p->cb_data, cb_data);
		return;
	}

	const struct channelset cs = { SFINIT(.set,channels), SFINIT(.n, channels_n) };
	unsigned newchans = 0;
	if (channels != NULL)
		newchans = channelset_add(&p->channelset, &cs);

	if (p->channelset.set == NULL) {
		/* No channels to listen to. Straight cancel. */
		if (cb) cb(p, PNR_CANCELLED, NULL, NULL, p->cb_data, cb_data);
		return;
	}

	if (newchans > 0) {
		/* New channels. Issue a join(), that is subscribe with
		 * time token "0".  The callback will be resubscribe()
		 * which will call subscribe() again, typically with
		 * newchans==0 and we will proceed with a regular
		 * subscribe. */
		if (p->method) {
			/* Already ongoing subscribe - cancel that one now.
			 * Loud is ok, the new callback wins over the old. */
			pubnub_connection_cancel(p);
		}

		struct resubscribe_cb_http_data *cb_http_data = resubscribe_http_init(p);
		cb_http_data->sub_cb = cb;
		cb_http_data->sub_call_data = cb_data;
		cb_http_data->sub_timeout = timeout;

		cb = resubscribe_sub_http_cb;
		cb_data = cb_http_data;

		struct printbuf *channelset = channelset_printbuf(&cs);
		pubnub_join(p, channelset->buf, timeout, cb, cb_data);
		printbuf_free(channelset);

	} else {
		pubnub_subscribe_internal(p, timeout, cb, cb_data, false);
	}
}


PUBNUB_API
void
pubnub_reset_subscribe(struct pubnub *p, bool reset_timetoken)
{
	if (p->method && !strcmp(p->method, "subscribe")) {
		/* An ongoing subscribe, cancel. */
		pubnub_connection_cancel(p);
	}

	if (reset_timetoken) {
		/* Start fresh when subscribing again, ignoring any
		 * messages up to then. */
		strcpy(p->time_token, "0");
	}
}


static void
pubnub_leave(struct pubnub *p, const char *channelset, long timeout,
		pubnub_unsubscribe_cb cb, void *cb_data, bool cb_internal)
{
	/* As this is an internal API, we don't bother with
	 * the full-fledged PNR_OCCUPIED check. */
	assert(!p->method);
	p->method = "leave";

	if (timeout < 0)
		timeout = 5;

	const char *urlelems[] = { "v2", "presence", "sub-key", p->subscribe_key, "channel", channelset, "leave", NULL };
	const char *qparamelems[] = { "uuid", p->uuid, NULL };
	pubnub_http_setup(p, urlelems, qparamelems, timeout);
	pubnub_http_request(p, (pubnub_http_cb) cb, cb_data, cb_internal, true);
}

PUBNUB_API
void
pubnub_unsubscribe(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_unsubscribe_cb cb, void *cb_data)
{
	if (!cb) cb = p->cb->unsubscribe;

	if (p->method && strcmp(p->method, "subscribe")) {
		if (cb)
			cb(p, pubnub_error_report(p, PNR_OCCUPIED, NULL, "unsubscribe", false),
				NULL, p->cb_data, cb_data);
		return;
	}


	/* Edit the channelset. */
	const struct channelset cs = { SFINIT(.set, channels), SFINIT(.n, channels_n) };
	if (p->channelset.set) {
		if (channels != NULL) {
			channelset_rm(&p->channelset, &cs);
		} else {
			/* Unsubscribe from all channels. */
			channelset_done(&p->channelset);
		}
		if (p->channelset.set == NULL) {
			/* A fresh subscribe, restart fresh (we do not care about
			 * messages received while we were not subscribed anywhere). */
			strcpy(p->time_token, "0");
		}
	}

	bool cb_internal = false;
	/* If we have an ongoing subscribe... */
	if (p->method) {
		if (p->channelset.set) {
			/* ... we will want to resume it later! */
			struct resubscribe_cb_http_data *cb_http_data = resubscribe_http_init(p);
			cb_http_data->unsub_cb = cb;
			cb_http_data->unsub_call_data = cb_data;

			cb = resubscribe_http_cb;
			cb_data = cb_http_data;
			cb_internal = true;

			pubnub_connection_cleanup(p, false);
		} else {
			/* ... cancel it! */
			pubnub_connection_cancel(p);
		}
	}

	/* Next thing, we issue the leave() call. */
	struct printbuf *channelset = channelset_printbuf(&cs);
	pubnub_leave(p, channelset->buf, timeout, cb, cb_data, cb_internal);
	printbuf_free(channelset);
}


struct pubnub_history_http_cb {
	pubnub_history_cb cb;
	void *call_data;
};

static void
pubnub_history_http_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	struct pubnub_history_http_cb *cb_http_data = (struct pubnub_history_http_cb *)call_data;
	call_data = cb_http_data->call_data;
	pubnub_history_cb cb = cb_http_data->cb;
	free(cb_http_data);
	p->finished_cb = NULL;
	p->finished_cb_data = NULL;

	if (result != PNR_OK) {
		/* pubnub_handle_error() has been already called along
		 * the way to here. */
		if (cb) cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Response must be an array. */
	if (!response || !json_object_is_type(response, json_type_array)) {
		result = PNR_FORMAT_ERROR;
error:
		if (pubnub_handle_error(p, result, response, "history", false) && cb)
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
	if (cb) cb(p, result, response, ctx_data, call_data);

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

	struct pubnub_history_http_cb *cb_http_data = (struct pubnub_history_http_cb *)malloc(sizeof(*cb_http_data));
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
	struct pubnub_time_http_cb *cb_http_data = (struct pubnub_time_http_cb *)call_data;
	call_data = cb_http_data->call_data;
	pubnub_history_cb cb = cb_http_data->cb;
	free(cb_http_data);
	p->finished_cb = NULL;
	p->finished_cb_data = NULL;

	if (result != PNR_OK) {
		/* pubnub_handle_error() has been already called along
		 * the way to here. */
		if (cb) cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Response must be an array. */
	if (!response || !json_object_is_type(response, json_type_array)) {
		result = PNR_FORMAT_ERROR;
		if (pubnub_handle_error(p, result, response, "time", false) && cb)
			cb(p, result, response, ctx_data, call_data);
		return;
	}

	/* Extract the first element. */
	json_object *ts = json_object_array_get_idx(response, 0);
	json_object_get(ts);

	/* Finally call the user callback. */
	p->cb->stop_wait(p, p->cb_data);
	if (cb) cb(p, result, ts, ctx_data, call_data);

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

	struct pubnub_time_http_cb *cb_http_data = (struct pubnub_time_http_cb *)malloc(sizeof(*cb_http_data));
	cb_http_data->cb = cb;
	cb_http_data->call_data = cb_data;

	const char *urlelems[] = { "time", "0", NULL };
	pubnub_http_setup(p, urlelems, NULL, timeout);
	pubnub_http_request(p, pubnub_time_http_cb, cb_http_data, true, true);
}
