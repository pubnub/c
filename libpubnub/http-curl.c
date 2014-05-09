#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <json.h>
#include <printbuf.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

#include "http-curl.h"
#include "pubnub-priv.h"

/* TODO: Use curl shares. */

/* See the beginning of pubnub.c for a whole-picture control flow diagram
 * of how the individual functions below are dispatched. */


static void
pubnub_connection_finished(struct pubnub *p, CURLcode res)
{
	DBGMSG("DONE: (%d) %s\n", res, p->http->curl_error);

	/* pubnub_connection_cleanup() will clobber p->method */
	const char *method = p->method;

	/* Check against I/O errors */
	if (res != CURLE_OK) {
		pubnub_connection_cleanup(p);
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
	curl_easy_getinfo(p->http->curl, CURLINFO_RESPONSE_CODE, &code);
	/* At this point, we can tear down the connection. */
	pubnub_connection_cleanup(p);
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
		p->finished_cb(p, PNR_OK, response, p->cb_data, p->finished_cb_data);
	json_object_put(response);
}

/* Let curl take care of the ongoing connections, then check for new events
 * and handle them (call the user callbacks etc.). Returns true if the
 * connection has finished, otherwise it is still running. */
static bool
pubnub_connection_check(struct pubnub *p, int fd, int bitmask)
{
	int running_handles = 0;
	DBGMSG("event_sockcb fd %d bitmask %d rh %d...\n", fd, bitmask, running_handles);
	CURLMcode rc = curl_multi_socket_action(p->http->curlm, fd, bitmask, &running_handles);
	DBGMSG("event_sockcb ...rc %d\n", rc);
	if (rc != CURLM_OK) {
		const char *method = p->method;
		pubnub_connection_cleanup(p);
		json_object *msgstr = json_object_new_string(curl_multi_strerror(rc));
		pubnub_handle_error(p, PNR_IO_ERROR, msgstr, method, true);
		json_object_put(msgstr);
		return true;
	}

	CURLMsg *msg;
	int msgs_left;
	bool done = false;

	while ((msg = curl_multi_info_read(p->http->curlm, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Done! */
		pubnub_connection_finished(p, msg->data.result);
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

	pubnub_connection_check(p, fd, ev_bitmask);
}

static void
pubnub_event_timeoutcb(struct pubnub *p, void *cb_data)
{
	pubnub_connection_check(p, CURL_SOCKET_TIMEOUT, 0);
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
		curl_multi_assign(p->http->curlm, s, /* anything not NULL */ easy);
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


struct pubnub_http *
http_init(struct pubnub *p)
{
	struct pubnub_http *http = (struct pubnub_http *) calloc(1, sizeof(*http));

	http->curlm = curl_multi_init();
	curl_multi_setopt(http->curlm, CURLMOPT_SOCKETFUNCTION, pubnub_http_sockcb);
	curl_multi_setopt(http->curlm, CURLMOPT_SOCKETDATA, p);
	curl_multi_setopt(http->curlm, CURLMOPT_TIMERFUNCTION, pubnub_http_timercb);
	curl_multi_setopt(http->curlm, CURLMOPT_TIMERDATA, p);

	http->curl_headers = curl_slist_append(http->curl_headers, "User-Agent: c-generic/0");
	http->curl_headers = curl_slist_append(http->curl_headers, "V: 3.4");

	return http;
}

void
http_done(struct pubnub_http *http)
{
	assert(!http->curl);
	curl_multi_cleanup(http->curlm);
	curl_slist_free_all(http->curl_headers);

	free(http);
}


void
http_cleanup(struct pubnub_http *http)
{
	if (http->curl) {
		curl_multi_remove_handle(http->curlm, http->curl);
		curl_easy_cleanup(http->curl);
		http->curl = NULL;
	}
}


void
http_printbuf_urlappend(struct pubnub_http *http, struct printbuf *url, const char *urlelem)
{
	char *urlenc = curl_easy_escape(http->curl, urlelem, strlen(urlelem));
	printbuf_memappend_fast(url, urlenc, strlen(urlenc));
	curl_free(urlenc);
}

void
pubnub_http_request(struct pubnub *p, pubnub_http_cb cb, void *cb_data, bool cb_internal, bool wait)
{
	p->http->curl = curl_easy_init();

	curl_easy_setopt(p->http->curl, CURLOPT_URL, p->url->buf);
	curl_easy_setopt(p->http->curl, CURLOPT_HTTPHEADER, p->http->curl_headers);
	curl_easy_setopt(p->http->curl, CURLOPT_WRITEFUNCTION, pubnub_http_inputcb);
	curl_easy_setopt(p->http->curl, CURLOPT_WRITEDATA, p);
	curl_easy_setopt(p->http->curl, CURLOPT_VERBOSE, VERBOSE_VAL);
	curl_easy_setopt(p->http->curl, CURLOPT_ERRORBUFFER, p->http->curl_error);
	curl_easy_setopt(p->http->curl, CURLOPT_PRIVATE, p);
	curl_easy_setopt(p->http->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(p->http->curl, CURLOPT_NOSIGNAL, (long) p->nosignal);
	curl_easy_setopt(p->http->curl, CURLOPT_TIMEOUT, p->timeout);
	curl_easy_setopt(p->http->curl, CURLOPT_SSL_CTX_FUNCTION, pubnub_ssl_contextcb);
	curl_easy_setopt(p->http->curl, CURLOPT_SSL_CTX_DATA, p);

	printbuf_reset(p->body);
	p->finished_cb = cb;
	p->finished_cb_data = cb_data;
	p->finished_cb_internal = cb_internal;

	DBGMSG("add handle: pre\n");
	curl_multi_add_handle(p->http->curlm, p->http->curl);
	DBGMSG("add handle: post\n");

	if (!pubnub_connection_check(p, CURL_SOCKET_TIMEOUT, 0)) {
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
