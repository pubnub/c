#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>
#include <openssl/ssl.h>


#include "pubnub-http-libcurl.h"
#include "pubnub-priv.h"


/** Data structures. */

struct pubnub_http_libcurl {
	struct pubnub *p;
	CURL *curl;
	CURLM *curlm;
	struct curl_slist *curl_headers;
	char curl_error[CURL_ERROR_SIZE];
	struct stack_st_X509_INFO *ssl_cacerts;
};

/** libcurl callbacks */

static void
pubnub_http_libcurl_connection_finished(struct pubnub_http_libcurl *c, CURLcode res, bool stop_wait)
{
	DBGMSG("DONE: (%d) %s\n", res, c->curl_error);

	/* pubnub_connection_cleanup() will clobber p->method */
	const char *method = c->p->method;

	/* Check against I/O errors */
	if (res != CURLE_OK) {
		if (res == CURLE_OPERATION_TIMEDOUT) {
			pubnub_handle_error_cb(c->p, PNR_TIMEOUT, NULL, 0, false, stop_wait);
		} else {
			pubnub_handle_error_cb(c->p, PNR_IO_ERROR, curl_easy_strerror(res), 0, false, stop_wait);
		}
		return;
	}

	/* Check HTTP code */
	long code = 599;
	curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &code);
	/* At this point, we can tear down the connection. */
	pubnub_connection_cleanup(c->p, stop_wait);
	if (code / 100 != 2) {
		pubnub_handle_error_cb(c->p, PNR_HTTP_ERROR, NULL, code, true, stop_wait);
		return;
	}
	pubnub_connection_finished(c->p, method);
}

/* Let curl take care of the ongoing connections, then check for new events
 * and handle them (call the user callbacks etc.).  If stop_wait == true,
 * we have already called cb->wait and need to call cb->stop_wait if the
 * connection is over. Returns true if the connection has finished, otherwise
 * it is still running. */
static bool
pubnub_connection_check(struct pubnub_http_libcurl *c, int fd, int bitmask, bool stop_wait)
{
	int running_handles = 0;
	CURLMcode rc = curl_multi_socket_action(c->curlm, fd, bitmask, &running_handles);
	DBGMSG("event_sockcb fd %d bitmask %d rc %d rh %d\n", fd, bitmask, rc, running_handles);
	if (rc != CURLM_OK) {
		pubnub_handle_error_cb(c->p, PNR_IO_ERROR, curl_multi_strerror(rc), 0, false, stop_wait);
		return true;
	}

	CURLMsg *msg;
	int msgs_left;
	bool done = false;

	while ((msg = curl_multi_info_read(c->curlm, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Done! */
		pubnub_http_libcurl_connection_finished(c, msg->data.result, stop_wait);
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

	pubnub_connection_check((struct pubnub_http_libcurl*)p->http_data, fd, ev_bitmask, true);
}

static void
pubnub_event_timeoutcb(struct pubnub *p, void *cb_data)
{
	pubnub_connection_check((struct pubnub_http_libcurl*)p->http_data, CURL_SOCKET_TIMEOUT, 0, true);
}

/* Socket callback for libcurl setting up / tearing down watches. */
static int
pubnub_http_sockcb(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)userp;
	struct pubnub *p = c->p;

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
		curl_multi_assign(c->curlm, s, /* anything not NULL */ easy);
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

void *
pubnub_http_libcurl_init(void *ctx_data, struct pubnub *p, void *extra)
{
	struct pubnub_http_libcurl *r;
	if (ctx_data) {
		r = (struct pubnub_http_libcurl *)ctx_data;
	} else {
		r = (struct pubnub_http_libcurl *)calloc(1, sizeof(*r));
		r->curlm = curl_multi_init();
		curl_multi_setopt(r->curlm, CURLMOPT_SOCKETFUNCTION, pubnub_http_sockcb);
		curl_multi_setopt(r->curlm, CURLMOPT_SOCKETDATA, r);
		curl_multi_setopt(r->curlm, CURLMOPT_TIMERFUNCTION, pubnub_http_timercb);
		curl_multi_setopt(r->curlm, CURLMOPT_TIMERDATA, p);

		r->curl_headers = curl_slist_append(r->curl_headers, "User-Agent: c-generic/0");
		r->curl_headers = curl_slist_append(r->curl_headers, "V: 3.4");
	}
	r->p = p;
	return r;
}

void
pubnub_http_libcurl_cleanup(void *ctx_data)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	if (c->curl) {
		curl_multi_remove_handle(c->curlm, c->curl);
		curl_easy_cleanup(c->curl);
		c->curl = NULL;
	}
}

void
pubnub_http_libcurl_check(void *ctx_data)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
}

char *
pubnub_http_libcurl_escape(void *ctx_data, const char *str, int n)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	return curl_easy_escape(c->curl, str, n);
}

void
pubnub_http_libcurl_escape_free(void *ctx_data, char *str)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	curl_free(str);
}

static CURLcode
pubnub_ssl_contextcb(CURL *curl, void *context, void *userdata)
{
	SSL_CTX *ssl_context = (SSL_CTX *)context;
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)userdata;

	if (c->ssl_cacerts) {
		X509_STORE *cert_store = SSL_CTX_get_cert_store(ssl_context);
		int i;

		for (i = 0; i < sk_X509_INFO_num(c->ssl_cacerts); i++) {
			X509_INFO *cert_info = sk_X509_INFO_value(c->ssl_cacerts, i);
			if (cert_info->x509)
				X509_STORE_add_cert(cert_store, cert_info->x509);
			if (cert_info->crl)
				X509_STORE_add_crl(cert_store, cert_info->crl);
		}
	}

	return CURLE_OK;
}

static void
pubnub_free_ssl_cacerts(struct pubnub_http_libcurl *c)
{
	if (c->ssl_cacerts) {
		sk_X509_INFO_pop_free(c->ssl_cacerts, X509_INFO_free);
		c->ssl_cacerts = NULL;
	}
}

void
pubnub_http_libcurl_set_ssl_cacerts(void *ctx_data, const char *cacerts, size_t len)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	BIO *bio;

	pubnub_free_ssl_cacerts(c);

	bio = BIO_new_mem_buf((char *)cacerts, len);
	c->ssl_cacerts = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	BIO_free(bio);
}

bool
pubnub_http_libcurl_request(void *ctx_data, char *url)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	c->curl = curl_easy_init();

	curl_easy_setopt(c->curl, CURLOPT_URL, url);
	curl_easy_setopt(c->curl, CURLOPT_HTTPHEADER, c->curl_headers);
	curl_easy_setopt(c->curl, CURLOPT_WRITEFUNCTION, pubnub_http_inputcb);
	curl_easy_setopt(c->curl, CURLOPT_WRITEDATA, c->p);
	curl_easy_setopt(c->curl, CURLOPT_VERBOSE, VERBOSE_VAL);
	curl_easy_setopt(c->curl, CURLOPT_ERRORBUFFER, c->curl_error);
	curl_easy_setopt(c->curl, CURLOPT_PRIVATE, c);
	curl_easy_setopt(c->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(c->curl, CURLOPT_NOSIGNAL, (long) c->p->nosignal);
	curl_easy_setopt(c->curl, CURLOPT_TIMEOUT, c->p->timeout);
	curl_easy_setopt(c->curl, CURLOPT_SSL_CTX_FUNCTION, pubnub_ssl_contextcb);
	curl_easy_setopt(c->curl, CURLOPT_SSL_CTX_DATA, c);

	DBGMSG("add handle: pre\n");
	curl_multi_add_handle(c->curlm, c->curl);
	DBGMSG("add handle: post\n");

	return !pubnub_connection_check(c, CURL_SOCKET_TIMEOUT, 0, false);
}

void
pubnub_http_libcurl_done(void *ctx_data)
{
	struct pubnub_http_libcurl *c = (struct pubnub_http_libcurl *)ctx_data;
	assert(!c->curl);

	curl_multi_cleanup(c->curlm);
	curl_slist_free_all(c->curl_headers);
	pubnub_free_ssl_cacerts(c);

	free(ctx_data);
}

/** Callback table */

PUBNUB_API
const struct pubnub_http_callbacks pubnub_http_libcurl_callbacks = {
	SFINIT(.init, pubnub_http_libcurl_init),
	SFINIT(.cleanup, pubnub_http_libcurl_cleanup),
	SFINIT(.set_ssl_cacerts, pubnub_http_libcurl_set_ssl_cacerts),
	SFINIT(.escape, pubnub_http_libcurl_escape),
	SFINIT(.escape_free, pubnub_http_libcurl_escape_free),
	SFINIT(.request, pubnub_http_libcurl_request),
	SFINIT(.done, pubnub_http_libcurl_done),
};
