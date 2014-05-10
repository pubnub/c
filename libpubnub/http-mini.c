#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <json.h>
#include <printbuf.h>

#include "http.h"
#include "pubnub-priv.h"

/* This HTTP implementation is a pretty naive, minimal implementation
 * that does not support SSL or more fancy HTTP; it is meant for
 * embedded environments. */

struct pubnub_http {
	const char *originhost;
	struct addrinfo *ai, *aip;
	int fd;

	enum pubnub_state {
		PS_IDLE,
		PS_CONNECT,
		PS_HTTPREQUEST,
		PS_HTTPREPLY,
		PS_HTTPBODY,
		PS_PROCESS
	} state;
	int substate, code;
	char hdrbuf[256];
	int hdrbuf_len;
	int content_length;
};


static int
http_try_connect(struct pubnub_http *http)
{
	for (; http->aip; http->aip = http->aip->ai_next) {
		struct addrinfo *aip = http->aip;
		int sfd = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
		if (sfd == -1)
			continue;
		fcntl(sfd, F_SETFL, O_NONBLOCK);

		if (connect(sfd, aip->ai_addr, aip->ai_addrlen) != -1) {
			http->state = PS_HTTPREQUEST;
			return sfd;

		} else if (errno == EINPROGRESS) {
			http->state = PS_CONNECT;
			return sfd;
		}

		close(sfd);
	}
	return -1;
}

static void
http_update_sendrequest(struct pubnub *p)
{
	/* We just test write() < 0. If it is EAGAIN, we'll get called
	 * again. If it is another error, we'll also get called again,
	 * with an error flag. */

	if (p->http->substate <= 0) {
#define S "GET "
		if (write(p->http->fd, S, sizeof(S)-1) < 0)
			return;
#undef S
		p->http->substate++;
	}

	if (p->http->substate <= 1) {
		/* Remove the host part. */
		int skiplen = strlen(p->origin);
		if (write(p->http->fd, p->url->buf + skiplen, p->url->bpos-1 - skiplen) < 0)
			return;
		p->http->substate++;
	}

	if (p->http->substate <= 2) {
#define S " HTTP/1.1\r\nHost: "
		if (write(p->http->fd, S, sizeof(S)-1) < 0)
			return;
#undef S
		p->http->substate++;
	}

	if (p->http->substate <= 3) {
		int namelen = strlen(p->http->originhost);
		if (write(p->http->fd, p->http->originhost, namelen) < 0)
			return;
		p->http->substate++;
	}

	if (p->http->substate <= 4) {
#define S "\r\nUser-Agent: c-mini/0.2\r\nConnection: Keep-Alive\r\n\r\n"
		if (write(p->http->fd, S, sizeof(S)-1) < 0)
			return;
#undef S
		p->http->state = PS_HTTPREPLY;
		p->http->substate = 0;
	}
}

static void
http_update_recvhdr(struct pubnub *p, char *hdrline, char *newline)
{
	if (newline - hdrline == 0) {
		/* Empty line handling. */
		switch (p->http->substate) {
		case 0:
			p->cb->rem_socket(p, p->cb_data, p->http->fd);
			pubnub_connection_finished(p, PNR_IO_ERROR, "Empty initial HTTP reply line.", 599);
			break;
		case 1: /* Content follows. */
			p->http->substate = 4;
			break;
		case 2: /* Chunked encoding, another line
			 * with content length follows. */
			p->http->substate = 3;
			break;
		case 3:
			p->cb->rem_socket(p, p->cb_data, p->http->fd);
			pubnub_connection_finished(p, PNR_IO_ERROR, "Missing HTTP chunk delimiter.", 599);
			break;
		}

	} else if (p->http->substate == 0) {
		/* An HTTP status line. */
		if (strncmp(hdrline, "HTTP/1.", 7) || !hdrline[7] || !hdrline[8]) {
			p->cb->rem_socket(p, p->cb_data, p->http->fd);
			pubnub_connection_finished(p, PNR_IO_ERROR, "Unsupported HTTP version.", 599);
			return;
		}
		p->http->code = atoi(hdrline+9);
		/* We do not panic in case of non-200 code; instead,
		 * calmly load the response. */
		p->http->substate = 1;

	} else if (p->http->substate < 3) {
		/* An HTTP header line. */
		char h_chunked[] = "Transfer-Encoding: chunked";
		char h_length[] = "Content-Length: ";
		if (!strncmp(hdrline, h_chunked, sizeof(h_chunked)-1)) {
			p->http->substate = 2;

		} else if (!strncmp(hdrline, h_length, sizeof(h_length)-1)) {
			p->http->content_length = atoi(hdrline + sizeof(h_length)-1);
		}

	} else if (p->http->substate == 3) {
		/* A chunk size line. */
		p->http->content_length = strtoul(hdrline, NULL, 16);
		p->http->substate = 4;
	}

	if (p->http->substate == 4) {
		p->http->state = PS_HTTPBODY;
	}
}

static void
http_update_recvreply(struct pubnub *p)
{
	/* http->substate:
	 * 0 first line (status code etc.)
	 * 1 plain header
	 * 2 plain header, chunked encoding detected
	 * 3 chunk size line
	 * 4 body follows now (transient) */
	while (p->http->state == PS_HTTPREPLY) {
		if (p->http->hdrbuf_len >= sizeof(p->http->hdrbuf)-1) {
			/* Our buffer is already full and we did not extract a line.
			 * Normally, hitting a long line in the HTTP header should
			 * not happen, let's just flush the buffer. */
			p->http->hdrbuf_len = 0;
		}

		int gotlen = read(p->http->fd,
				p->http->hdrbuf + p->http->hdrbuf_len,
				sizeof(p->http->hdrbuf) - p->http->hdrbuf_len - 1);
		if (gotlen < 0) {
			/* EAGAIN or other error, no matter. */
			return;
		} else if (gotlen == 0) {
			/* Premature EOF! */
			p->cb->rem_socket(p, p->cb_data, p->http->fd);
			pubnub_connection_finished(p, PNR_IO_ERROR, "Premature end of HTTP headers.", 599);
			return;
		}

		p->http->hdrbuf_len += gotlen;
		p->http->hdrbuf[p->http->hdrbuf_len] = 0;

		char *bufptr = p->http->hdrbuf;
		char *newline;
		while (p->http->state == PS_HTTPREPLY && (newline = strstr(bufptr, "\r\n"))) {
			*newline = 0;

			http_update_recvhdr(p, bufptr, newline);

			p->http->hdrbuf_len -= (newline+2 - bufptr);
			bufptr = newline+2;
		}
		memmove(p->http->hdrbuf, bufptr, p->http->hdrbuf_len + 1);
	}
}

static void
http_update_recvbody(struct pubnub *p)
{
	if (!p->body->bpos) {
		/* First data! */
		printbuf_memappend_fast(p->body, p->http->hdrbuf, p->http->hdrbuf_len);
	}
	if (p->http->content_length == 0) {
		p->http->state = PS_PROCESS;
		return;
	}

	while (p->body->bpos < p->http->content_length) {
		char buf[256];

		int gotlen = read(p->http->fd, buf, sizeof(buf));
		if (gotlen < 0) {
			return;
		} else if (gotlen == 0) {
			/* Premature EOF! */
			p->cb->rem_socket(p, p->cb_data, p->http->fd);
			pubnub_connection_finished(p, PNR_IO_ERROR, "Premature end of HTTP body.", 599);
			return;
		}

		printbuf_memappend_fast(p->body, buf, gotlen);
	}

	p->http->state = PS_PROCESS;
}


/* Socket callback for pubnub_callbacks event notification. */
static void
http_sockcb(struct pubnub *p, int fd, int mode, void *cb_data)
{
	if (mode & 4) {
		/* Error. */
		int s_errno = errno;
		p->cb->rem_socket(p, p->cb_data, fd);

		if (p->http->state == PS_CONNECT) {
			/* Try to jump to the next socket in case of
			 * an error during connect itself. */
			p->http->fd = http_try_connect(p->http);
			if (p->http->fd >= 0) {
				p->cb->add_socket(p, p->cb_data, p->http->fd, 2/*w*/, http_sockcb, p);
				return;
			}
		}

		pubnub_connection_finished(p, PNR_IO_ERROR, strerror(s_errno), 599);
		return;
	}

	if (p->http->state == PS_CONNECT) {
		p->http->state = PS_HTTPREQUEST;
	}

	if (p->http->state == PS_HTTPREQUEST) {
		http_update_sendrequest(p);
		if (p->http->state == PS_HTTPREPLY) {
			/* State transition requires switching from write
			 * to read polling. */
			p->cb->rem_socket(p, p->cb_data, fd);
			p->cb->add_socket(p, p->cb_data, p->http->fd, 1/*r*/, http_sockcb, p);
			return;
		}
	}

	if (p->http->state == PS_HTTPREPLY) {
		http_update_recvreply(p);
	}

	if (p->http->state == PS_HTTPBODY) {
		http_update_recvbody(p);
	}

	if (p->http->state == PS_PROCESS) {
		pubnub_connection_finished(p, PNR_OK, NULL, p->http->code);
	}
}

static void
http_timeoutcb(struct pubnub *p, void *cb_data)
{
	p->cb->rem_socket(p, p->cb_data, p->http->fd);
	pubnub_connection_finished(p, PNR_TIMEOUT, NULL, 599);
}


struct pubnub_http *
http_init(struct pubnub *p)
{
	struct pubnub_http *http = (struct pubnub_http *) calloc(1, sizeof(*http));

	return http;
}

void
http_done(struct pubnub_http *http)
{
	http_cleanup(http);
	free(http);
}


void
http_request(struct pubnub *p, bool wait)
{
	assert(p->http->state == PS_IDLE);

	/* Setup originhost. */
	if (!strncmp(p->origin, "http://", 7)) {
		p->http->originhost = p->origin + 7;

	} else if (!strncmp(p->origin, "https://", 8)) {
		pubnub_connection_finished(p, PNR_IO_ERROR, "SSL not supported in http-mini", 599);
		return;
	} else {
		pubnub_connection_finished(p, PNR_IO_ERROR, "Origin does not start with http://", 599);
		return;
	}

	/* Resolve originhost. */
	int s = getaddrinfo(p->http->originhost, "80", NULL, &p->http->ai);
	if (s != 0) {
		pubnub_connection_finished(p, PNR_IO_ERROR, gai_strerror(s), 599);
		return;
	}
	p->http->aip = p->http->ai;

	/* Start the connection flow. */
	p->http->fd = http_try_connect(p->http);
	if (p->http->fd < 0) {
		/* Immediate fail. */
		pubnub_connection_finished(p, PNR_IO_ERROR, strerror(errno), 599);
		return;
	}

	/* Ok, work is ongoing. */
	
	/* Set up timeout. */
	struct timespec timeout_ts;
	timeout_ts.tv_sec = p->timeout;
	timeout_ts.tv_nsec = 0;
	p->cb->timeout(p, p->cb_data, &timeout_ts, http_timeoutcb, p);

	/* Poll the socket. */
	p->cb->add_socket(p, p->cb_data, p->http->fd, 2/*w*/, http_sockcb, p);

	DBGMSG("wait: pre\n");
	/* Call wait() only if this is not an error retry; wait
	 * and stop_wait should be paired 1:1 and we did not
	 * call stop_wait either. */
	if (wait)
		p->cb->wait(p, p->cb_data);
	DBGMSG("wait: post\n");
}

void
http_cleanup(struct pubnub_http *http)
{
	freeaddrinfo(http->ai);
	http->ai = NULL;
	http->aip = NULL;

	http->state = PS_IDLE;
	http->substate = 0;
	http->code = 0;
	http->hdrbuf_len = 0;
	http->content_length = 0;
}


void
http_printbuf_urlappend(struct pubnub_http *http, struct printbuf *url, const char *urlelem)
{
	const char *pmessage = urlelem;
	while (pmessage[0]) {
		/* RFC 3986 Unreserved characters plus few
		 * safe reserved ones. */
		size_t okspan = strspn(pmessage, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.");
		if (okspan > 0) {
			printbuf_memappend_fast(url, pmessage, okspan);
			pmessage += okspan;
		}
		if (pmessage[0]) {
			/* %-encode a non-ok character. */
			char enc[4] = {'%'};
			enc[1] = "0123456789ABCDEF"[pmessage[0] / 16];
			enc[2] = "0123456789ABCDEF"[pmessage[0] % 16];
			printbuf_memappend_fast(url, enc, 3);
			pmessage++;
		}
	}
}
