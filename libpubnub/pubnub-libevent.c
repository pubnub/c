#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/event.h>

#include "pubnub.h"
#include "pubnub-libevent.h"
#include "pubnub-priv.h"


/** Data structures. */

struct pubnub_cb_info {
	void (*cb)(struct pubnub *p, int fd, int mode, void *cb_data);
	void *cb_data;
};

struct pubnub_libevent {
	int n;
	int *fdset;
	struct event **evset;
	struct pubnub_cb_info *cbset;

	struct event *timer_event;
	void (*timer_cb)(struct pubnub *p, void *cb_data);
	void *timer_cb_data;

	struct pubnub *p;
};


/** libevent callbacks */

static void
pubnub_libevent_timercb(int fd, short kind, void *userp)
{
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)userp;
	libevent->timer_cb(libevent->p, libevent->timer_cb_data);
}

static void
pubnub_libevent_eventcb(int fd, short kind, void *userp)
{
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)userp;
	int mode = (kind & EV_READ ? 1 : 0) | (kind & EV_WRITE ? 2 : 0);

	int i;
	for (i = 0; i < libevent->n; i++)
		if (libevent->fdset[i] == fd)
			break;

	if (i < libevent->n) {
		libevent->cbset[i].cb(libevent->p, fd, mode, libevent->cbset[i].cb_data);
	} else {
		DBGMSG("eventcb with unknown fd %d\n", fd);
	}
}


/** Public API */

PUBNUB_API
struct pubnub_libevent *
pubnub_libevent_init(void)
{
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)calloc(1, sizeof(*libevent));
	evtimer_set(libevent->timer_event, pubnub_libevent_timercb, libevent);
	return libevent;
}


/** Event callbacks */

void
pubnub_libevent_add_socket(struct pubnub *p, void *ctx_data, int fd, int mode,
		void (*cb)(struct pubnub *p, int fd, int mode, void *cb_data), void *cb_data)
{
	DBGMSG("+ socket %d\n", fd);

	struct pubnub_libevent *libevent = (struct pubnub_libevent *)ctx_data;
	libevent->p = p;

	int i = libevent->n++;

	libevent->fdset = (int*)realloc(libevent->fdset, sizeof(*libevent->fdset) * libevent->n);
	libevent->fdset[i] = fd;

	libevent->cbset = (struct pubnub_cb_info*)realloc(libevent->cbset, sizeof(*libevent->cbset) * libevent->n);
	libevent->cbset[i].cb = cb;
	libevent->cbset[i].cb_data = cb_data;

	libevent->evset = (struct event **)realloc(libevent->evset, sizeof(*libevent->evset) * libevent->n);
	int kind = (mode & 1 ? EV_READ : 0) | (mode & 2 ? EV_WRITE : 0) | EV_PERSIST;
	libevent->evset[i] = event_new(NULL, fd, kind, pubnub_libevent_eventcb, libevent);
	event_add(libevent->evset[i], NULL);

	DBGMSG("watching %d sockets\n", libevent->n);
}

void
pubnub_libevent_rem_socket(struct pubnub *p, void *ctx_data, int fd)
{
	DBGMSG("- socket %d\n", fd);
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)ctx_data;

	for (int i = 0; i < libevent->n; i++) {
		if (libevent->fdset[i] != fd)
			continue;
		event_del(libevent->evset[i]);
		event_free(libevent->evset[i]);
		memmove(&libevent->fdset[i], &libevent->fdset[i + 1], (libevent->n - i - 1) * sizeof(*libevent->fdset));
		memmove(&libevent->cbset[i], &libevent->cbset[i + 1], (libevent->n - i - 1) * sizeof(*libevent->cbset));
		memmove(libevent->evset + i, libevent->evset + i + 1, (libevent->n - i - 1) * sizeof(*libevent->evset));
		libevent->n--;
		return;
	}
	DBGMSG("! did not find socket %d\n", fd);
}

void
pubnub_libevent_timeout(struct pubnub *p, void *ctx_data, const struct timespec *ts,
		void (*cb)(struct pubnub *p, void *cb_data), void *cb_data)
{
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)ctx_data;
	if (evtimer_pending(libevent->timer_event, NULL))
		evtimer_del(libevent->timer_event);

	libevent->p = p;

	libevent->timer_cb = cb;
	libevent->timer_cb_data = cb_data;

	if (libevent->timer_cb) {
		struct timeval timeout = { SFINIT(.tv_sec, ts->tv_sec), SFINIT(.tv_usec, ts->tv_nsec / 1000) };
		evtimer_add(libevent->timer_event, &timeout);
	}
}

void
pubnub_libevent_wait(struct pubnub *p, void *ctx_data)
{
	/* nop, just return to caller immediately, we don't block */
}

void
pubnub_libevent_stop_wait(struct pubnub *p, void *ctx_data)
{
	/* cancel timer, all other events should be already cancelled */
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)ctx_data;
	if (libevent->n > 0)
		DBGMSG("warning: stop_wait with %d sockets still registered\n", libevent->n);
	if (evtimer_pending(libevent->timer_event, NULL))
		evtimer_del(libevent->timer_event);
}

void
pubnub_libevent_done(struct pubnub *p, void *ctx_data)
{
	struct pubnub_libevent *libevent = (struct pubnub_libevent *)ctx_data;

	for (int i = 0; i < libevent->n; i++) {
		event_del(libevent->evset[i]);
		event_free(libevent->evset[i]);
	}
	evtimer_del(libevent->timer_event);
	event_free(libevent->timer_event);

	if (libevent->fdset) free(libevent->fdset);
	if (libevent->evset) free(libevent->evset);
	if (libevent->cbset) free(libevent->cbset);
	free(libevent);
}


/** Callback table */

PUBNUB_API
const struct pubnub_callbacks pubnub_libevent_callbacks = {
	SFINIT(.add_socket, pubnub_libevent_add_socket),
	SFINIT(.rem_socket, pubnub_libevent_rem_socket),
	SFINIT(.timeout, pubnub_libevent_timeout),
	SFINIT(.wait, pubnub_libevent_wait),
	SFINIT(.stop_wait, pubnub_libevent_stop_wait),
	SFINIT(.done, pubnub_libevent_done),
};
