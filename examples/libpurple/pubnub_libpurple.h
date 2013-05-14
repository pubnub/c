#ifndef PUBNUB_LIBPURPLE_H
#define PUBNUB_LIBPURPLE_H

#include <glib.h>

#include <libpurple/plugin.h>
#include <libpurple/prpl.h>

#ifdef ADIUM
#include <libpurple/internal.h>
#else
#include <glib/gi18n.h>
#endif

#include "pubnub_options.h"
#include "pubnub.h"

#define PLUGIN_ID "prpl-avy-pubnub"
#define PLUGIN_AUTHOR "Alexey Yesipenko <alex7y@gmail.com>"

typedef struct
{
	struct pubnub *pn;
	void (*socket_cb) (struct pubnub * p, int fd, int mode, void *cb_data);
	void *socket_cb_data;
	gint input;
	gint timeout_timer;
	void (*timeout_cb) (struct pubnub * p, void *cb_data);
	void *timeout_cb_data;
} PubnubEvents;

extern PubnubEvents *pubnub_events_new(PurpleAccount * account,
				       const char *uuid);
extern void pubnub_events_free(PubnubEvents * e);

typedef struct
{
	PurpleAccount *account;
	PurpleConnection *gc;

	PubnubEvents *e;
	PubnubEvents *private_e;

	GList *rooms;

	gboolean is_sub_active;
} PubnubConn;

typedef struct
{
	const char *channels[2];
	PubnubEvents *e;
	guint id;
	gboolean is_subscribed;
	PubnubConn *con;
} PubnubRoom;

#endif // PUBNUB_LIBPURPLE_H
