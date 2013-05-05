#ifndef PUBNUB_LIBPURPLE_H
#define PUBNUB_LIBPURPLE_H

#include <glib/gi18n.h>

#include <plugin.h>
#include <prpl.h>

#define DEFAULT_PUBLISH_KEY "demo"
#define OPTION_PUBLISH_KEY "pub_key"
#define DEFAULT_SUBSCRIBE_KEY "demo"
#define OPTION_SUBSCRIBE_KEY "sub_key"
#define DEFAULT_HISTORY_N 5
#define OPTION_HISTORY_N "history_n"
#define DEFAULT_ORIGIN_SERVER "http://pubsub.pubnub.com"
#define OPTION_ORIGIN_SERVER "origin_server"
#define DEFAULT_CIPHER_KEY ""
#define OPTION_CIPHER_KEY "cipher_key"
#define DEFAULT_SECRET_KEY ""
#define OPTION_SECRET_KEY "secret_key"

#include <pubnub.h>

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

	bool is_sub_active;
} PubnubConn;

typedef struct
{
	const char *channels[2];
	PubnubEvents *e;
	guint id;
	bool is_subscribed;
	PubnubConn *con;
} PubnubRoom;

#endif // PUBNUB_LIBPURPLE_H
