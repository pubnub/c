
#include "pubnub_libpurple.h"

static void
socket_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PubnubEvents *d = data;
	d->socket_cb(d->pn, source, cond, d->socket_cb_data);
}

void
pubnub_events_add_socket(G_GNUC_UNUSED struct pubnub *p, void *ctx_data, int fd,
			 int mode, void (*cb) (struct pubnub * p, int fd,
					       int mode, void *cb_data),
			 void *cb_data)
{
	PubnubEvents *d = ctx_data;
	d->socket_cb = cb;
	d->socket_cb_data = cb_data;
	d->input = purple_input_add(fd, mode, socket_cb, d);
}

void
pubnub_events_rem_socket(G_GNUC_UNUSED struct pubnub *p, void *ctx_data,
			 G_GNUC_UNUSED int fd)
{
	PubnubEvents *d = ctx_data;
	purple_input_remove(d->input);
}

static gboolean
timeout_cb(gpointer data)
{
	PubnubEvents *d = data;
	purple_timeout_remove(d->timeout_timer);
	d->timeout_timer = 0;
	d->timeout_cb(d->pn, d->timeout_cb_data);
	return TRUE;
}

void
pubnub_events_timeout(G_GNUC_UNUSED struct pubnub *p, void *ctx_data,
		      const struct timespec *ts, void (*cb) (struct pubnub * p,
							     void *cb_data),
		      void *cb_data)
{
	PubnubEvents *d = ctx_data;
	if (d->timeout_timer) {
		purple_timeout_remove(d->timeout_timer);
		d->timeout_timer = 0;
	}
	d->timeout_cb = cb;
	d->timeout_cb_data = cb_data;
	gint msecs = ts->tv_sec * 1000 + ts->tv_nsec / 1000000;
	if (msecs && cb) {
		d->timeout_timer = purple_timeout_add(msecs, timeout_cb, d);
	}
}

void
pubnub_events_wait(G_GNUC_UNUSED struct pubnub *p, G_GNUC_UNUSED void *ctx_data)
{
}

void
pubnub_events_stop_wait(G_GNUC_UNUSED struct pubnub *p, void *ctx_data)
{
	PubnubEvents *d = ctx_data;
	if (d->timeout_timer) {
		purple_timeout_remove(d->timeout_timer);
		d->timeout_timer = 0;
	}
}

void
pubnub_events_done(G_GNUC_UNUSED struct pubnub *p, G_GNUC_UNUSED void *ctx_data)
{
}

const struct pubnub_callbacks pubnub_events_callbacks = {
	.add_socket = pubnub_events_add_socket,
	.rem_socket = pubnub_events_rem_socket,
	.timeout = pubnub_events_timeout,
	.wait = pubnub_events_wait,
	.stop_wait = pubnub_events_stop_wait,
	.done = pubnub_events_done,
};

PubnubEvents *
pubnub_events_new(PurpleAccount * account, const char *username)
{
	PubnubEvents *e = g_new0(PubnubEvents, 1);
	const char *pub_key =
		purple_account_get_string(account, OPTION_PUBLISH_KEY,
					  DEFAULT_PUBLISH_KEY);
	const char *sub_key =
		purple_account_get_string(account, OPTION_SUBSCRIBE_KEY,
					  DEFAULT_SUBSCRIBE_KEY);
	const char *origin_server =
		purple_account_get_string(account, OPTION_ORIGIN_SERVER,
					  DEFAULT_ORIGIN_SERVER);
	const char *secret_key =
		purple_account_get_string(account, OPTION_SECRET_KEY,
					  DEFAULT_SECRET_KEY);
	const char *cipher_key =
		purple_account_get_string(account, OPTION_CIPHER_KEY,
					  DEFAULT_CIPHER_KEY);
	e->pn = pubnub_init(pub_key, sub_key, &pubnub_events_callbacks, e);
	pubnub_set_origin(e->pn, origin_server);
	if (*secret_key) {
		pubnub_set_secret_key(e->pn, secret_key);
	}
	if (*cipher_key) {
		pubnub_set_cipher_key(e->pn, cipher_key);
	}
	pubnub_error_policy(e->pn, 0, true);
	if (username) {
		char *new_uuid = g_strdup_printf("%s@%s", username,
						 pubnub_current_uuid(e->pn));
		pubnub_set_uuid(e->pn, new_uuid);
		g_free(new_uuid);
	}
	return e;
}

void
pubnub_events_free(PubnubEvents * e)
{
	pubnub_done(e->pn);
	g_free(e);
}
