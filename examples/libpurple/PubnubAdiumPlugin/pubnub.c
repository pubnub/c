
#include "pubnub_libpurple.h"

#include <libpurple/debug.h>
#include <libpurple/version.h>
#include <libpurple/accountopt.h>

#define PLUGIN_ID "prpl-avy-pubnub"
#define PLUGIN_AUTHOR "Alexey Yesipenko <alex7y@gmail.com>"

static void
add_chat_messages(PubnubRoom * room, char **channels, json_object * msgs)
{
	if (json_object_get_type(msgs) != json_type_array) {
		return;
	}
	guint len = json_object_array_length(msgs);
	purple_debug_misc(PLUGIN_ID, "number of messages: %d\n", len);
	guint i;
	gint chat_id = g_str_hash(room->name);
	for (i = 0; i < len; i++) {
		json_object *msg = json_object_array_get_idx(msgs, i);
		int flag = PURPLE_MESSAGE_RECV;
		char *username = g_strdup("?");
#if 0
		json_object *from = json_object_object_get(msg, "from");
		json_object *message = json_object_object_get(msg, "message");
		if (from
		    && json_object_get_type(from) == json_type_string
		    && message
		    && json_object_get_type(message) == json_type_string) {
			msg = message;
			const char *from_s = json_object_get_string(from);
			if (strcmp
			    (from_s,
			     pubnub_current_uuid(room->con->pn_pub->pn)) == 0) {
				flag = PURPLE_MESSAGE_SEND;
			}
			const char *t = strchr(from_s, '@');
			if (t && t != from_s) {
				username = g_strndup(from_s, t - from_s);
			}
		}
#endif
		if (!channels) {
			flag |= PURPLE_MESSAGE_DELAYED | PURPLE_MESSAGE_NO_LOG;
		}
		const char *s = json_object_get_string(msg);
		serv_got_chat_in(room->con->gc, chat_id,
				 username, flag, s, time(NULL));
		g_free(username);
		if (channels) {
			g_free(channels[i]);
		}
	}
	g_free(channels);
}


static void subscribe_cb(struct pubnub *p, enum pubnub_res result,
			 char **channels, struct json_object *response,
			 void *ctx_data, void *call_data);

static void
history_cb(G_GNUC_UNUSED struct pubnub *p, G_GNUC_UNUSED enum pubnub_res result,
	   G_GNUC_UNUSED struct json_object *msg, G_GNUC_UNUSED void *ctx_data,
	   G_GNUC_UNUSED void *call_data)
{
	PubnubRoom *room = call_data;
	json_object *msgs = json_object_get(msg);
	add_chat_messages(room, NULL, msgs);
	json_object_put(msgs);
	pubnub_subscribe(room->e->pn, room->name, -1, subscribe_cb, room);
}

static void
subscribe_cb(G_GNUC_UNUSED struct pubnub *p, enum pubnub_res result,
	     char **channels, struct json_object *response,
	     G_GNUC_UNUSED void *ctx_data, void *call_data)
{
	PubnubRoom *room = call_data;
	if (result == PNR_OK && response) {
		int history_n = 0;
		if (room->is_subscribed) {
			json_object *msgs = json_object_get(response);
			add_chat_messages(room, channels, msgs);
			json_object_put(msgs);
		} else {
			room->is_subscribed = true;
			history_n =
				purple_account_get_int(room->con->account,
						       OPTION_HISTORY_N,
						       DEFAULT_HISTORY_N);
		}
		if (history_n > 0) {
			pubnub_history(room->e->pn, room->name, history_n, -1,
				       history_cb, room);
		} else {
			pubnub_subscribe(room->e->pn, room->name, -1,
					 subscribe_cb, room);
		}
	}
}

static gint
users_compare_fn(gconstpointer a, gconstpointer b)
{
	const PurpleConvChatBuddy *ab = a;
	const PurpleConvChatBuddy *bb = b;
	return strcmp(ab->name, bb->name);
}

static void
add_users(json_object * list, PurpleConversation * conv)
{
	guint len = json_object_array_length(list);
	GList *list_old = purple_conv_chat_get_users(PURPLE_CONV_CHAT(conv));
	guint i;
	if (len == g_list_length(list_old)) {
		for (i = 0; i < len; i++) {
			json_object *uuid = json_object_array_get_idx(list, i);
			PurpleConvChatBuddy u;
			u.name = (char *) json_object_get_string(uuid);
			if (g_list_find_custom(list_old, &u, users_compare_fn)
			    == NULL) {
				break;
			}
		}
		if (i >= len) {
			return;
		}
	}
	GList *users = NULL;
	GList *flags = NULL;
	for (i = 0; i < len; i++) {
		json_object *uuid = json_object_array_get_idx(list, i);
		users = g_list_prepend(users,
				       (gpointer) json_object_get_string(uuid));
		flags = g_list_prepend(flags,
				       GINT_TO_POINTER(PURPLE_CBFLAGS_NONE));
	}
	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(conv));
	purple_conv_chat_add_users
		(PURPLE_CONV_CHAT(conv), users, NULL, flags, FALSE);
	g_list_free(users);
	g_list_free(flags);
}

static void
here_cb(G_GNUC_UNUSED struct pubnub *p, enum pubnub_res result,
	struct json_object *msg, G_GNUC_UNUSED void *ctx_data, void *call_data)
{
	PubnubConn *con = call_data;
	PurpleConversation *conv =
		purple_find_chat(con->gc, g_str_hash(con->here_channel));
	if (conv) {
		if (result == PNR_OK && msg) {
			json_object *uuids =
				json_object_object_get(msg, "uuids");
			if (uuids
			    && json_object_get_type(uuids) == json_type_array) {
				add_users(uuids, conv);
			}
		}
	}
	g_free(con->here_channel);
	con->here_channel = 0;
}

static gboolean
here_timer(gpointer data)
{
	PubnubConn *con = data;
	if (g_list_position(con->rooms, con->next_here) < 0) {
		con->next_here = con->rooms;
	}
	if (con->next_here && !con->here_channel) {
		PubnubRoom *room = con->next_here->data;
		con->here_channel = g_strdup(room->name);
		pubnub_here_now(con->pn_here->pn, con->here_channel, -1,
				here_cb, con);
	}
	con->next_here = g_list_next(con->next_here);
	if (!con->next_here) {
		con->next_here = con->rooms;
	}
	return TRUE;
}


static void
pubnub_login(PurpleAccount * account)
{
	PurpleConnection *gc = purple_account_get_connection(account);

	PubnubConn *con = gc->proto_data = g_new0(PubnubConn, 1);
	con->gc = gc;
	con->account = account;

	const char *username = purple_account_get_username(account);

	con->pn_pub = pubnub_events_new(account, username);
	con->pn_here = pubnub_events_new(account, NULL);

	con->here_timer = purple_timeout_add_seconds(5, here_timer, con);
	purple_connection_set_state(gc, PURPLE_CONNECTED);
}

static void
pubnub_close(PurpleConnection * gc)
{
	PubnubConn *con = gc->proto_data;
	purple_timeout_remove(con->here_timer);
	if (con->here_channel) {
		g_free(con->here_channel);
	}
	pubnub_events_free(con->pn_pub);
	GList *i = g_list_last(con->rooms);
	while (i) {
		PubnubRoom *room = i->data;
		i = g_list_previous(i);
		PurpleConversation *conv =
			purple_find_chat(con->gc, g_str_hash(room->name));
		purple_conversation_destroy(conv);
	}
}

static const char *
pubnub_list_icon(G_GNUC_UNUSED PurpleAccount * account,
		 G_GNUC_UNUSED PurpleBuddy * buddy)
{
	return "pubnub";
}

static GList *
pubnub_statuses(G_GNUC_UNUSED PurpleAccount * acct)
{
	GList *types = NULL;
	PurpleStatusType *status;

	/*Online people have a status message and also a date when it was set */
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL,
					     ("Online"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	/*Offline people dont have messages */
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL,
					     ("Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;

}

static gchar *
pubnub_status_text(G_GNUC_UNUSED PurpleBuddy * buddy)
{
	return NULL;
}

static void
pubnub_set_status(G_GNUC_UNUSED PurpleAccount * acct,
		  G_GNUC_UNUSED PurpleStatus * status)
{
}

static GList *
pubnub_chat_info(G_GNUC_UNUSED PurpleConnection * gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = ("_Room:");
	pce->identifier = "room";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static GHashTable *
pubnub_chat_info_defaults(G_GNUC_UNUSED PurpleConnection * gc,
			  G_GNUC_UNUSED const char *room)
{
	GHashTable *defaults;

	defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	g_hash_table_insert(defaults, "room", g_strdup("my_channel"));

	return defaults;
}

static char *
pubnub_get_chat_name(GHashTable * data)
{
	return g_strdup(g_hash_table_lookup(data, "room"));
}

static void
pubnub_join_chat(PurpleConnection * gc, GHashTable * data)
{
    purple_debug_misc(PLUGIN_ID, "i'm in join chat\n");
	const char *username = gc->account->username;
	const char *roomname = g_hash_table_lookup(data, "room");
    purple_debug_misc(PLUGIN_ID, "chat name: %s\n", roomname);
    //return;
	int chat_id = g_str_hash(roomname);

	if (!purple_find_chat(gc, chat_id)) {
		serv_got_joined_chat(gc, chat_id, roomname);
		PubnubConn *con = gc->proto_data;
		PubnubRoom *room = g_new0(PubnubRoom, 1);
		room->e = pubnub_events_new(con->account, NULL);
		room->con = con;
		room->name = g_strdup(roomname);
		con->rooms = g_list_prepend(con->rooms, room);
		con->next_here = con->rooms;
		pubnub_subscribe(room->e->pn, room->name, -1, subscribe_cb,
				 room);
	} else {
		char *tmp = g_strdup_printf(("%s is already in chat room %s."),
					    username, roomname);
		purple_notify_info(gc, ("Join chat"), ("Join chat"), tmp);
		g_free(tmp);
	}
}

static void
pubnub_chat_leave(PurpleConnection * gc, int id)
{
	PurpleConversation *conv = purple_find_chat(gc, id);
	if (conv) {
		PubnubConn *con = gc->proto_data;
		GList *it;
		for (it = con->rooms; it; it = g_list_next(it)) {
			PubnubRoom *room = it->data;
			if (strcmp(conv->name, room->name) == 0) {
				pubnub_events_free(room->e);
				g_free(room->name);
				g_free(room);
				con->rooms = g_list_remove(con->rooms, room);
				break;
			}
		}
	}
}

static void
publish_cb(G_GNUC_UNUSED struct pubnub *p,
	   G_GNUC_UNUSED enum pubnub_res result,
	   G_GNUC_UNUSED struct json_object *msg,
	   G_GNUC_UNUSED void *ctx_data, G_GNUC_UNUSED void *call_data)
{
}

int
pubnub_chat_send(PurpleConnection * gc, int id, const char *message,
		 G_GNUC_UNUSED PurpleMessageFlags flags)
{
	PurpleConversation *conv = purple_find_chat(gc, id);
    purple_debug_misc(PLUGIN_ID, "i'm in chat send: %s\n", message);
//    return 0;

	if (conv) {
		PubnubConn *con = gc->proto_data;
		char *txt = purple_unescape_text(message);
        purple_debug_misc(PLUGIN_ID, "chat send: %s\n", txt);
		json_object *msg; // = json_tokener_parse(txt);
        purple_debug_misc(PLUGIN_ID, "parsed: %p\n", msg);
		if (true || !msg) {
			msg = json_object_new_object();
			json_object_object_add(msg, "from",
					       json_object_new_string
					       (pubnub_current_uuid
						(con->pn_pub->pn)));
			json_object_object_add(msg, "message",
					       json_object_new_string(txt));
		}
		g_free(txt);
		pubnub_publish(con->pn_pub->pn, conv->name, msg, -1, publish_cb,
			       NULL);
		json_object_put(msg);
	}
	return 0;
}

PurplePluginProtocolInfo pubnub_protocol_info = {
	/* options */
	OPT_PROTO_NO_PASSWORD, NULL,	/* user_splits */
	NULL,			/* protocol_options */
	NO_BUDDY_ICONS, pubnub_list_icon,	/* list_icon */
	NULL,			/* list_emblems */
	pubnub_status_text,	/* status_text */
	NULL, pubnub_statuses,	/* status_types */
	NULL,			/* blist_node_menu */
	pubnub_chat_info,	/* chat_info */
	pubnub_chat_info_defaults,	/* chat_info_defaults */
	pubnub_login,		/* login */
	pubnub_close,		/* close */
	NULL,			/* send_im */
	NULL,			/* set_info */
	NULL,			/* send_typing */
	NULL,			/* get_info */
	pubnub_set_status,	/* set_status */
	NULL,			/* set_idle */
	NULL,			/* change_passwd */
	NULL,			/* add_buddy */
	NULL,			/* add_buddies */
	NULL,			/* remove_buddy */
	NULL,			/* remove_buddies */
	NULL,			/* add_permit */
	NULL,			/* add_deny */
	NULL,			/* rem_permit */
	NULL,			/* rem_deny */
	NULL,			/* set_permit_deny */
	pubnub_join_chat,	/* join_chat */
	NULL,			/* reject chat invite */
	pubnub_get_chat_name,	/* get_chat_name */
	NULL,			/* chat_invite */
	pubnub_chat_leave,	/* chat_leave */
	NULL,			/* chat_whisper */
	pubnub_chat_send,	/* chat_send */
	NULL,			/* keepalive */
	NULL,			/* register_user */
	NULL,			/* get_cb_info */
	NULL,			/* get_cb_away */
	NULL,			/* alias_buddy */
	NULL,			/* group_buddy */
	NULL,			/* rename_group */
	NULL,			/* buddy_free */
	NULL,			/* convo_closed */
	NULL,			/* normalize */
	NULL,			/* set_buddy_icon */
	NULL,			/* remove_group */
	NULL,			/* get_cb_real_name */
	NULL,			/* set_chat_topic */
	NULL,			/* find_blist_chat */
	NULL,			/* roomlist_get_list */
	NULL,			/* roomlist_cancel */
	NULL,			/* roomlist_expand_category */
	NULL,			/* can_receive_file */
	NULL,			/* send_file */
	NULL,			/* new_xfer */
	NULL,			/* offline_message */
	NULL,			/* whiteboard_prpl_ops */
	NULL,			/* send_raw */
	NULL,			/* roomlist_room_serialize */
	NULL,			/* unregister_user */
	NULL,			/* send_attention */
	NULL,			/* attention_types */
	sizeof(PurplePluginProtocolInfo),	/* struct_size */
	NULL,			/*campfire_get_account_text_table *//* get_account_text_table */
	NULL,			/* initiate_media */
	NULL,			/* get_media_caps */
#if PURPLE_MAJOR_VERSION > 1
#if PURPLE_MINOR_VERSION > 6
	NULL,			/* get_moods */
	NULL,			/* set_public_alias */
	NULL,			/* get_public_alias */
#if PURPLE_MINOR_VERSION > 7
	NULL,			/* add_buddy_with_invite */
	NULL,			/* add_buddies_with_invite */
#endif /* PURPLE_MINOR_VERSION > 7 */
#endif /* PURPLE_MINOR_VERSION > 6 */
#endif /* PURPLE_MAJOR_VERSION > 1 */
};

static gboolean
plugin_load(G_GNUC_UNUSED PurplePlugin * plugin)
{
	return TRUE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,	/* magic number */
	PURPLE_MAJOR_VERSION,	/* purple major */
	PURPLE_MINOR_VERSION,	/* purple minor */
	PURPLE_PLUGIN_PROTOCOL,	/* plugin type */
	NULL,			/* UI requirement */
	0,			/* flags */
	NULL,			/* dependencies */
	PURPLE_PRIORITY_DEFAULT,	/* priority */
	PLUGIN_ID,		/* id */
	"PubNub",		/* name */
	"1.0",			/* version */
	"PubNub",		/* summary */
	"PubNub",		/* description */
	PLUGIN_AUTHOR,		/* author */
	"http://pidgin.im",	/* homepage */
	plugin_load,		/* load */
	NULL,			/* unload */
	NULL,			/* destroy */
	NULL,			/* ui info */
	&pubnub_protocol_info,	/* extra info */
	NULL,			/* prefs info */
	NULL,			/* actions */
	NULL,			/* reserved */
	NULL,			/* reserved */
	NULL,			/* reserved */
	NULL			/* reserved */
};

static void
init_plugin(G_GNUC_UNUSED PurplePlugin * plugin)
{
	PurpleAccountOption *opts[] = {
		purple_account_option_string_new(("Publish key"),
						 OPTION_PUBLISH_KEY,
						 DEFAULT_PUBLISH_KEY),
		purple_account_option_string_new(("Subscribe key"),
						 OPTION_SUBSCRIBE_KEY,
						 DEFAULT_SUBSCRIBE_KEY),
		purple_account_option_int_new(("Retrieve # last messages"),
					      OPTION_HISTORY_N,
					      DEFAULT_HISTORY_N),
		purple_account_option_string_new(("Origin server"),
						 OPTION_ORIGIN_SERVER,
						 DEFAULT_ORIGIN_SERVER),
		purple_account_option_string_new(("Secret key"),
						 OPTION_SECRET_KEY,
						 DEFAULT_SECRET_KEY),
		purple_account_option_string_new(("Cipher key"),
						 OPTION_CIPHER_KEY,
						 DEFAULT_CIPHER_KEY),
		NULL
	};
	PurpleAccountOption **i;
	for (i = opts; *i; ++i) {
		pubnub_protocol_info.protocol_options =
			g_list_append(pubnub_protocol_info.protocol_options,
				      *i);
	}
    purple_debug_misc(PLUGIN_ID, "init plugin\n");

}

PURPLE_INIT_PLUGIN(pubnub, init_plugin, info)
