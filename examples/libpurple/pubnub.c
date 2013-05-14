
#include "pubnub_libpurple.h"

#include <libpurple/debug.h>
#include <libpurple/version.h>
#include <libpurple/accountopt.h>

#define PLUGIN_ID "prpl-avy-pubnub"
#define PLUGIN_AUTHOR "Alexey Yesipenko <alex7y@gmail.com>"
#define PRESENCE_SUFFIX "-pnpres"

static void
add_chat_message(PubnubRoom * room, json_object * msg, bool is_history,
		 bool is_private)
{
	json_object *from = json_object_object_get(msg, "from");
	json_object *message = json_object_object_get(msg, "message");
	int flag = PURPLE_MESSAGE_RECV;
	const char *from_s = NULL;
	if (from
	    && json_object_get_type(from) == json_type_string
	    && message && json_object_get_type(message) == json_type_string) {
		msg = message;
		from_s = json_object_get_string(from);
		if (strcmp(from_s, pubnub_current_uuid(room->con->e->pn)) == 0) {
			flag = PURPLE_MESSAGE_SEND;
		}
	}
	if (is_history) {
		flag |= PURPLE_MESSAGE_DELAYED | PURPLE_MESSAGE_NO_LOG;
	}
	const char *s = json_object_get_string(msg);
	if (is_private) {
		if (from_s) {
			serv_got_im(room->con->gc, from_s, s, flag, time(NULL));
		}
	} else {
		serv_got_chat_in(room->con->gc, room->id,
				 (from_s ? from_s : "?"), flag, s, time(NULL));
	}
}

static void
process_chat_presence(PubnubRoom * room, json_object * msg)
{
	PurpleConversation *conv = purple_find_chat(room->con->gc, room->id);
	json_object *action = json_object_object_get(msg, "action");
	json_object *uuid = json_object_object_get(msg, "uuid");
	purple_debug_misc(PLUGIN_ID, "PRESENCE MESSAGE\n");
	if (action && json_object_get_type(action) == json_type_string
	    && uuid && json_object_get_type(uuid) == json_type_string) {
		const char *action_s = json_object_get_string(action);
		const char *uuid_s = json_object_get_string(uuid);
		if (strcmp(action_s, "join") == 0) {
			purple_conv_chat_add_user
				(PURPLE_CONV_CHAT(conv), uuid_s, NULL, 0, TRUE);
			purple_serv_got_private_alias(room->con->gc, uuid_s,
						      "username");
		} else if (strcmp(action_s, "leave") == 0) {
			purple_conv_chat_remove_user
				(PURPLE_CONV_CHAT(conv), uuid_s, NULL);
		}

	}
}

static void
add_chat_messages(PubnubRoom * room, char **channels, json_object * msgs,
		  bool is_private)
{
	if (json_object_get_type(msgs) != json_type_array) {
		return;
	}
	guint len = json_object_array_length(msgs);
	purple_debug_misc(PLUGIN_ID, "number of messages: %d\n", len);
	guint i;
	for (i = 0; i < len; i++) {
		json_object *msg = json_object_array_get_idx(msgs, i);
		if (is_private || !channels
		    || !g_str_has_suffix(channels[i], PRESENCE_SUFFIX)) {
			add_chat_message(room, msg, channels == NULL,
					 is_private);
		} else {
			process_chat_presence(room, msg);
		}
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
	add_chat_messages(room, NULL, msgs, false);
	json_object_put(msgs);
	pubnub_subscribe_multi(room->e->pn, room->channels, 2, -1, subscribe_cb,
			       room);
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
	PubnubRoom *room = call_data;
	PurpleConversation *conv = purple_find_chat(room->con->gc, room->id);
	if (conv) {
		if (result == PNR_OK && msg) {
			json_object *uuids =
				json_object_object_get(msg, "uuids");
			if (uuids
			    && json_object_get_type(uuids) == json_type_array) {
				add_users(uuids, conv);
			}
		}
		int history_n = purple_account_get_int(room->con->account,
						       OPTION_HISTORY_N,
						       DEFAULT_HISTORY_N);
		if (history_n > 0) {
			pubnub_history(room->e->pn, room->channels[0],
				       history_n, -1, history_cb, room);
		} else {
			pubnub_subscribe_multi(room->e->pn, room->channels, 2,
					       -1, subscribe_cb, room);
		}
	}
}

static void
subscribe_cb(G_GNUC_UNUSED struct pubnub *p, enum pubnub_res result,
	     char **channels, struct json_object *response,
	     G_GNUC_UNUSED void *ctx_data, void *call_data)
{
	PubnubRoom *room = call_data;
	if (result == PNR_OK && response) {
		if (room->is_subscribed) {
			json_object *msgs = json_object_get(response);
			add_chat_messages(room, channels, msgs, false);
			json_object_put(msgs);
			pubnub_subscribe_multi(room->e->pn, room->channels, 2,
					       -1, subscribe_cb, room);
		} else {
			room->is_subscribed = true;
			pubnub_here_now(room->e->pn, room->channels[0], -1,
					here_cb, room);
		}
	}
}

static void
private_subscribe_cb(G_GNUC_UNUSED struct pubnub *p, enum pubnub_res result,
		     char **channels, struct json_object *response,
		     G_GNUC_UNUSED void *ctx_data, void *call_data)
{
	PubnubConn *con = call_data;
	if (result == PNR_OK && response) {
		json_object *msgs = json_object_get(response);
		json_object_put(msgs);
		PubnubRoom room;
		room.con = con;
		add_chat_messages(&room, channels, msgs, true);
		pubnub_subscribe(con->private_e->pn,
				 pubnub_current_uuid(con->e->pn), -1,
				 private_subscribe_cb, con);
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
					     _("Online"), TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	/*Offline people dont have messages */
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL,
					     _("Offline"), TRUE, TRUE, FALSE);
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
	pce->label = _("_Room:");
	pce->identifier = "room";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

static char *
pubnub_get_chat_name(GHashTable * data)
{
	return g_strdup(g_hash_table_lookup(data, "room"));
}

static void
pubnub_join_chat(PurpleConnection * gc, GHashTable * data)
{
	PubnubConn *con = gc->proto_data;
	const char *roomname = g_hash_table_lookup(data, "room");

	// finch missing room name fix
	if (!roomname) {
		const GList *chats = purple_get_chats();
		for (; chats; chats = g_list_next(chats)) {
			PurpleConversation *p = chats->data;
			if (p->account == con->account && !p->u.chat->id) {
				roomname = p->name;
				break;
			}
		}
	}

	if (roomname) {
		int chat_id = g_str_hash(roomname);
		purple_debug_misc(PLUGIN_ID, "join chat: %s\n", roomname);

		if (!purple_find_chat(gc, chat_id)) {
			serv_got_joined_chat(gc, chat_id, roomname);
			PubnubRoom *room = g_new0(PubnubRoom, 1);
			room->e = pubnub_events_new(con->account, NULL);
			room->con = con;
			room->name = g_strdup(roomname);
			con->rooms = g_list_prepend(con->rooms, room);
			con->next_here = con->rooms;
			pubnub_subscribe(room->e->pn, room->name, -1,
					 subscribe_cb, room);
		}
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
			if (strcmp(conv->name, room->channels[0]) == 0) {
				pubnub_events_free(room->e);
				g_free((gpointer) room->channels[0]);
				g_free((gpointer) room->channels[1]);
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

static void
pubnub_send_message(PurpleConnection * gc, const char *who, const char *message)
{
	PubnubConn *con = gc->proto_data;
	char *txt = purple_unescape_text(message);
		json_object *msg = NULL;
#ifndef ADIUM
		msg = json_tokener_parse(txt);
#endif
	if (!msg) {
		msg = json_object_new_object();
		json_object_object_add(msg, "from",
				       json_object_new_string
				       (pubnub_current_uuid(con->e->pn)));
		json_object_object_add(msg, "message",
				       json_object_new_string(txt));
	}
	g_free(txt);
	pubnub_publish(con->e->pn, who, msg, -1, publish_cb, NULL);
	json_object_put(msg);
}

int
pubnub_chat_send(PurpleConnection * gc, int id, const char *message,
		 G_GNUC_UNUSED PurpleMessageFlags flags)
{
	PurpleConversation *conv = purple_find_chat(gc, id);
	if (conv) {
		pubnub_send_message(gc, conv->name, message);
	}
	return 0;
}

int
pubnub_message_send_im(PurpleConnection * gc, const char *who, const char *msg,
		       G_GNUC_UNUSED PurpleMessageFlags flags)
{
	pubnub_send_message(gc, who, msg);
	serv_got_im(gc, who, msg, PURPLE_MESSAGE_SEND, time(0));
	return 0;
}

static void
pubnub_login(PurpleAccount * account)
{
	PurpleConnection *gc = purple_account_get_connection(account);

	PubnubConn *con = gc->proto_data = g_new0(PubnubConn, 1);
	con->gc = gc;
	con->account = account;

	con->e = pubnub_events_new(account, NULL);
	con->private_e = pubnub_events_new(account, NULL);

	purple_connection_set_state(gc, PURPLE_CONNECTED);

	pubnub_subscribe(con->private_e->pn, pubnub_current_uuid(con->e->pn),
			 -1, private_subscribe_cb, con);
}

static void
pubnub_close(PurpleConnection * gc)
{
	PubnubConn *con = gc->proto_data;
	pubnub_events_free(con->e);
	pubnub_events_free(con->private_e);
	GList *i = g_list_last(con->rooms);
	while (i) {
		PubnubRoom *room = i->data;
		i = g_list_previous(i);
		PurpleConversation *conv = purple_find_chat(con->gc, room->id);
		purple_conversation_destroy(conv);
	}
	g_free(con);
	gc->proto_data = NULL;
}

static PurplePluginProtocolInfo pubnub_protocol_info = {
	/* options */
	OPT_PROTO_NO_PASSWORD, NULL,	/* user_splits */
	NULL,			/* protocol_options */
	NO_BUDDY_ICONS, pubnub_list_icon,	/* list_icon */
	NULL,			/* list_emblems */
	pubnub_status_text,	/* status_text */
	NULL, pubnub_statuses,	/* status_types */
	NULL,			/* blist_node_menu */
	pubnub_chat_info,	/* chat_info */
	NULL,			/* chat_info_defaults */
	pubnub_login,		/* login */
	pubnub_close,		/* close */
	pubnub_message_send_im,	/* send_im */
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
		purple_account_option_string_new(_("Publish key"),
						 OPTION_PUBLISH_KEY,
						 DEFAULT_PUBLISH_KEY),
		purple_account_option_string_new(_("Subscribe key"),
						 OPTION_SUBSCRIBE_KEY,
						 DEFAULT_SUBSCRIBE_KEY),
		purple_account_option_int_new(_("Retrieve # last messages"),
					      OPTION_HISTORY_N,
					      DEFAULT_HISTORY_N),
		purple_account_option_string_new(_("Origin server"),
						 OPTION_ORIGIN_SERVER,
						 DEFAULT_ORIGIN_SERVER),
		purple_account_option_string_new(_("Secret key"),
						 OPTION_SECRET_KEY,
						 DEFAULT_SECRET_KEY),
		purple_account_option_string_new(_("Cipher key"),
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
}

PURPLE_INIT_PLUGIN(pubnub, init_plugin, info)
