#include <string>
#include <vector>

#include <json.h>

#include "pubnub.hpp"
#include "pubnub.h"
#include "pubnub-priv.h"


/** PubNub lifetime */

PUBNUB_API
PubNub::PubNub(const std::string &publish_key, const std::string &subscribe_key,
	const struct pubnub_callbacks *cb, void *cb_data)
{
	p = pubnub_init(publish_key.c_str(), subscribe_key.c_str(), cb, cb_data);
	p_autodestroy = true;
}

PUBNUB_API
PubNub::PubNub(struct pubnub *p_, bool p_autodestroy_)
	: p(p_), p_autodestroy(p_autodestroy_)
{ }

PUBNUB_API
PubNub::~PubNub()
{
	if (p_autodestroy)
		pubnub_done(p);
}


/** PubNub setters / getters */

PUBNUB_API
void
PubNub::set_secret_key(const std::string &secret_key)
{
	pubnub_set_secret_key(p, secret_key.c_str());
}

PUBNUB_API
void
PubNub::set_cipher_key(const std::string &cipher_key)
{
	pubnub_set_cipher_key(p, cipher_key.c_str());
}

PUBNUB_API
void
PubNub::set_origin(const std::string &origin)
{
	pubnub_set_origin(p, origin.c_str());
}

PUBNUB_API
std::string
PubNub::current_uuid()
{
	return std::string(pubnub_current_uuid(p));
}

PUBNUB_API
void
PubNub::set_uuid(const std::string &uuid)
{
	pubnub_set_uuid(p, uuid.c_str());
}

PUBNUB_API
void
PubNub::set_nosignal(bool nosignal)
{
	pubnub_set_nosignal(p, nosignal);
}

PUBNUB_API
void
PubNub::error_policy(unsigned int retry_mask, bool print)
{
	pubnub_error_policy(p, retry_mask, print);
}


/** PubNub API */

/* If the user passes a PubNub_*_cb function pointer, we funnel the callback
 * through our callback that will call the user callback function using
 * our C++-friendly calling convention (most importantly, passing PubNub*
 * instead of pubnub* as the first argument).
 *
 * On the other hand, if the user passed no custom function pointer, we are
 * falling back to the default callback of the used frontend (usually sync)
 * and we don't care about C++-ish callbacks, therefore we pass on a NULL. */


/** PubNub API publish */

typedef std::pair<std::pair<PubNub_publish_cb, PubNub *>, void *> publish_pair;

static void
pubnub_cpp_publish_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	publish_pair *cb_info = (publish_pair *) call_data;
	cb_info->first.first(*cb_info->first.second, result, response, ctx_data, cb_info->second);
	delete cb_info;
}

PUBNUB_API
void
PubNub::publish(const std::string &channel, json_object &message,
		long timeout, PubNub_publish_cb cb, void *cb_data)
{
	if (cb) {
		publish_pair *cb_info = new publish_pair(std::pair<PubNub_publish_cb, PubNub *>(cb, this), cb_data);
		pubnub_publish(p, channel.c_str(), &message, timeout, pubnub_cpp_publish_cb, cb_info);
	} else {
		pubnub_publish(p, channel.c_str(), &message, timeout, NULL, NULL);
	}
}


/** PubNub API subscribe */

typedef std::pair<std::pair<PubNub_subscribe_cb, PubNub *>, void *> subscribe_pair;

static void
pubnub_cpp_subscribe_cb(struct pubnub *p, enum pubnub_res result, char **channels, struct json_object *response, void *ctx_data, void *call_data)
{
	int ch_n = 0;
	if (channels) {
		for (char **i = channels; *i; i++)
			ch_n++;
	}
	std::vector<std::string> ch(channels, channels + ch_n);

	subscribe_pair *cb_info = (subscribe_pair *) call_data;
	cb_info->first.first(*cb_info->first.second, result, ch, response, ctx_data, cb_info->second);
	delete cb_info;
}

PUBNUB_API
void
PubNub::subscribe(const std::string &channel,
		long timeout, PubNub_subscribe_cb cb, void *cb_data)
{
	if (cb) {
		subscribe_pair *cb_info = new subscribe_pair(std::pair<PubNub_subscribe_cb, PubNub *>(cb, this), cb_data);
		pubnub_subscribe(p, channel.c_str(), timeout, pubnub_cpp_subscribe_cb, cb_info);
	} else {
		pubnub_subscribe(p, channel.c_str(), timeout, NULL, NULL);
	}
}

PUBNUB_API
void
PubNub::subscribe_multi(const std::vector<std::string> &channels,
		long timeout, PubNub_subscribe_cb cb, void *cb_data)
{
	const char **ch = (const char **) malloc(channels.size() * sizeof(ch[0]));
	for (unsigned int i = 0; i < channels.size(); i++) {
		ch[i] = channels[i].c_str();
	}

	if (cb) {
		subscribe_pair *cb_info = new subscribe_pair(std::pair<PubNub_subscribe_cb, PubNub *>(cb, this), cb_data);
		pubnub_subscribe_multi(p, ch, channels.size(), timeout, pubnub_cpp_subscribe_cb, cb_info);
	} else {
		pubnub_subscribe_multi(p, ch, channels.size(), timeout, NULL, NULL);
	}

	free(ch);
}


/** PubNub API history */

typedef std::pair<std::pair<PubNub_history_cb, PubNub *>, void *> history_pair;

static void
pubnub_cpp_history_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	history_pair *cb_info = (history_pair *) call_data;
	cb_info->first.first(*cb_info->first.second, result, response, ctx_data, cb_info->second);
	delete cb_info;
}

PUBNUB_API
void
PubNub::history(const std::string &channel, int limit,
		long timeout, PubNub_history_cb cb, void *cb_data)
{
	if (cb) {
		history_pair *cb_info = new history_pair(std::pair<PubNub_history_cb, PubNub *>(cb, this), cb_data);
		pubnub_history(p, channel.c_str(), limit, timeout, pubnub_cpp_history_cb, cb_info);
	} else {
		pubnub_history(p, channel.c_str(), limit, timeout, NULL, NULL);
	}
}


/** PubNub API here_now */

typedef std::pair<std::pair<PubNub_here_now_cb, PubNub *>, void *> here_now_pair;

static void
pubnub_cpp_here_now_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	here_now_pair *cb_info = (here_now_pair *) call_data;
	cb_info->first.first(*cb_info->first.second, result, response, ctx_data, cb_info->second);
	delete cb_info;
}

PUBNUB_API
void
PubNub::here_now(const std::string &channel,
		long timeout, PubNub_here_now_cb cb, void *cb_data)
{
	if (cb) {
		here_now_pair *cb_info = new here_now_pair(std::pair<PubNub_here_now_cb, PubNub *>(cb, this), cb_data);
		pubnub_here_now(p, channel.c_str(), timeout, pubnub_cpp_here_now_cb, cb_info);
	} else {
		pubnub_here_now(p, channel.c_str(), timeout, NULL, NULL);
	}
}


/** PubNub API time */

typedef std::pair<std::pair<PubNub_time_cb, PubNub *>, void *> time_pair;

static void
pubnub_cpp_time_cb(struct pubnub *p, enum pubnub_res result, struct json_object *response, void *ctx_data, void *call_data)
{
	time_pair *cb_info = (time_pair *) call_data;
	cb_info->first.first(*cb_info->first.second, result, response, ctx_data, cb_info->second);
	delete cb_info;
}

PUBNUB_API
void
PubNub::time(long timeout, PubNub_time_cb cb, void *cb_data)
{
	if (cb) {
		time_pair *cb_info = new time_pair(std::pair<PubNub_time_cb, PubNub *>(cb, this), cb_data);
		pubnub_time(p, timeout, pubnub_cpp_time_cb, cb_info);
	} else {
		pubnub_time(p, timeout, NULL, NULL);
	}
}
