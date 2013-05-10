#include <string>
#include <vector>

#include <json.h>

#include "pubnub.hpp"
#include "pubnub-sync.hpp"
#include "pubnub-sync.h"
#include "pubnub-priv.h"


PUBNUB_API
PubNub_sync_reply::PubNub_sync_reply(enum pubnub_res res_, json_object *resp_, std::vector<std::string> &ch_)
	: res(res_), resp(resp_), ch(ch_)
{
	/* XXX: We do not call json_object_get(resp); as
	 * pubnub_sync_last_reply() will give us resp with the refcount
	 * already bumped by pubnub_sync_last_response(). */
}

PUBNUB_API
PubNub_sync_reply::~PubNub_sync_reply()
{
	if (resp)
		json_object_put(resp);
}


PUBNUB_API
PubNub_sync_reply
pubnub_sync_last_reply(struct pubnub_sync *sync)
{
	char **ch_cstr = pubnub_sync_last_channels(sync);
	int ch_n = 0;
	if (ch_cstr) {
		for (char **i = ch_cstr; *i; i++)
			ch_n++;
	}

	std::vector<std::string> ch(ch_cstr, ch_cstr + ch_n);

	return PubNub_sync_reply(
			pubnub_sync_last_result(sync),
			pubnub_sync_last_response(sync),
			ch
		);
}
