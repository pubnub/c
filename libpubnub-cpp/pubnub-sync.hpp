#ifndef PUBNUB__PubNub_sync_hpp
#define PUBNUB__PubNub_sync_hpp

#include <pubnub-sync.h>
#include <pubnub.hpp>


class PubNub_sync_reply {
public:
	/* Normally, you won't build this object all by yourself,
	 * this constructor is meant to be used just by the factory
	 * function pubnub_sync_last_reply(). */
	PubNub_sync_reply(enum pubnub_res res_, json_object *resp_, std::vector<std::string> &ch_);
	~PubNub_sync_reply();

	/* Return result of the last issued method. Always check whether
	 * this is PNR_OK before examining response(). */
	enum pubnub_res result() const { return res; };

	/* Return JSON object the server response from the last PubNub method
	 * call issued. Unlike pubnub_sync_last_response(), the refcounted
	 * lifetime of object returned from response() is bound to the lifetime
	 * of the PubNub_sync_reply instance; if you need the JSON object to
	 * outlive it, call json_object_get() on the return value. */
	/* In case of PNR_OK after subscribe call, the object is an array of
	 * messages; use standard json accessors to access the individual
	 * messages. The array may also be empty if no new messages arrived
	 * for some time (and in case of the first call). */
	/* In case of !PNR_OK, the object may specify error code as described
	 * with regards to 'response' value in pubnub.h. */
	json_object *response() const { return resp; };

	/* Return names of the channels carrying the messages returned by the last
	 * subscribe method call. The subscribe call returns array of messages,
	 * corresponding items in this array are the respective channel names. */
	std::vector<std::string> channels() const { return ch; };

protected:
	enum pubnub_res res;
	json_object *resp;
	std::vector<std::string> ch;
};

/* Return PubNub_sync_reply instance representing the server response
 * to the last PubNub method call issued. The returned object can describe
 * both a regular response and an error condition description. */
PubNub_sync_reply pubnub_sync_last_reply(struct pubnub_sync *sync);

#endif
