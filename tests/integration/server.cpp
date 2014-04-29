
#include <fcntl.h>
#ifdef _MSC_VER
#else
#include <unistd.h>
#endif
#include "itesting.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include <json.h>

#include "pubnub.hpp"
#include "pubnub-libevent.h"

void router(struct evhttp_request *r, void *arg);

#define ADDR "127.0.0.1"

class ServerTest : public ::testing::Test
{
public:
	static bool publishSuccess;
	static bool historySuccess;

	bool usedTheSameConnection;

	event_base *evbase;
	evhttp *libsrv;
	evhttp_connection *evcon;
	PubNub *p;

	virtual void SetUp() {
		publishSuccess = false;
		historySuccess = false;
		usedTheSameConnection = true;
		evcon = NULL;
		evbase = event_base_new();
		libsrv = evhttp_new(evbase);
		int t = evhttp_bind_socket(libsrv, ADDR, 4000);
		evhttp_set_gencb(libsrv, router, this);
		p = new PubNub("demo", "demo", &pubnub_libevent_callbacks, pubnub_libevent_init(evbase));
		p->set_origin("http://" ADDR ":4000/");
	}

	virtual void TearDown() {
		evhttp_free(libsrv);
		event_base_free(evbase);
		delete p;

	}
};

bool ServerTest::publishSuccess, ServerTest::historySuccess;

void conClose(struct evhttp_connection *c, void *arg)
{
	ServerTest *p = (ServerTest*)arg;
	p->usedTheSameConnection = false;
}

void router(struct evhttp_request *r, void *arg)
{
	ServerTest *p = (ServerTest*)arg;
	if (p->evcon) {
		p->usedTheSameConnection = p->usedTheSameConnection && (p->evcon == evhttp_request_get_connection(r));
	} else {
		p->evcon = evhttp_request_get_connection(r);
		evhttp_connection_set_closecb(p->evcon, conClose, arg);
	}
	const char *uri = evhttp_request_get_uri(r);
	struct evbuffer *evb = evbuffer_new();
	evhttp_add_header(evhttp_request_get_output_headers(r),
		"Content-Type", "text/javascript");
	evbuffer_add_printf(evb, "[1,\"Sent\",\"13983273523470477\"]");
	evhttp_send_reply(r, 200, "OK", evb);
	evbuffer_free(evb);	
	if (strstr(uri, "history")) {
		timeval t;
		t.tv_sec = 0;
		t.tv_usec = 200;
		event_base_loopexit(p->evbase, &t);
	}
}


static void
history_received(PubNub &p, enum pubnub_res result, json_object *msg, void *ctx_data, void *call_data)
{
	ServerTest::historySuccess = (result == PNR_OK);
}

static void
history(PubNub &p)
{
	p.history("demo_channel", 10, -1, history_received);
}

static void
publish_done(PubNub &p, enum pubnub_res result, json_object *msg, void *ctx_data, void *call_data)
{
	ServerTest::publishSuccess = (result == PNR_OK);
	history(p);
}

static void
publish(PubNub &p)
{
	json_object *msg = json_object_new_object();
	json_object_object_add(msg, "num", json_object_new_int(42));
	json_object_object_add(msg, "str", json_object_new_string("\"Hello, world!\" she said."));

	p.publish("demo_channel", *msg, -1, publish_done);

	json_object_put(msg);
}

TEST_F(ServerTest, UsingTheSameConnection) {
	publish(*p);
	event_base_dispatch(evbase);
	EXPECT_TRUE(publishSuccess);
	EXPECT_TRUE(historySuccess);
	EXPECT_TRUE(usedTheSameConnection);
}


