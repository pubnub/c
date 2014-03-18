#include "gtest.h"

#include "../libpubnub/pubnub.h"
#include "../libpubnub/pubnub-priv.h"

#undef PUBNUB_API
#define PUBNUB_API

class PubNub;

class PubNubCppTest : public ::testing::Test
{
public:
	static bool initCalled;
	static bool doneCalled;
	static bool publishCalled;
	static bool subscribeCalled;
	static bool cb_funCalled;
protected:
	pubnub_callbacks cb;
	virtual void SetUp() {
		initCalled = false;
		doneCalled = false;
		publishCalled = false;
		subscribeCalled = false;
		cb_funCalled = false;
		memset(&cb, 0, sizeof(cb));
	}
	static void cb_fun(PubNub &p, enum pubnub_res result, json_object *response, void *ctx_data, void *call_data)
	{
		cb_funCalled = true;
	}
	static void cb_fun2(PubNub &p, enum pubnub_res result, std::vector<std::string> &channels, json_object *response, void *ctx_data, void *call_data)
	{
		cb_funCalled = true;
	}
};

bool PubNubCppTest::initCalled;
bool PubNubCppTest::doneCalled;
bool PubNubCppTest::publishCalled;
bool PubNubCppTest::subscribeCalled;
bool PubNubCppTest::cb_funCalled;

struct pubnub *test_pubnub_init(const char *publish_key, const char *subscribe_key,
			const struct pubnub_callbacks *cb, void *cb_data)
{
	PubNubCppTest::initCalled = true;
	return pubnub_init(publish_key, subscribe_key, cb, cb_data);
}

void test_pubnub_done(struct pubnub *p)
{
	PubNubCppTest::doneCalled = true;
	pubnub_done(p);
}

void test_pubnub_publish(struct pubnub *p, const char *channel,
		struct json_object *message,
		long timeout, pubnub_publish_cb cb, void *cb_data)
{
	PubNubCppTest::publishCalled = true;
	if (cb) {
		cb(NULL, PNR_OK, NULL, NULL, cb_data);
	}
}

void test_pubnub_subscribe(struct pubnub *p, const char *channel,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	PubNubCppTest::subscribeCalled = true;
	if (cb) {
		char **channels = (char**)malloc(sizeof(char*)*2);
		channels[0] = strdup(channel);
		channels[1] = NULL;
		cb(NULL, PNR_OK, channels, NULL, NULL, cb_data);
	}
}


#define pubnub_init test_pubnub_init
#define pubnub_done test_pubnub_done
#define pubnub_publish test_pubnub_publish
#define pubnub_subscribe test_pubnub_subscribe

#include "../libpubnub-cpp/pubnub.cpp"

#undef pubnub_init
#undef pubnub_done
#undef pubnub_publish
#undef pubnub_subscribe

TEST_F(PubNubCppTest, PubNubInitDone) {
	{
		PubNub pn("demo", "demo", &cb, NULL);
		EXPECT_TRUE(initCalled);
	}
	EXPECT_TRUE(doneCalled);
}

TEST_F(PubNubCppTest, PubNubNotAutoDone) {
	pubnub *p = pubnub_init("demo", "demo", &cb, NULL);
	{
		PubNub pn(p);
		EXPECT_FALSE(initCalled);
	}
	ASSERT_FALSE(doneCalled);
	pubnub_done(p);
}

TEST_F(PubNubCppTest, PubNubAutoDone) {
	pubnub *p = pubnub_init("demo", "demo", &cb, NULL);
	{
		PubNub pn(p, true);
		EXPECT_FALSE(initCalled);
	}
	EXPECT_TRUE(doneCalled);
}

TEST_F(PubNubCppTest, PubNubSettersGetters) {
	pubnub *p = pubnub_init("demo", "demo", &cb, NULL);
	PubNub pn(p, true);
	const char *sk = "secret_key";
	pn.set_secret_key(sk);
	EXPECT_STREQ(sk, p->secret_key);
	const char *ck = "cipher_key";
	pn.set_cipher_key(ck);
	EXPECT_STREQ(ck, p->cipher_key);
	const char *org = "origin";
	pn.set_origin(org);
	EXPECT_STREQ(org, p->origin);
	const char *uuid = "uuid";
	pn.set_uuid(uuid);
	EXPECT_STREQ(uuid, pn.current_uuid().c_str());
}

TEST_F(PubNubCppTest, PubNubPublish) {
	PubNub pn("demo", "demo", &cb, NULL);
	json_object *msg;
	msg = json_object_new_object();
	json_object_object_add(msg, "str", json_object_new_string("test"));
	pn.publish("channel", *msg, -1, NULL, NULL);
	ASSERT_TRUE(publishCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.publish("channel", *msg, -1, cb_fun, msg);
	ASSERT_TRUE(cb_funCalled);
	json_object_put(msg);
}

TEST_F(PubNubCppTest, PubNubSubscribe) {
	PubNub pn("demo", "demo", &cb, NULL);
	pn.subscribe("channel", -1);
	ASSERT_TRUE(subscribeCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.subscribe("channel", -1, cb_fun2, NULL);
	ASSERT_TRUE(cb_funCalled);
}

