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
	static bool subscribeMultiCalled;
	static bool historyCalled;
	static bool herenowCalled;
	static bool timeCalled;
	static bool cb_funCalled;
	static PubNub *_pn;
	static void *_data;
protected:
	pubnub_callbacks cb;
	virtual void SetUp() {
		initCalled = false;
		doneCalled = false;
		publishCalled = false;
		subscribeCalled = false;
		subscribeMultiCalled = false;
		historyCalled = false;
		herenowCalled = false;
		timeCalled = false;
		cb_funCalled = false;
		memset(&cb, 0, sizeof(cb));
	}
	static void cb_fun(PubNub &p, enum pubnub_res result, json_object *response, void *ctx_data, void *call_data)
	{
		_pn = &p;
		_data = call_data;
		cb_funCalled = true;
	}
	static void cb_fun2(PubNub &p, enum pubnub_res result, std::vector<std::string> &channels, json_object *response, void *ctx_data, void *call_data)
	{
		_pn = &p;
		cb_funCalled = true;
	}
};

bool PubNubCppTest::initCalled;
bool PubNubCppTest::doneCalled;
bool PubNubCppTest::publishCalled;
bool PubNubCppTest::subscribeCalled;
bool PubNubCppTest::subscribeMultiCalled;
bool PubNubCppTest::historyCalled;
bool PubNubCppTest::herenowCalled;
bool PubNubCppTest::timeCalled;
bool PubNubCppTest::cb_funCalled;
PubNub *PubNubCppTest::_pn;
void *PubNubCppTest::_data;

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

void test_pubnub_subscribe_multi(struct pubnub *p, const char *channels[], int channels_n,
		long timeout, pubnub_subscribe_cb cb, void *cb_data)
{
	PubNubCppTest::subscribeMultiCalled = true;
	if (cb) {
		int n = 0;
		for (;channels[n];n++);
		char **_channels = (char**)malloc(sizeof(char*)*(n+1));
		for (int i = 0; i < n; i++) {
			_channels[i] = strdup(channels[i]);
		}
		cb(NULL, PNR_OK, _channels, NULL, NULL, cb_data);
	}
}

void test_pubnub_history(struct pubnub *p, const char *channel, int limit,
		long timeout, pubnub_history_cb cb, void *cb_data)
{
	PubNubCppTest::historyCalled = true;
	if (cb) {
		cb(NULL, PNR_OK, NULL, NULL, cb_data);
	}
}

void test_pubnub_here_now(struct pubnub *p, const char *channel,
		long timeout, pubnub_here_now_cb cb, void *cb_data)
{
	PubNubCppTest::herenowCalled = true;
	if (cb) {
		cb(NULL, PNR_OK, NULL, NULL, cb_data);
	}
}

void test_pubnub_time(struct pubnub *p, long timeout, pubnub_time_cb cb, void *cb_data)
{
	PubNubCppTest::timeCalled = true;
	if (cb) {
		cb(NULL, PNR_OK, NULL, NULL, cb_data);
	}
}

#define pubnub_init test_pubnub_init
#define pubnub_done test_pubnub_done
#define pubnub_publish test_pubnub_publish
#define pubnub_subscribe test_pubnub_subscribe
#define pubnub_subscribe_multi test_pubnub_subscribe_multi
#define pubnub_history test_pubnub_history
#define pubnub_here_now test_pubnub_here_now
#define pubnub_time test_pubnub_time

#include "../libpubnub-cpp/pubnub.cpp"

#undef pubnub_init
#undef pubnub_done
#undef pubnub_publish
#undef pubnub_subscribe
#undef pubnub_subscribe_multi
#undef pubnub_history
#undef pubnub_here_now
#undef pubnub_time

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
	pn.publish("channel", *msg, -1, cb_fun, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
	json_object_put(msg);
}

TEST_F(PubNubCppTest, PubNubSubscribe) {
	PubNub pn("demo", "demo", &cb, NULL);
	pn.subscribe("channel", -1);
	ASSERT_TRUE(subscribeCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.subscribe("channel", -1, cb_fun2, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
}


TEST_F(PubNubCppTest, PubNubSubscribeMulti) {
	PubNub pn("demo", "demo", &cb, NULL);
	std::vector<std::string> channels;
	pn.subscribe_multi(channels, -1);
	ASSERT_TRUE(subscribeMultiCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.subscribe("channel", -1, cb_fun2, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
}

TEST_F(PubNubCppTest, PubNubHistory) {
	PubNub pn("demo", "demo", &cb, NULL);
	pn.history("channel", 10, -1);
	ASSERT_TRUE(historyCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.history("channel", 10, -1, cb_fun, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
}

TEST_F(PubNubCppTest, PubNubHereNow) {
	PubNub pn("demo", "demo", &cb, NULL);
	pn.here_now("channel", -1);
	ASSERT_TRUE(herenowCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.here_now("channel", -1, cb_fun, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
}

TEST_F(PubNubCppTest, PubNubTime) {
	PubNub pn("demo", "demo", &cb, NULL);
	pn.time(-1);
	ASSERT_TRUE(timeCalled);
	ASSERT_FALSE(cb_funCalled);
	pn.time(-1, cb_fun, this);
	ASSERT_TRUE(cb_funCalled);
	ASSERT_TRUE(&pn == _pn);
	ASSERT_TRUE(this == _data);
}
