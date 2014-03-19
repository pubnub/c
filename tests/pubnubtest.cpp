
#include "gtest.h"

#include <curl/curl.h>


namespace Test {

#include "../libpubnub/crypto.h"
#include "../libpubnub/pubnub.h"
#include "../libpubnub/pubnub-priv.h"

#undef PUBNUB_API
#define PUBNUB_API

static bool curlInit = false;


CURLM *curl_multi_init(void)
{
	curlInit = true;
	return ::curl_multi_init();
}

CURLMsg *curl_multi_info_read( CURLM *multi_handle,   int *msgs_in_queue)
{
	return NULL;
}

CURLMcode curl_multi_socket_action(CURLM * multi_handle,
                                    curl_socket_t sockfd, int ev_bitmask,
                                    int *running_handles)
{
	return CURLM_OK;
}

#include "../libpubnub/pubnub.c"


class PubnubTest : public ::testing::Test
{
protected:
	pubnub_callbacks cb;
	pubnub *p;
	char *url;

	static int addSock;
	static int addSockMode;

	static void
	pubnub_test_add_socket(struct pubnub *p, void *ctx_data, int fd, int mode,
			void (*cb)(struct pubnub *p, int fd, int mode, void *cb_data), void *cb_data)
	{
		addSock = fd;
		addSockMode = mode;
	}

	static int remSock;

	static void
	pubnub_test_rem_socket(struct pubnub *p, void *ctx_data, int fd)
	{
		remSock = fd;
	}

	static void
	pubnub_test_timeout(struct pubnub *p, void *ctx_data, const struct timespec *ts,
			void (*cb)(struct pubnub *p, void *cb_data), void *cb_data)
	{
	}

	static void
	pubnub_test_wait(struct pubnub *p, void *ctx_data)
	{
	}

	virtual void SetUp() {

		memset(&cb, 0, sizeof(cb));
		cb.add_socket = pubnub_test_add_socket;
		cb.rem_socket = pubnub_test_rem_socket;
		cb.timeout = pubnub_test_timeout;
		cb.wait = pubnub_test_wait;

		curlInit = false;

		p = pubnub_init("demo", "demo", &cb, NULL);

		addSock = remSock = 0;
		addSockMode = 0;
	}
	virtual void TearDown() {
		pubnub_done(p);
	}
};

int PubnubTest::addSock, PubnubTest::addSockMode, PubnubTest::remSock;

TEST_F(PubnubTest, Publish) {
	ASSERT_TRUE(curlInit);
	json_object *msg;
	msg = json_object_new_object();
	json_object_object_add(msg, "str", json_object_new_string("test"));
	pubnub_publish(p, "channel", msg, -1, NULL, NULL);
	json_object_put(msg);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	EXPECT_STREQ("http://pubsub.pubnub.com/publish/demo/demo/0/channel/0/%7B%20%22str%22%3A%20%22test%22%20%7D", url);
}

TEST_F(PubnubTest, Subscribe) {
	ASSERT_TRUE(curlInit);
	pubnub_subscribe(p, "channel", -1, NULL, NULL);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	char *p = strchr(url,'=');
	ASSERT_TRUE(p);
	char *s = strdup(url);
	s[p - url] = 0;
	EXPECT_STREQ("http://pubsub.pubnub.com/subscribe/demo/channel/0/0?uuid", s);
	free(s);
}

TEST_F(PubnubTest, SubscribeMulti) {
	ASSERT_TRUE(curlInit);
	const char *channels[] = {"channel1", "channel2"};
	pubnub_subscribe_multi(p, channels, 2, -1, NULL, NULL);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	char *p = strchr(url,'=');
	ASSERT_TRUE(p);
	char *s = strdup(url);
	s[p - url] = 0;
	EXPECT_STREQ("http://pubsub.pubnub.com/subscribe/demo/channel1%2Cchannel2/0/0?uuid", s);
	free(s);
}

TEST_F(PubnubTest, History) {
	ASSERT_TRUE(curlInit);
	pubnub_history(p, "channel", 10, -1, NULL, NULL);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	EXPECT_STREQ("http://pubsub.pubnub.com/history/demo/channel/0/10", url);
}

TEST_F(PubnubTest, HereNow) {
	ASSERT_TRUE(curlInit);
	pubnub_here_now(p, "channel", -1, NULL, NULL);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	EXPECT_STREQ("http://pubsub.pubnub.com/v2/presence/sub-key/demo/channel/channel", url);
}

TEST_F(PubnubTest, Time) {
	ASSERT_TRUE(curlInit);
	pubnub_time(p, -1, NULL, NULL);
	curl_easy_getinfo(p->curl, CURLINFO_EFFECTIVE_URL, &url);
	EXPECT_STREQ("http://pubsub.pubnub.com/time/0", url);
}

TEST(ChannelSetTest, AddRemove) {
	struct channelset cs = {NULL, 0};
	EXPECT_EQ(0, channelset_add(&cs, &cs));
	const char *ch1[] = {"abc", "cde"};
	struct channelset cs1 = {ch1, 2};
	EXPECT_EQ(0, channelset_add(&cs1, &cs1));
	const char *ch2[] = {"abc", "fgh", "cde"};
	struct channelset cs2 = {ch2, 3};
	struct channelset *cs3 = (struct channelset*)calloc(1, sizeof(struct channelset));
	EXPECT_EQ(2, channelset_add(cs3, &cs1));
	EXPECT_EQ(1, channelset_add(cs3, &cs2));
	EXPECT_EQ(2, channelset_rm(cs3, &cs1));
	EXPECT_EQ(0, channelset_rm(cs3, &cs1));
	EXPECT_STREQ(ch2[1], cs3->set[0]);
	EXPECT_EQ(1, channelset_rm(cs3, &cs2));
	free(cs3);
}

}

