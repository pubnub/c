
#include "gtest.h"


#include "gtest.h"

namespace Test {

#include "../libpubnub/pubnub.h"
#include "../libpubnub/pubnub-priv.h"

#undef PUBNUB_API
#define PUBNUB_API

struct pubnub_sync;

class SyncTest : public ::testing::Test
{
public:
	pubnub *p;
	static struct pubnub_sync *sync;
	static int _nfds;
	static int poll(struct pollfd *ufds, unsigned int nfds, int timeout);
	virtual void SetUp();
	virtual void TearDown();
};

#ifdef _MSC_VER
int WSAPoll(struct pollfd *ufds, int nfds, int timeout)
#else
int poll(struct pollfd *ufds, int nfds, int timeout)
#endif
{
	return SyncTest::poll(ufds, nfds, timeout);
}

#include "../libpubnub/pubnub-sync.c"

struct pubnub_sync *SyncTest::sync;
int SyncTest::_nfds;

int SyncTest::poll(struct pollfd *ufds, unsigned int nfds, int timeout) {
	sync->stop = true;
	_nfds = nfds;
	return -1;
}

void SyncTest::SetUp() {
	sync = pubnub_sync_init();
	p = pubnub_init("demo", "demo", &pubnub_sync_callbacks, sync);
	_nfds = 0;
}
void SyncTest::TearDown() {
	pubnub_done(p);
}

TEST_F(SyncTest, WaitOneSocket) {
	pubnub_sync_add_socket(p, p->cb_data, 10, 1, NULL, NULL);
	pubnub_sync_wait(p, p->cb_data);
	EXPECT_EQ(1, _nfds);
}

TEST_F(SyncTest, WaitTwoSockets) {
	pubnub_sync_add_socket(p, p->cb_data, 10, 1, NULL, NULL);
	pubnub_sync_add_socket(p, p->cb_data, 10, 2, NULL, NULL);
	pubnub_sync_wait(p, p->cb_data);
	EXPECT_EQ(2, _nfds);
}

TEST_F(SyncTest, StopWait) {
	sync->stop = false;
	pubnub_sync_stop_wait(p, p->cb_data);
	EXPECT_TRUE(sync->stop);
}

}
