
#include <fcntl.h>
#ifdef _MSC_VER
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include "itesting.h"

#include <json.h>

#include "pubnub.hpp"
#include "pubnub-sync.hpp"

class WaitingTest : public ::testing::Test
{
public:
	static const int pubCount = 10;
	PROCESS_INFORMATION pi;

	int _out_pipe[2];
	int _old_out;
	std::string _out;

	virtual void SetUp() {
		_out_pipe[0] = 0;
		_out_pipe[1] = 0;
		_old_out = 0;

		_out.clear();
#if 1
#ifdef _MSC_VER
		if (_pipe(_out_pipe, 65536, O_BINARY) != -1) {
#define READ_PIPE(hnd, buf, size) (eof(hnd) ? 0 : read(hnd, buf, size))
#else		
		if (pipe2(_out_pipe, O_NONBLOCK) != -1) {
#define READ_PIPE(hnd, buf, size) read(hnd, buf, size)
#endif		
			_old_out = dup(fileno(stdout));
			fflush(stdout);
			dup2(_out_pipe[1], fileno(stdout));
		}
#endif
	}

	virtual void TearDown() {
		if (_old_out > 0) {
			dup2(_old_out, fileno(stdout));
			close(_old_out);
		}
		if (_out_pipe[0] > 0) {
			close(_out_pipe[0]);
		}
		if (_out_pipe[1] > 0) {
			close(_out_pipe[1]);
		}
	}

	void run(TCHAR *name) {
		TCHAR fname[256];
		GetModuleFileName(NULL, fname, _countof(fname));
		TCHAR *s = wcsrchr(fname,'\\');
		if (s) {
			s++;
		} else {
			s = fname;
		}
		wcscpy_s(s, _countof(fname) - (s-fname), name);
		STARTUPINFO si;

		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi, sizeof(pi) );

		if (!CreateProcess(fname, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
			printf( "CreateProcess failed (%d).\n", GetLastError() );
		}
	}

	void runSync() {
		run(_T("sync-demo.exe"));
	}

	void runLibEvent() {
		run(_T("libevent-demo.exe"));
	}
#if 1
	void getOut() {
		fflush(stdout);
		if (_old_out > 0) {
			dup2(_old_out, fileno(stdout));
			close(_old_out);
			_old_out = 0;
		}
		std::string buf;
		const int bufSize = 1024;
		buf.resize(bufSize);
		int bytesRead = READ_PIPE(_out_pipe[0], &(*buf.begin()), bufSize);
		while(bytesRead == bufSize) {
			_out += buf;
			bytesRead = READ_PIPE(_out_pipe[0], &(*buf.begin()), bufSize);
		}
		if (bytesRead > 0) {
			buf.resize(bytesRead);
			_out += buf;
		}
	}
#endif
	bool publish() {
		pubnub_sync *sync = pubnub_sync_init();
		PubNub p("demo", "demo", &pubnub_sync_callbacks, sync);
		json_object *msg;

		msg = json_object_new_object();
		json_object_object_add(msg, "num", json_object_new_int(42));
		json_object_object_add(msg, "str", json_object_new_string("integration testing"));

		for (int i = 0; i < pubCount; i++) {
			p.publish("demo_channel", *msg);

			PubNub_sync_reply publish_reply = pubnub_sync_last_reply(sync);
			if (publish_reply.result() != PNR_OK) {
				json_object_put(msg);
				return false;
			}
		}

		json_object_put(msg);
		return true;
	}

	int countOut(std::string substring) {
		int startpos = 0;
		int res = 0;
		getOut();
		while ((startpos = _out.find(substring, startpos+1)) != std::string::npos) {
			++res;
		}
		return res;
	}

	void testing() {
		Sleep(1000);
		EXPECT_TRUE(publish());
		Sleep(2000);
		EXPECT_EQ(pubCount, countOut("integration testing"));
		TerminateProcess(pi.hProcess, 0);
	}
};

TEST_F(WaitingTest, Sync) {
	runSync();
	testing();
}

TEST_F(WaitingTest, LibEvent) {
	runLibEvent();
	testing();
}

