
#include "itesting.h"
#ifdef _WIN32
#include "windows.h"
#endif

int main(int argc, char* argv[])
{
#ifdef _WIN32
	WSADATA WSAData;
	WSAStartup(0x101, &WSAData);
#endif
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
