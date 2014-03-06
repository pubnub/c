#ifndef _PUBNUB_GTEST
#define _PUBNUB_GTEST

#include <stdio.h>

#ifdef _WIN32
#include <tchar.h>
#define _VARIADIC_MAX 10
#define snprintf _snprintf
#endif

#ifdef _WIN32
#define __MINGW32__
struct timespec {
	long tv_sec;
	long tv_nsec;
};
#endif


#include "gtest/gtest.h"

#endif