#ifndef _PUBNUB_GTEST
#define _PUBNUB_GTEST

#include <stdio.h>

#ifdef _WIN32

#include <tchar.h>
#define _VARIADIC_MAX 10
#define snprintf _snprintf

#endif // _WIN32

#include "gtest/gtest.h"

#endif // _PUBNUB_GTEST