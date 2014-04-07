Microsoft Visual C++ projects:
==============================

Description:
------------

## libevent-demo

C++ libevent demo project (see [examples-cpp/libevent-demo](../examples-cpp/libevent-demo))

## libpub

PubNub library project (see [libpubnub](../libpubnub) + [libpubnub-cpp](../libpubnub-cpp))

## libtest

PubNub library google testing project (see [tests](../tests))

Installation of the libraries:
------------------------------

## libcurl

1. Get curl binary archive [here](http://curl.haxx.se/) or [here](http://www.confusedbycode.com/curl/)

2. Extract it to curl

## json-c

1. Get json-c library

		git clone https://github.com/json-c/json-c.git

2. Open & build json-c.sln

## openssl

1. Get openssl source [archive](https://www.openssl.org/)

2. Unzip it

3. Build it (you should have installed ActivePerl)

		perl Configure VC-WIN32 no-asm --prefix=../openssl
		ms\do_ms
		nmake -f ms\ntdll.mak
		nmake -f ms\ntdll.mak install

## googletest

1. Get google test library [archive](http://googletest.googlecode.com/files/gtest-1.7.0.zip)

2. Unzip it to googletest

3. Open & build msvc/gtest-md.sln

## libevent

1. Get libevent source [here](http://libevent.org/)

2. Unpack it to libevent

3. Build it

		nmake -f Makefile.nmake
