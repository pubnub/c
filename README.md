PubNub C Library
================

The generic PubNub C library provides an elegant, easy-to-use but
flexible API for C programs to use the PubNub cloud messaging service.

The library supports multiple event notification backends - this
allows it to be used in a synchronous manner (in simple C programs),
asynchronously with the libevent library, or integrated with any other
event loop as the user can provide their own set of callbacks.

The library should be fully thread safe and signal safe. The code currently
covers only POSIX systems and has not been tested on Windows yet.
Suitable platforms for using this library include Raspberry Pi.

C++ bindings wrapping the C library in a C++ friendly interface is also
distributed alongside.

C Synopsis
----------

Build your program with compile flags as provided by
``pkg-config --cflags libpubnub'' and build flags based on
``pkg-config --libs libpubnub''.

	#include <json.h>
	#include <pubnub.h>
	#include <pubnub-sync.h>

	struct pubnub_sync *sync = pubnub_sync_init();
	struct pubnub *p = pubnub_init("demo", "demo",
			 &pubnub_sync_callbacks, sync);

	pubnub_publish(p, "my_channel", json_object, -1, NULL, NULL);

	do {
		pubnub_subscribe(p, "my_channel", -1, NULL, NULL);
		if (pubnub_sync_last_result(sync) != PNR_OK)
			exit(EXIT_FAILURE);
		struct json_object *msg = pubnub_sync_last_response(sync);
		for (int i = 0; i < json_object_array_length(msg); i++) {
			json_object *msg1 = json_object_array_get_idx(msg, i);
			printf("received: %s\n", json_object_get_string(msg1));
		}
	} while (1);

See the provided examples for more desriptive code.

C++ Synopsis
------------

Build your program with compile flags as provided by
``pkg-config --cflags libpubnub-cpp'' and build flags based on
``pkg-config --libs libpubnub-cpp''.

	#include <json.h>
	#include <pubnub.hpp>
	#include <pubnub-sync.hpp>

	pubnub_sync *sync = pubnub_sync_init();
	PubNub p("demo", "demo", &pubnub_sync_callbacks, sync);

	p.publish("my_channel", json_object);

	do {
		p.subscribe("my_channel");
		PubNub_sync_reply reply = pubnub_sync_last_reply(sync);
		if (reply.result() != PNR_OK)
			exit(EXIT_FAILURE);
		json_object *msg = reply.response();
		for (int i = 0; i < json_object_array_length(msg); i++) {
			json_object *msg1 = json_object_array_get_idx(msg, i);
			std::cout << "received: "
				<< json_object_get_string(msg1) << std::endl;
		}
	} while (1);

See the provided examples for more desriptive code.

Installation
------------

Libraries libevent, libjson, libcurl and OpenSSL are required to build
libpubnub. Since we are compiling the library, it is not enough to have
the libraries installed, you will also need header files (usually distributed
as development packages). On Debian-like systems, use the command:

	sudo apt-get install libevent-dev libjson0-dev libcurl4-openssl-dev libssl-dev

Use the command

	make

to build the library. In case of errors, verify that you really have
all the libraries installed.

By default, the library will be installed to /usr/local. To change
the install location, edit the PREFIX line in ``Makefile'', but you will
need to make arrangements for the ld.so dynamic linker to be able to
find libpubnub in your chosen location (e.g. adding the directory to
/etc/ld.so.conf or using $LD_LIBRARY_PATH environment variable).

After you have made sure the install location matches your expectations
(if you aren't sure, the /usr/local default is a fine choice), run

	sudo make install

and enjoy libpubnub!

API Description
---------------

This section of the documentation is still TODO. In the meantime, please refer
to the header files in libpubnub/ (pubnub.h, pubnub-sync.h, pubnub-libevent.h)
which are heavily commented (in general).

The C++ API wraps the C library. While a full C++ "view" is provided for the
basic struct pubnub (class PubNub in libpubnub-cpp/pubnub.hpp), the libevent
frontend is so thin that a separate C++ view would not make any difference.
The sync frontend struct does not have a C++ view, but information about
the last pubnub call can be accessed through a C++ class as described in
libpubnub-cpp/pubnub-sync.hpp.

Examples
--------

A set of examples to show-case basic and recommended usage of the library
can be found in the examples/ directory. Beginners should first examine
the simplest ``sync-demo'' example which presents a coherent PubNub based
application, or walk through the ``sync-basics'' examples that briefly
demonstrate all the PubNub API calls.

The examples can be built and run after the library itself is installed.
A simple ``make'' command should suffice to build the binary. Refer to the
local README.md files regarding any special details regarding each example.

Some of the C examples have their C++ counterparts in the examples-cpp/
directory.

## Adium, Pidgin, and Finch Chat Plugins
Using our own C client, we've built example chat plugins for Adium, Pidgin, and Finch.

Check them out in our examples directory at https://github.com/pubnub/c/blob/master/examples/libpurple !

