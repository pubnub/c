Running google tests
====================

Installation google testing framework
-------------------------------------

## Linux/Mac OS X

1. Get the googletest framework

		wget http://googletest.googlecode.com/files/gtest-1.7.0.zip

2. Unzip and build google test

		unzip gtest-1.7.0.zip
		cd gtest-1.7.0
		./configure
		make

3. "Install" the headers and libs on your system.

		sudo cp -a include/gtest /usr/include
		sudo cp -a lib/.libs/* /usr/lib/

Building and running tests
--------------------------

## Linux/Mac OS X

	make
	./libtest

