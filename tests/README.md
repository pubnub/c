Running Tests
=============

These are pretty tight unit tests that do not involve any communication
with the network server either.  In the integration/ directory, we cover
some cases of actual network communication.

We use the Google tests (gtest) framework.

Installation google testing framework
-------------------------------------

## Debian compatible

Install the libgtest-dev package.

## Other Linux/Mac OS X

1. Get the googletest framework

		wget http://googletest.googlecode.com/files/gtest-1.7.0.zip

2. Unzip in some directory

		unzip gtest-1.7.0.zip

3. Adjust the Makefile in the directory of this README, modifying the
   GTEST_DIR variable value near the top of the file, passing the path
   to the unpacked gtest.  Alternatively, pass GTEST_DIR=... on the
   commandline of `make` below.

## MS Windows

See [msvc](../msvc)

Building and running tests
--------------------------

## Linux/Mac OS X

	make
	./libtest

## MS Windows

See [msvc](../msvc)
