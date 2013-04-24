CUSTOM_CXXFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS=`pkg-config --cflags libpubnub-cpp`
LIBS=`pkg-config --libs libpubnub-cpp`

OBJS=example-libevent-demo-cpp.o

all: example-libevent-demo-cpp

example-libevent-demo-cpp: example-libevent-demo-cpp.o
	$(call cmd,cxxlink)

clean:
	rm -f *.o example-libevent-demo-cpp

install:

-include ../../Makefile.lib
