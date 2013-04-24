CUSTOM_CXXFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS=`pkg-config --cflags libpubnub-cpp`
LIBS=`pkg-config --libs libpubnub-cpp`

OBJS=example-sync-demo-cpp

all: example-sync-demo-cpp

example-sync-demo-cpp: example-sync-demo-cpp.o
	$(call cmd,cxxlink)

clean:
	rm -f *.o example-sync-demo-cpp

install:

-include ../../Makefile.lib
