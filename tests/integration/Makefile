CUSTOM_CXXFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS=`pkg-config --cflags libpubnub-cpp`
LIBS=`pkg-config --libs json libcurl libcrypto libevent`-lgtest

OBJS=itesting.o waiting.o

all: itesting

itesting: $(OBJS)
	$(call cmd,cxxlink)

clean:
	rm -f *.o itesting

install:

-include ../../Makefile.lib
