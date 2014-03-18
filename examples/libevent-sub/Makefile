CUSTOM_CFLAGS=-Wall -ggdb3 -O3
SYS_CFLAGS=-std=gnu99 `pkg-config --cflags libpubnub`
LIBS=`pkg-config --libs libpubnub`

OBJS=example-libevent-sub.o

all: example-libevent-sub

example-libevent-sub: example-libevent-sub.o
	$(call cmd,link)

clean:
	rm -f *.o example-libevent-sub

install:

-include ../../Makefile.lib
