# Compile using `make XCFLAGS=-DDEBUG` to enable debugging code.
CUSTOM_CFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS= -I. -I../libpubnub `pkg-config --cflags json libcurl libcrypto libevent`
LIBS=`pkg-config --libs json libcurl libcrypto libevent`
LDFLAGS=

OBJS=pubnubtest.o synctest.o libeventtest.o cryptotest.o gtest.o

all: libtest

libtest: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o libtest


-include ../Makefile.lib
