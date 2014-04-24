# Compile using `make XCFLAGS=-DDEBUG` to enable debugging code.
CUSTOM_CFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS= -I. -I../libpubnub `pkg-config --cflags json libcurl libcrypto libpubnub-cpp`
LIBS=`pkg-config --libs json libcurl libcrypto libpubnub-cpp`-lgtest -lpthread
LDFLAGS=

OBJS=itesting.o waiting.o server.o

all: itesting

itesting: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o itesting


-include ../../Makefile.lib
