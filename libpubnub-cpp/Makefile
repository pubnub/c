# Compile using `make XCFLAGS=-DDEBUG` to enable debugging code.
CUSTOM_CXXFLAGS=-Wall -ggdb3 -O3
SOFLAGS=-fPIC -fvisibility=internal
SYS_CXXFLAGS=$(SOFLAGS) -I. -I../libpubnub $(shell pkg-config --cflags $(shell pkg-config --exists json-c && echo json-c || echo json) libcurl libcrypto libevent)
LIBS=$(shell pkg-config --libs $(shell pkg-config --exists json-c && echo json-c || echo json) libcurl libcrypto libevent)
LDFLAGS=$(SOFLAGS) -shared -Wl,-soname,libpubnub-cpp.so.0

OBJS=pubnub.o pubnub-sync.o

all: libpubnub-cpp.so.0.1 libpubnub-cpp.pc

libpubnub-cpp.so.0.1: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

libpubnub-cpp.pc: libpubnub-cpp.pc.in
ifndef INCDIR
	$(error INCDIR is undefined; have you run make in the project root?)
endif
	sed -e 's#@LIBDIR@#$(LIBDIR)#g; s#@INCDIR@#$(INCDIR)#g' $^ >$@

clean:
	rm -f *.o libpubnub-cpp.so.0.1 libpubnub-cpp.pc

install:
ifndef INCDIR
	$(error INCDIR is undefined; have you run make in the project root?)
endif
	$(INSTALL) -D -m 0644 pubnub.hpp $(DESTDIR)$(INCDIR)/pubnub.hpp
	$(INSTALL) -D -m 0644 pubnub-sync.hpp $(DESTDIR)$(INCDIR)/pubnub-sync.hpp
	$(INSTALL) -D -m 0755 libpubnub-cpp.so.0.1 $(DESTDIR)$(LIBDIR)/libpubnub-cpp.so.0.1
	ln -s -f libpubnub-cpp.so.0.1 $(DESTDIR)$(LIBDIR)/libpubnub-cpp.so.0
	ln -s -f libpubnub-cpp.so.0.1 $(DESTDIR)$(LIBDIR)/libpubnub-cpp.so
	$(INSTALL) -D -m 0644 libpubnub-cpp.pc $(DESTDIR)$(LIBDIR)/pkgconfig/libpubnub-cpp.pc
	ldconfig

-include ../Makefile.lib
