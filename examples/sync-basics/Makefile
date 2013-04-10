CUSTOM_CFLAGS=-Wall -ggdb3 -O3
SYS_CFLAGS=-std=gnu99 `pkg-config --cflags libpubnub`
LIBS=`pkg-config --libs libpubnub`

PROGS=subscribe publish history here_now time
OBJS=$(foreach p,$(PROGS),$(p).o)

all: $(PROGS)

$(PROGS): %: %.o
	$(call cmd,link)

clean:
	rm -f $(OBJS) $(PROGS)

install:

-include ../../Makefile.lib
