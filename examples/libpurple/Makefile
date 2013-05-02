LIBNAME = libpubnub.so

.PHONY: all
all: $(LIBNAME)

C_SRCS = pubnub.c events.c

# Object file names using 'Substitution Reference'
C_OBJS = $(C_SRCS:.c=.o)

CC = gcc
LD = $(CC)
CFLAGS_PURPLE = $(shell pkg-config --cflags purple json)
CFLAGS = \
    -g \
    -O2 \
    -Wall \
    -Wextra \
    -fPIC \
    -DPURPLE_PLUGINS \
    -DPIC -DENABLE_NLS \
    $(CFLAGS_PURPLE)

LIBS = $(shell pkg-config --libs purple libpubnub json)
LDFLAGS = -shared

%.o: %.c pubnub_libpurple.h
	$(V_CC)$(CC) -c $(CFLAGS) -o $@ $<

$(LIBNAME): $(C_OBJS)
	$(V_LINK)$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

PLUGIN_DIR_PURPLE:=$(shell pkg-config --variable=plugindir purple)
DATA_ROOT_DIR_PURPLE:=$(shell pkg-config --variable=datarootdir purple)

.PHONY: install
install: $(LIBNAME)
	install -D $(LIBNAME) $(PLUGIN_DIR_PURPLE)/$(LIBNAME)
	install --mode=0644 pubnub16.png $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/16/pubnub.png
	install --mode=0644 pubnub22.png $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/22/pubnub.png
	install --mode=0644 pubnub48.png $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/48/pubnub.png

.PHONY: uninstall
uninstall: $(LIBNAME)
	rm $(PLUGIN_DIR_PURPLE)/$(LIBNAME)
	rm $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/16/pubnub.png
	rm $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/22/pubnub.png
	rm $(DATA_ROOT_DIR_PURPLE)/pixmaps/pidgin/protocols/48/pubnub.png

.PHONY: clean
clean:
	-rm *.o
	-rm $(LIBNAME)


# Quiet by default
VERBOSE ?= 0

# Define printf macro
v_printf = @printf "  %-8s%s\n"

# Define C verbose macro
V_CC = $(v_CC_$(V))
v_CC_ = $(v_CC_$(VERBOSE))
v_CC_0 = $(v_printf) CC $(@F);

# Define LINK verbose macro
V_LINK = $(v_LINK_$(V))
v_LINK_ = $(v_LINK_$(VERBOSE))
v_LINK_0 = $(v_printf) LINK $(@F);
