# Compile using `make XCFLAGS=-DDEBUG` to enable debugging code.
CUSTOM_CFLAGS=-Wall -ggdb3 -O3
SYS_CXXFLAGS= -I. -I../libpubnub `pkg-config --cflags json libcurl libcrypto libpubnub-cpp` -pthread
LIBS=`pkg-config --libs json libcurl libcrypto libpubnub-cpp libssl`
LDFLAGS=-pthread

all: itesting

## The section below is specific to the gtest library.

# Points to the root of Google Test source code.  This default
# corresponds to Debian's libgtest-dev package.
GTEST_DIR = /usr/src/gtest

# Flags passed to the preprocessor.
# Set Google Test's header directory as a system directory, such that
# the compiler doesn't generate warnings in Google Test headers.
CUSTOM_CPPFLAGS += -isystem $(GTEST_DIR)/include

# All Google Test headers.  Usually you shouldn't change this
# definition.
GTEST_HEADERS = /usr/include/gtest/*.h \
                /usr/include/gtest/internal/*.h

# Builds gtest.a and gtest_main.a.

# Usually you shouldn't tweak such internal variables, indicated by a
# trailing _.
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

# For simplicity and to avoid depending on Google Test's
# implementation details, the dependencies specified below are
# conservative and not optimized.  This is fine as Google Test
# compiles fast and for ordinary users its source rarely changes.
gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

## End of gtest-specific section.


OBJS=itesting.o waiting.o server.o

itesting: $(OBJS) gtest.a
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o itesting gtest.a gtest_main.a


-include ../../Makefile.lib
