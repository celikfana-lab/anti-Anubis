# Native messaging host for the Anubis Native Solver extension.
#
# The host is statically linked on purpose: snap Firefox runs native hosts
# inside its own mount namespace (core24), where the host's libcrypto/libc are
# not visible (and the host glibc is newer than core24's).

CC      ?= gcc
SRC     := solver
CFLAGS  ?= -O3 -g -Wall -Wextra -Wno-deprecated-declarations
CFLAGS  += -std=gnu11 -I$(SRC) -pthread
LDLIBS  := -lcrypto -lpthread -lm -ldl -lzstd -lz

SOURCES := anubis_native.c $(SRC)/anubis.c $(SRC)/hashx.c $(SRC)/util.c
HEADERS := $(SRC)/anubis.h $(SRC)/hashx.h $(SRC)/util.h

all: anubis_native

anubis_native: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -static -o $@ $(SOURCES) $(LDLIBS)

dynamic: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o anubis_native.dynamic $(SOURCES) $(LDLIBS)

clean:
	rm -f anubis_native anubis_native.dynamic

.PHONY: all dynamic clean
