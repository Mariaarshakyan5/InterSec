CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
CFLAGS  += -pthread $(shell pkg-config --cflags libnetfilter_queue libcrypto)
LDLIBS  += $(shell pkg-config --libs libnetfilter_queue libcrypto) -pthread

secgw: secgw.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

test: secgw
	./secgw -t

clean:
	rm -f secgw
.PHONY: test clean
