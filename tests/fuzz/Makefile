# tests/fuzz/Makefile
#
# Plain gcc build for the AFL fuzz harness(es) in this directory --
# deliberately does NOT include mk/toolchain.mk (no -Werror, no hardening
# flags that fight afl-gcc/afl-clang-fast instrumentation) and is NOT
# wired into the top-level Makefile's SUBDIRS or `make test`. Per
# docs/design/02-packet-and-parsing.md (WP-05), the harness only needs to
# exist and build; running it under AFL is a manual/local step (see
# README.md in this directory).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
PACKET_DIR := $(ROOT)/libs/cloudflow-packet
PACKET_LIB := $(PACKET_DIR)/build/libcloudflow-packet.a

# Override on the command line to fuzz, e.g.:
#   make CC=afl-gcc
CC ?= gcc
CFLAGS ?= -std=gnu11 -O1 -g -Wall -Wextra -I$(PACKET_DIR)

BIN := decap_fuzz

.PHONY: all clean

all: $(BIN)

$(PACKET_LIB):
	$(MAKE) -C $(PACKET_DIR) all

$(BIN): decap_fuzz.c $(PACKET_LIB)
	$(CC) $(CFLAGS) -o $@ decap_fuzz.c $(PACKET_LIB)

clean:
	rm -f $(BIN)
