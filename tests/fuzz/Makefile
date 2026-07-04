# tests/fuzz/Makefile
#
# Plain gcc build for the AFL fuzz harness(es) in this directory --
# deliberately does NOT include mk/toolchain.mk (no -Werror, no hardening
# flags that fight afl-gcc/afl-clang-fast instrumentation) and is NOT
# wired into the top-level Makefile's SUBDIRS or `make test`. Per
# docs/dhcp-source.md (WP-05/WP-06), the harnesses only
# need to exist and build; running them under AFL is a manual/local step
# (see README.md in this directory).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
PACKET_DIR := $(ROOT)/libs/cloudflow-packet
PACKET_LIB := $(PACKET_DIR)/build/libcloudflow-packet.a
CODEC_DIR := $(ROOT)/libs/cloudflow-codec
CODEC_GEN_DIR := $(CODEC_DIR)/gen
CODEC_LIB := $(CODEC_DIR)/build/libcloudflow-codec.a

# Override on the command line to fuzz, e.g.:
#   make CC=afl-gcc
CC ?= gcc
CFLAGS ?= -std=gnu11 -O1 -g -Wall -Wextra -I$(PACKET_DIR)

# dhcpv4_fuzz.c/dhcpv6_fuzz.c additionally need the generated protobuf-c
# headers/lib (cf_dhcpv4.h/cf_dhcpv6.h pull in cloudflow/v1/dhcp.pb-c.h) on
# top of decap_fuzz's plain -I$(PACKET_DIR).
DHCPV4_CFLAGS := $(CFLAGS) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
DHCPV4_LDLIBS := $(shell pkg-config --libs libprotobuf-c)

DHCPV6_CFLAGS := $(CFLAGS) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
DHCPV6_LDLIBS := $(shell pkg-config --libs libprotobuf-c)

# dns_fuzz.c likewise needs the generated protobuf-c headers/lib (cf_dns.h
# pulls in cloudflow/v1/dns.pb-c.h) on top of decap_fuzz's plain
# -I$(PACKET_DIR).
DNS_CFLAGS := $(CFLAGS) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
DNS_LDLIBS := $(shell pkg-config --libs libprotobuf-c)

BIN := decap_fuzz
DHCPV4_BIN := dhcpv4_fuzz
DHCPV6_BIN := dhcpv6_fuzz
DNS_BIN := dns_fuzz

.PHONY: all clean

all: $(BIN) $(DHCPV4_BIN) $(DHCPV6_BIN) $(DNS_BIN)

$(PACKET_LIB):
	$(MAKE) -C $(PACKET_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(BIN): decap_fuzz.c $(PACKET_LIB)
	$(CC) $(CFLAGS) -o $@ decap_fuzz.c $(PACKET_LIB)

$(DHCPV4_BIN): dhcpv4_fuzz.c $(PACKET_LIB) $(CODEC_LIB)
	$(CC) $(DHCPV4_CFLAGS) -o $@ dhcpv4_fuzz.c $(PACKET_LIB) $(CODEC_LIB) $(DHCPV4_LDLIBS)

$(DHCPV6_BIN): dhcpv6_fuzz.c $(PACKET_LIB) $(CODEC_LIB)
	$(CC) $(DHCPV6_CFLAGS) -o $@ dhcpv6_fuzz.c $(PACKET_LIB) $(CODEC_LIB) $(DHCPV6_LDLIBS)

$(DNS_BIN): dns_fuzz.c $(PACKET_LIB) $(CODEC_LIB)
	$(CC) $(DNS_CFLAGS) -o $@ dns_fuzz.c $(PACKET_LIB) $(CODEC_LIB) $(DNS_LDLIBS)

clean:
	rm -f $(BIN) $(DHCPV4_BIN) $(DHCPV6_BIN) $(DNS_BIN)
