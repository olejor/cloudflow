# libs/cloudflow-packet/Makefile
#
# Builds libcloudflow-packet.a. SOURCES live next to this Makefile -- copied
# verbatim from the libs/cloudflow-core/Makefile template (WP-01 convention).
#
# WP-06 adds the DHCPv4 parser (cf_dhcpv4*.c), which builds
# Cloudflow__V1__DhcpV4PacketEvent trees using the generated protobuf-c
# types from libs/cloudflow-codec/gen, so CPPFLAGS grows the codec gen dir
# and libprotobuf-c's own headers on top of WP-05's plain "-I.". This
# library still only builds an archive of object files (no link step), so
# it does not need libprotobuf-c's *libs* -- only its headers; the
# consumers that link a final binary (tests/unit, tests/fuzz) pull in
# libcloudflow-codec.a and `pkg-config --libs libprotobuf-c` themselves,
# the same way tests/unit/Makefile's cf_codec_test already does.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CODEC_GEN_DIR := $(ROOT)/libs/cloudflow-codec/gen

CPPFLAGS := -I. -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)

BUILD_DIR := build

SOURCES := cf_decap.c cf_ipfmt.c cf_parse_util.c cf_dns.c \
           cf_dhcpv4.c cf_dhcpv4_decode.c cf_dhcpv4_util.c cf_dhcpv4_optnames.c \
           cf_dhcpv6.c cf_dhcpv6_decode.c cf_dhcpv6_util.c cf_dhcpv6_optnames.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-packet.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
