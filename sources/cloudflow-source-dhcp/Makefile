# sources/cloudflow-source-dhcp/Makefile
#
# Builds build/libcloudflow-source-dhcp.a from src/ (the DHCP-specific
# pipeline: dhcp_bpf, formatter, config, stats) and the cloudflow-source-dhcp
# binary. The generic capture layer (rx-ring, pcap replay, queue policy, rx
# stats, cBPF assembler) now lives in libs/cloudflow-capture and is linked in;
# only the DHCP-specific filter leaf (src/dhcp_bpf.c, built on cf_bpf) and the
# event formatter remain here.
#
# formatter.c builds Cloudflow__V1__CloudFlowEvent trees with protobuf-c, so
# CPPFLAGS grows the packet library's headers, the generated codec headers,
# libprotobuf-c's headers, and the capture library's headers. The archive
# itself still only needs headers (no link step); test/test-asan below are
# what actually pull in the library archives.
#
# `make -C sources/cloudflow-source-dhcp all test clean` must work standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

CAPTURE_DIR := $(ROOT)/libs/cloudflow-capture
CAPTURE_LIB := $(CAPTURE_DIR)/build/libcloudflow-capture.a

PACKET_DIR := $(ROOT)/libs/cloudflow-packet
PACKET_LIB := $(PACKET_DIR)/build/libcloudflow-packet.a

CODEC_DIR     := $(ROOT)/libs/cloudflow-codec
CODEC_GEN_DIR := $(CODEC_DIR)/gen
CODEC_LIB     := $(CODEC_DIR)/build/libcloudflow-codec.a

REDIS_DIR := $(ROOT)/libs/cloudflow-redis
REDIS_LIB := $(REDIS_DIR)/build/libcloudflow-redis.a

FIXTURES_DIR := $(ROOT)/tests/fixtures/dhcp

# config.c (libyaml) and main.c (cf_redis_producer.h) grow the include path
# with the redis library headers and yaml/hiredis pkg-config cflags.
YAML_CFLAGS    := $(shell pkg-config --cflags yaml-0.1)
YAML_LIBS      := $(shell pkg-config --libs yaml-0.1)
HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)
PROTOBUF_LIBS  := $(shell pkg-config --libs libprotobuf-c)

CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(CAPTURE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) -I$(REDIS_DIR) \
            $(shell pkg-config --cflags libprotobuf-c) $(YAML_CFLAGS) $(HIREDIS_CFLAGS)

BUILD_DIR := build

# Library sources (DHCP-specific pipeline modules). main.c is NOT archived
# here -- it defines main() and links straight into $(BIN).
SOURCES := src/dhcp_bpf.c src/formatter.c src/config.c src/stats.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-source-dhcp.a

# The application binary.
BIN := $(BUILD_DIR)/cloudflow-source-dhcp

.PHONY: all test test-asan clean

all: $(LIB) $(BIN)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CAPTURE_LIB):
	$(MAKE) -C $(CAPTURE_DIR) all

$(PACKET_LIB):
	$(MAKE) -C $(PACKET_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(REDIS_LIB):
	$(MAKE) -C $(REDIS_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# ---------------------------------------------------------------------------
# cloudflow-source-dhcp binary: links the source library archive plus the
# capture, redis, packet, codec, and core libraries and their external deps
# (hiredis, protobuf-c, yaml), with -pthread for the three pipeline threads.
BIN_LDLIBS := $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(YAML_LIBS) -pthread

$(BIN): $(BUILD_DIR)/src/main.o $(LIB) $(CAPTURE_LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/src/main.o $(LIB) $(CAPTURE_LIB) $(REDIS_LIB) $(PACKET_LIB) \
	    $(CODEC_LIB) $(CORE_LIB) $(BIN_LDLIBS)

# ---------------------------------------------------------------------------
# test: CUnit acceptance suites -- tests/formatter_test.c (the event
# formatter) and tests/dhcp_bpf_test.c (the DHCP cBPF filter byte-identical
# invariant). formatter_test needs the packet/codec libraries, the capture
# library (pcap replay + queue policy), and libprotobuf-c; dhcp_bpf_test needs
# only the capture library (cf_bpf) and libcunit.
FORMATTER_TEST_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(CAPTURE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                            $(shell pkg-config --cflags libprotobuf-c) -pthread \
                            -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
FORMATTER_TEST_LDLIBS := -lcunit -pthread $(shell pkg-config --libs libprotobuf-c)

FORMATTER_TEST_BIN := $(BUILD_DIR)/formatter_test

$(BUILD_DIR)/formatter_test.o: tests/formatter_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(FORMATTER_TEST_CPPFLAGS) -c $< -o $@

$(FORMATTER_TEST_BIN): $(BUILD_DIR)/formatter_test.o $(LIB) $(CAPTURE_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/formatter_test.o $(LIB) $(CAPTURE_LIB) $(PACKET_LIB) $(CODEC_LIB) \
	    $(CORE_LIB) $(FORMATTER_TEST_LDLIBS)

DHCP_BPF_TEST_CPPFLAGS := -I. -Isrc -I$(CAPTURE_DIR)
DHCP_BPF_TEST_LDLIBS   := -lcunit

DHCP_BPF_TEST_BIN := $(BUILD_DIR)/dhcp_bpf_test

$(BUILD_DIR)/dhcp_bpf_test.o: tests/dhcp_bpf_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DHCP_BPF_TEST_CPPFLAGS) -c $< -o $@

$(DHCP_BPF_TEST_BIN): $(BUILD_DIR)/dhcp_bpf_test.o $(LIB) $(CAPTURE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/dhcp_bpf_test.o $(LIB) $(CAPTURE_LIB) $(DHCP_BPF_TEST_LDLIBS)

test: $(FORMATTER_TEST_BIN) $(DHCP_BPF_TEST_BIN)
	./$(FORMATTER_TEST_BIN)
	./$(DHCP_BPF_TEST_BIN)

# ---------------------------------------------------------------------------
# test-asan: ASan+UBSan build of the CUnit suites. Every library source the
# binary needs is recompiled straight into the instrumented binary (linking
# the plain, uninstrumented .a would leave that code itself uninstrumented),
# with a per-source object prefix so these objects never collide with the
# plain build above. The capture-layer sources the formatter suite exercises
# (cf_pcap_replay.c, cf_queue_policy.c) are compiled from libs/cloudflow-capture.
ASAN_CFLAGS  := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LDFLAGS := -fsanitize=address,undefined $(LDFLAGS) -pthread
ASAN_LDLIBS  := -lcunit -pthread $(shell pkg-config --libs libprotobuf-c)

ASAN_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(CAPTURE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                 $(shell pkg-config --cflags libprotobuf-c) -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"

ASAN_TEST_SOURCES    := tests/formatter_test.c src/formatter.c
ASAN_CAPTURE_SOURCES := cf_pcap_replay.c cf_queue_policy.c
ASAN_CORE_SOURCES    := cloudflow.c cf_time.c cf_sync.c cf_log.c cf_event_id.c sha256.c cf_queue.c
ASAN_PACKET_SOURCES  := cf_decap.c cf_ipfmt.c cf_dhcpv4.c cf_dhcpv4_decode.c cf_dhcpv4_util.c \
                        cf_dhcpv4_optnames.c cf_dhcpv6.c cf_dhcpv6_decode.c cf_dhcpv6_util.c \
                        cf_dhcpv6_optnames.c
ASAN_GEN_SOURCES     := common.pb-c.c dhcp.pb-c.c dns.pb-c.c envelope.pb-c.c

ASAN_OBJECTS := $(addprefix $(BUILD_DIR)/asan_formatter_,$(notdir $(ASAN_TEST_SOURCES:.c=.o))) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_CAPTURE_SOURCES:.c=.o)) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_CORE_SOURCES:.c=.o)) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_PACKET_SOURCES:.c=.o)) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_GEN_SOURCES:.c=.o))

ASAN_BIN := $(BUILD_DIR)/formatter_test_asan

$(BUILD_DIR)/asan_formatter_formatter_test.o: tests/formatter_test.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_formatter.o: src/formatter.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(CAPTURE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(CORE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(ASAN_BIN): $(ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(ASAN_OBJECTS) $(ASAN_LDLIBS)

# dhcp_bpf byte-identical test under ASan/UBSan: dhcp_bpf.c + cf_bpf.c only.
ASAN_BPF_CPPFLAGS := -I. -Isrc -I$(CAPTURE_DIR)
ASAN_BPF_LDLIBS   := -lcunit

$(BUILD_DIR)/asan_dhcp_bpf_dhcp_bpf_test.o: tests/dhcp_bpf_test.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_BPF_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcp_bpf_dhcp_bpf.o: src/dhcp_bpf.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_BPF_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcp_bpf_cf_bpf.o: $(CAPTURE_DIR)/cf_bpf.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_BPF_CPPFLAGS) -c $< -o $@

ASAN_BPF_BIN := $(BUILD_DIR)/dhcp_bpf_test_asan

$(ASAN_BPF_BIN): $(BUILD_DIR)/asan_dhcp_bpf_dhcp_bpf_test.o $(BUILD_DIR)/asan_dhcp_bpf_dhcp_bpf.o \
                 $(BUILD_DIR)/asan_dhcp_bpf_cf_bpf.o
	$(CC) $(ASAN_LDFLAGS) -o $@ $^ $(ASAN_BPF_LDLIBS)

test-asan: $(ASAN_BIN) $(ASAN_BPF_BIN)
	./$(ASAN_BIN)
	./$(ASAN_BPF_BIN)

clean:
	rm -rf $(BUILD_DIR)
