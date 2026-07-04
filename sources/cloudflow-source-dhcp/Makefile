# sources/cloudflow-source-dhcp/Makefile
#
# Builds build/libcloudflow-source-dhcp.a from src/ (WP-08: rx_reader,
# pcap_replay, queue_policy; WP-10 adds formatter.c; later WPs add config.c,
# stats.c, main.c to SOURCES and a cloudflow-source-dhcp binary target here).
# Follows the libs/cloudflow-core Makefile template, plus a `test` target
# this Makefile owns directly -- like libs/cloudflow-redis, tests/unit/ is
# owned by a parallel WP right now, so WP-08/WP-10's CUnit suites
# (tests/rx_reader_test.c, tests/formatter_test.c) live under this
# directory's own tests/ instead.
#
# WP-10's formatter.c builds Cloudflow__V1__CloudFlowEvent trees with
# protobuf-c, so CPPFLAGS grows the packet library's headers (cf_decap.h,
# cf_dhcpv4.h, cf_dhcpv6.h, cf_ipfmt.h) and the generated codec headers/
# libprotobuf-c's own headers, mirroring libs/cloudflow-packet/Makefile's
# comment on the same topic. The archive itself still only needs headers
# (no link step); test/test-asan below are what actually pull in
# libcloudflow-packet.a, libcloudflow-codec.a, and libprotobuf-c.
#
# Also provides a hidden `rx-smoke` target (build/rx-smoke): a tiny manual
# test binary that runs rx_reader against a real interface for a few
# seconds and prints stats, used for the CAP_NET_RAW veth acceptance test
# documented in README.md. It is not part of `all`/`test` since it needs a
# real AF_PACKET-capable interface and CAP_NET_RAW/root, neither available
# in an ordinary build/CI environment.
#
# `make -C sources/cloudflow-source-dhcp all test clean` must work standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

PACKET_DIR := $(ROOT)/libs/cloudflow-packet
PACKET_LIB := $(PACKET_DIR)/build/libcloudflow-packet.a

CODEC_DIR     := $(ROOT)/libs/cloudflow-codec
CODEC_GEN_DIR := $(CODEC_DIR)/gen
CODEC_LIB     := $(CODEC_DIR)/build/libcloudflow-codec.a

REDIS_DIR := $(ROOT)/libs/cloudflow-redis
REDIS_LIB := $(REDIS_DIR)/build/libcloudflow-redis.a

FIXTURES_DIR := $(ROOT)/tests/fixtures/dhcp

# WP-11's config.c (libyaml) and main.c (cf_redis_producer.h) grow the include
# path with the redis library headers and yaml/hiredis pkg-config cflags on
# top of WP-10's set.
YAML_CFLAGS    := $(shell pkg-config --cflags yaml-0.1)
YAML_LIBS      := $(shell pkg-config --libs yaml-0.1)
HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)
PROTOBUF_LIBS  := $(shell pkg-config --libs libprotobuf-c)

CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) -I$(REDIS_DIR) \
            $(shell pkg-config --cflags libprotobuf-c) $(YAML_CFLAGS) $(HIREDIS_CFLAGS)

BUILD_DIR := build

# Library sources (WP-08/10 pipeline modules + WP-11 config/stats). main.c is
# NOT archived here -- it defines main() and links straight into $(BIN).
SOURCES := src/rx_reader.c src/pcap_replay.c src/queue_policy.c src/formatter.c \
           src/config.c src/stats.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-source-dhcp.a

# The WP-11 application binary.
BIN := $(BUILD_DIR)/cloudflow-source-dhcp

.PHONY: all test test-asan clean rx-smoke

all: $(LIB) $(BIN)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(PACKET_LIB):
	$(MAKE) -C $(PACKET_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(REDIS_LIB):
	$(MAKE) -C $(REDIS_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# ---------------------------------------------------------------------------
# cloudflow-source-dhcp binary (WP-11): links the source library archive plus
# the redis, packet, codec, and core libraries and their external deps
# (hiredis, protobuf-c, yaml), with -pthread for the three pipeline threads.
BIN_LDLIBS := $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(YAML_LIBS) -pthread

$(BIN): $(BUILD_DIR)/src/main.o $(LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/src/main.o $(LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) \
	    $(CORE_LIB) $(BIN_LDLIBS)

# ---------------------------------------------------------------------------
# test: CUnit acceptance suites -- tests/rx_reader_test.c (WP-08) and
# tests/formatter_test.c (WP-10). Both need pthread (rx_reader_test's
# block-mode policy test spawns a consumer thread; formatter.c itself links
# pthread for its thread wrapper) on top of libcunit; formatter_test.c also
# needs the packet/codec libraries and libprotobuf-c.
TEST_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -pthread
TEST_LDLIBS   := -lcunit -pthread

TEST_BIN := $(BUILD_DIR)/rx_reader_test

$(BUILD_DIR)/rx_reader_test.o: tests/rx_reader_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB) $(TEST_LDLIBS)

FORMATTER_TEST_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                            $(shell pkg-config --cflags libprotobuf-c) -pthread \
                            -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
FORMATTER_TEST_LDLIBS := -lcunit -pthread $(shell pkg-config --libs libprotobuf-c)

FORMATTER_TEST_BIN := $(BUILD_DIR)/formatter_test

$(BUILD_DIR)/formatter_test.o: tests/formatter_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(FORMATTER_TEST_CPPFLAGS) -c $< -o $@

$(FORMATTER_TEST_BIN): $(BUILD_DIR)/formatter_test.o $(LIB) $(CORE_LIB) $(PACKET_LIB) $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/formatter_test.o $(LIB) $(CORE_LIB) $(PACKET_LIB) $(CODEC_LIB) $(FORMATTER_TEST_LDLIBS)

test: $(TEST_BIN) $(FORMATTER_TEST_BIN)
	./$(TEST_BIN)
	./$(FORMATTER_TEST_BIN)

# ---------------------------------------------------------------------------
# test-asan: ASan+UBSan build of tests/formatter_test.c (WP-10's own
# acceptance criterion: "confirm no leaks across all fixtures" -- the
# free-path with an attached PacketObservation subtree is the risky part).
# Follows tests/unit/Makefile's test-asan recipe: every library source
# formatter_test.c's binary actually needs is recompiled straight into this
# binary with instrumentation (linking the plain, uninstrumented .a files
# built by `make all` would leave that code itself uninstrumented), with a
# per-source object prefix (asan_formatter_<file>.o) so these objects never
# collide with the plain $(BUILD_DIR)/*.o build above.
ASAN_CFLAGS  := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LDFLAGS := -fsanitize=address,undefined $(LDFLAGS) -pthread
ASAN_LDLIBS  := -lcunit -pthread $(shell pkg-config --libs libprotobuf-c)

ASAN_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                 $(shell pkg-config --cflags libprotobuf-c) -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"

ASAN_TEST_SOURCES   := tests/formatter_test.c src/formatter.c src/queue_policy.c src/pcap_replay.c
ASAN_CORE_SOURCES   := cloudflow.c cf_time.c cf_sync.c cf_log.c cf_event_id.c sha256.c cf_queue.c
ASAN_PACKET_SOURCES := cf_decap.c cf_ipfmt.c cf_dhcpv4.c cf_dhcpv4_decode.c cf_dhcpv4_util.c \
                       cf_dhcpv4_optnames.c cf_dhcpv6.c cf_dhcpv6_decode.c cf_dhcpv6_util.c \
                       cf_dhcpv6_optnames.c
ASAN_GEN_SOURCES    := common.pb-c.c dhcp.pb-c.c dns.pb-c.c envelope.pb-c.c

ASAN_OBJECTS := $(addprefix $(BUILD_DIR)/asan_formatter_,$(notdir $(ASAN_TEST_SOURCES:.c=.o))) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_CORE_SOURCES:.c=.o)) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_PACKET_SOURCES:.c=.o)) \
                $(addprefix $(BUILD_DIR)/asan_formatter_,$(ASAN_GEN_SOURCES:.c=.o))

ASAN_BIN := $(BUILD_DIR)/formatter_test_asan

$(BUILD_DIR)/asan_formatter_formatter_test.o: tests/formatter_test.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_formatter.o: src/formatter.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_queue_policy.o: src/queue_policy.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_pcap_replay.o: src/pcap_replay.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(CORE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_formatter_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(ASAN_BIN): $(ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(ASAN_OBJECTS) $(ASAN_LDLIBS)

test-asan: $(ASAN_BIN)
	./$(ASAN_BIN)

# ---------------------------------------------------------------------------
# rx-smoke: manual/live-capture harness, see README.md's "Manual veth
# capture test" section. Not part of `all`/`test`.
SMOKE_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -pthread
SMOKE_LDLIBS   := -pthread

SMOKE_BIN := $(BUILD_DIR)/rx-smoke

$(BUILD_DIR)/rx_smoke_main.o: tests/rx_smoke_main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SMOKE_CPPFLAGS) -c $< -o $@

$(SMOKE_BIN): $(BUILD_DIR)/rx_smoke_main.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/rx_smoke_main.o $(LIB) $(CORE_LIB) $(SMOKE_LDLIBS)

rx-smoke: $(SMOKE_BIN)

clean:
	rm -rf $(BUILD_DIR)
