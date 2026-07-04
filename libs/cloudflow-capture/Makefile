# libs/cloudflow-capture/Makefile
#
# Builds build/libcloudflow-capture.a: the generic packet-capture layer
# extracted out of cloudflow-source-dhcp (synergy item A2) so a second source
# (DNS) can reuse it -- the TPACKET_V3 rx-ring loop (cf_rx_reader), the
# classic-pcap replay reader (cf_pcap_replay), the D9 on_full queue policy
# (cf_queue_policy), the generic rx counters (cf_rx_stats), and the two-pass
# cBPF assembler + UDP/VLAN-offset primitives (cf_bpf). Protocol-specific
# filter leaves (e.g. the DHCP source's dhcp_bpf.c) build on cf_bpf.
#
# Follows the libs/cloudflow-core Makefile template, plus `test`/`test-asan`
# targets this Makefile owns directly (like libs/cloudflow-redis and the DHCP
# source): tests/rx_reader_test.c exercises the offline paths (pcap replay +
# queue policy). A hidden `rx-smoke` target builds the manual live-capture
# harness (needs a real AF_PACKET interface + CAP_NET_RAW, so it is not part
# of `all`/`test`).
#
# `make -C libs/cloudflow-capture all test clean` must work standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

CPPFLAGS := -I. -I$(CORE_DIR)

BUILD_DIR := build

SOURCES := cf_queue_policy.c cf_pcap_replay.c cf_bpf.c cf_rx_reader.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-capture.a

.PHONY: all test test-asan clean rx-smoke

all: $(LIB)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# ---------------------------------------------------------------------------
# test: CUnit suite for the offline capture paths (pcap replay + queue
# policy). Needs pthread (the block-mode policy test spawns a consumer
# thread) on top of libcunit; links the capture archive plus the core
# library.
TEST_CPPFLAGS := -I. -I$(CORE_DIR) -pthread
TEST_LDLIBS   := -lcunit -pthread

TEST_BIN := $(BUILD_DIR)/rx_reader_test

$(BUILD_DIR)/rx_reader_test.o: tests/rx_reader_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB) $(TEST_LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

# ---------------------------------------------------------------------------
# test-asan: ASan+UBSan build of the offline suite. Follows the DHCP source /
# tests/unit recipe: every library source the binary needs is recompiled
# straight into the instrumented binary (linking the plain .a would leave that
# code uninstrumented), with an asan_ object prefix so these never collide
# with the plain build above.
ASAN_CFLAGS  := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LDFLAGS := -fsanitize=address,undefined $(LDFLAGS) -pthread
ASAN_LDLIBS  := -lcunit -pthread

ASAN_CPPFLAGS := -I. -I$(CORE_DIR)

ASAN_TEST_SOURCES    := tests/rx_reader_test.c cf_pcap_replay.c cf_queue_policy.c
ASAN_CORE_SOURCES    := cloudflow.c cf_time.c cf_sync.c cf_log.c cf_event_id.c sha256.c cf_queue.c

ASAN_OBJECTS := $(addprefix $(BUILD_DIR)/asan_,$(notdir $(ASAN_TEST_SOURCES:.c=.o))) \
                $(addprefix $(BUILD_DIR)/asan_,$(ASAN_CORE_SOURCES:.c=.o))

ASAN_BIN := $(BUILD_DIR)/rx_reader_test_asan

$(BUILD_DIR)/asan_rx_reader_test.o: tests/rx_reader_test.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_cf_pcap_replay.o: cf_pcap_replay.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_cf_queue_policy.o: cf_queue_policy.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_%.o: $(CORE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(ASAN_CPPFLAGS) -c $< -o $@

$(ASAN_BIN): $(ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(ASAN_OBJECTS) $(ASAN_LDLIBS)

test-asan: $(ASAN_BIN)
	./$(ASAN_BIN)

# ---------------------------------------------------------------------------
# rx-smoke: manual/live-capture harness. Not part of `all`/`test`.
SMOKE_CPPFLAGS := -I. -I$(CORE_DIR) -pthread
SMOKE_LDLIBS   := -pthread

SMOKE_BIN := $(BUILD_DIR)/rx-smoke

$(BUILD_DIR)/rx_smoke_main.o: tests/rx_smoke_main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SMOKE_CPPFLAGS) -c $< -o $@

$(SMOKE_BIN): $(BUILD_DIR)/rx_smoke_main.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/rx_smoke_main.o $(LIB) $(CORE_LIB) $(SMOKE_LDLIBS)

rx-smoke: $(SMOKE_BIN)

clean:
	rm -rf $(BUILD_DIR)
