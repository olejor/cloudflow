# sources/cloudflow-source-dhcp/Makefile
#
# Builds build/libcloudflow-source-dhcp.a from src/ (WP-08: rx_reader,
# pcap_replay, queue_policy; later WPs add formatter.c, config.c, stats.c,
# main.c to SOURCES and a cloudflow-source-dhcp binary target here).
# Follows the libs/cloudflow-core Makefile template, plus a `test` target
# this Makefile owns directly -- like libs/cloudflow-redis, tests/unit/ is
# owned by a parallel WP right now, so WP-08's CUnit suite
# (tests/rx_reader_test.c) lives under this directory's own tests/ instead.
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

CPPFLAGS := -I. -Isrc -I$(CORE_DIR)

BUILD_DIR := build

SOURCES := src/rx_reader.c src/pcap_replay.c src/queue_policy.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-source-dhcp.a

.PHONY: all test clean rx-smoke

all: $(LIB)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# ---------------------------------------------------------------------------
# test: CUnit acceptance suite (tests/rx_reader_test.c). Needs pthread (the
# block-mode policy test spawns a consumer thread) on top of libcunit.
TEST_CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -pthread
TEST_LDLIBS   := -lcunit -pthread

TEST_BIN := $(BUILD_DIR)/rx_reader_test

$(BUILD_DIR)/rx_reader_test.o: tests/rx_reader_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/rx_reader_test.o $(LIB) $(CORE_LIB) $(TEST_LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

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
