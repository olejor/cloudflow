# tests/unit/Makefile
#
# Builds and runs the CUnit acceptance tests for libcloudflow-core (WP-03),
# the libcloudflow-codec round-trip tests (WP-02), and the cf_queue
# hardening tests (WP-04). Follows the WP-01 sub-Makefile pattern: include
# mk/toolchain.mk, extend CPPFLAGS/LDLIBS rather than overriding
# CFLAGS/LDFLAGS.
#
# Three independent CUnit binaries are built so this file's core-test
# SOURCES list doesn't need to change as later WPs land: build/cf_core_test
# (WP-03), build/cf_codec_test (WP-02), and build/cf_queue_test (WP-04).
# test-unit runs all three, plus the Python codec round-trip check.
#
# test-tsan (WP-04) is a separate target/binary: it recompiles cf_queue.c
# and cf_queue_test.c with -fsanitize=thread instead of linking
# libcloudflow-core.a, since TSan needs to instrument the queue code itself
# to see the accesses on both sides of the ring buffer. It is not part of
# `all`/test-unit -- it is its own target, invoked by the top-level
# Makefile's test-tsan target.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

CODEC_DIR     := $(ROOT)/libs/cloudflow-codec
CODEC_GEN_DIR := $(CODEC_DIR)/gen
CODEC_LIB     := $(CODEC_DIR)/build/libcloudflow-codec.a

# The generated *_pb2.py files cross-import each other as
# `from cloudflow.v1 import ..._pb2` (absolute, matching the protoc
# --proto_path), so the directory containing the cloudflow/ package itself
# must be on PYTHONPATH -- see sinks/cloudflow-sink-splunk/src/cloudflow_pb/README.md.
PY_CODEC_DIR := $(ROOT)/sinks/cloudflow-sink-splunk/src/cloudflow_pb

CPPFLAGS := -I$(CORE_DIR)
LDLIBS   := -lcunit

BUILD_DIR := build

SOURCES := cf_core_test.c cf_sha256_test.c cf_event_id_test.c cf_log_test.c cf_time_test.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

BIN := $(BUILD_DIR)/cf_core_test

# cf_codec_test.c needs the generated protobuf-c headers (-I gen, so
# "cloudflow/v1/..." includes resolve) and libprotobuf-c, on top of the
# CUnit link already used by cf_core_test.
CODEC_TEST_CPPFLAGS := -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
CODEC_TEST_LDLIBS   := -lcunit $(shell pkg-config --libs libprotobuf-c)

CODEC_BIN := $(BUILD_DIR)/cf_codec_test

# cf_queue_test.c's 2-thread stress test links pthread on top of the usual
# CUnit link used by cf_core_test.
QUEUE_TEST_CPPFLAGS := -pthread
QUEUE_TEST_LDLIBS   := -lcunit -pthread

QUEUE_BIN := $(BUILD_DIR)/cf_queue_test

.PHONY: all test-unit test-tsan clean

all: $(BIN) $(CODEC_BIN) $(QUEUE_BIN)

# Builds (if needed) and runs all unit test binaries plus the Python codec
# round-trip script; fails the build if any of them fails (the C binaries
# return non-zero on CUnit failure, and codec_roundtrip.py raises on
# assertion failure).
test-unit: $(BIN) $(CODEC_BIN) $(QUEUE_BIN)
	./$(BIN)
	./$(CODEC_BIN)
	./$(QUEUE_BIN)
	PYTHONPATH=$(PY_CODEC_DIR) python3 $(ROOT)/tests/unit/codec_roundtrip.py

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(BIN): $(OBJECTS) $(CORE_LIB)
	$(LINK.o) -o $@ $(OBJECTS) $(CORE_LIB) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

# Explicit (non-pattern) rule for cf_codec_test.o so it gets its own
# CPPFLAGS (gen/ + libprotobuf-c) instead of the generic rule's -I core
# above; an explicit rule for a target always wins over a pattern rule.
$(BUILD_DIR)/cf_codec_test.o: cf_codec_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CODEC_TEST_CPPFLAGS) -c $< -o $@

$(CODEC_BIN): $(BUILD_DIR)/cf_codec_test.o $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_codec_test.o $(CODEC_LIB) $(CODEC_TEST_LDLIBS)

# Explicit rule for cf_queue_test.o so it picks up -pthread on top of the
# generic -I core CPPFLAGS.
$(BUILD_DIR)/cf_queue_test.o: cf_queue_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(QUEUE_TEST_CPPFLAGS) -c $< -o $@

$(QUEUE_BIN): $(BUILD_DIR)/cf_queue_test.o $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_queue_test.o $(CORE_LIB) $(QUEUE_TEST_LDLIBS)

# ---------------------------------------------------------------------------
# test-tsan (WP-04)
#
# TSan has to see every load/store it's asked to reason about, so linking
# against the plain libcloudflow-core.a (built without -fsanitize=thread by
# `make build`) is not enough -- cf_queue.c needs to be compiled straight
# into this binary with instrumentation. -O1 -g is the flag combination TSan
# itself recommends (higher optimization can fold away the very loads/stores
# under test; no optimization makes the run needlessly slow).
#
# The hardened link flags from mk/toolchain.mk (-pie -z relro -z now
# -z noexecstack) are kept here because they link cleanly together with
# -fsanitize=thread on this toolchain (gcc 13 / glibc, tested); if a future
# toolchain's link fails with them, drop $(HARDEN_LDFLAGS)/-pie for this
# binary only (not for the regular build) and note why here.
TSAN_CFLAGS    := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=thread -pthread
TSAN_CPPFLAGS  := -I$(CORE_DIR)
TSAN_LDFLAGS   := -fsanitize=thread -pthread $(LDFLAGS)
TSAN_LDLIBS    := -lcunit -pthread

TSAN_BIN := $(BUILD_DIR)/cf_queue_test_tsan

test-tsan: $(TSAN_BIN)
	./$(TSAN_BIN)

$(BUILD_DIR)/cf_queue_test.tsan.o: cf_queue_test.c | $(BUILD_DIR)
	$(CC) $(TSAN_CFLAGS) $(TSAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/cf_queue.tsan.o: $(CORE_DIR)/cf_queue.c | $(BUILD_DIR)
	$(CC) $(TSAN_CFLAGS) $(TSAN_CPPFLAGS) -c $< -o $@

$(TSAN_BIN): $(BUILD_DIR)/cf_queue_test.tsan.o $(BUILD_DIR)/cf_queue.tsan.o
	$(CC) $(TSAN_LDFLAGS) -o $@ $(BUILD_DIR)/cf_queue_test.tsan.o $(BUILD_DIR)/cf_queue.tsan.o $(TSAN_LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
