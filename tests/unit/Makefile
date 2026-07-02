# tests/unit/Makefile
#
# Builds and runs the CUnit acceptance tests for libcloudflow-core (WP-03)
# and the libcloudflow-codec round-trip tests (WP-02). Follows the WP-01
# sub-Makefile pattern: include mk/toolchain.mk, extend CPPFLAGS/LDLIBS
# rather than overriding CFLAGS/LDFLAGS.
#
# Two independent CUnit binaries are built so this file's core-test SOURCES
# list doesn't need to change for WP-02: build/cf_core_test (WP-03) and
# build/cf_codec_test (WP-02). test-unit runs both, plus the Python codec
# round-trip check.

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

.PHONY: all test-unit clean

all: $(BIN) $(CODEC_BIN)

# Builds (if needed) and runs both unit test binaries plus the Python codec
# round-trip script; fails the build if any of them fails (the C binaries
# return non-zero on CUnit failure, and codec_roundtrip.py raises on
# assertion failure).
test-unit: $(BIN) $(CODEC_BIN)
	./$(BIN)
	./$(CODEC_BIN)
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

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
