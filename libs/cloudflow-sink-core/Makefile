# libs/cloudflow-sink-core/Makefile
#
# Builds build/libcloudflow-sink-core.a: the generic Splunk-sink spine
# extracted out of cloudflow-sink-splunk (synergy item A1) so a second sink
# (the designed Splunk metrics sink) can reuse it -- the hiredis consumer-group
# loop (cf_sink_consumer: XGROUP CREATE / XAUTOCLAIM / XREADGROUP, entry
# validation, protobuf unpack), the libcurl HEC client (cf_sink_hec:
# keep-alive, batched POST, backoff/retry, poison-batch bisection, TLS verify,
# parameterized endpoint path), the dead-letter writer (cf_sink_deadletter,
# stream name is config), the base YAML config (cf_sink_config), the base
# counters + stats line (cf_sink_stats), and the run harness (cf_sink_run)
# parameterized by a transform callback. Sink-specific transforms build on top.
#
# Follows the libs/cloudflow-capture archive-Makefile template (include
# mk/toolchain.mk, produce a .a, own test/test-asan targets), plus the
# external deps the spine needs (hiredis, libcurl, libyaml, protobuf-c, the
# generated codec headers). The moved CUnit suites (tests/test_consumer.c
# against a private redis-server, tests/test_hec.c against a python http stub)
# live here and reuse the spine objects directly.
#
# `make -C libs/cloudflow-sink-core all test test-asan clean` works standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR  := $(ROOT)/libs/cloudflow-core
CODEC_DIR := $(ROOT)/libs/cloudflow-codec
CODEC_GEN := $(CODEC_DIR)/gen

CORE_LIB  := $(CORE_DIR)/build/libcloudflow-core.a
CODEC_LIB := $(CODEC_DIR)/build/libcloudflow-codec.a

HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)
CURL_CFLAGS    := $(shell pkg-config --cflags libcurl)
CURL_LIBS      := $(shell pkg-config --libs libcurl)
YAML_CFLAGS    := $(shell pkg-config --cflags yaml-0.1)
YAML_LIBS      := $(shell pkg-config --libs yaml-0.1)
PBC_CFLAGS     := $(shell pkg-config --cflags libprotobuf-c)
PBC_LIBS       := $(shell pkg-config --libs libprotobuf-c)

CPPFLAGS := -I. -I$(CORE_DIR) -I$(CODEC_GEN) \
            $(HIREDIS_CFLAGS) $(CURL_CFLAGS) $(YAML_CFLAGS) $(PBC_CFLAGS)

# Sanitizer flags injected by the test-asan target (empty otherwise).
SAN_CFLAGS  :=
SAN_LDFLAGS :=

BUILD_DIR := build

SOURCES := cf_sink_config.c cf_sink_stats.c cf_sink_deadletter.c cf_sink_hec.c \
           cf_sink_httpdeliver.c cf_sink_consumer.c cf_sink_run.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-sink-core.a

.PHONY: all test test-asan clean

all: $(LIB)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SAN_CFLAGS) $(CPPFLAGS) -c $< -o $@

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# --- tests -----------------------------------------------------------------
#
# Two CUnit suites moved out of the event sink: consumer semantics against a
# private redis-server, and HEC retry/bisection against a python http stub.
# They reuse the spine objects (instrumented too when SAN flags are injected)
# and provide their own trivial transform. The event sink keeps the golden
# transform suite (which depends on the event mapping).

TEST_CPPFLAGS := $(CPPFLAGS) -Itests
TEST_LDLIBS   := $(CODEC_LIB) $(CORE_LIB) $(HIREDIS_LIBS) $(CURL_LIBS) $(YAML_LIBS) \
                 $(PBC_LIBS) -lcunit -pthread

TEST_CONSUMER := $(BUILD_DIR)/test_consumer
TEST_HEC      := $(BUILD_DIR)/test_hec

$(BUILD_DIR)/%.o: tests/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SAN_CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_CONSUMER): $(BUILD_DIR)/test_consumer.o $(OBJECTS) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_consumer.o $(OBJECTS) $(TEST_LDLIBS)

$(TEST_HEC): $(BUILD_DIR)/test_hec.o $(OBJECTS) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_hec.o $(OBJECTS) $(TEST_LDLIBS)

test: $(TEST_CONSUMER) $(TEST_HEC)
	./$(TEST_CONSUMER)
	./$(TEST_HEC)

test-asan:
	$(MAKE) SAN_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -U_FORTIFY_SOURCE" \
	        SAN_LDFLAGS="-fsanitize=address,undefined" test

clean:
	rm -rf $(BUILD_DIR)
