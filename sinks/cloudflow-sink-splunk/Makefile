# sinks/cloudflow-sink-splunk/Makefile
#
# Builds build/cloudflow-sink-splunk, the Splunk *event* sink. After synergy
# item A1 the generic sink spine (consumer group, HEC client, dead-letter, run
# loop, base config/stats) lives in libs/cloudflow-sink-core; this app keeps
# only the event-specific transform (src/transform.c) + the config layer that
# adds `sourcetypes`/`include_raw_payload` + thin wiring (src/main.c), and
# links libcloudflow-sink-core.a.
#
# Follows the libs/cloudflow-core sub-Makefile template (include
# mk/toolchain.mk, extend CPPFLAGS rather than overriding CFLAGS), plus a
# `test` target that owns the golden transform suite here (the generic
# consumer/HEC suites moved to libs/cloudflow-sink-core).
#
# `make -C sinks/cloudflow-sink-splunk all test test-asan clean` works standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR       := $(ROOT)/libs/cloudflow-core
CODEC_DIR      := $(ROOT)/libs/cloudflow-codec
CODEC_GEN      := $(CODEC_DIR)/gen
SINK_CORE_DIR  := $(ROOT)/libs/cloudflow-sink-core
YYJSON_DIR     := $(ROOT)/third_party/yyjson

CORE_LIB      := $(CORE_DIR)/build/libcloudflow-core.a
CODEC_LIB     := $(CODEC_DIR)/build/libcloudflow-codec.a
SINK_CORE_LIB := $(SINK_CORE_DIR)/build/libcloudflow-sink-core.a

HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)
CURL_CFLAGS    := $(shell pkg-config --cflags libcurl)
CURL_LIBS      := $(shell pkg-config --libs libcurl)
YAML_CFLAGS    := $(shell pkg-config --cflags yaml-0.1)
YAML_LIBS      := $(shell pkg-config --libs yaml-0.1)
PBC_CFLAGS     := $(shell pkg-config --cflags libprotobuf-c)
PBC_LIBS       := $(shell pkg-config --libs libprotobuf-c)

CPPFLAGS := -Isrc -I$(SINK_CORE_DIR) -I$(CORE_DIR) -I$(CODEC_GEN) -I$(YYJSON_DIR) \
            $(HIREDIS_CFLAGS) $(CURL_CFLAGS) $(YAML_CFLAGS) $(PBC_CFLAGS)

LDLIBS := $(SINK_CORE_LIB) $(CODEC_LIB) $(CORE_LIB) \
          $(HIREDIS_LIBS) $(CURL_LIBS) $(YAML_LIBS) $(PBC_LIBS)

# Sanitizer flags injected by the test-asan target (empty otherwise).
SAN_CFLAGS  :=
SAN_LDFLAGS :=

BUILD_DIR := build

# Event-specific application objects (config layer + transform); reused by the
# golden test. main.c is the thin entry point.
APP_SRCS := config.c transform.c
APP_OBJS := $(addprefix $(BUILD_DIR)/,$(APP_SRCS:.c=.o))
MAIN_OBJ := $(BUILD_DIR)/main.o
YYJSON_OBJ := $(BUILD_DIR)/yyjson.o

BIN := $(BUILD_DIR)/cloudflow-sink-splunk

.PHONY: all test test-asan clean fixtures

all: $(BIN)

# --- app objects -----------------------------------------------------------

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SAN_CFLAGS) $(CPPFLAGS) -c $< -o $@

# yyjson is vendored third-party code; compile it with locally relaxed
# warnings so the repo's -Werror baseline still applies to our own sources
# (mirrors how libs/cloudflow-codec documents handling generated code).
$(YYJSON_OBJ): $(YYJSON_DIR)/yyjson.c | $(BUILD_DIR)
	$(CC) $(CSTD) -O2 $(HARDEN_CFLAGS) $(SAN_CFLAGS) -I$(YYJSON_DIR) \
	    -Wno-unused-function -c $< -o $@

$(BIN): $(APP_OBJS) $(MAIN_OBJ) $(YYJSON_OBJ) $(SINK_CORE_LIB) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(APP_OBJS) $(MAIN_OBJ) $(YYJSON_OBJ) $(LDLIBS)

$(SINK_CORE_LIB):
	$(MAKE) -C $(SINK_CORE_DIR) all

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# --- tests -----------------------------------------------------------------
#
# The golden structural-compatibility suite stays with the event sink because
# it depends on the event->HEC-JSON mapping. It reuses the app objects above.

TEST_CPPFLAGS := $(CPPFLAGS) -Itests
TEST_LDLIBS   := $(LDLIBS) -lcunit -pthread

TEST_GOLDEN := $(BUILD_DIR)/test_transform_golden

$(BUILD_DIR)/%.o: tests/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SAN_CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_GOLDEN): $(BUILD_DIR)/test_transform_golden.o $(APP_OBJS) $(YYJSON_OBJ) $(SINK_CORE_LIB) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_transform_golden.o $(APP_OBJS) $(YYJSON_OBJ) $(TEST_LDLIBS)

# Rebuild the packed protobuf fixtures the golden test reads (uses the kept
# Python bindings; the golden generator is the compatibility oracle).
fixtures:
	cd tests && python3 generate_fixtures.py >/dev/null 2>&1 || \
	    echo "warning: could not regenerate fixtures (python bindings?)"

test: fixtures $(TEST_GOLDEN)
	./$(TEST_GOLDEN)

test-asan:
	$(MAKE) SAN_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -U_FORTIFY_SOURCE" \
	        SAN_LDFLAGS="-fsanitize=address,undefined" test

clean:
	rm -rf $(BUILD_DIR) tests/fixtures
