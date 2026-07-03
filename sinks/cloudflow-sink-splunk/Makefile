# sinks/cloudflow-sink-splunk/Makefile
#
# Builds build/cloudflow-sink-splunk (WP-17, the C rewrite of the WP-12 Python
# sink). Follows the libs/cloudflow-core sub-Makefile template (include
# mk/toolchain.mk, extend CPPFLAGS rather than overriding CFLAGS), plus a
# `test` target that -- like libs/cloudflow-redis -- owns its own CUnit suites
# here (they spawn a private redis-server / HTTP stub) instead of wiring into
# tests/unit/.
#
# `make -C sinks/cloudflow-sink-splunk all test test-asan clean` works standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR  := $(ROOT)/libs/cloudflow-core
CODEC_DIR := $(ROOT)/libs/cloudflow-codec
CODEC_GEN := $(CODEC_DIR)/gen
YYJSON_DIR := $(ROOT)/third_party/yyjson

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

CPPFLAGS := -Isrc -I$(CORE_DIR) -I$(CODEC_GEN) -I$(YYJSON_DIR) \
            $(HIREDIS_CFLAGS) $(CURL_CFLAGS) $(YAML_CFLAGS) $(PBC_CFLAGS)

LDLIBS := $(CODEC_LIB) $(CORE_LIB) $(HIREDIS_LIBS) $(CURL_LIBS) $(YAML_LIBS) $(PBC_LIBS)

# Sanitizer flags injected by the test-asan target (empty otherwise).
SAN_CFLAGS  :=
SAN_LDFLAGS :=

BUILD_DIR := build

# Application objects (everything under src/ except main.c is reused by tests).
APP_SRCS := config.c transform.c hec.c deadletter.c stats.c consumer.c
APP_OBJS := $(addprefix $(BUILD_DIR)/,$(APP_SRCS:.c=.o))
MAIN_OBJ := $(BUILD_DIR)/main.o
YYJSON_OBJ := $(BUILD_DIR)/yyjson.o

BIN := $(BUILD_DIR)/cloudflow-sink-splunk

.PHONY: all test test-asan clean

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

$(BIN): $(APP_OBJS) $(MAIN_OBJ) $(YYJSON_OBJ) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(APP_OBJS) $(MAIN_OBJ) $(YYJSON_OBJ) $(LDLIBS)

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(BUILD_DIR):
	mkdir -p $@

# --- tests -----------------------------------------------------------------
#
# Three CUnit suites (tests/): golden structural compatibility, consumer
# against a private redis-server, and HEC retry/bisection against a python
# http stub. They reuse the application objects above.

TEST_CPPFLAGS := $(CPPFLAGS) -Itests
TEST_LDLIBS   := $(LDLIBS) -lcunit -pthread

TEST_GOLDEN := $(BUILD_DIR)/test_transform_golden
TEST_CONSUMER := $(BUILD_DIR)/test_consumer
TEST_HEC := $(BUILD_DIR)/test_hec

$(BUILD_DIR)/%.o: tests/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SAN_CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_GOLDEN): $(BUILD_DIR)/test_transform_golden.o $(APP_OBJS) $(YYJSON_OBJ) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_transform_golden.o $(APP_OBJS) $(YYJSON_OBJ) $(TEST_LDLIBS)

$(TEST_CONSUMER): $(BUILD_DIR)/test_consumer.o $(APP_OBJS) $(YYJSON_OBJ) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_consumer.o $(APP_OBJS) $(YYJSON_OBJ) $(TEST_LDLIBS)

$(TEST_HEC): $(BUILD_DIR)/test_hec.o $(APP_OBJS) $(YYJSON_OBJ) $(CORE_LIB) $(CODEC_LIB)
	$(CC) $(LDFLAGS) $(SAN_LDFLAGS) -o $@ $(BUILD_DIR)/test_hec.o $(APP_OBJS) $(YYJSON_OBJ) $(TEST_LDLIBS)

# Rebuild the packed protobuf fixtures the golden/consumer tests read (uses
# the kept Python bindings; the golden generator is the compatibility oracle).
.PHONY: fixtures
fixtures:
	cd tests && python3 generate_fixtures.py >/dev/null 2>&1 || \
	    echo "warning: could not regenerate fixtures (python bindings?)"

test: fixtures $(TEST_GOLDEN) $(TEST_CONSUMER) $(TEST_HEC)
	./$(TEST_GOLDEN)
	./$(TEST_CONSUMER)
	./$(TEST_HEC)

test-asan:
	$(MAKE) SAN_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -U_FORTIFY_SOURCE" \
	        SAN_LDFLAGS="-fsanitize=address,undefined" test

clean:
	rm -rf $(BUILD_DIR) tests/fixtures
