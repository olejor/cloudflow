# sources/cloudflow-source-dns/Makefile
#
# Builds the cloudflow-source-dns application (v0.2, docs/dns-source.md).
# Mirrors sources/cloudflow-source-dhcp/Makefile's plain + ASan structure,
# but is DELIBERATELY wildcard-driven so independent work packages can add
# their module without ever editing this file:
#
#   * every src/*.c except src/main.c is archived into
#     libcloudflow-source-dns.a (the pipeline modules: correlation.c,
#     leg_classify.c, config.c, stats.c, formatter/encode, ...);
#   * src/main.c (when it lands, WP-DNS07) links straight into the binary;
#   * every tests/*_test.c becomes its own CUnit binary, in a plain and an
#     ASan+UBSan variant.
#
# So WP-DNS04 (correlation) and WP-DNS05 (leg classifier) each only add
# src/<module>.{c,h} + tests/<module>_test.c and this Makefile picks them up
# automatically -- no merge contention on a shared SOURCES list.
#
# ASan note: the ASan test binaries compile the test and the app's own src/
# modules with -fsanitize=address,undefined (the new, under-test code) and
# link the plain library archives. ASan's malloc/free interceptors are
# process-global once the binary is linked with -fsanitize=address, so leaks
# and heap errors are caught across the whole binary (including allocations
# made inside libcloudflow-packet's cf_dns_parse); the shared libraries' own
# access instrumentation is covered by tests/unit's ASan suite.
#
# `make -C sources/cloudflow-source-dns all test test-asan clean` works
# standalone (it builds the prerequisite libraries via $(MAKE) -C).

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

FIXTURES_DIR := $(ROOT)/tests/fixtures/dns

YAML_CFLAGS    := $(shell pkg-config --cflags yaml-0.1)
YAML_LIBS      := $(shell pkg-config --libs yaml-0.1)
HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)
PROTOBUF_CFLAGS := $(shell pkg-config --cflags libprotobuf-c)
PROTOBUF_LIBS   := $(shell pkg-config --libs libprotobuf-c)

CPPFLAGS := -I. -Isrc -I$(CORE_DIR) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) -I$(REDIS_DIR) \
            $(PROTOBUF_CFLAGS) $(YAML_CFLAGS) $(HIREDIS_CFLAGS)

BUILD_DIR := build

# --- app library: every src/*.c except main.c -------------------------------
ALL_SRCS := $(wildcard src/*.c)
MAIN_SRC := src/main.c
LIB_SRCS := $(filter-out $(MAIN_SRC),$(ALL_SRCS))
LIB_OBJS := $(addprefix $(BUILD_DIR)/,$(LIB_SRCS:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-source-dns.a
BIN := $(BUILD_DIR)/cloudflow-source-dns

# --- tests: one CUnit binary per tests/*_test.c (plain + asan) ---------------
TEST_SRCS      := $(wildcard tests/*_test.c)
TEST_BINS      := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))
TEST_ASAN_BINS := $(patsubst tests/%.c,$(BUILD_DIR)/%_asan,$(TEST_SRCS))

# app modules recompiled with instrumentation for the ASan test binaries
ASAN_APP_OBJS := $(patsubst src/%.c,$(BUILD_DIR)/asan/%.o,$(LIB_SRCS))

ASAN_CFLAGS := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=address,undefined \
               -fno-omit-frame-pointer
ASAN_LDLIBS := -lcunit $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(YAML_LIBS) -pthread

TEST_CPPFLAGS := $(CPPFLAGS) -pthread -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
TEST_LDLIBS   := -lcunit $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(YAML_LIBS) -pthread

.PHONY: all test test-asan clean

# Build the app archive once there is at least one module, and the binary
# once src/main.c exists (WP-DNS07). Until then (bare scaffold) `all` is a
# clean no-op rather than an empty `ar` invocation.
all: $(if $(LIB_SRCS),$(LIB)) $(if $(wildcard $(MAIN_SRC)),$(BIN))

$(LIB): $(LIB_OBJS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@

$(BUILD_DIR)/asan/%.o: src/%.c | $(BUILD_DIR)
	mkdir -p $(dir $@)
	$(CC) $(ASAN_CFLAGS) $(CPPFLAGS) -c $< -o $@

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

# --- binary (WP-DNS07): main.o + app lib + all shared libs ------------------
BIN_LDLIBS := $(HIREDIS_LIBS) $(PROTOBUF_LIBS) $(YAML_LIBS) -pthread

$(BIN): $(BUILD_DIR)/src/main.o $(LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/src/main.o $(LIB) $(REDIS_LIB) $(PACKET_LIB) \
	    $(CODEC_LIB) $(CORE_LIB) $(BIN_LDLIBS)

# --- plain CUnit test binaries ----------------------------------------------
$(TEST_BINS): $(BUILD_DIR)/%: tests/%.c $(LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -o $@ $< \
	    $(LIB) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB) $(TEST_LDLIBS)

test: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do echo "== $$t =="; ./$$t; done

# --- ASan+UBSan test binaries -----------------------------------------------
$(TEST_ASAN_BINS): $(BUILD_DIR)/%_asan: tests/%.c $(ASAN_APP_OBJS) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB) | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) $(TEST_CPPFLAGS) -o $@ $< \
	    $(ASAN_APP_OBJS) $(REDIS_LIB) $(PACKET_LIB) $(CODEC_LIB) $(CORE_LIB) $(ASAN_LDLIBS)

test-asan: $(TEST_ASAN_BINS)
	@set -e; for t in $(TEST_ASAN_BINS); do echo "== $$t (asan) =="; ./$$t; done

clean:
	rm -rf $(BUILD_DIR)
