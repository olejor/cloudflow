# libs/cloudflow-redis/Makefile
#
# Builds libcloudflow-redis.a (WP-09). Follows the libs/cloudflow-core
# Makefile template verbatim, plus a `test` target (CUnit, requires a
# private redis-server spawned by the test binary itself -- see
# tests/cf_redis_producer_test.c) that this Makefile owns directly, per the
# WP-09 task instructions: tests/unit/Makefile is owned by a parallel WP
# right now, so this library wires its own tests in here instead of there.
#
# `make -C libs/cloudflow-redis all test clean` must work standalone.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)

CPPFLAGS := -I. -I$(CORE_DIR) $(HIREDIS_CFLAGS)

BUILD_DIR := build

SOURCES := cf_redis_producer.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-redis.a

.PHONY: all test clean

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
# test: CUnit acceptance suite (tests/cf_redis_producer_test.c). Needs
# pthread (the test spawns/reaps a private redis-server child and drives the
# producer, which is itself threaded) on top of hiredis (both to drive the
# producer and, separately, for the test's own raw verification connection)
# and libcunit.
TEST_CPPFLAGS := -I. -I$(CORE_DIR) $(HIREDIS_CFLAGS) -pthread
TEST_LDLIBS   := $(HIREDIS_LIBS) -lcunit -pthread

TEST_BIN := $(BUILD_DIR)/cf_redis_producer_test

$(BUILD_DIR)/cf_redis_producer_test.o: tests/cf_redis_producer_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(BUILD_DIR)/cf_redis_producer_test.o $(LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_redis_producer_test.o $(LIB) $(CORE_LIB) $(TEST_LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
