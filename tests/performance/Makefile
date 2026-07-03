# tests/performance/Makefile
#
# Builds build/bench_xadd (WP-15): the XADD producer benchmark binary.
# Follows the WP-01 sub-Makefile pattern (see libs/cloudflow-core/Makefile,
# the canonical example): include mk/toolchain.mk, extend
# CPPFLAGS/LDLIBS rather than overriding CFLAGS/LDFLAGS.
#
# `make -C tests/performance all clean` must work standalone. This
# Makefile does not add a `test` target -- scripts/benchmark-xadd.sh is the
# entry point that builds (via this Makefile) and runs bench_xadd against a
# private redis-server.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR  := $(ROOT)/libs/cloudflow-core
CORE_LIB  := $(CORE_DIR)/build/libcloudflow-core.a

REDIS_DIR := $(ROOT)/libs/cloudflow-redis
REDIS_LIB := $(REDIS_DIR)/build/libcloudflow-redis.a

HIREDIS_CFLAGS := $(shell pkg-config --cflags hiredis)
HIREDIS_LIBS   := $(shell pkg-config --libs hiredis)

CPPFLAGS := -I$(CORE_DIR) -I$(REDIS_DIR) $(HIREDIS_CFLAGS)
LDLIBS   := $(HIREDIS_LIBS) -pthread

BUILD_DIR := build

BIN := $(BUILD_DIR)/bench_xadd

.PHONY: all clean

all: $(BIN)

$(BUILD_DIR)/bench_xadd.o: bench_xadd.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

$(BIN): $(BUILD_DIR)/bench_xadd.o $(REDIS_LIB) $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/bench_xadd.o $(REDIS_LIB) $(CORE_LIB) $(LDLIBS)

$(REDIS_LIB):
	$(MAKE) -C $(REDIS_DIR) all

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
