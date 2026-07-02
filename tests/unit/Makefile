# tests/unit/Makefile
#
# Builds and runs the CUnit acceptance tests for libcloudflow-core (WP-03).
# Follows the WP-01 sub-Makefile pattern: include mk/toolchain.mk, extend
# CPPFLAGS/LDLIBS rather than overriding CFLAGS/LDFLAGS.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

CPPFLAGS := -I$(CORE_DIR)
LDLIBS   := -lcunit

BUILD_DIR := build

SOURCES := cf_core_test.c cf_sha256_test.c cf_event_id_test.c cf_log_test.c cf_time_test.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

BIN := $(BUILD_DIR)/cf_core_test

.PHONY: all test-unit clean

all: $(BIN)

# Builds (if needed) and runs the unit test binary; fails the build if any
# test fails (cf_core_test.c returns non-zero on failure).
test-unit: $(BIN)
	./$(BIN)

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(BIN): $(OBJECTS) $(CORE_LIB)
	$(LINK.o) -o $@ $(OBJECTS) $(CORE_LIB) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
