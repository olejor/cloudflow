# libs/cloudflow-codec/Makefile
#
# Builds libcloudflow-codec.a from the generated protobuf-c sources under
# gen/ (WP-02). No hand-written code in this WP -- see gen/README.md.
#
# Follows the WP-01 sub-Makefile pattern (libs/cloudflow-core/Makefile is the
# canonical template): include mk/toolchain.mk, extend CPPFLAGS/CFLAGS
# rather than overriding them wholesale.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

GEN_DIR := gen

# The generated cloudflow/v1/*.pb-c.{c,h} files #include "cloudflow/v1/...",
# so gen/ (not gen/cloudflow/v1) must be on the include path.
CPPFLAGS := -I$(GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)

# NOTE (WP-02 acceptance criterion): with protoc-c 1.4.1 / libprotobuf-c
# 1.4.1 the generated cloudflow/v1/*.pb-c.c sources compile warning-clean
# under the repo's -Wall -Wextra -Werror baseline (mk/toolchain.mk), so no
# per-directory warning suppression is currently needed. If a future
# protoc/protobuf-c upgrade introduces generator warnings, add targeted
# `CFLAGS += -Wno-<specific-warning>` lines here (this directory only --
# never relax warnings globally in mk/toolchain.mk).

BUILD_DIR := build

SOURCES := $(wildcard $(GEN_DIR)/cloudflow/v1/*.pb-c.c)
OBJECTS := $(patsubst $(GEN_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

LIB := $(BUILD_DIR)/libcloudflow-codec.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: $(GEN_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(COMPILE.c) $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
