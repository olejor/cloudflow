# libs/cloudflow-core/Makefile
#
# Builds libcloudflow-core.a.
#
# Deviation from docs/design/01-foundations.md (WP-01), approved: the spec
# says this WP creates the sub-Makefile pattern "with a stub library so
# later WPs only copy it". WP-03 has not landed yet, so there is no core
# source under this directory to build a stub from. Instead this Makefile
# builds the real libcloudflow-core.a from the existing sources at the
# top-level src/ (src/cloudflow.c, src/cf_queue.c) via VPATH. WP-03 moves
# src/cloudflow.{c,h} and src/cf_queue.{c,h} into this directory and deletes
# src/; at that point SRC_DIR/VPATH go away and SOURCES simply live next to
# this Makefile like every other library -- everything below this comment
# block is otherwise the template later WPs copy verbatim.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

# --- WP-03 indirection (see deviation note above) ---
SRC_DIR := $(ROOT)/src
VPATH   := $(SRC_DIR)
CPPFLAGS := -I$(SRC_DIR)
# --- end WP-03 indirection ---

BUILD_DIR := build

SOURCES := cloudflow.c cf_queue.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-core.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJECTS)
	$(ARCHIVE.a) $@ $^

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
