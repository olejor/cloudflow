# libs/cloudflow-core/Makefile
#
# Builds libcloudflow-core.a. SOURCES live next to this Makefile -- this is
# the template later WPs copy verbatim.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CPPFLAGS := -I.

BUILD_DIR := build

SOURCES := cloudflow.c cf_queue.c cf_time.c cf_sync.c cf_log.c cf_event_id.c sha256.c
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
