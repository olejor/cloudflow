# libs/cloudflow-packet/Makefile
#
# Builds libcloudflow-packet.a. SOURCES live next to this Makefile -- copied
# verbatim from the libs/cloudflow-core/Makefile template (WP-01 convention).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CPPFLAGS := -I.

BUILD_DIR := build

SOURCES := cf_decap.c cf_ipfmt.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

LIB := $(BUILD_DIR)/libcloudflow-packet.a

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
