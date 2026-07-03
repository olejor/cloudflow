# mk/toolchain.mk
#
# Single definition of the CloudFlow C toolchain, included by every
# library/app Makefile in the repo (Convention 3 in
# docs/architecture.md, "Conventions for implementers"):
#
#   C11, -Wall -Wextra -Werror -O2 -std=gnu11 -D_FORTIFY_SOURCE=2
#   -fstack-protector-strong -fPIE, hardened link flags
#   -z relro -z now -z noexecstack. Do NOT add -march=native -- it pins the
#   resulting binaries to the build host.
#
# Usage from a sub-Makefile (see libs/cloudflow-core/Makefile for the
# canonical example every later WP's Makefile copies):
#
#   ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
#   include $(ROOT)/mk/toolchain.mk
#
# Adjust the number of "/.." segments to how deep the including Makefile
# lives relative to the repo root.

CC ?= gcc
AR ?= ar

CSTD          := -std=gnu11
WARN_FLAGS    := -Wall -Wextra -Werror
HARDEN_CFLAGS := -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE

# Sub-Makefiles should extend CPPFLAGS (include paths, -D defines) rather
# than overriding CFLAGS, so every target keeps the same warning/hardening
# baseline.
CFLAGS ?= $(CSTD) $(WARN_FLAGS) -O2 $(HARDEN_CFLAGS)

HARDEN_LDFLAGS := -z relro -z now -z noexecstack
LDFLAGS ?= -pie $(HARDEN_LDFLAGS)

ARFLAGS := rcs

# Recursively-expanded command templates. These are plain variables (not
# pattern rules) so they can be referenced safely from pattern rules defined
# in the including Makefile regardless of include order, e.g.:
#
#   $(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
#           $(COMPILE.c) $< -o $@
#
#   $(BUILD_DIR)/libfoo.a: $(OBJECTS)
#           $(ARCHIVE.a) $@ $^
#
#   $(BUILD_DIR)/some-app: $(OBJECTS)
#           $(LINK.o) -o $@ $^ $(LDLIBS)
COMPILE.c = $(CC) $(CFLAGS) $(CPPFLAGS) -c
LINK.o    = $(CC) $(LDFLAGS)
ARCHIVE.a = $(AR) $(ARFLAGS)
