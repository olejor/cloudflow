# tests/unit/Makefile
#
# Builds and runs the CUnit acceptance tests for libcloudflow-core (WP-03),
# the libcloudflow-codec round-trip tests (WP-02), and the cf_queue
# hardening tests (WP-04). Follows the WP-01 sub-Makefile pattern: include
# mk/toolchain.mk, extend CPPFLAGS/LDLIBS rather than overriding
# CFLAGS/LDFLAGS.
#
# Six independent CUnit binaries are built so this file's core-test
# SOURCES list doesn't need to change as later WPs land: build/cf_core_test
# (WP-03), build/cf_codec_test (WP-02), build/cf_queue_test (WP-04),
# build/cf_decap_test (WP-05), build/cf_dhcpv4_test (WP-06), and
# build/cf_dhcpv6_test (WP-07). test-unit runs all six, plus the Python
# codec round-trip check.
#
# test-tsan (WP-04) is a separate target/binary: it recompiles cf_queue.c
# and cf_queue_test.c with -fsanitize=thread instead of linking
# libcloudflow-core.a, since TSan needs to instrument the queue code itself
# to see the accesses on both sides of the ring buffer. It is not part of
# `all`/test-unit -- it is its own target, invoked by the top-level
# Makefile's test-tsan target.
#
# test-asan (WP-16) follows the same "compile the library sources straight
# into the test binary" approach, but -- unlike test-tsan, which only
# rebuilds the queue stress test -- it rebuilds and runs all six suites
# (core, codec, queue, decap, dhcpv4, dhcpv6), since ASan/UBSan misuse
# (buffer overflows, UB, leaks) can hide in any of them, not just the queue.
# It is its own target, invoked by the top-level Makefile's test-asan target.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
include $(ROOT)/mk/toolchain.mk

CORE_DIR := $(ROOT)/libs/cloudflow-core
CORE_LIB := $(CORE_DIR)/build/libcloudflow-core.a

CODEC_DIR     := $(ROOT)/libs/cloudflow-codec
CODEC_GEN_DIR := $(CODEC_DIR)/gen
CODEC_LIB     := $(CODEC_DIR)/build/libcloudflow-codec.a

PACKET_DIR := $(ROOT)/libs/cloudflow-packet
PACKET_LIB := $(PACKET_DIR)/build/libcloudflow-packet.a

# The generated *_pb2.py files cross-import each other as
# `from cloudflow.v1 import ..._pb2` (absolute, matching the protoc
# --proto_path), so the directory containing the cloudflow/ package itself
# must be on PYTHONPATH -- see sinks/cloudflow-sink-splunk/src/cloudflow_pb/README.md.
PY_CODEC_DIR := $(ROOT)/sinks/cloudflow-sink-splunk/src/cloudflow_pb

CPPFLAGS := -I$(CORE_DIR)
LDLIBS   := -lcunit

BUILD_DIR := build

SOURCES := cf_core_test.c cf_sha256_test.c cf_event_id_test.c cf_log_test.c cf_time_test.c cf_sync_test.c
OBJECTS := $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))

BIN := $(BUILD_DIR)/cf_core_test

# cf_codec_test.c needs the generated protobuf-c headers (-I gen, so
# "cloudflow/v1/..." includes resolve) and libprotobuf-c, on top of the
# CUnit link already used by cf_core_test.
CODEC_TEST_CPPFLAGS := -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
CODEC_TEST_LDLIBS   := -lcunit $(shell pkg-config --libs libprotobuf-c)

CODEC_BIN := $(BUILD_DIR)/cf_codec_test

# cf_queue_test.c's 2-thread stress test links pthread on top of the usual
# CUnit link used by cf_core_test.
QUEUE_TEST_CPPFLAGS := -pthread
QUEUE_TEST_LDLIBS   := -lcunit -pthread

QUEUE_BIN := $(BUILD_DIR)/cf_queue_test

# cf_decap_test.c only needs the packet library and CUnit -- it has no
# dependency on cloudflow-core.
DECAP_TEST_CPPFLAGS := -I$(PACKET_DIR)
DECAP_TEST_LDLIBS   := -lcunit

DECAP_BIN := $(BUILD_DIR)/cf_decap_test

# cf_dhcpv4_test.c needs the packet library (cf_decap + cf_dhcpv4), the
# generated protobuf-c headers/lib (dhcp.pb-c.h et al, same as cf_codec_test
# above), and CUnit. FIXTURES_DIR points it at the committed WP-06 fixture
# pcaps regardless of the directory `make`/the resulting binary is invoked
# from.
FIXTURES_DIR := $(ROOT)/tests/fixtures/dhcp

DHCPV4_TEST_CPPFLAGS := -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c) \
                         -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
DHCPV4_TEST_LDLIBS   := -lcunit $(shell pkg-config --libs libprotobuf-c)

DHCPV4_BIN := $(BUILD_DIR)/cf_dhcpv4_test

# cf_dhcpv6_test.c needs exactly what cf_dhcpv4_test.c needs (the packet
# library, the generated protobuf-c headers/lib, CUnit, and FIXTURES_DIR) --
# see cf_dhcpv4_test.c's Makefile comment above.
DHCPV6_TEST_CPPFLAGS := -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c) \
                         -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
DHCPV6_TEST_LDLIBS   := -lcunit $(shell pkg-config --libs libprotobuf-c)

DHCPV6_BIN := $(BUILD_DIR)/cf_dhcpv6_test

# cf_dns_test.c (WP-DNS03) needs the packet library (cf_parse_util + cf_dns),
# the generated protobuf-c headers/lib (dns.pb-c.h / common.pb-c.h), and
# CUnit. Unlike the DHCP tests it is driven entirely by hand-built DNS byte
# arrays (the scapy fixture corpus is a separate WP), so it needs no
# FIXTURES_DIR.
DNS_TEST_CPPFLAGS := -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
DNS_TEST_LDLIBS   := -lcunit $(shell pkg-config --libs libprotobuf-c)

DNS_BIN := $(BUILD_DIR)/cf_dns_test

.PHONY: all test-unit test-tsan test-asan clean

all: $(BIN) $(CODEC_BIN) $(QUEUE_BIN) $(DECAP_BIN) $(DHCPV4_BIN) $(DHCPV6_BIN) $(DNS_BIN)

# Builds (if needed) and runs all unit test binaries plus the Python codec
# round-trip script; fails the build if any of them fails (the C binaries
# return non-zero on CUnit failure, and codec_roundtrip.py raises on
# assertion failure).
test-unit: $(BIN) $(CODEC_BIN) $(QUEUE_BIN) $(DECAP_BIN) $(DHCPV4_BIN) $(DHCPV6_BIN) $(DNS_BIN)
	./$(BIN)
	./$(CODEC_BIN)
	./$(QUEUE_BIN)
	./$(DECAP_BIN)
	./$(DHCPV4_BIN)
	./$(DHCPV6_BIN)
	./$(DNS_BIN)
	PYTHONPATH=$(PY_CODEC_DIR) python3 $(ROOT)/tests/unit/codec_roundtrip.py

$(CORE_LIB):
	$(MAKE) -C $(CORE_DIR) all

$(CODEC_LIB):
	$(MAKE) -C $(CODEC_DIR) all

$(PACKET_LIB):
	$(MAKE) -C $(PACKET_DIR) all

$(BIN): $(OBJECTS) $(CORE_LIB)
	$(LINK.o) -o $@ $(OBJECTS) $(CORE_LIB) $(LDLIBS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(COMPILE.c) $< -o $@

# Explicit (non-pattern) rule for cf_codec_test.o so it gets its own
# CPPFLAGS (gen/ + libprotobuf-c) instead of the generic rule's -I core
# above; an explicit rule for a target always wins over a pattern rule.
$(BUILD_DIR)/cf_codec_test.o: cf_codec_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CODEC_TEST_CPPFLAGS) -c $< -o $@

$(CODEC_BIN): $(BUILD_DIR)/cf_codec_test.o $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_codec_test.o $(CODEC_LIB) $(CODEC_TEST_LDLIBS)

# Explicit rule for cf_queue_test.o so it picks up -pthread on top of the
# generic -I core CPPFLAGS.
$(BUILD_DIR)/cf_queue_test.o: cf_queue_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(QUEUE_TEST_CPPFLAGS) -c $< -o $@

$(QUEUE_BIN): $(BUILD_DIR)/cf_queue_test.o $(CORE_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_queue_test.o $(CORE_LIB) $(QUEUE_TEST_LDLIBS)

# Explicit rule for cf_decap_test.o so it gets -I$(PACKET_DIR) instead of
# the generic rule's -I core.
$(BUILD_DIR)/cf_decap_test.o: cf_decap_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DECAP_TEST_CPPFLAGS) -c $< -o $@

$(DECAP_BIN): $(BUILD_DIR)/cf_decap_test.o $(PACKET_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_decap_test.o $(PACKET_LIB) $(DECAP_TEST_LDLIBS)

# Explicit rule for cf_dhcpv4_test.o so it gets -I$(PACKET_DIR) + the codec
# gen dir + libprotobuf-c cflags + -DFIXTURES_DIR instead of the generic
# rule's -I core.
$(BUILD_DIR)/cf_dhcpv4_test.o: cf_dhcpv4_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DHCPV4_TEST_CPPFLAGS) -c $< -o $@

$(DHCPV4_BIN): $(BUILD_DIR)/cf_dhcpv4_test.o $(PACKET_LIB) $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_dhcpv4_test.o $(PACKET_LIB) $(CODEC_LIB) $(DHCPV4_TEST_LDLIBS)

# Explicit rule for cf_dhcpv6_test.o, same reasoning as cf_dhcpv4_test.o
# above.
$(BUILD_DIR)/cf_dhcpv6_test.o: cf_dhcpv6_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DHCPV6_TEST_CPPFLAGS) -c $< -o $@

$(DHCPV6_BIN): $(BUILD_DIR)/cf_dhcpv6_test.o $(PACKET_LIB) $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_dhcpv6_test.o $(PACKET_LIB) $(CODEC_LIB) $(DHCPV6_TEST_LDLIBS)

# Explicit rule for cf_dns_test.o (WP-DNS03), same reasoning as the DHCP test
# objects above: it needs -I$(PACKET_DIR) + the codec gen dir + libprotobuf-c
# cflags instead of the generic rule's -I core.
$(BUILD_DIR)/cf_dns_test.o: cf_dns_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DNS_TEST_CPPFLAGS) -c $< -o $@

$(DNS_BIN): $(BUILD_DIR)/cf_dns_test.o $(PACKET_LIB) $(CODEC_LIB)
	$(LINK.o) -o $@ $(BUILD_DIR)/cf_dns_test.o $(PACKET_LIB) $(CODEC_LIB) $(DNS_TEST_LDLIBS)

# ---------------------------------------------------------------------------
# test-tsan (WP-04)
#
# TSan has to see every load/store it's asked to reason about, so linking
# against the plain libcloudflow-core.a (built without -fsanitize=thread by
# `make build`) is not enough -- cf_queue.c needs to be compiled straight
# into this binary with instrumentation. -O1 -g is the flag combination TSan
# itself recommends (higher optimization can fold away the very loads/stores
# under test; no optimization makes the run needlessly slow).
#
# The hardened link flags from mk/toolchain.mk (-pie -z relro -z now
# -z noexecstack) are kept here because they link cleanly together with
# -fsanitize=thread on this toolchain (gcc 13 / glibc, tested); if a future
# toolchain's link fails with them, drop $(HARDEN_LDFLAGS)/-pie for this
# binary only (not for the regular build) and note why here.
TSAN_CFLAGS    := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=thread -pthread
TSAN_CPPFLAGS  := -I$(CORE_DIR)
TSAN_LDFLAGS   := -fsanitize=thread -pthread $(LDFLAGS)
TSAN_LDLIBS    := -lcunit -pthread

TSAN_BIN := $(BUILD_DIR)/cf_queue_test_tsan

test-tsan: $(TSAN_BIN)
	./$(TSAN_BIN)

$(BUILD_DIR)/cf_queue_test.tsan.o: cf_queue_test.c | $(BUILD_DIR)
	$(CC) $(TSAN_CFLAGS) $(TSAN_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/cf_queue.tsan.o: $(CORE_DIR)/cf_queue.c | $(BUILD_DIR)
	$(CC) $(TSAN_CFLAGS) $(TSAN_CPPFLAGS) -c $< -o $@

$(TSAN_BIN): $(BUILD_DIR)/cf_queue_test.tsan.o $(BUILD_DIR)/cf_queue.tsan.o
	$(CC) $(TSAN_LDFLAGS) -o $@ $(BUILD_DIR)/cf_queue_test.tsan.o $(BUILD_DIR)/cf_queue.tsan.o $(TSAN_LDLIBS)

# ---------------------------------------------------------------------------
# test-asan (WP-16)
#
# ASan+UBSan build of all four unit test binaries. -O1 -g matches the
# TSan recipe above (ASan's own recommendation: high enough to run at a
# reasonable speed, low enough that loads/stores under test survive
# unfolded); -fno-omit-frame-pointer keeps ASan's stack traces symbolized.
# Each binary compiles the library sources it needs straight in (same
# reasoning as test-tsan: linking the plain, uninstrumented .a built by
# `make build` would leave the library code itself uninstrumented), using a
# per-binary object suffix (asan_<binary>_<source>.o) so the four binaries'
# objects -- several of which share a source basename (e.g. cf_queue.c is
# compiled for both the queue binary and, indirectly, nothing else here) --
# never collide in $(BUILD_DIR).
#
# As with test-tsan, the hardened link flags from mk/toolchain.mk are kept
# on the theory that they link cleanly with -fsanitize=address,undefined on
# this toolchain (gcc 13 / glibc, tested); if a future toolchain's link
# fails with them, drop $(HARDEN_LDFLAGS)/-pie for these binaries only and
# note why here.
ASAN_CFLAGS   := $(CSTD) $(WARN_FLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_LDFLAGS  := -fsanitize=address,undefined $(LDFLAGS)
ASAN_LDLIBS   := -lcunit

# -- core (cf_core_test + the core lib sources it actually exercises: the
# core suites cover sha256/event-id/log/time, not the queue, so cf_queue.c
# is intentionally left out here -- it gets its own instrumented build
# below, under the queue binary.) --
CORE_ASAN_TEST_SOURCES := cf_core_test.c cf_sha256_test.c cf_event_id_test.c cf_log_test.c cf_time_test.c cf_sync_test.c
CORE_ASAN_LIB_SOURCES  := cloudflow.c cf_time.c cf_sync.c cf_log.c cf_event_id.c sha256.c

CORE_ASAN_OBJECTS := $(addprefix $(BUILD_DIR)/asan_core_,$(CORE_ASAN_TEST_SOURCES:.c=.o)) \
                      $(addprefix $(BUILD_DIR)/asan_core_,$(CORE_ASAN_LIB_SOURCES:.c=.o))

CORE_ASAN_BIN := $(BUILD_DIR)/cf_core_test_asan

$(BUILD_DIR)/asan_core_%.o: %.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) -I$(CORE_DIR) -c $< -o $@

$(BUILD_DIR)/asan_core_%.o: $(CORE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(ASAN_CFLAGS) -I$(CORE_DIR) -c $< -o $@

$(CORE_ASAN_BIN): $(CORE_ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(CORE_ASAN_OBJECTS) $(ASAN_LDLIBS)

# -- codec (cf_codec_test + the generated protobuf-c sources) --
CODEC_ASAN_SOURCES := cf_codec_test.c
CODEC_ASAN_GEN_SOURCES := $(notdir $(wildcard $(CODEC_GEN_DIR)/cloudflow/v1/*.pb-c.c))

CODEC_ASAN_OBJECTS := $(addprefix $(BUILD_DIR)/asan_codec_,$(CODEC_ASAN_SOURCES:.c=.o)) \
                       $(addprefix $(BUILD_DIR)/asan_codec_,$(CODEC_ASAN_GEN_SOURCES:.c=.o))

CODEC_ASAN_CFLAGS := $(ASAN_CFLAGS) -I$(CODEC_GEN_DIR) $(shell pkg-config --cflags libprotobuf-c)
CODEC_ASAN_LDLIBS := -lcunit $(shell pkg-config --libs libprotobuf-c)

CODEC_ASAN_BIN := $(BUILD_DIR)/cf_codec_test_asan

$(BUILD_DIR)/asan_codec_%.o: %.c | $(BUILD_DIR)
	$(CC) $(CODEC_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_codec_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(CODEC_ASAN_CFLAGS) -c $< -o $@

$(CODEC_ASAN_BIN): $(CODEC_ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(CODEC_ASAN_OBJECTS) $(CODEC_ASAN_LDLIBS)

# -- queue (cf_queue_test + cf_queue.c, instrumented -- the 2-thread stress
# test needs pthread on top of the base ASan flags) --
QUEUE_ASAN_CFLAGS  := $(ASAN_CFLAGS) -pthread -I$(CORE_DIR)
QUEUE_ASAN_LDFLAGS := $(ASAN_LDFLAGS) -pthread
QUEUE_ASAN_LDLIBS  := -lcunit -pthread

QUEUE_ASAN_BIN := $(BUILD_DIR)/cf_queue_test_asan

$(BUILD_DIR)/asan_queue_cf_queue_test.o: cf_queue_test.c | $(BUILD_DIR)
	$(CC) $(QUEUE_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_queue_cf_queue.o: $(CORE_DIR)/cf_queue.c | $(BUILD_DIR)
	$(CC) $(QUEUE_ASAN_CFLAGS) -c $< -o $@

$(QUEUE_ASAN_BIN): $(BUILD_DIR)/asan_queue_cf_queue_test.o $(BUILD_DIR)/asan_queue_cf_queue.o
	$(CC) $(QUEUE_ASAN_LDFLAGS) -o $@ $(BUILD_DIR)/asan_queue_cf_queue_test.o $(BUILD_DIR)/asan_queue_cf_queue.o $(QUEUE_ASAN_LDLIBS)

# -- decap (cf_decap_test + cf_decap.c, cf_ipfmt.c) --
DECAP_ASAN_CFLAGS := $(ASAN_CFLAGS) -I$(PACKET_DIR)

DECAP_ASAN_BIN := $(BUILD_DIR)/cf_decap_test_asan

$(BUILD_DIR)/asan_decap_%.o: %.c | $(BUILD_DIR)
	$(CC) $(DECAP_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_decap_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(DECAP_ASAN_CFLAGS) -c $< -o $@

$(DECAP_ASAN_BIN): $(BUILD_DIR)/asan_decap_cf_decap_test.o $(BUILD_DIR)/asan_decap_cf_decap.o $(BUILD_DIR)/asan_decap_cf_ipfmt.o
	$(CC) $(ASAN_LDFLAGS) -o $@ $(BUILD_DIR)/asan_decap_cf_decap_test.o $(BUILD_DIR)/asan_decap_cf_decap.o $(BUILD_DIR)/asan_decap_cf_ipfmt.o $(ASAN_LDLIBS)

# -- dhcpv4 (cf_dhcpv4_test + cf_decap.c/cf_ipfmt.c + the WP-06 cf_dhcpv4*.c
# sources, instrumented, plus the generated common.pb-c.c/dhcp.pb-c.c
# sources DhcpV4PacketEvent needs -- envelope.pb-c.c is intentionally left
# out, nothing here touches EventEnvelope/CloudFlowEvent) --
DHCPV4_ASAN_CFLAGS := $(ASAN_CFLAGS) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                       $(shell pkg-config --cflags libprotobuf-c) -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
DHCPV4_ASAN_LDLIBS := -lcunit $(shell pkg-config --libs libprotobuf-c)

DHCPV4_ASAN_PACKET_SOURCES := cf_decap.c cf_ipfmt.c cf_dhcpv4.c cf_dhcpv4_decode.c \
                               cf_dhcpv4_util.c cf_dhcpv4_optnames.c
DHCPV4_ASAN_GEN_SOURCES    := common.pb-c.c dhcp.pb-c.c

DHCPV4_ASAN_OBJECTS := $(BUILD_DIR)/asan_dhcpv4_cf_dhcpv4_test.o \
                        $(addprefix $(BUILD_DIR)/asan_dhcpv4_,$(DHCPV4_ASAN_PACKET_SOURCES:.c=.o)) \
                        $(addprefix $(BUILD_DIR)/asan_dhcpv4_,$(DHCPV4_ASAN_GEN_SOURCES:.c=.o))

DHCPV4_ASAN_BIN := $(BUILD_DIR)/cf_dhcpv4_test_asan

$(BUILD_DIR)/asan_dhcpv4_cf_dhcpv4_test.o: cf_dhcpv4_test.c | $(BUILD_DIR)
	$(CC) $(DHCPV4_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcpv4_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(DHCPV4_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcpv4_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(DHCPV4_ASAN_CFLAGS) -c $< -o $@

$(DHCPV4_ASAN_BIN): $(DHCPV4_ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(DHCPV4_ASAN_OBJECTS) $(DHCPV4_ASAN_LDLIBS)

# -- dhcpv6 (cf_dhcpv6_test + cf_decap.c/cf_ipfmt.c + the WP-07 cf_dhcpv6*.c
# sources, instrumented, plus the generated common.pb-c.c/dhcp.pb-c.c
# sources DhcpV6PacketEvent needs -- same reasoning as the dhcpv4 block
# above) --
DHCPV6_ASAN_CFLAGS := $(ASAN_CFLAGS) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                       $(shell pkg-config --cflags libprotobuf-c) -DFIXTURES_DIR=\"$(FIXTURES_DIR)\"
DHCPV6_ASAN_LDLIBS := -lcunit $(shell pkg-config --libs libprotobuf-c)

DHCPV6_ASAN_PACKET_SOURCES := cf_decap.c cf_ipfmt.c cf_dhcpv6.c cf_dhcpv6_decode.c \
                               cf_dhcpv6_util.c cf_dhcpv6_optnames.c
DHCPV6_ASAN_GEN_SOURCES    := common.pb-c.c dhcp.pb-c.c

DHCPV6_ASAN_OBJECTS := $(BUILD_DIR)/asan_dhcpv6_cf_dhcpv6_test.o \
                        $(addprefix $(BUILD_DIR)/asan_dhcpv6_,$(DHCPV6_ASAN_PACKET_SOURCES:.c=.o)) \
                        $(addprefix $(BUILD_DIR)/asan_dhcpv6_,$(DHCPV6_ASAN_GEN_SOURCES:.c=.o))

DHCPV6_ASAN_BIN := $(BUILD_DIR)/cf_dhcpv6_test_asan

$(BUILD_DIR)/asan_dhcpv6_cf_dhcpv6_test.o: cf_dhcpv6_test.c | $(BUILD_DIR)
	$(CC) $(DHCPV6_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcpv6_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(DHCPV6_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dhcpv6_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(DHCPV6_ASAN_CFLAGS) -c $< -o $@

$(DHCPV6_ASAN_BIN): $(DHCPV6_ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(DHCPV6_ASAN_OBJECTS) $(DHCPV6_ASAN_LDLIBS)

# -- dns (cf_dns_test + cf_ipfmt.c + the WP-DNS03 cf_parse_util.c/cf_dns.c
# sources, instrumented, plus the generated common.pb-c.c/dns.pb-c.c sources
# DnsMessage needs -- same "compile the library sources straight in" reasoning
# as the dhcpv4/dhcpv6 blocks above. This is the security-critical suite
# (name decompression / compression-loop fuzzing), so an ASan/UBSan run over
# it is the point of the exercise.) --
DNS_ASAN_CFLAGS := $(ASAN_CFLAGS) -I$(PACKET_DIR) -I$(CODEC_GEN_DIR) \
                    $(shell pkg-config --cflags libprotobuf-c)
DNS_ASAN_LDLIBS := -lcunit $(shell pkg-config --libs libprotobuf-c)

DNS_ASAN_PACKET_SOURCES := cf_ipfmt.c cf_parse_util.c cf_dns.c
DNS_ASAN_GEN_SOURCES    := common.pb-c.c dns.pb-c.c

DNS_ASAN_OBJECTS := $(BUILD_DIR)/asan_dns_cf_dns_test.o \
                     $(addprefix $(BUILD_DIR)/asan_dns_,$(DNS_ASAN_PACKET_SOURCES:.c=.o)) \
                     $(addprefix $(BUILD_DIR)/asan_dns_,$(DNS_ASAN_GEN_SOURCES:.c=.o))

DNS_ASAN_BIN := $(BUILD_DIR)/cf_dns_test_asan

$(BUILD_DIR)/asan_dns_cf_dns_test.o: cf_dns_test.c | $(BUILD_DIR)
	$(CC) $(DNS_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dns_%.o: $(PACKET_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(DNS_ASAN_CFLAGS) -c $< -o $@

$(BUILD_DIR)/asan_dns_%.o: $(CODEC_GEN_DIR)/cloudflow/v1/%.c | $(BUILD_DIR)
	$(CC) $(DNS_ASAN_CFLAGS) -c $< -o $@

$(DNS_ASAN_BIN): $(DNS_ASAN_OBJECTS)
	$(CC) $(ASAN_LDFLAGS) -o $@ $(DNS_ASAN_OBJECTS) $(DNS_ASAN_LDLIBS)

test-asan: $(CORE_ASAN_BIN) $(CODEC_ASAN_BIN) $(QUEUE_ASAN_BIN) $(DECAP_ASAN_BIN) $(DHCPV4_ASAN_BIN) $(DHCPV6_ASAN_BIN) $(DNS_ASAN_BIN)
	./$(CORE_ASAN_BIN)
	./$(CODEC_ASAN_BIN)
	./$(QUEUE_ASAN_BIN)
	./$(DECAP_ASAN_BIN)
	./$(DHCPV4_ASAN_BIN)
	./$(DHCPV6_ASAN_BIN)
	./$(DNS_ASAN_BIN)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
