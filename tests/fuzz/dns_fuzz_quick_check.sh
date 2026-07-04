#!/usr/bin/env bash
# tests/fuzz/dns_fuzz_quick_check.sh
#
# WP-DNS09 fallback for "10-minute local AFL run" when AFL isn't installed
# (mirrors dhcpv4_fuzz_quick_check.sh / dhcpv6_fuzz_quick_check.sh). Builds
# dns_fuzz once with ASan+UBSan (more likely to turn a bad read into a hard
# failure than a silent pass), extracts a BARE DNS message from every
# committed tests/fixtures/dns/*.pcap as a seed corpus -- for udp/53 the UDP
# payload, for tcp/53 the TCP payload with its leading 2-byte length prefix
# stripped (DNS-D1: cf_dns_parse takes a bare message, never framing) -- runs
# the harness over each seed, then generates 1000 deterministic
# truncation/bit-flip variants of those seeds and runs the harness over all
# of them. Prints a summary and exits non-zero if any invocation crashed or
# leaked.
#
# Usage: tests/fuzz/dns_fuzz_quick_check.sh
# (requires libs/cloudflow-packet + libs/cloudflow-codec to be buildable,
# and python3 with scapy to extract seed messages from the fixture pcaps)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FUZZ_DIR="$ROOT/tests/fuzz"
FIXTURES_DIR="$ROOT/tests/fixtures/dns"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== building ASan dns_fuzz =="
"${CC:-gcc}" -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I "$ROOT/libs/cloudflow-packet" -I "$ROOT/libs/cloudflow-codec/gen" \
    $(pkg-config --cflags libprotobuf-c) \
    -o "$WORK_DIR/dns_fuzz_asan" "$FUZZ_DIR/dns_fuzz.c" \
    "$ROOT/libs/cloudflow-packet/build/libcloudflow-packet.a" \
    "$ROOT/libs/cloudflow-codec/build/libcloudflow-codec.a" \
    $(pkg-config --libs libprotobuf-c)

BIN="$WORK_DIR/dns_fuzz_asan"
SEEDS_DIR="$WORK_DIR/seeds"
mkdir -p "$SEEDS_DIR"

echo "== extracting bare-DNS-message seeds from tests/fixtures/dns/*.pcap =="
python3 - "$FIXTURES_DIR" "$SEEDS_DIR" <<'PYEOF'
import sys
import glob
import os
from scapy.all import rdpcap, TCP, UDP

fixtures_dir, seeds_dir = sys.argv[1], sys.argv[2]
count = 0
for path in sorted(glob.glob(os.path.join(fixtures_dir, "*.pcap"))):
    pkt = rdpcap(path)[0]
    if pkt.haslayer(UDP):
        # udp/53: the UDP payload is already a bare DNS message.
        payload = bytes(pkt[UDP].payload)
    elif pkt.haslayer(TCP):
        # tcp/53: strip the leading 2-byte length prefix (RFC 1035 4.2.2).
        payload = bytes(pkt[TCP].payload)[2:]
    else:
        continue
    name = os.path.splitext(os.path.basename(path))[0]
    with open(os.path.join(seeds_dir, name + ".bin"), "wb") as f:
        f.write(payload)
    count += 1
print(f"extracted {count} seed messages")
PYEOF

echo "== running harness over seed messages =="
seed_count=0
for seed in "$SEEDS_DIR"/*.bin; do
    "$BIN" "$seed"
    seed_count=$((seed_count + 1))
done
echo "ran $seed_count seed messages: no crash"

echo "== generating + running 1000 truncation/bit-flip variants =="
python3 - "$SEEDS_DIR" "$WORK_DIR/variants" <<'PYEOF'
import glob
import os
import sys

seeds_dir, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)

seeds = sorted(glob.glob(os.path.join(seeds_dir, "*.bin")))
variants = []
i = 0
# Deterministic pseudo-random bit-flip positions (no external RNG needed):
# a simple LCG seeded from a fixed constant, so this script's output is
# reproducible run to run.
state = 0x2545F4914F6CDD1D
def next_val(modulus):
    global state
    state = (state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
    return (state >> 33) % modulus

while len(variants) < 1000:
    seed_path = seeds[i % len(seeds)]
    with open(seed_path, "rb") as f:
        data = bytearray(f.read())
    i += 1
    if i % 2 == 0 and len(data) > 0:
        # truncation variant
        cut = next_val(len(data) + 1)
        data = data[:cut]
    else:
        # bit-flip variant(s)
        if len(data) > 0:
            for _ in range(next_val(4) + 1):
                pos = next_val(len(data))
                bit = next_val(8)
                data[pos] ^= (1 << bit)
    out_path = os.path.join(out_dir, f"variant_{len(variants):04d}.bin")
    with open(out_path, "wb") as f:
        f.write(data)
    variants.append(out_path)

print(f"generated {len(variants)} variants")
PYEOF

variant_count=0
for variant in "$WORK_DIR/variants"/*.bin; do
    "$BIN" "$variant"
    variant_count=$((variant_count + 1))
done
echo "ran $variant_count truncation/bit-flip variants: no crash"

echo "== ASan-instrumented dns_fuzz quick check: PASS (no crash across $((seed_count + variant_count)) inputs) =="
