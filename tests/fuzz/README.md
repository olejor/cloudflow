# Fuzzing cf_decap_udp()

`decap_fuzz.c` is an AFL-style harness: it reads one frame (from the file
named in `argv[1]`, or stdin if no argument is given) and calls
`cf_decap_udp()` on it. Not wired into `make test` or the top-level
`SUBDIRS` -- it only needs to build; running it under AFL is a manual local
step. Same conventions as
`import/network_syslog_collector/tests/Fuzzing.md`.

Build the harness (plain gcc, not the hardened toolchain):

```sh
make -C libs/cloudflow-packet all   # build/libcloudflow-packet.a
make -C tests/fuzz all              # tests/fuzz/decap_fuzz
```

Run it once against a single file to sanity-check it (exit code 0, no
crash):

```sh
./tests/fuzz/decap_fuzz some_frame.bin
```

To fuzz with AFL, rebuild with the instrumenting compiler and run
`afl-fuzz` against a small seed corpus (e.g. the raw bytes of the frames
built in `tests/unit/cf_decap_test.c`):

```sh
make -C tests/fuzz clean
make -C tests/fuzz CC=afl-gcc all

mkdir -p tests/fuzz/testcases tests/fuzz/findings
# seed with a couple of plausible frames, e.g. an untagged IPv4/UDP frame
# and a QinQ IPv6/UDP frame dumped to disk from the unit test builders.

timeout 10m afl-fuzz -i tests/fuzz/testcases -o tests/fuzz/findings \
    -- ./tests/fuzz/decap_fuzz @@
```

## Fuzzing cf_dhcpv4_parse() (WP-06)

`dhcpv4_fuzz.c` is the same style of harness for the DHCPv4 parser
(`libs/cloudflow-packet/cf_dhcpv4.c`): it reads one DHCPv4 payload (the
bytes that would follow the UDP header -- not a full frame) from
`argv[1]`/stdin, calls `cf_dhcpv4_parse()`, and if that succeeds also packs
and frees the resulting event (so packing/freeing a maximally-populated,
possibly-malformed tree is exercised too). Build it the same way:

```sh
make -C libs/cloudflow-packet all   # build/libcloudflow-packet.a
make -C libs/cloudflow-codec all    # build/libcloudflow-codec.a
make -C tests/fuzz all              # tests/fuzz/dhcpv4_fuzz
```

To fuzz with AFL, seed with the DHCPv4 payloads extracted from
`tests/fixtures/dhcp/v4_*.pcap` (strip Ethernet/IP/UDP -- e.g. via scapy's
`bytes(pkt[UDP].payload)`) and run the same way as `decap_fuzz` above,
substituting `./tests/fuzz/dhcpv4_fuzz`.

If AFL isn't available, `dhcpv4_fuzz_quick_check.sh` is a one-shot
fallback: it builds an ASan+UBSan `dhcpv4_fuzz`, extracts a seed payload
from every `v4_*.pcap` fixture, runs the harness over each seed, generates
1000 deterministic truncation/bit-flip variants of those seeds, and runs
the harness over all of them, failing if anything crashes or leaks.

```sh
./tests/fuzz/dhcpv4_fuzz_quick_check.sh
```

## Fuzzing cf_dhcpv6_parse() (WP-07)

`dhcpv6_fuzz.c` is the same style of harness for the DHCPv6 parser
(`libs/cloudflow-packet/cf_dhcpv6.c`): it reads one DHCPv6 payload (the
bytes that would follow the UDP header) from `argv[1]`/stdin, calls
`cf_dhcpv6_parse()`, and if that succeeds also packs and frees the
resulting event. Build it the same way:

```sh
make -C libs/cloudflow-packet all   # build/libcloudflow-packet.a
make -C libs/cloudflow-codec all    # build/libcloudflow-codec.a
make -C tests/fuzz all              # tests/fuzz/dhcpv6_fuzz
```

To fuzz with AFL, seed with the DHCPv6 payloads extracted from
`tests/fixtures/dhcp/v6_*.pcap` (strip Ethernet/IPv6/UDP -- e.g. via
scapy's `bytes(pkt[UDP].payload)`) and run the same way as `decap_fuzz`
above, substituting `./tests/fuzz/dhcpv6_fuzz`.

If AFL isn't available, `dhcpv6_fuzz_quick_check.sh` is the same one-shot
fallback as `dhcpv4_fuzz_quick_check.sh`, over the `v6_*.pcap` fixtures:

```sh
./tests/fuzz/dhcpv6_fuzz_quick_check.sh
```
